package algorithms

import java.lang.Double

import com.google.inject.{Inject, Singleton}
import models.{IterationResultHistory, Packet}
import play.api.Logger
import services.{HoneypotService, IterationResultHistoryService, PacketService}
import worker.ScanDetectWorker
import AlgorithmUtils._
import akka.actor.ActorSystem
import neuralnetwork.CheckingContext
import neuralnetwork.CheckingContext._
import utils.Constants.SettingsKeys
import utils.{Constants, Protocols}

import collection.JavaConverters._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration._

trait Algorithm {
  def detect(worker: ScanDetectWorker, packets: Seq[Packet]): Future[Unit]
  def fetchPacketsFromThisConnection(flowKey: Long): Future[Seq[Packet]]
  def filterIterationResult[A <: IterationResult](iterationResult: A): Future[IterationResult]
  def checkForAttack[A <: IterationResult](iterationResult: A)(old: Seq[Packet], analyzed: Seq[Packet])
  def createCheckingContext[A <: IterationResult](sourceAddress: String, iterationResult: A): Future[CheckingContext]
  def checkForAttackWithNeuralNetwork[A <: IterationResult](iterationResult: A): Future[String]
  def createIterationResultHistory[A <: IterationResult](iterationResult: A)
}

object ScanDetectionAlgorithm {

  /**
  Zbiór etykiet oznaczajacych potencjalny atak skanowania portów
    */
  val PORT_SCAN_CONTEXT_LABELS = Set(
    //brak transferu danych
    IterationResultHistoryLabels.didNotSendData,

    //zamknięty port
    IterationResultHistoryLabels.portClosed,

    //podejrzany atak TCP FIN
    IterationResultHistoryLabels.suspiciousFinScanAttack,

    //podejrzany atak TCP ACK WIN
    IterationResultHistoryLabels.suspiciousAckWinScanAttack,

    //podejrzany atak TCP Maimon
    IterationResultHistoryLabels.suspiciousMaimonScanAttack
  )

  /**
  Zbiór etykiet określających zdarzenie otwartego portu
   */
  val OPEN_PORTS_COUNTER_LABELS = Set(
    //transfer danych
    IterationResultHistoryLabels.sendData,

    //zakończony transfer danych
    IterationResultHistoryLabels.removeFinePackets,

    //brak transferu danych
    IterationResultHistoryLabels.didNotSendData
  )

  /**
  Zbiór etykiet określających zdarzenie zamkniętego/filtrowanego portu
   */
  val CLOSED_PORTS_COUNTER_LABELS = Set(
    //zamknięty port
    IterationResultHistoryLabels.portClosed,

    //podejrzany atak TCP FIN
    IterationResultHistoryLabels.suspiciousFinScanAttack,

    //podejrzany atak TCP ACK WIN
    IterationResultHistoryLabels.suspiciousAckWinScanAttack,

    //podejrzany atak TCP Maimon
    IterationResultHistoryLabels.suspiciousMaimonScanAttack
  )

  /**
  Etykiety zdarzeń zapisywanych do bazy danych
   */
  object IterationResultHistoryLabels {
    //brak transferu danych
    val didNotSendData = DidNotSendData.getClass.getName.split("\\$").last

    //maszyna na której zaisntalwoany ejst rpogram inicjuje połączenie
    val initializingConnection = InitializingConnection.getClass.getName.split("\\$").last

    //transfer danych
    val sendData = SendData.getClass.getName.split("\\$").last

    //transfer danych, pakiety do usunięcia i host inicjował połaczenie
    val initializingRemoveFinePackets = InitializingRemoveFinePackets.getClass.getName.split("\\$").last

    //zamknięty port
    val portClosed = PortClosed.getClass.getName.split("\\$").last

    //podejrzany atak skanowania sieci
    val suspiciousNetworkScan = SuspiciousNetworkScan.getClass.getName.split("\\$").last

    //zakończony transfer danych
    val removeFinePackets = RemoveFinePackets.getClass.getName.split("\\$").last

    //podejrzany atak TCP FIN
    val suspiciousFinScanAttack = SuspiciousFinScanAttack.getClass.getName.split("\\$").last

    //podejrzany atak TCP ACK WIN
    val suspiciousAckWinScanAttack = SuspiciousAckWinScanAttack.getClass.getName.split("\\$").last

    //podejrzany atak TCP Maimon
    val suspiciousMaimonScanAttack = SuspiciousMaimonScanAttack.getClass.getName.split("\\$").last
  }

}

/**
  * Created by Marcin on 2016-10-22.
  */
@Singleton
class ScanDetectionAlgorithm @Inject() (packetService: PacketService,
                                        iterationResultHistoryService: IterationResultHistoryService,
                                        honeypotService: HoneypotService,
                                        akkaSystem: ActorSystem) {

  val log = Logger

  /**
    * Pula wątków algorytmu.
    */
  implicit val workerContext: ExecutionContext = akkaSystem.dispatchers.lookup("worker-context")

  /**
    * Referencja do workera wywołującego algorytm.
    */
  var worker: ScanDetectWorker = _

  /**
    * Metoda wykrywająca zdarzenia jakie wystapiło dla danej grupy pakietów. Przyjmuje jako argument sekwencję do 500
    * pakietów. Metoda grupuje te pakiety i każda grupa analizowana jest oddzielnie aby okreslić konkretne zdarzenie.
    *
    * @param worker - referencja workera wywołującego algorytm
    * @param packets - sekwencja pakietów do analizy (maksymalnie 500)
    * @return
    */
  def detect(worker: ScanDetectWorker, packets: Seq[Packet]): Seq[Future[Any]] = {
    //Przypisanie referencji workera
    this.worker = worker

    //Pogrupowanie pakietów na podstawie klucza połączenia i klucza wygenerowanego tylko dla warstwy internetowej.
    //Dzięki temu mamy grupę pakietów UDP z powiązanymi pakietami ICMP i na odwrót.
    val groupByForNetworkLayer = packets.sortBy(_.timestamp).groupBy(p =>
      (p.flowKey, p.additionalHashNetwork)
    )

    //Pogrupwoanie pakietów na podstawie klucza połaczenia, hash kodu warstwy transportowej oraz
    //hash kodu warstwy internetowej. Pakiety ICMP są grupowane oddzielnie.
    log.info(s"Starting iteration for detecting scans for ${packets.size} packets.")
    val groupedByFlowKey: Map[(Long, Long, Long), Seq[Packet]] = packets.sortBy(_.timestamp).groupBy(p =>
      if (p.protocol != Protocols.ICMP)
      (p.flowKey, p.additionalHash, p.additionalHashNetwork)
      else
      (p.flowKey, Constants.ICMP_HASHCODE, p.additionalHashNetwork)
    )

    log.info(s"Got ${groupedByFlowKey.size} groups of flow keys.")

    //Iterowanie po grupach pakietów. Zwracana będzie sekwencja asynchronicznych wyników z konkretnymi zdarzeniami
    val iterationResult: Future[Iterable[IterationResult]] = Future.sequence(groupedByFlowKey.map(entry => {
      val f = Future {
        val flowKey : Long = entry._1._1 //klucz połaczenia
        val protocol = entry._2.head.protocol //protokół
        val additionalHash : Long = entry._1._2 //hash kod warstwy transportowej
        val additionalHashNetwork : Long = entry._1._3 //hash kod warstwy internetowej
        val newPackets = entry._2 ++ (if (protocol == Protocols.ICMP) {
          groupByForNetworkLayer.getOrElse((flowKey, additionalHashNetwork), Seq())
            .filter(_.isUdp)
        } else if (protocol == Protocols.UDP) {
          groupedByFlowKey.getOrElse((flowKey, Constants.ICMP_HASHCODE, additionalHashNetwork), Seq())
            .filter(_.isIcmp)
        } else {
          Seq()
        }) //nowe pakiety do analizy i dodatkowe pakiety ICMP w przypadku protokołu UDP i na odwrót

        log.info(s"Starting analyzing packets for $flowKey flow key.")

        //Pobranie dodatkowych pakietów z tego połaczenia, które zostały już wcześniej przeanalizowane.
        val f1 = fetchPacketsFromThisConnection(protocol, flowKey, additionalHash)
        while (!f1.isCompleted) Thread.sleep(500)
        val analyzed = f1.value.get.get //pakiety wcześniej przeanalizowane

        if (analyzed.nonEmpty) log.info(s"Fetched ${analyzed.size} packets for $flowKey flow key.")
        log.info(s"Got ${newPackets.size} new packets to analyze.")

        //Stworzenie jednej kolekcji składającej się z nowych pakietów,
        //przeanalizowanych, dodatkowych pakietów UDP lub ICMP i posortowanie ich po czasie przechwycenia.
        val packetsToAnalyze = (newPackets ++ analyzed).sortBy(_.timestamp)

        log.info(s"Analyzing total ${packetsToAnalyze.size} packets.")

        //Określenie adresu łączącego się z maszyną na której działa program
        val sourceAddress = getSourceAddress(packetsToAnalyze)

        //Jeżeli adres został odnotowany na maszynie Honeypota to zgłaszany jest atak skanowania sieci.
        if (wasRegisteredByHoneypot(sourceAddress)) {
          log.info(s"$sourceAddress was registered by honeypot.")
          NetworkScanAlert(newPackets, analyzed)

        //Sprawdzenie czy protokół jest z warstwy internetowej i jest wspierany. Jeżeli tak to zwracane jest
        //zdarzenie podejrzanego ataku skanowania sieci
        } else if (isSupportedInternetProtocol(protocol) &&
          incomingContainsInternetProtocol(packetsToAnalyze, protocol)) {

          log.info(s"Marking $sourceAddress as suspicious network scan.")
          SuspiciousNetworkScan(newPackets, analyzed)

        //Sprawdzenie czy protokół jest z warstwy transportowej i jest wspierany
        } else if (isSupportedTransportProtocol(protocol)) {

            //Sprawdzenie czy protokół jest połączeniowy
            if (isConnectionProtocol(protocol)) {

              //Sprawdzenie czy występuje pakiet bez jakiejkolwiek flagi. Jeżeli tak to tworzone jest zdarzenie
              //określające atak TCP NULL.
              if (tcpPacketWithoutAnyFlag(protocol, packetsToAnalyze)) {
                log.info(s"TCP NULL scan attack from $sourceAddress.")
                TcpNullScanAttack(newPackets, analyzed)

              //Sprawdzenie czy występuje pakiet TCP ACK z wartością sekwencji równej 0. Jeżeli tak to tworzone
              //jest zdarzenie określające atak TCP ACK.
              } else if (isAckWinScan(protocol, packetsToAnalyze)) {
                log.info(s"ACK/WIN scan attack from $sourceAddress. Port scan alarm.")
                AckWinScanAttack(newPackets, analyzed, 100) //100% szansy

              //Sprawdzenie czy występuje podejrzany atak TCP ACK.
              } else if (isSuspiciousAckWinScan(protocol, packetsToAnalyze)) {
                log.info(s"Suspicious ACK/WIN scan attack from $sourceAddress.")
                SuspiciousAckWinScanAttack(newPackets, analyzed)

              //Sprawdzenie czy występuje pakiet TCP z flagami FIN PSH URG. Jeżeli tak to tworzone
              //jest zdarzenie określające atak TCP Xmas.
              } else if (isXmasAttack(protocol, packetsToAnalyze)) {
                log.info(s"Xmas scan attack from $sourceAddress.")
                XmasScanAttack(newPackets, analyzed)

              } else if (isInitializingConnection(protocol, packetsToAnalyze) && //Czy ta maszyna inicjuje połączenie
                !isConnectionClosed(protocol, packetsToAnalyze)) {   //Czy połączenie nie zostało zakończone

                log.info(s"Initialized connection")
                if (didSendAnyData(protocol, packetsToAnalyze)) {
                  //Zdarzenie inicjowania połączenia i transferu danych
                  InitializingConnectionAndDataTransfer(newPackets, analyzed)
                } else {
                  //Zdarzenie inicjowania połączenia
                  InitializingConnection(newPackets, analyzed)
                }

              //Zgłoszenie zdarzenia, że port jest zamknięty
              } else if (isPortClosed(protocol, packetsToAnalyze)) {
                log.info(s"$sourceAddress tried to connect to an closed port.")
                PortClosed(newPackets, analyzed)

              //Zgłoszenie zdarzenia braku transmisji danych gdy pakiety nie miały żadnych danych i połaczenie
              //zostało zakończone. Wszystkie ataki nie przesyłają danych.
              } else if (!didSendAnyData(protocol, packetsToAnalyze) &&
                isConnectionClosed(protocol, packetsToAnalyze) &&
                wasNotProperlyFinished(protocol, packetsToAnalyze) &&
                (lastIsIncoming(protocol, packetsToAnalyze) || packetsToAnalyze.last.containsOnlyRstFlag ||
                  packetsToAnalyze.last.containsOnlyRstAckFLags)) {

                log.info(s"$sourceAddress connected to a port, did not send any data and connection was not properly " +
                  s"finished.")
                DidNotSendData(newPackets, analyzed)

              //Zgłoszenie zdarzenia usunięcia pakietów z danymi i gdy połączenie zostało juz zakończone.
              //Służy to oszczędności miejsca na dysku twardym.
              } else if (didSendAnyData(protocol, packetsToAnalyze) && isConnectionClosed(protocol, packetsToAnalyze)) {
                log.info(s"Removing ${packetsToAnalyze.size} fine packets")
                if (isInitializingConnection(protocol, packetsToAnalyze)) {
                  InitializingRemoveFinePackets(newPackets, analyzed)
                } else {
                  RemoveFinePackets(newPackets, analyzed)
                }

              //Sprawdzenie czy występuje pakiet TCP z flagami FIN ACK oraz z konkretnymi wartościami tj. sekwencja = 0,
              //okno = 1024, pakiet odpowiadajacy TCP z flagą RST
              } else if (isMaimonAttack(protocol, packetsToAnalyze)) {
                log.info(s"Maimon scan attack from $sourceAddress.")
                MaimonScanAttack(newPackets, analyzed, 100)

              //Sprawdzenie czy występuje podejrzany atak TCP Maimon.
              } else if (isSuspiciousMaimonAttack(protocol, packetsToAnalyze)) {
                log.info(s"Suspicious Maimon scan attack from $sourceAddress.")
                SuspiciousMaimonScanAttack(newPackets, analyzed)

              //Sprawdzenie czy występuje pakiet TCP z flaga FIN oraz z konkretnymi wartościami tj. sekwencja = 1,
              //okno = 1024, pakiet odpowiadajacy TCP z flagami RST i ACK i wartościami: sekwencja = 1, okno = 0
              } else if (isFinAttack(protocol, packetsToAnalyze)) {
                log.info(s"FIN scan attack from $sourceAddress.")
                FinScanAttack(newPackets, analyzed, 100)

              //Sprawdzenie czy występuje podejrzany atak TCP FIN.
              } else if (isSuspiciousFinAttack(protocol, packetsToAnalyze)) {
                log.info(s"Suspicious FIN scan attack from $sourceAddress.")
                SuspiciousFinScanAttack(newPackets, analyzed)

              } else {
                //Kontynuowanie interacji
                ContinueIteration(newPackets, analyzed)
              }
            } else {
              //Protokół jest bezpołaczeniowy

              if (isPortClosed(protocol, packetsToAnalyze)) {
                //Zgłoszenie zdarzenia, że port jest zamknięty
                PortClosed(newPackets, analyzed)
              } else {
                if (didSendAnyData(protocol, packetsToAnalyze)) {
                  //Zgłoszenie zdarzenia, że wystapiła transmisja danych
                  SendData(newPackets, analyzed)
                } else {
                  //Zgłoszenie zdarzenia, że nie wystapiło transmisji danych
                  DidNotSendData(newPackets, analyzed)
                }
              }
            }
        } else {
          //Kontynuowanie interacji
          ContinueIteration(newPackets, analyzed)
        }
      }
      f.onFailure{case e: Throwable => e.printStackTrace()} //Zgłoszenie błędu
      f //Zwrócenie asynchronciznego wyniku ze zdarzeniem
    }
    ))

    //Wyświetlenie liczby zarejestrowanych zdarzeń
    iterationResult.onSuccess {
      case rs =>
        log.info(s"Iteration finished. Got ${rs.size} iteration results.")
    }

    //Filtrowanie zarejestrowanych zdarzeń i ich obsłużenie
    Seq(iterationResult.map(rs =>
      rs.map(iterationRs => filterIterationResult(iterationRs).map(x => worker.dispatch(x)))
    ))
  }

  def detectNetworkScans(worker: ScanDetectWorker,
                         iterationResultHistoryData: Seq[IterationResultHistory]): Seq[Future[Any]] = {

    //Zdarzenia pogrupowane po adresie IP źródłowym
    val groupedBySourceAddress = iterationResultHistoryData.groupBy(_.sourceAddress)

    val iterationResult: Seq[NetworkScanAlert] = groupedBySourceAddress.flatMap(history => {
      val result = wasRegisteredByHoneypot(history._1) //czy adres został zarejestrowany przez honeypota

      //Jeżeli został zarejestrowany
      if (result) {
        val alerts = history._2.map(rs => {
          //Pobranie pakietów z tego połaczenia, które zostały już wcześniej przeanalizowane.
          val f1 = fetchPacketsFromThisConnection(rs.flowKey, rs.additionalHash)
          while (!f1.isCompleted) Thread.sleep(500)
          val analyzed = f1.value.get.get //pakiety wcześniej przeanalizowane
          NetworkScanAlert(Seq(), analyzed) //zgłoszenie alarmu skanowania sieci
        })
        alerts //zwrócenie alarmów
      } else {
        Seq() //brak alarmów
      }
    }).toSeq

    //Filtrowanie zarejestrowanych zdarzeń i ich obsłużenie
    iterationResult.map(rs => filterIterationResult(rs).map(x => worker.dispatch(x)))
  }

  /**
    * Metoda pobiera dodatkowe pakieta dla danego połączenia.
    *
    * @param protocol protokół
    * @param flowKey identyfikator połączenia
    * @param additionalHash dodatkowy hash kod
    * @return asynchroniczny wynik z sekwencja dodatkowych pakietów
    */
  def fetchPacketsFromThisConnection(protocol: String, flowKey: Long, additionalHash: Long): Future[Seq[Packet]] = {
    if (protocol == Protocols.UDP) {
      packetService.getAssociatedWithFlowKeyAndProtocol(flowKey, Protocols.ICMP)
        .flatMap(result => packetService.getAssociatedWithFlowKey(flowKey, additionalHash).map(rs => rs++result))
    } else if (protocol == Protocols.ICMP) {
      packetService.getAssociatedWithFlowKeyAndProtocol(flowKey, Protocols.UDP)
        .flatMap(result => packetService.getAssociatedWithFlowKey(flowKey, additionalHash).map(rs => rs++result))
    } else {
      fetchPacketsFromThisConnection(flowKey, additionalHash)
    }
  }

  /**
    * Metoda pobiera dodatkowe pakieta dla danego połączenia.
    *
    * @param flowKey identyfikator połączenia
    * @param additionalHash dodatkowy hash kod
    * @return asynchroniczny wynik z sekwencja dodatkowych pakietów
    */
  def fetchPacketsFromThisConnection(flowKey: Long, additionalHash: Long): Future[Seq[Packet]] = {
    packetService.getAssociatedWithFlowKey(flowKey, additionalHash)
  }

  /**
    * Metoda filtruje zdarzenia. Każde zdarzenie zapisywane jest w bazie danych i w zależności od typu zdarzenia
    * analizowane jest pod względem wystapienia ataku skanowania za pomocą sieci neuronowej. Gdy wykryty zostanie atak
    * to zdarzenie wejściowe zamieniane jest na atak skanowania portów, w przeciwnym razie kontynuowana jest iteracja.
    *
    * @param iterationResult zdarzenie
    * @tparam A typ zdarzenia
    * @return zwraca wynik fitlracji
    */
  def filterIterationResult[A <: IterationResult](iterationResult: A): Future[IterationResult] = {
    iterationResult match {
      case result@InitializingConnection(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Zapisanie zdarzenia do bazy danych i zwrócenie zdarzenia kontynuowania iteracji
        iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        ).map(rs => ContinueIteration(captured, analyzed))

      case result@InitializingRemoveFinePackets(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Zapisanie zdarzenia do bazy danych i zwrócenie zdarzenia kontynuowania iteracji
        iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        ).map(rs => RemoveFinePackets(captured, analyzed))

      case result@SendData(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Zapisanie zdarzenia do bazy danych i zwrócenie zdarzenia kontynuowania iteracji
        iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        ).map( rs => ContinueIteration(captured, analyzed))

      case result@DidNotSendData(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Sprawdzenie czy wystapił atak skanowania
        checkForAttack(iterationResult)

      case result@InitializingConnectionAndDataTransfer(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Zapisanie zdarzenia do bazy danych
        val f_1 = iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        )
        //Zapisanie zdarzenia do bazy danych
        val f_2 = iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        )

        //Zwrócenie zdarzenia kontynuowania iteracji
        Future.sequence(Seq(f_1, f_2)).map(rs => ContinueIteration(captured, analyzed))

      case SuspiciousFinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Poczekanie i sprawdzenie czy wystapił atak skanowania
        awaitAndCheckForAttack(iterationResult)
      case SuspiciousAckWinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Poczekanie i sprawdzenie czy wystapił atak skanowania
        awaitAndCheckForAttack(iterationResult)
      case SuspiciousMaimonScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Poczekanie i sprawdzenie czy wystapił atak skanowania
        awaitAndCheckForAttack(iterationResult)

      case iterationResult@PortClosed(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Sprawdzenie czy wystapił atak skanowania
        checkForAttack(iterationResult)
      case iterationResult@SuspiciousNetworkScan(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Zapisanie zdarzenia do bazy danych i zwrócenie zdarzenia kontynuowania iteracji
        iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        ).map( rs => ContinueIteration(captured, analyzed))
      case iterationResult@RemoveFinePackets(captured: Seq[Packet], analyzed: Seq[Packet]) =>
        //Zapisanie zdarzenia do bazy danych i zwrócenie zdarzenia kontynuowania iteracji
        iterationResultHistoryService.create(
          createIterationResultHistory(iterationResult)
        ).map( rs => RemoveFinePackets(captured, analyzed))

        //Zwrócenie zdarzenia kontynuowania iteracji
      case _ => Future(iterationResult)
    }
  }

  /**
    * Metoda sprawdza czy po jednej sekundzie doszło do przesyłu pakiętu.
    *
    * @param iterationResult zdarzenie
    * @tparam A typ zdarzenia
    * @return zwraca zdarzenie kontynuowania iteracji lub wystapienia ataku
    */
  def awaitAndCheckForAttack[A <: IterationResult](iterationResult: A) = {
    val f = Future (
      //Poczekanie jednej sekundy
      Thread.sleep(Constants.ONE_SECOND)
    )
    .flatMap(_ => iterationResult match {
      case _ => packetService.areThereMorePackets(iterationResult.captured.head.flowKey,
        iterationResult.captured.head.additionalHash).flatMap(result =>

        //Czy doszło do przesyłu pakietu
        if (result) {
          Future{
            //Kontynuacja iteracji
            ContinueIteration(iterationResult.captured, iterationResult.analyzed)
          }
        } else {
          //Sprawdzenie czy wystąpił atak
          checkForAttack(iterationResult)
        }
      )
    })

    f
  }

  /**
    * Metoda sprawdza czy wystąpił atak skanowania. Pierwszym etapem jest zapisanie zdarzenia w bazie danych,
    * a następnie obliczenie szansy wystąpienia ataku za pomocą sieci neuronowej. Gdy owa szansa jest większa niż 40
    * procent to zwracany jest typ ataku.
    *
    * @param iterationResult zdarzenie
    * @tparam A rodzaj zdarzenia
    * @return zwraca typ ataku lub informację że iteracja ma być kontynuowana
    */
  def checkForAttack[A <: IterationResult](iterationResult: A) = {
    iterationResultHistoryService.create(
      //Zapisanie zdarzenia do bazy danych
      createIterationResultHistory(iterationResult)
    ).flatMap(createResultHistory =>
      checkForAttackWithNeuralNetwork(iterationResult).map(chance => {
        //Sprawdzenie wartości szansy
        if (chance >= 50) {
          //Określenie typu ataku
          getAttackType(iterationResult, if (chance >= 100) 100 else chance)
        } else {
          //Kontynuacja iteracji
          ContinueIteration(iterationResult.captured, iterationResult.analyzed)
        }
      })
    )
  }

  /**
    * Metoda na podstawie historii zdarzeń tworzy obiekt kontekstu z cechami i współczynnikami dla sieci neuronowej
    *
    * @param sourceAddress adres źródłowy
    * @param iterationResult zdarzenie
    * @tparam A typ zdarzenia
    * @return kontekst cech i współczynników
    */
  def createCheckingContext[A <: IterationResult](sourceAddress: String,
                                                  iterationResult: A): Future[CheckingContext] = {
    //Pobranie historii zdarzeń na podstawie adresu żródłowego
    val f = iterationResultHistoryService.findBySourceAddress(sourceAddress).map(result => {
      //Pogrupowanie po typie zdarzenia
      val resultTypes = result.groupBy(_.resultType)

      //Stworzenie sekwencji zdarzeń związanych z otwartymi portami
      val openPortsTypes = resultTypes
        .filter(entry => ScanDetectionAlgorithm.OPEN_PORTS_COUNTER_LABELS.contains(entry._1))
        .values.flatten

      //Liczba pakietów, która brała udział w transferze na otwartych portach
      val numberOfTransportedPacketsToOpenPorts = openPortsTypes
        .map(_.info.getOrElse(IterationResultHistory.InfoKeys.INFO_KEYS, Constants.ZERO).toInt).sum

      //Stworzenie sekwencji zdarzeń związanych z zamkniętymi portami lub filtrowanymi
      val closedPortsTypes = resultTypes
        .filter(entry => ScanDetectionAlgorithm.CLOSED_PORTS_COUNTER_LABELS.contains(entry._1))
        .values.flatten

      //Czy maszyna na której działą program inicjowała połączenie z tym adresem źródłowym
      val hostWasInitializingConnection = resultTypes.values.flatten
        .exists(ir => ir.resultType == ScanDetectionAlgorithm.IterationResultHistoryLabels.initializingConnection ||
          ir.resultType == ScanDetectionAlgorithm.IterationResultHistoryLabels.initializingRemoveFinePackets
        )

      //Czy wystąpiła transmisja danych
      val sendData = resultTypes.values.flatten
        .exists(ir => ir.resultType == ScanDetectionAlgorithm.IterationResultHistoryLabels.sendData ||
          ir.resultType == ScanDetectionAlgorithm.IterationResultHistoryLabels.removeFinePackets ||
          ir.resultType == ScanDetectionAlgorithm.IterationResultHistoryLabels.initializingRemoveFinePackets
        )

      //Czy niewystąpiła transmisja danych
      val didNotSendData = resultTypes.get(ScanDetectionAlgorithm.IterationResultHistoryLabels.didNotSendData)
        .exists(_ => true)

      //Zbiór zamkniętych portów
      val closedPorts = closedPortsTypes.map(_.port).toSet
      //Liczba zamkniętych portów
      val closedPortSize = closedPorts.size

      //Zbiór otwartych portów
      val openPorts = openPortsTypes.map(_.port).toSet
      //Wartość progowa prób nawiązania połączenia z zamknietymi portami
      val closedPortThreshold = this.worker.scanDetectContext
        .getSettingsValueOrUseDefault(SettingsKeys.CLOSED_PORT_THRESHOLD).toString.toInt

      //Czy liczba prób przekroczyła wartość progową, czy osiągnęła ją, czy jest poniżej
      val closedPortsThresholdResult = if (closedPortSize == closedPortThreshold) {
        //Próg osiągnięty
        AtThreshold(sourceAddress, closedPortThreshold)
      } else {
        if (closedPortSize > closedPortThreshold) {
          //Powyżej progu
          BeyondThreshold(sourceAddress, closedPortThreshold)
        } else {
          //Poniżej progu
          UnderThreshold(sourceAddress, closedPortThreshold)
        }
      }

      //Pogrupowanie historii zdarzeń po użytych portach
      val groupedByPort: Map[Int, Seq[String]] = result
        .groupBy(_.port)
        .map(entry => (entry._1, entry._2.map(_.resultType)))
      //Sekwencja użytych portów
      val usedPorts = groupedByPort.keys

      //Sprawdzenie czy próbowano połączyć się z zamkniętym portem po poprzednim połączeniu się z otwartym
      //i nie wysłaniu żadnych danych
      val triedConnectToClosedPortAfterOpen = if (usedPorts.size >= 2) {
        usedPorts.sliding(2)
          .exists(
            part =>
              //Pobranie dwóch historii zdarzen - brak transmisji danych oraz port zamknięty
              groupedByPort(part.head).contains(ScanDetectionAlgorithm.IterationResultHistoryLabels.didNotSendData) &&
              groupedByPort(part.last).contains(ScanDetectionAlgorithm.IterationResultHistoryLabels.portClosed)
          )
      } else {
        false
      }

      //Stworzenie obiektu kontekstu z danymi dla sieci neuronowej
      CheckingContext(hostWasInitializingConnection,
        sendData,
        didNotSendData,
        triedConnectToClosedPortAfterOpen,
        closedPortsThresholdResult,
        numberOfTransportedPacketsToOpenPorts,
        closedPorts,
        openPorts
      )
    })

    f.onFailure({
      case e: Throwable => e.printStackTrace()
    })

    f
  }

  /**
    * Metoda sprawdza czy wystąpił atak skanowania portów za pomocą sieci neuronowej.
    *
    * @param iterationResult zdarzenie
    * @tparam A rodzaj zdarzenia
    * @return wynik z sieci neuronowej jako procent
    */
  def checkForAttackWithNeuralNetwork[A <: IterationResult](iterationResult: A): Future[Int] = {
    createCheckingContext(getSourceAddress(iterationResult.all), iterationResult).map(
      checkingContext => {
        val chance = try {
          val neuralNetworkResult = worker.scanDetectContext.scanDetectNeuralNetwork
            .getResultAsPercentage(checkingContext.createWeights.map(new Double(_)).toList.asJava)
          log.info("Neural network result => " + neuralNetworkResult)
          neuralNetworkResult
        } catch {
          case e: Throwable =>
            log.error("Error while getting result from neural network.", e)
            Constants.Numbers.ZERO
        }
        chance
      }
    )
  }

  /**
    * Stworzenie obiektu historii zdarzeń, który zostanei zapisany w bazie danych.
    *
    * @param iterationResult - zdarzenie do zapisu
    * @tparam A - typ zdarzenia
    * @return obiekt zdarzenia do zapisu w bazie danych
    */
  def createIterationResultHistory[A <: IterationResult](iterationResult: A) = {
    IterationResultHistory(
      None,
      getSourceAddress(iterationResult.all),
      iterationResult.all.head.flowKey,
      iterationResult.all.head.additionalHash,
      getDestinationPort(iterationResult.all),
      Map(IterationResultHistory.InfoKeys.INFO_KEYS -> iterationResult.all.size.toString),
      iterationResult.getClass.getName
    )
  }

  /**
    * Sprawdzenie czy podany adres IP zostął zarejestrowany przez honeypota. Metoda łaczy się do bazy danych honeypota.
    *
    * @param sourceAddress sprawdzany adres IP
    * @return true jeżeli adres został odnotowany, w przeciwnym razie false
    */
  def wasRegisteredByHoneypot(sourceAddress: String): Boolean = {
    try {
      if (worker.scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.USE_HONEYPOT).toString.toBoolean) {
        Await.result(honeypotService.wasRegisteredByHoneypot(sourceAddress), 10.seconds)
      } else {
        false
      }
    } catch {
      case ex: Throwable => false
    }
  }

}



