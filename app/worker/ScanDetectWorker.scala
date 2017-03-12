package worker

import java.util.concurrent.atomic.AtomicBoolean

import actors.ScanAttackAndTypeDetectorActor
import akka.actor.{ActorSystem, Props}
import algorithms._
import com.google.inject.{Inject, Singleton}
import models.Packet
import play.api.Logger
import services.{AlertsService, IterationResultHistoryService, PacketService}
import akka.pattern.ask
import akka.util.Timeout
import context.ScanDetectContext
import utils.Constants.SettingsKeys

import scala.concurrent.Future
import scala.util.{Failure, Success}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._

@Singleton
class ScanDetectWorker @Inject() (packetService: PacketService,
                                  scanDetectionAlgorithm: ScanDetectionAlgorithm,
                                  system: ActorSystem,
                                  alertsService: AlertsService,
                                  iterationResultHistoryService: IterationResultHistoryService) {

  implicit val timeout = Timeout(5.seconds)

  //Referencja do kontekstu programu
  var scanDetectContext: ScanDetectContext = _

  val log = Logger

  //Flaga sterująca wykrywanie skanowania
  val doWork = new AtomicBoolean(false)

  //Referencja do aktora wykrywajacego użyte oprogramowanie do skanwoania sieci lub portów
  val scanAttackAndTypeDetectorActor = system.actorOf(Props(new ScanAttackAndTypeDetectorActor(alertsService,
    iterationResultHistoryService)))

  def setContext(scanDetectContext: ScanDetectContext) = {
    this.scanDetectContext = scanDetectContext
  }

  /**
  Rozpoczecie wykrywania skanowania sieci i portów
   */
  def start(): Unit = {
    doWork.set(true)
    detectScans()

    if (scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.USE_HONEYPOT).toString.toBoolean) {
      detectNetworkScans()
    }
  }

  /**
  Zatrzymanie wykrywania skanowania sieci i portów
   */
  def stop(): Unit = {
    doWork.set(false)
  }

  /**
  Metoda w każdej iteracji pobiera do 500 pakietów i analizuje je pod względem wystapienia ataku skanowania portów
   */
  def detectScans(): Unit = {
    if (doWork.get()) {
      packetService
        .getToAnalyze(500)
        .onComplete {
          case Success(rs) =>
            Future.sequence(
              if (rs.nonEmpty) scanDetectionAlgorithm.detect(this, rs) else Seq()
            ).map(_ => {
              detectScans()
            })
          case Failure(ex) => ex.printStackTrace()
        }
    }
  }

  /**
    * Metoda w każdej iteracji pobiera zdarzenia określające podejrzane ataki skanwoania sieci i sprawdza je pod
    * względem wystąpienia ataku skanowania sieci
    */
  def detectNetworkScans(): Unit = {
    if (doWork.get()) {
      iterationResultHistoryService
         .findByResultType(ScanDetectionAlgorithm.IterationResultHistoryLabels.suspiciousNetworkScan)
          .onComplete {
          case Success(rs) =>
            Future.sequence(
              if (rs.nonEmpty) scanDetectionAlgorithm.detectNetworkScans(this, rs) else Seq()
            ).map(_ => {
              detectNetworkScans()
            })
          case Failure(ex) => ex.printStackTrace()
        }
    }
  }

  /**
    * Metoda po iteracji algorytmu w zależności od wyników zgłasza alarm skanowania lub nie i kontynuuje działanie
    * algorytmu wykrywania skanowania
    *
    * @param iterationResult zdarzenie
    * @tparam A typ zdarzenia
    * @return asynchroncizne zadanie
    */
  def dispatch[A <: IterationResult](iterationResult: A): Any = {
    if (scanDetectContext.isHoneypot) {
      //Przeniesienie pakietow do kolekcji przeanalizowanych
      packetService.markAsAnalyzedAndRemoveOld(iterationResult.captured).map(_ =>
        //wysłanie alarmu skanowania do aktora określającego użyte oprogramowanie
        scanAttackAndTypeDetectorActor ? NetworkScanAlert(iterationResult.captured, iterationResult.analyzed)
      )
    } else {
      iterationResult match {
        case RemoveFinePackets(old: Seq[Packet], analyzed: Seq[Packet]) =>
          //Usuwanie pakietów z bazy danych
          packetService.removeMultiple(old).map(_ =>
            packetService.removeMultipleAnalyzed(analyzed)
          )
        case _ =>
          //Przeniesienie pakietow do kolekcji przeanalizowanych
          packetService.markAsAnalyzedAndRemoveOld(iterationResult.captured).map(_ =>
            iterationResult match {
              // Kontynuacja iteracji
              case r@ContinueIteration(old: Seq[Packet], analyzed: Seq[Packet]) =>
              //wysłanie alarmu skanowania do aktora określającego użyte oprogramowanie
              case r => scanAttackAndTypeDetectorActor ? r
            }
          )
      }
    }
  }

}
