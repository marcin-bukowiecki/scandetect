package services

import java.lang.StringBuilder
import java.util.concurrent.{Executors, ThreadFactory}
import java.util.concurrent.atomic.AtomicBoolean

import com.google.inject.{Inject, Singleton}

import scala.collection.JavaConverters._
import models.Packet
import org.jnetpcap.packet.{PcapPacket, PcapPacketHandler}
import org.jnetpcap.packet.format.FormatUtils
import org.jnetpcap.protocol.network.{Arp, Icmp, Ip4, Ip6}
import org.jnetpcap.protocol.tcpip.{Tcp, Udp}
import org.jnetpcap.{Pcap, PcapIf}
import org.jnetpcap.protocol.network.Icmp.IcmpType
import org.jnetpcap.protocol.sigtran.SctpChunk.SctpChunkType
import org.jnetpcap.protocol.sigtran._
import play.api._
import utils._

import scala.concurrent.{ExecutionContext, Future}

@Singleton
class CaptureService @Inject() (packetService: PacketService) {
  val log = Logger
  val NUMBER_OF_THREADS = 2

  /**
    * Mapa (klucz - wersja protokołu IP, adres IP) wybranego interfejsu sieciwoego
    */
  var addresses = Map[Protocol, String]()

  /**
    * Zbiór adresów IP wybranego interfejsu sieciowego
    */
  var networkInterfaceAddressesAsSet = Set[String]()

  /**
    * Sekwencja adresów IP do ignorowania
    */
  var addressesToIgnore = Seq[String]()

  /**
    * Pobranie adresów do ignorowania
    *
    * @return
    */
  def getAddressesToIgnore = addressesToIgnore

  /**
    * Ustawienei adresów to ignorowania podczas zapisu pakietów
    *
    * @param ips sekwencja adresów do ignorowania
    */
  def setAddressesToIgnore(ips: Seq[String]) = {
    addressesToIgnore = ips
  }

  /**
    * Flaga oznaczająca możliwość przechwytywania pakietów
    */
  val allowCapturing = new AtomicBoolean

  /**
    * Pula wątków do przechwytywania pakietów
    */
  implicit val captureExecutionContext = new ExecutionContext {

    val threadPool = Executors.newFixedThreadPool(NUMBER_OF_THREADS)

    val threadFactory = new ThreadFactory {
      override def newThread(r: Runnable): Thread = {
        val t = new Thread(r)
        t.setName("capturePacketThreadPool")
        t
      }
    }

    override def reportFailure(cause: Throwable): Unit = {
      log.error("Error while capturing packet", cause)
    }

    override def execute(runnable: Runnable): Unit = {
      threadPool.submit(threadFactory.newThread(runnable))
    }
  }

  /**
    * Handler wywoływany w momencie przechwycenia pakietu.
    * Tworzy obiekt pakietu, która zostaje zapsiana w bazie danych.
    */
  val packetHandler = new PcapPacketHandler[String]() {

    override def nextPacket(pcapPacket: PcapPacket, interfaceAddress: String): Unit = {
      //Tworzenie obiektu pakietu do zapisu
      val packetToSave = createPacketToSave(pcapPacket, interfaceAddress)

      //Pakiet zostaje zapisany do bazy danych jeżeli został stworzony, adres IP nie jest ignorowany oraz został
      //przechwycony przez wybrany interfejs sieciowy
      if (packetToSave.isDefined &&
        !getAddressesToIgnore.contains(packetToSave.get.sourceAddress) &&
        !getAddressesToIgnore.contains(packetToSave.get.destinationAddress)
      ) {
        if (!(networkInterfaceAddressesAsSet.contains(packetToSave.get.sourceAddress) ||
          networkInterfaceAddressesAsSet.contains(packetToSave.get.destinationAddress))) {
          return
        } else {
          //Zapisanie obiektu pakietu do bazy danych
          packetService.create(packetToSave.get)
        }
      }
    }
  }

  /**
    * Tworzenie obiektu pakietu do zapisu w bazie danych.
    *
    * @param pcapPacket przechwycony pakiet przez bibliotekę JNetPcap
    * @param extraParams dodatkowe parametry (adresy IP interfejsu sieciowego)
    * @return stworzony obiekt pakietu
    */
  def createPacketToSave(pcapPacket: PcapPacket, extraParams: String): Option[Packet] = {
    //Klucz połączenia oznaczający przynależność pakietu do konkretnej grupy
    val flowKey = pcapPacket.getFlowKey.hashCode()
    //Czas przechwycenia pakietu
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    //obiekty konkretnych protokołów, służące do sprawdzania jakie nagłówki znajdują się w przechwyconym pakiecie
    val tcp = new Tcp
    val ip4 = new Ip4
    val ip6 = new Ip6
    val arp = new Arp
    val udp = new Udp
    val sctp = new Sctp
    val sctpInit = new SctpInit
    val sctpInitAck = new SctpInitAck
    val sctpAbort = new SctpAbort
    val sctpData = new SctpData
    val sctpCookie = new SctpCookie
    val icmp = new Icmp
    val icmpUnreachable = new Icmp.DestinationUnreachable
    val icmpPing = new Icmp.EchoRequest

    //Stworzenie pakietu ICMP
    val packetToSave = if (pcapPacket.hasHeader(icmp)) {
      val sourceAddress: String = getSourceAddress(pcapPacket, ip4, ip6)
      val destinationAddress: String = getDestinationAddress(pcapPacket, ip4, ip6)
      val direction = getDirection(sourceAddress)
      if (icmp.hasSubHeader(icmpPing)) {
        buildPacket(
          timestamp,
          Protocols.ICMP,
          sourceAddress,
          PortUtils.NO_PORT,
          destinationAddress,
          PortUtils.NO_PORT,
          Map(),
          Seq(),
          flowKey,
          Constants.ICMP_HASHCODE,
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          icmp.getPayloadLength
        )
      } else if (icmp.hasSubHeader(icmpUnreachable)) {
        buildPacket(
          timestamp,
          Protocols.ICMP,
          sourceAddress,
          PortUtils.NO_PORT,
          destinationAddress,
          PortUtils.NO_PORT,
          Map(),
          if (icmp.codeEnum() == null) {
            Seq(IcmpType.DESTINATION_UNREACHABLE.toString, Constants.EMPTY_STRING, icmp.code.toString)
          } else {
            Seq(IcmpType.DESTINATION_UNREACHABLE.toString, icmp.codeEnum().toString, icmp.code.toString)
          }
          ,
          flowKey,
          Constants.ICMP_HASHCODE,
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          icmp.getPayloadLength
        )
      } else {
        None
      }
    } else if (pcapPacket.hasHeader(tcp)) {
      //Stworzenie pakietu TCP
      val sourcePort = tcp.source()
      val destinationPort = tcp.destination()
      val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
      val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)
      val direction = getDirection(sourceAddress)

      buildPacket(
        timestamp,
        Protocols.TCP,
        sourceAddress,
        sourcePort,
        destinationAddress,
        destinationPort,
        Map(
          PacketInfo.Tcp.SEQ->tcp.seq().toString,
          PacketInfo.Tcp.ACK->tcp.ack().toString,
          PacketInfo.Tcp.WIN->tcp.window().toString,
          PacketInfo.Tcp.WIN_SCALE->tcp.windowScaled().toString,
          PacketInfo.Tcp.CHECKSUM_CORRECT->String.valueOf(tcp.isChecksumValid),
          PacketInfo.Tcp.HEADER_LENGTH->tcp.getHeaderLength.toString
        ),
        tcp.flagsEnum().asScala.toSeq.map(flag => flag.name()),
        PacketUtils.generateAdditionalHashcode(sourcePort, destinationPort, direction),
        PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
        flowKey,
        direction,
        tcp.getPayloadLength)
    } else if (pcapPacket.hasHeader(udp)) {
      //Stworzenie pakietu UDP
      val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
      val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)
      val direction = getDirection(sourceAddress)

      if (!Multicast.ADDRESSES.contains(destinationAddress) &&
        !networkInterfaceAddressesAsSet.contains(sourceAddress)) {

        buildPacket(
          timestamp,
          Protocols.UDP,
          sourceAddress,
          udp.source(),
          destinationAddress,
          udp.destination(),
          Map(),
          Seq(),
          flowKey,
          PacketUtils.generateAdditionalHashcode(udp.source(), udp.destination(), direction),
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          udp.getPayloadLength
        )
      } else {
        None
      }
    } else if (pcapPacket.hasHeader(sctp)) {
      //Stworzenie pakietów SCTP

      if (pcapPacket.hasHeader(sctpInit)) {
        //Stworzenie pakietu SCTP Init
        val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
        val direction = getDirection(sourceAddress)
        val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)

        buildPacket(
          timestamp,
          Protocols.SCTP,
          sourceAddress,
          sctp.source(),
          destinationAddress,
          sctp.destination(),
          Map(),
          Seq(SctpChunkType.valueOf(sctpInit.`type`())),
          flowKey,
          PacketUtils.generateAdditionalHashcode(sctp.source(), sctp.destination(), direction),
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          getDirection(sourceAddress),
          pcapPacket.size()
        )
      } else if (pcapPacket.hasHeader(sctpInitAck)) {
        //Stworzenie pakietu SCTP Init Ack
        val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
        val direction = getDirection(sourceAddress)
        val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)

        buildPacket(
          timestamp,
          Protocols.SCTP,
          sourceAddress,
          sctp.source(),
          getDestinationAddress(pcapPacket, ip4, ip6),
          sctp.destination(),
          Map(),
          Seq(SctpChunkType.valueOf(sctpInitAck.`type`())),
          flowKey,
          PacketUtils.generateAdditionalHashcode(sctp.source(), sctp.destination(), direction),
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          pcapPacket.size()
        )
      } else if (pcapPacket.hasHeader(sctpAbort)) {
        //Stworzenie pakietu SCTP Abort
        val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
        val direction = getDirection(sourceAddress)
        val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)

        buildPacket(
          timestamp,
          Protocols.SCTP,
          sourceAddress,
          sctp.source(),
          destinationAddress,
          sctp.destination(),
          Map(),
          Seq(SctpChunkType.valueOf(sctpAbort.`type`())),
          flowKey,
          PacketUtils.generateAdditionalHashcode(sctp.source(), sctp.destination(), direction),
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          pcapPacket.size()
        )
      } else if (pcapPacket.hasHeader(sctpData)) {
        //Stworzenie pakietu SCTP Data
        val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
        val direction = getDirection(sourceAddress)
        val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)

        buildPacket(
          timestamp,
          Protocols.SCTP,
          sourceAddress,
          sctp.source(),
          destinationAddress,
          sctp.destination(),
          Map(),
          Seq(SctpChunkType.valueOf(sctpData.`type`())),
          flowKey,
          PacketUtils.generateAdditionalHashcode(sctp.source(), sctp.destination(), direction),
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          sctpData.size()
        )
      } else if (pcapPacket.hasHeader(sctpCookie)) {
        //Stworzenie pakietu SCTP Cookie
        val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
        val direction = getDirection(sourceAddress)
        val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)

        buildPacket(
          timestamp,
          Protocols.SCTP,
          sourceAddress,
          sctp.source(),
          destinationAddress,
          sctp.destination(),
          Map(),
          Seq(SctpChunkType.valueOf(sctpCookie.`type`())),
          flowKey,
          PacketUtils.generateAdditionalHashcode(sctp.source(), sctp.destination(), direction),
          PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
          direction,
          sctpData.size()
        )
      } else {
        None
      }
    } else if (pcapPacket.hasHeader(arp)) {
      //Stworzenie pakietu ARP
      val sourceAddress = FormatUtils.ip(arp.spa())
      val destinationAddress = FormatUtils.ip(arp.tpa())
      val direction = getDirection(sourceAddress)

      buildPacket(
        timestamp,
        Protocols.ARP,
        sourceAddress,
        PortUtils.NO_PORT,
        destinationAddress,
        PortUtils.NO_PORT,
        Map(),
        Seq(),
        flowKey,
        Constants.NO_HASHCODE,
        PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
        direction,
        pcapPacket.size()
      )
    } else {
      None
    }

    if (packetToSave.isEmpty) {
      //Stworzenie pakietu IP
      val protocol = if (pcapPacket.hasHeader(ip4)) {
        Protocols.IP4
      } else if (pcapPacket.hasHeader(ip6)) {
        Protocols.IP6
      } else {
        Constants.EMPTY_STRING
      }

      if (protocol.isEmpty) {
        None
      } else {
        val sourceAddress = getSourceAddress(pcapPacket, ip4, ip6)
        val direction = getDirection(sourceAddress)
        val destinationAddress = getDestinationAddress(pcapPacket, ip4, ip6)

        if (!Multicast.ADDRESSES.contains(destinationAddress) &&
          !networkInterfaceAddressesAsSet.contains(sourceAddress) && pcapPacket.getHeaderCount == 2) {

          buildPacket(
            timestamp,
            protocol,
            sourceAddress,
            PortUtils.NO_PORT,
            destinationAddress,
            PortUtils.NO_PORT,
            Map(),
            Seq(),
            flowKey,
            Constants.NO_HASHCODE,
            PacketUtils.generateAdditionalHashcode(sourceAddress, destinationAddress, direction),
            direction,
            pcapPacket.size()
          )
        } else {
          None
        }
      }
    } else {
      packetToSave
    }
  }

  /**
    * Stworzenie obiektu pakietu do zapisu.
    *
    * @param timestamp czas przechwycenia
    * @param protocol protokół
    * @param sourceAddress adres źródłowy
    * @param sourcePort port źródłowy
    * @param destinationAddress adres docelowy
    * @param destinationPort ort docelowy
    * @param info dodatkowe informacje
    * @param flags flagi
    * @param flowKey klucz połaczenia
    * @param additionalHash dodatkowy hash kod
    * @param additionalHashNetwork dodatkowy hash kod warstwy itnernetowej
    * @param direction kierunek pakietu
    * @param length wielkość danych
    * @return
    */
  def buildPacket(timestamp: Long, protocol: String, sourceAddress: String, sourcePort: Int, destinationAddress: String,
                  destinationPort: Int,
                  info: Map[String, String],
                  flags: Seq[String],
                  flowKey: Long,
                  additionalHash: Long,
                  additionalHashNetwork: Long,
                  direction: String,
                  length: Int): Some[Packet] = {

    Some(Packet(None, timestamp, protocol, sourceAddress, sourcePort, destinationAddress, destinationPort,
      info, flags, flowKey, additionalHash, additionalHashNetwork, direction, length)
    )
  }

  /**
    * Zatrzymanie przechwytywania pakietów.
    */
  def stopCapturing() = allowCapturing.set(false)

  /**
    * Rozpoczęcie przechwytywania pakietów.
    *
    * @param networkInterface wybrany interfejs sieciowy
    */
  def startCapturing(networkInterface: PcapIf) : Unit = {
    allowCapturing.set(true)
    log.info(networkInterface.getAddresses.asScala.toString())
    Future.apply(startCapturingPackets(networkInterface))
  }

  def startCapturingPackets(networkInterface: PcapIf): Unit = {
    try {
      log.info("Starting capturing packets")

      val errorBuffer = new StringBuilder() //buffor do zapisu błędów
      val snapLength = 64 * 1024  //brak obcinania pakietów
      val flags = Pcap.MODE_PROMISCUOUS //przechwytywanie wszystkich pakietów
      val timeout = 10 * 1000 //czas oczekiwania na przechwycenie pakietu

      //Otwarcie kanału do przechwytywania pakietów
      val packetCapture = Pcap.openLive(networkInterface.getName, snapLength, flags, timeout, errorBuffer)

      //Stworzenie mapy adresów wybranego interfejsu sieciowego w zależności od protokołu
      addresses = networkInterface.getAddresses.asScala.map(_.getAddr.getData).map(bytes => {
        if (bytes.length == 4) IPv4 -> FormatUtils.ip(bytes) else IPv6 -> FormatUtils.ip(bytes)
      }).toMap

      //Stworzenie zbioru adresów wybranego interfejsu sieciwoego
      networkInterfaceAddressesAsSet = networkInterface.getAddresses.asScala
        .map(_.getAddr.getData)
        .map(bytes => FormatUtils.ip(bytes)).toSet

      //Jeżeli kanał został stworzony to pętla będzie przechwytywała pakiety tak długo, aż flaga allowCapturing
      //zostanie ustawiona na false
      if (packetCapture == null) {
        log.error("Error while opening device for capture: " + errorBuffer.toString)
      } else {
        while (allowCapturing.get()) {
          packetCapture.loop(1, packetHandler, Constants.EMPTY_STRING)
        }
      }
    }catch {
      case e : Throwable => log.error("got error", e)
    }
  }

  /**
    * Określenie adresu źródłowego w zależności od wersji protokołu IP.
    *
    * @param pcapPacket przechwycony pakiet
    * @param ip4 obiekt klasy Ip4
    * @param ip6 obiekt klasy Ip6
    * @return adres przechwyconego pakietu
    */
  def getSourceAddress(pcapPacket: PcapPacket, ip4: Ip4, ip6: Ip6): String =
    if (pcapPacket.hasHeader(ip4)) FormatUtils.ip(ip4.source())
    else if (pcapPacket.hasHeader(ip6)) FormatUtils.ip(ip6.source())
    else Constants.EMPTY_STRING

  /**
    * Określenie adresu docelowego w zależności od wersji protokołu IP.
    *
    * @param pcapPacket przechwycony pakiet
    * @param ip4 obiekt klasy Ip4
    * @param ip6 obiekt klasy Ip6
    * @return adres przechwyconego pakietu
    */
  def getDestinationAddress(pcapPacket: PcapPacket, ip4: Ip4, ip6: Ip6): String =
    if (pcapPacket.hasHeader(ip4)) FormatUtils.ip(ip4.destination())
    else if (pcapPacket.hasHeader(ip6)) FormatUtils.ip(ip6.destination())
    else Constants.EMPTY_STRING

  /**
    * Określenie kierunku pakietu. Czy jest przychodzacy czy wychodzący z maszyny na której działa dane oprogramowanie
    *
    * @param sourceAddress adres źródłowy pakietu
    * @return
    */
  def getDirection(sourceAddress: String): String =
    if (networkInterfaceAddressesAsSet.contains(sourceAddress)) utils.Direction.OUTCOME.toString
    else utils.Direction.INCOME.toString

  /**
    * Określenie wersji protokołu IP.
    *
    * @param pcapPacket przechwycony pakiet
    * @param ip4 obiekt klasy Ip4
    * @param ip6 obiekt klasy Ip6
    * @return protokół IP wersji 4 lub 6
    */
  def getIpVersion(pcapPacket: PcapPacket, ip4: Ip4, ip6: Ip6): Protocol ={
    if (pcapPacket.hasHeader(ip4)) IPv4 else IPv6
  }
}