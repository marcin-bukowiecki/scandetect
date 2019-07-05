package repositories

import java.lang.StringBuilder
import java.util.concurrent.atomic.AtomicBoolean

import com.google.inject.{Inject, Singleton}
import com.mb.packet.handlers._
import models.Packet
import org.jnetpcap.packet.format.FormatUtils
import org.jnetpcap.packet.{PcapPacket, PcapPacketHandler}
import org.jnetpcap.{Pcap, PcapIf}
import play.api._
import repositories.concurrent.CaptureServiceExecutionContext
import repositories.handler.CaptureServicePacketHandler
import utils._

import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class CaptureService @Inject()(val packetService: PacketRepositoryImpl) {

  private val log = Logger

  private var addresses = Map[Protocol, String]()

  private var addressesToIgnore = Seq[String]()

  private val capturing = new AtomicBoolean

  private implicit val captureExecutionContext: ExecutionContext = new CaptureServiceExecutionContext

  private val packetHandler: PcapPacketHandler[String] = CaptureServicePacketHandler(this)

  var networkInterfaceAddressesAsSet: Set[String] = Set[String]()

  def isCapturing(): Boolean = {
    capturing.get()
  }

  def allowCapturing: Unit = {
    capturing.set(true)
  }

  def getAddressesToIgnore: Seq[String] = addressesToIgnore

  def setAddressesToIgnore(ips: Seq[String]): Unit = {
    addressesToIgnore = ips
  }

  def createPacketToSave(pcapPacket: PcapPacket, extraParams: String): Option[Packet] = {
    val packetToSave = HandlerFactory.getPcapPacketHandler(pcapPacket, networkInterfaceAddressesAsSet).handle(pcapPacket)

    if (packetToSave.isEmpty) {
      IpHandler(networkInterfaceAddressesAsSet).handle(pcapPacket)
    } else {
      packetToSave
    }
  }

  def stopCapturing(): Unit = capturing.set(false)

  def startCapturing(networkInterface: PcapIf): Unit = {
    capturing.set(true)
    log.info(networkInterface.getAddresses.asScala.toString())
    Future.apply(startCapturingPackets(networkInterface))
  }

  def startCapturingPackets(networkInterface: PcapIf): Unit = {
    try {
      log.info("Starting capturing packets")

      val errorBuffer = new StringBuilder()
      val snapLength = 64 * 1024
      val flags = Pcap.MODE_PROMISCUOUS
      val timeout = 10 * 1000

      val packetCapture = Pcap.openLive(networkInterface.getName, snapLength, flags, timeout, errorBuffer)

      addresses = networkInterface.getAddresses.asScala.map(_.getAddr.getData).map(bytes => {
        if (bytes.length == 4) IPv4 -> FormatUtils.ip(bytes) else IPv6 -> FormatUtils.ip(bytes)
      }).toMap

      networkInterfaceAddressesAsSet = networkInterface.getAddresses.asScala
        .map(_.getAddr.getData)
        .map(bytes => FormatUtils.ip(bytes)).toSet

      if (packetCapture == null) {
        log.error("Error while opening device for capture: " + errorBuffer.toString)
      } else {
        while (capturing.get()) {
          packetCapture.loop(1, packetHandler, Constants.EMPTY_STRING)
        }
      }
    } catch {
      case e: Throwable => log.error("got error", e)
    }
  }

}