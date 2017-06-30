package services

import java.lang.StringBuilder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.{Executors, ThreadFactory}

import com.google.inject.{Inject, Singleton}
import com.mb.packet.handlers._
import models.Packet
import org.jnetpcap.packet.format.FormatUtils
import org.jnetpcap.packet.{PcapPacket, PcapPacketHandler}
import org.jnetpcap.{Pcap, PcapIf}
import play.api._
import utils._

import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class CaptureService @Inject() (packetService: PacketService) {
  val log = Logger
  val NUMBER_OF_THREADS = 2

  var addresses = Map[Protocol, String]()

  var networkInterfaceAddressesAsSet = Set[String]()

  var addressesToIgnore = Seq[String]()

  def getAddressesToIgnore = addressesToIgnore

  def setAddressesToIgnore(ips: Seq[String]) = {
    addressesToIgnore = ips
  }

  val allowCapturing = new AtomicBoolean

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

  val packetHandler = new PcapPacketHandler[String]() {

    override def nextPacket(pcapPacket: PcapPacket, interfaceAddress: String): Unit = {
      val packetToSave = createPacketToSave(pcapPacket, interfaceAddress)

      if (packetToSave.isDefined &&
        !getAddressesToIgnore.contains(packetToSave.get.sourceAddress) &&
        !getAddressesToIgnore.contains(packetToSave.get.destinationAddress)
      ) {
        if (!(networkInterfaceAddressesAsSet.contains(packetToSave.get.sourceAddress) ||
          networkInterfaceAddressesAsSet.contains(packetToSave.get.destinationAddress))) {
          return
        } else {
          packetService.create(packetToSave.get)
        }
      }
    }
  }

  def createPacketToSave(pcapPacket: PcapPacket, extraParams: String): Option[Packet] = {
    val packetToSave = HandlerFactory.getPcapPacketHandler(pcapPacket, networkInterfaceAddressesAsSet).handle(pcapPacket)

    if (packetToSave.isEmpty) {
      new IpHandler(networkInterfaceAddressesAsSet).handle(pcapPacket)
    } else {
      packetToSave
    }
  }

  def stopCapturing() = allowCapturing.set(false)

  def startCapturing(networkInterface: PcapIf) : Unit = {
    allowCapturing.set(true)
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
        while (allowCapturing.get()) {
          packetCapture.loop(1, packetHandler, Constants.EMPTY_STRING)
        }
      }
    }catch {
      case e : Throwable => log.error("got error", e)
    }
  }

}