package repositories

import java.lang.StringBuilder
import java.util

import models.{NetworkInterface, Packet}
import org.jnetpcap.{Pcap, PcapIf}

/**
  * Created by Marcin on 2016-09-15.
  */
object Main extends App {

  val cs = new CaptureService(new PacketRepositoryImplTester)

  val errbuf = new StringBuilder()
  val snaplen = 64 * 1024 // Capture all packets, no trucation
  val flags = Pcap.MODE_PROMISCUOUS // capture all packets
  val timeout = 10 * 1000 // 10 seconds in millis

  val devices = new util.ArrayList[PcapIf]()

  try {
    Pcap.findAllDevs(devices, errbuf)
  } catch {
    case ex: UnsatisfiedLinkError => ex.printStackTrace()
  }

  val ni = NetworkInterface(devices.get(0).getName, null, null, 1)

  cs.startCapturing(devices.get(0))

}
