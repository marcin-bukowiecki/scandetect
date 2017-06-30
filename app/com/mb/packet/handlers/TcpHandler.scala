package com.mb.packet.handlers
import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.protocol.network.{Ip4, Ip6}
import org.jnetpcap.protocol.tcpip.Tcp
import utils.PacketUtils.PacketBuilder
import utils.{PacketInfo, PacketUtils, Protocols}

import scala.collection.JavaConverters._

/**
  * Created by Marcin on 2017-06-30.
  */
class TcpHandler(networkInterfacesAddresses: Set[String], tcp: Tcp) extends BaseHandler {

  override def handle(pcapPacket: PcapPacket): Option[Packet] = {
    val flowKey = pcapPacket.getFlowKey.hashCode()
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    val ip4 = new Ip4
    val ip6 = new Ip6

    val sourcePort = tcp.source()
    val destinationPort = tcp.destination()
    val sourceAddress = PacketUtils.getSourceAddress(pcapPacket, ip4, ip6)
    val destinationAddress = PacketUtils.getDestinationAddress(pcapPacket, ip4, ip6)
    val direction = PacketUtils.getDirection(sourceAddress, networkInterfacesAddresses)

    PacketBuilder.build(
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
  }

}
