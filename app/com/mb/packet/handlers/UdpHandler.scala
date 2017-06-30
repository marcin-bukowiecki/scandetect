package com.mb.packet.handlers
import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.protocol.network.{Ip4, Ip6}
import org.jnetpcap.protocol.tcpip.Udp
import utils.PacketUtils.PacketBuilder
import utils.{Multicast, PacketUtils, Protocols}

/**
  * Created by Marcin on 2017-06-30.
  */
class UdpHandler(networkInterfacesAddresses: Set[String], udp: Udp) extends BaseHandler {

  override def handle(pcapPacket: PcapPacket): Option[Packet] = {
    val flowKey = pcapPacket.getFlowKey.hashCode()
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    val ip4 = new Ip4
    val ip6 = new Ip6

    val sourceAddress = PacketUtils.getSourceAddress(pcapPacket, ip4, ip6)
    val destinationAddress = PacketUtils.getDestinationAddress(pcapPacket, ip4, ip6)
    val direction = PacketUtils.getDirection(sourceAddress, networkInterfacesAddresses)

    if (!Multicast.ADDRESSES.contains(destinationAddress) && !networkInterfacesAddresses.contains(sourceAddress)) {
      PacketBuilder.build(
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
        udp.getPayloadLength)
    } else {
      None
    }
  }

}
