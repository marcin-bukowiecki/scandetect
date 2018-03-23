package com.mb.packet.handlers

import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.protocol.network.{Ip4, Ip6}
import utils.PacketUtils.PacketBuilder
import utils._

object IpHandler {

  def apply(networkInterfacesAddresses: Set[String]): IpHandler = new IpHandler(networkInterfacesAddresses)
  
}

class IpHandler(networkInterfacesAddresses: Set[String]) extends BaseHandler {

  override def handle(pcapPacket: PcapPacket): Option[Packet] = {
    val flowKey = pcapPacket.getFlowKey.hashCode()
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    val ip4 = new Ip4
    val ip6 = new Ip6

    val protocol = if (pcapPacket.hasHeader(ip4)) {
      Protocols.IP4
    } else if (pcapPacket.hasHeader(ip6)) {
      Protocols.IP6
    } else {
      Constants.EMPTY_STRING
    }

    val sourceAddress = PacketUtils.getSourceAddress(pcapPacket, ip4, ip6)
    val destinationAddress = PacketUtils.getDestinationAddress(pcapPacket, ip4, ip6)
    val direction = PacketUtils.getDirection(sourceAddress, networkInterfacesAddresses)

    if (protocol.isEmpty) {
      None
    } else {
      if (!Multicast.ADDRESSES.contains(destinationAddress) && !networkInterfacesAddresses.contains(sourceAddress) && pcapPacket.getHeaderCount == 2) {

        PacketBuilder.build(
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
  }

}
