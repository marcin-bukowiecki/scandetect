package com.mb.packet.handlers

import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.protocol.network.Icmp.IcmpType
import org.jnetpcap.protocol.network.{Icmp, Ip4, Ip6}
import utils.PacketUtils.PacketBuilder
import utils.{Constants, PacketUtils, PortUtils, Protocols}

/**
  * Created by Marcin on 2017-06-30.
  */
class IcmpHandler(networkInterfacesAddresses: Set[String], icmp: Icmp) extends BaseHandler {

  override def handle(pcapPacket: PcapPacket): Option[Packet] = {
    val icmpUnreachable = new Icmp.DestinationUnreachable
    val icmpPing = new Icmp.EchoRequest
    val ip4 = new Ip4
    val ip6 = new Ip6

    val sourceAddress: String = PacketUtils.getSourceAddress(pcapPacket, ip4, ip6)
    val destinationAddress: String = PacketUtils.getDestinationAddress(pcapPacket, ip4, ip6)
    val direction = PacketUtils.getDirection(sourceAddress, networkInterfacesAddresses)
    val flowKey = pcapPacket.getFlowKey.hashCode()
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    if (icmp.hasSubHeader(icmpPing)) {
      PacketBuilder.build(
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
      PacketBuilder.build(
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
  }

}
