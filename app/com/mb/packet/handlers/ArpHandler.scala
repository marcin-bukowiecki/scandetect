package com.mb.packet.handlers
import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.packet.format.FormatUtils
import org.jnetpcap.protocol.network.Arp
import utils.PacketUtils.PacketBuilder
import utils.{Constants, PacketUtils, PortUtils, Protocols}

/**
  * Created by Marcin on 2017-06-30.
  */
class ArpHandler(networkInterfacesAddresses: Set[String], arp: Arp) extends BaseHandler {

  override def handle(pcapPacket: PcapPacket): Option[Packet] = {
    val flowKey = pcapPacket.getFlowKey.hashCode()
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    val sourceAddress = FormatUtils.ip(arp.spa())
    val destinationAddress = FormatUtils.ip(arp.tpa())
    val direction = PacketUtils.getDirection(sourceAddress, networkInterfacesAddresses)

    PacketBuilder.build(
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
  }

}
