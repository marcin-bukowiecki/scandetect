package com.mb.packet.handlers

import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.protocol.network.{Ip4, Ip6}
import org.jnetpcap.protocol.sigtran.SctpChunk.SctpChunkType
import org.jnetpcap.protocol.sigtran._
import utils.PacketUtils.PacketBuilder
import utils.{PacketUtils, Protocols}

/**
  * Created by Marcin on 2017-06-30.
  */
class SctpHandler(networkInterfacesAddresses: Set[String], sctp: Sctp) extends BaseHandler {

  override def handle(pcapPacket: PcapPacket): Option[Packet] = {
    val flowKey = pcapPacket.getFlowKey.hashCode()
    val timestamp = pcapPacket.getCaptureHeader.timestampInMicros()

    val sctpInit = new SctpInit
    val sctpInitAck = new SctpInitAck
    val sctpAbort = new SctpAbort
    val sctpData = new SctpData
    val sctpCookie = new SctpCookie
    val ip4 = new Ip4
    val ip6 = new Ip6

    val sourceAddress = PacketUtils.getSourceAddress(pcapPacket, ip4, ip6)
    val direction = PacketUtils.getDirection(sourceAddress, networkInterfacesAddresses)
    val destinationAddress = PacketUtils.getDestinationAddress(pcapPacket, ip4, ip6)

    if (pcapPacket.hasHeader(sctpInit)) {
      PacketBuilder.build(
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
        direction,
        pcapPacket.size()
      )
    } else if (pcapPacket.hasHeader(sctpInitAck)) {
      PacketBuilder.build(
        timestamp,
        Protocols.SCTP,
        sourceAddress,
        sctp.source(),
        destinationAddress,
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
      PacketBuilder.build(
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
      PacketBuilder.build(
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
      PacketBuilder.build(
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
  }

}
