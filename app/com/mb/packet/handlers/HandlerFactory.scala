package com.mb.packet.handlers

import org.jnetpcap.packet.{JHeader, PcapPacket}
import org.jnetpcap.protocol.network.{Arp, Icmp}
import org.jnetpcap.protocol.sigtran.Sctp
import org.jnetpcap.protocol.tcpip.{Tcp, Udp}

/**
  * Created by Marcin on 2017-06-30.
  */
object HandlerFactory {

  val emptyHandler = new EmptyHandler

  def getPcapPacketHandler(pcapPacket: PcapPacket, networkInterfacesAddresses: Set[String]): BaseHandler = {
    val tcp = new Tcp
    val arp = new Arp
    val udp = new Udp
    val sctp = new Sctp
    val icmp = new Icmp

    if (pcapPacket.hasHeader(icmp)) {
      new IcmpHandler(networkInterfacesAddresses, icmp)
    } else if (pcapPacket.hasHeader(tcp)) {
      new TcpHandler(networkInterfacesAddresses, tcp)
    } else if (pcapPacket.hasHeader(udp)) {
      new UdpHandler(networkInterfacesAddresses, udp)
    } else if (pcapPacket.hasHeader(sctp)) {
      new SctpHandler(networkInterfacesAddresses, sctp)
    } else if (pcapPacket.hasHeader(arp)) {
      new ArpHandler(networkInterfacesAddresses, arp)
    } else {
      new EmptyHandler
    }
  }

}
