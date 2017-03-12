package utils

object Protocols {

  val ICMP = "ICMP"
  val TCP = "TCP"
  val UDP = "UDP"
  val SCTP = "SCTP"
  val SCTP_INIT = "SCTP_INIT"
  val SCTP_INIT_ACK = "SCTP_INIT_ACK"
  val SCTP_ABORT = "SCTP_ABORT"
  val IP4 = "IPv4"
  val IP6 = "IPv6"
  val ARP = "ARP"

  val supportedProtocols = Seq(
    ICMP,
    TCP,
    UDP,
    SCTP,
    SCTP_INIT,
    SCTP_INIT_ACK,
    SCTP_ABORT,
    IP4,
    IP6,
    ARP
  )

}

abstract class Protocol
case object IPv4 extends Protocol
case object IPv6 extends Protocol



