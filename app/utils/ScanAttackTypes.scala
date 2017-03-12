package utils

object ScanAttackTypes {

  object ScanType {
    val NETWORK_SCAN = "NETWORK SCAN"
    val PORT_SCAN = "PORT SCAN"
  }

  object AttackType {
    val TCP_SYN = "TCP SYN"
    val TCP_SYN_OR_TCP_CONNECT = "TCP SYN, TCP CONNECT"
    val TCP_ACK = "TCP ACK"
    val TCP_CONNECT = "TCP CONNECT"
    val TCP_NULL = "TCP NULL"
    val TCP_XMAS = "TCP XMAS"
    val TCP_MAIMON = "TCP MAIMON"
    val TCP_FIN = "TCP FIN"
    val TCP_ACK_WIN = "TCP ACK WIN"
    val SCTP_INIT = "SCTP INIT"
    val UDP = "UDP"
    val ARP = "ARP"
    val ICMP = "ICMP"
    val IP = "IP"
    val UNKNOWN = Constants.UNKNOWN
  }

}


