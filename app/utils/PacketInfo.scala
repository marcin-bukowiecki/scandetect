package utils

/**
  * Created by Marcin on 2016-10-30.
  */
object PacketInfo {

  object Tcp {
    val LEN = "LEN"
    val LENGTH = "LENGTH"
    val TCP_SEGMENT = "TCP_SEGMENT"
    val SEQ = "SEQ"
    val ACK = "ACK"
    val WIN = "WIN"
    val WIN_SCALE = "WIN_SCALE"
    val CHECKSUM_CORRECT = "CHECKSUM_CORRECT"
    val NETWORK_LAYER_PRESENCE = "NETWORK_LAYER_PRESENCE"
    val HEADER_LENGTH = "HEADER_LENGTH"
  }

  object Udp {
    val NETWORK_LAYER_PRESENCE = "NETWORK_LAYER_PRESENCE"
  }

  object Ip {
    val ONLY_NETWORK_LAYER = "ONLY_NETWORK_LAYER"
  }

  object Sctp {
    val DATA = "DATA"
    val SHUTDOWN = "SHUTDOWN"
  }

}
