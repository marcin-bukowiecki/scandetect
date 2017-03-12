package utils

import Flags.TCP._

/**
  * Created by Marcin on 2016-10-25.
  */
object Tcp {

  object Patterns {
    val TCP_CONNECT_CLOSED_PORT = Seq(Seq(SYN), Seq(RST, ACK))
    val TCP_CONNECT_OPEN_PORT = Seq(Seq(SYN), Seq(SYN, ACK), Seq(ACK), Seq(RST, ACK))

    val TCP_SYN_ATTACK_OPEN_PORT = Seq(Seq(SYN), Seq(SYN, ACK), Seq(RST, ACK))
    val TCP_SYN_ATTACK_CLOSED_PORT = Seq(Seq(SYN), Seq(RST, ACK))
  }

}
