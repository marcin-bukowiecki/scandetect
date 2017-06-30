package com.mb.packet.handlers

import models.Packet
import org.jnetpcap.packet.PcapPacket

/**
  * Created by Marcin on 2017-06-30.
  */
abstract class BaseHandler {

  def handle(pcapPacket: PcapPacket): Option[Packet]

}
