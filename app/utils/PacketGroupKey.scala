package utils

import models.Packet

object PacketGroupKey {

  def apply(flowKey: Long, additionalHash: Long): PacketGroupKey = new PacketGroupKey(flowKey, additionalHash)

  def apply(packet: Packet):PacketGroupKey = new PacketGroupKey(packet)

}

class PacketGroupKey(val flowKey: Long, val additionalHash: Long) {

  private val keyTuple = (flowKey, additionalHash)

  def this(packet: Packet) = this(packet.flowKey, packet.additionalHash)

  override def hashCode(): Int = keyTuple.hashCode()

  override def equals(obj: scala.Any): Boolean = {
    if (obj == null || !obj.isInstanceOf[PacketGroupKey]) {
      false
    } else {
      obj.asInstanceOf[PacketGroupKey].keyTuple.equals(keyTuple)
    }
  }

}
