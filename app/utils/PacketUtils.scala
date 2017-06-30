package utils

import models.Packet
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.packet.format.FormatUtils
import org.jnetpcap.protocol.network.{Ip4, Ip6}

object PacketUtils {

  def concatFlags(flags: Seq[String]) = {
    flags.foldLeft("")((prev: String, next: String) => {
      prev + next
    })
  }

  def generateAdditionalHashcode(sourceAddress: String, destinationAddress: String, direction: String): Long = {
    if (direction == Direction.INCOME) {
      (sourceAddress + destinationAddress).hashCode
    } else {
      (destinationAddress + sourceAddress).hashCode
    }
  }

  def generateAdditionalHashcode(sourcePort: Int, destinationPort: Int, direction: String): Long = {
    if (direction == Direction.INCOME) {
      val s1 = "%05d".format(sourcePort)
      val s2 = "%05d".format(destinationPort)
      (s1 + s2).hashCode
    } else {
      val s1 = "%05d".format(destinationPort)
      val s2 = "%05d".format(sourcePort)
      (s1 + s2).hashCode
    }
  }

  def getSourceAddress(pcapPacket: PcapPacket, ip4: Ip4, ip6: Ip6): String =
    if (pcapPacket.hasHeader(ip4)) FormatUtils.ip(ip4.source())
    else if (pcapPacket.hasHeader(ip6)) FormatUtils.ip(ip6.source())
    else Constants.EMPTY_STRING

  def getDestinationAddress(pcapPacket: PcapPacket, ip4: Ip4, ip6: Ip6): String =
    if (pcapPacket.hasHeader(ip4)) FormatUtils.ip(ip4.destination())
    else if (pcapPacket.hasHeader(ip6)) FormatUtils.ip(ip6.destination())
    else Constants.EMPTY_STRING

  def getDirection(sourceAddress: String, networkInterfacesAddresses: Set[String]): String =
    if (networkInterfacesAddresses.contains(sourceAddress)) utils.Direction.OUTCOME.toString
    else utils.Direction.INCOME.toString

  object PacketBuilder {

    def build(timestamp: Long, protocol: String, sourceAddress: String, sourcePort: Int, destinationAddress: String,
              destinationPort: Int,
              info: Map[String, String],
              flags: Seq[String],
              flowKey: Long,
              additionalHash: Long,
              additionalHashNetwork: Long,
              direction: String,
              length: Int): Some[Packet] = {

      Some(Packet(None, timestamp, protocol, sourceAddress, sourcePort, destinationAddress, destinationPort,
        info, flags, flowKey, additionalHash, additionalHashNetwork, direction, length)
      )
    }
  }

}

