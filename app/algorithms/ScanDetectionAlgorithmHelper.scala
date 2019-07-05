package algorithms

import models.Packet
import utils.{Constants, NetworkLayerGroupKey, PacketGroupKey, Protocols}

object ScanDetectionAlgorithmHelper {

  def apply(): ScanDetectionAlgorithmHelper = new ScanDetectionAlgorithmHelper()

}

class ScanDetectionAlgorithmHelper {

  def groupPacketsByFlowKeyAdditionalHashAndNetworkProtocolHash(packets: Seq[Packet]): Map[NetworkLayerGroupKey, Seq[Packet]] = {
    packets
      .sortBy(_.timestamp)
      .groupBy(p =>
        if (p.protocol != Protocols.ICMP)
          NetworkLayerGroupKey(p.flowKey, p.additionalHash, p.additionalHashNetwork)
        else
          NetworkLayerGroupKey(p.flowKey, Constants.ICMP_HASHCODE, p.additionalHashNetwork)
      )
  }

  def groupPacketsByFlowKeyAndAdditionalHash(packets: Seq[Packet]): Map[PacketGroupKey, Seq[Packet]] = packets.sortBy(_.timestamp).groupBy(p => PacketGroupKey(p))


}
