package models

import org.jnetpcap.protocol.network.Icmp.IcmpType
import play.api.libs.json._
import reactivemongo.bson.{BSONDocument, BSONHandler, BSONObjectID, BSONString}
import utils._

object PacketData extends BSONHandler[BSONDocument, Map[String, String]] {

  override def read(bson: BSONDocument): Map[String, String] = {
    bson.elements.map {
      element => element.name.asInstanceOf[String] -> element.value.asInstanceOf[BSONString].as[String]
    }.toMap
  }

  override def write(doc: Map[String, String]): BSONDocument = {
      BSONDocument(doc.map (t => (t._1, BSONString(t._2))))
  }

}

class PacketData(_id: Option[BSONObjectID],
                 timestamp: Long,
                 protocol: String,
                 sourceAddress: String,
                 sourcePort: Int,
                 destinationAddress: String,
                 destinationPort: Int,
                 info: Map[String, String],
                 flags: Seq[String],
                 flowKey: Long,
                 additionalHash: Long,
                 additionalHashNetwork: Long,
                 direction: String,
                 length: Int) {

  def containsOnlyAckFlag = flags.size == 1 && flags.head == Flags.TCP.ACK

  def containsOnlyRstFlag = flags.size == 1 && flags.head == Flags.TCP.RST

  def isTcpPacket = protocol == Protocols.TCP

  def isUdpPacket = protocol == Protocols.UDP

  def isSctpPacket = protocol == Protocols.SCTP

  def isIp4Packet = protocol == Protocols.IP4

  def isIp6Packet = protocol == Protocols.IP6

  def isIcmpPacket = protocol == Protocols.ICMP

  def isIncoming = direction == Direction.INCOME

  def containsOnlyFinAckFlag = flags.size == 2 && flags.contains(Flags.TCP.FIN) && flags.contains(Flags.TCP.ACK)

  def isOutcoming = direction == Direction.OUTCOME

  def containsSynFlag = flags.contains(Flags.TCP.SYN)

  def containsOnlySynFlag = flags.size == 1 && flags.contains(Flags.TCP.SYN)

  def containsInitFlag = protocol == Protocols.SCTP && flags.contains(Flags.SCTP.INIT)

  def containsOnlySynAckFlags = flags.size == 2 && flags.head == Flags.TCP.SYN && flags(1) == Flags.TCP.ACK

  def containsOnlyRstAckFLags = flags.size == 2 && flags.head == Flags.TCP.RST && flags(1) == Flags.TCP.ACK

  def containsAbortFlag = protocol == Protocols.SCTP && flags.head == Flags.SCTP.ABORT

  def isIcmpType3Code3 = flags.head == IcmpType.DESTINATION_UNREACHABLE.toString && flags(2) == "3"

  def isIcmp = protocol == Protocols.ICMP

  def isUdp = protocol == Protocols.UDP

  def containsAckFlag = flags.contains(Flags.TCP.ACK)

  def containsOnlyPshAckFlag = flags.size == 2 && flags.contains(Flags.TCP.ACK) && flags.contains(Flags.TCP.PSH)

  def containsOnlyFinFlag = flags.size == 1 && flags.contains(Flags.TCP.FIN)

  def checksumIsCorrect = protocol == Protocols.TCP && info.contains(PacketInfo.Tcp.CHECKSUM_CORRECT) && info(PacketInfo.Tcp.CHECKSUM_CORRECT) == "true"

  def checksumIsNotCorrect = !checksumIsCorrect

  def containsOnlyFinPshUrgFlags = flags.size == 3 && flags.contains(Flags.TCP.FIN) && flags.contains(Flags.TCP.PSH) && flags.contains(Flags.TCP.URG)

  def isDataChunk = protocol == Protocols.SCTP && flags.contains(PacketInfo.Sctp.DATA)

  def isShutdownChunk = protocol == Protocols.SCTP && flags.contains(PacketInfo.Sctp.SHUTDOWN)

}

case class Packet(_id: Option[BSONObjectID],
                  timestamp: Long,
                  protocol: String,
                  sourceAddress: String,
                  sourcePort: Int,
                  destinationAddress: String,
                  destinationPort: Int,
                  info: Map[String, String],
                  flags: Seq[String],
                  flowKey: Long,
                  additionalHash: Long,
                  additionalHashNetwork: Long,
                  direction: String,
                  length: Int)

  extends PacketData(_id: Option[BSONObjectID],
                    timestamp: Long,
                    protocol: String,
                    sourceAddress: String,
                    sourcePort: Int,
                    destinationAddress: String,
                    destinationPort: Int,
                    info: Map[String, String],
                    flags: Seq[String],
                    flowKey: Long,
                    additionalHash: Long,
                    additionalHashNetwork: Long,
                    direction: String,
                    length: Int) {

}

object Packet {

  implicit object PacketReader extends Reads[Packet] {
    override def reads(json: JsValue): JsResult[Packet] = {
      try {
        val _id = (json \ "_id").as[BSONObjectID]
        val timestamp = (json \ "timestamp").as[Long]
        val protocol = (json \ "protocol").as[String]
        val sourceAddress = (json \ "sourceAddress").as[String]
        val sourcePort = (json \ "sourcePort").as[Int]
        val destinationAddress = (json \ "destinationAddress").as[String]
        val destinationPort = (json \ "destinationPort").as[Int]
        val info = (json \ "info").as[Map[String, String]]
        val flags = (json \ "flags").as[Seq[String]]
        val flowKey = (json \ "flowKey").as[Long]
        val additionalHash = (json \ "additionalHash").as[Long]
        val additionalHashNetwork = (json \ "additionalHashNetwork").as[Long]
        val direction = (json \ "direction").as[String]
        val length = (json \ "length").as[Int]

        JsSuccess(Packet(Option(_id), timestamp, protocol, sourceAddress, sourcePort, destinationAddress, destinationPort, info, flags, flowKey, additionalHash, additionalHashNetwork, direction, length))
      } catch {
        case e: Throwable => JsError(e.getMessage)
      }
    }
  }

  implicit object PacketWriter extends OWrites[Packet] {
    override def writes(packet: Packet) = Json.obj(
        "_id" -> packet._id.get,
        "timestamp" -> packet.timestamp,
        "protocol" -> packet.protocol,
        "sourceAddress" -> packet.sourceAddress,
        "sourcePort" -> packet.sourcePort,
        "destinationAddress" -> packet.destinationAddress,
        "destinationPort" -> packet.destinationPort,
        "info" -> packet.info,
        "flags" -> packet.flags,
        "flowKey" -> packet.flowKey,
        "additionalHash" -> packet.additionalHash,
        "additionalHashNetwork" -> packet.additionalHashNetwork,
        "direction" -> packet.direction,
        "length" -> packet.length
    )
  }

}
