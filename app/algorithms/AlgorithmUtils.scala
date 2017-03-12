package algorithms

import models.Packet
import utils._

import scala.math._
import scala.annotation.switch

/**
  * Created by Marcin on 2016-10-29.
  */
object AlgorithmUtils {

  val SUPPORTED_INTERNET_PROTOCOLS = Set(
    Protocols.ICMP,
    Protocols.ARP,
    Protocols.IP4,
    Protocols.IP6
  )

  val CONNECTION_PROTOCOLS = Set(
    Protocols.TCP,
    Protocols.SCTP
  )

  val SUPPORTED_TRANSPORT_PROTOCOLS = Set(
    Protocols.TCP,
    Protocols.UDP,
    Protocols.SCTP
  )

  def isConnectionProtocol(protocol: String) = CONNECTION_PROTOCOLS.contains(protocol)

  def isSupportedInternetProtocol(protocol: String) = SUPPORTED_INTERNET_PROTOCOLS.contains(protocol)

  def isSupportedTransportProtocol(protocol: String) = SUPPORTED_TRANSPORT_PROTOCOLS.contains(protocol)

  def isInitializingConnection(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP if packets.head.containsOnlySynFlag && packets.head.isOutcoming => true
      case Protocols.SCTP if packets.head.containsInitFlag && packets.head.isOutcoming => true
      case _ => false
    }
  }

  def isConnectionClosed(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP =>
        if (packets.map(_.flags).exists(flags => {
          (flags.size == 2 && flags.contains(Flags.TCP.RST) && flags.contains(Flags.TCP.ACK)) ||
            (flags.size == 1 && flags.contains(Flags.TCP.RST))
        })) true else {
          isConnectionProperlyClosed(protocol, packets)
        }
      case _ => false
    }
  }

  def isConnectionProperlyClosed(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP =>
        packets.foldLeft(Set[String]())((finFlagsHolders: Set[String], packet: Packet) => {
          packet.flags match {
            case Seq(Flags.TCP.FIN, Flags.TCP.ACK) => packet.direction match {
              case Direction.INCOME if !finFlagsHolders.contains(Direction.INCOME) =>
                finFlagsHolders ++ Set(Direction.INCOME)
              case Direction.OUTCOME if !finFlagsHolders.contains(Direction.OUTCOME) =>
                finFlagsHolders ++ Set(Direction.OUTCOME)
              case default => finFlagsHolders
            }
            case _ => finFlagsHolders
          }
        }).size == 2
      case Protocols.SCTP =>
        packets.exists(_.isShutdownChunk)
      case _ => true
    }
  }

  def isPortClosedForTwoPackets(packets: Seq[Packet]) = {
    packets.size match {
      case 2 => packets.head.isIncoming && packets.last.isOutcoming && packets.head.containsOnlySynFlag && (packets.last.containsOnlyRstAckFLags || packets.last.containsOnlyRstFlag)
      case _ => false
    }
  }

  def isPortClosedForFourPackets(packets: Seq[Packet]) = {
    packets.size match {
      case 4 => packets.head.isIncoming && packets.head.containsOnlySynFlag && packets.last.isIncoming && (packets.last.containsOnlyRstAckFLags || packets.last.containsOnlyRstFlag) &&
        packets(1).isOutcoming && packets(1).containsOnlySynAckFlags && packets(2).isIncoming && packets(2).containsOnlyAckFlag
      case _ => false
    }
  }

  def isPortClosed(protocol: String, packets: Seq[Packet]) = {
    protocol match {
      case Protocols.TCP => packets.size match {
        case 1 => false
        case 2 => isPortClosedForTwoPackets(packets)
        case _ => packets.sliding(2).exists(ps => isPortClosedForTwoPackets(ps))
      }
      case Protocols.SCTP if packets.size == 2 && (packets.head.isIncoming && packets.head.containsInitFlag &&
        packets.last.isOutcoming && (packets.last.containsAbortFlag || packets.last.isIcmp)) => true
      case Protocols.UDP =>
        if (packets.head.isIncoming && packets.last.isOutcoming && packets.last.isIcmpPacket && packets.last.isIcmpType3Code3) true
        else if (packets.last.isOutcoming && packets.last.isUdpPacket) false
        else if (packets.size > 2 && packets.sliding(2).exists(slide => slide.head.isIncoming && slide.head.isUdp && slide.last.isIcmp && slide.last.isOutcoming)) true
        else false
      case _ => false
    }
  }

  def didSendAnyData(protocol: String, packets: Seq[Packet]) = protocol match {
    case Protocols.TCP => packets.map(_.flags) match {
      case Tcp.Patterns.TCP_CONNECT_OPEN_PORT => false
      case Tcp.Patterns.TCP_CONNECT_CLOSED_PORT => false
      case default =>
        val fp = packets.filter(p => p.containsOnlyAckFlag || p.containsOnlyPshAckFlag)
        fp.nonEmpty && fp.exists(_.length > 0)
    }
    case Protocols.SCTP => packets.filter(_.isIncoming).exists(_.isDataChunk)
    case Protocols.UDP => packets.exists(p => p.isIncoming && p.length > 0)
    case default => false
  }

  def isAckWinScan(protocol: String, packets: Seq[Packet]) = protocol match {
    case Protocols.TCP =>
      packets.size == 2
      packets.head.isIncoming &&
      packets.head.containsOnlyAckFlag &&
      packets.head.info(PacketInfo.Tcp.SEQ) == "0" &&
      packets.last.containsOnlyRstFlag &&
      getTimeBetweenCapturedPackets(packets.head, packets.last) <= AttackPatterns.TIME_FRAMES_BETWEEN_PACKETS(ScanAttackTypes.AttackType.TCP_ACK)
    case _ => false
  }

  def isSuspiciousAckWinScan(protocol: String, packets: Seq[Packet]) = protocol match {
    case Protocols.TCP =>
      packets.size == 2
      packets.head.isIncoming &&
      packets.head.containsOnlyAckFlag &&
      packets.last.containsOnlyRstFlag &&
      getTimeBetweenCapturedPackets(packets.head, packets.last) <=
        AttackPatterns.TIME_FRAMES_BETWEEN_PACKETS(ScanAttackTypes.AttackType.TCP_ACK)
    case _ => false
  }

  def tcpPacketWithoutAnyFlag(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP => packets.exists(_.flags.isEmpty)
      case _ => false
    }
  }

  def isMaimonAttack(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP => packets.size == 2 &&
        packets.head.isIncoming &&
        packets.head.containsOnlyFinAckFlag &&
        packets.last.isOutcoming &&
        packets.last.containsOnlyRstFlag &&
        packets.last.checksumIsNotCorrect &&
        packets.head.info(PacketInfo.Tcp.SEQ) == "0" &&
        packets.head.info(PacketInfo.Tcp.WIN) == "1024" &&
        getTimeBetweenCapturedPackets(packets.head, packets.last) <= AttackPatterns.TIME_FRAMES_BETWEEN_PACKETS(ScanAttackTypes.AttackType.TCP_MAIMON)
      case _ => false
    }
  }

  def isSuspiciousMaimonAttack(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP => packets.size == 2 &&
        packets.head.isIncoming &&
        packets.head.containsOnlyFinAckFlag &&
        packets.last.isOutcoming &&
        packets.last.containsOnlyRstFlag &&
        getTimeBetweenCapturedPackets(packets.head, packets.last) <= AttackPatterns.TIME_FRAMES_BETWEEN_PACKETS(ScanAttackTypes.AttackType.TCP_MAIMON)
      case _ => false
    }
  }

  def isXmasAttack(protocol: String, packets: Seq[Packet]): Boolean = {
    (packets.size: @switch) match {
      case 2 if protocol == Protocols.TCP => packets.head.isIncoming &&
        packets.head.containsOnlyFinPshUrgFlags &&
        packets.last.containsOnlyRstAckFLags &&
        packets.last.info(PacketInfo.Tcp.WIN) == "0" &&
        ((packets.last.info(PacketInfo.Tcp.ACK).toLong - 1L) == packets.head.info(PacketInfo.Tcp.SEQ).toLong)
      case _ => false
    }
  }

  def isFinAttack(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP =>
        packets.size == 2 &&
        packets.head.isIncoming &&
        packets.head.containsOnlyFinFlag &&
        packets.head.info(PacketInfo.Tcp.SEQ) == "1" &&
        packets.head.info(PacketInfo.Tcp.WIN) == "1024"
        packets.last.containsOnlyRstAckFLags &&
        packets.last.info(PacketInfo.Tcp.SEQ) == "1" &&
        packets.last.checksumIsNotCorrect &&
        packets.last.info(PacketInfo.Tcp.WIN) == "0" &&
        (Integer.valueOf(packets.last.info(PacketInfo.Tcp.ACK)) == Integer.valueOf(packets.head.info(PacketInfo.Tcp.SEQ) + 1))
      case _ => false
    }
  }

  def isSuspiciousFinAttack(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP =>
        packets.size == 2 &&
        packets.head.isIncoming &&
        packets.head.containsOnlyFinFlag &&
        packets.last.containsOnlyRstAckFLags &&
        (Integer.valueOf(packets.last.info(PacketInfo.Tcp.ACK)) == Integer.valueOf(packets.head.info(PacketInfo.Tcp.SEQ) + 1))
      case _ => false
    }
  }

  def wasNotProperlyFinished(protocol: String, packets: Seq[Packet]): Boolean = {
    protocol match {
      case Protocols.TCP => packets.last.containsOnlyRstAckFLags || packets.last.containsOnlyRstFlag
      case _ => false
    }
  }

  def lastIsIncoming(protocol: String, packets: Seq[Packet]): Boolean = {
    packets.last.isIncoming
  }

  def getTimeBetweenCapturedPackets(p1: Packet, p2: Packet): Long = {
    p2.timestamp - p1.timestamp
  }

  def getSourceAddress(packets: Seq[Packet]) = {
    val incomingPackets = packets.filter(_.isIncoming)

    if (incomingPackets.isEmpty) {
      packets.filter(_.isOutcoming).head.destinationAddress
    } else {
      incomingPackets.head.sourceAddress
    }
  }

  def getDestinationPort(packets: Seq[Packet]) = {
    val incomingPackets = packets.filter(_.isIncoming)

    if (incomingPackets.isEmpty) {
      packets.filter(_.isOutcoming).head.sourcePort
    } else {
      incomingPackets.head.destinationPort
    }
  }

  def getAttackTypeAsString[A <: IterationResult](iterationResult: A) = iterationResult match {
    case SuspiciousMaimonScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) => ScanAttackTypes.AttackType.TCP_MAIMON
    case SuspiciousAckWinScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) => ScanAttackTypes.AttackType.TCP_ACK_WIN
    case SuspiciousFinScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) => ScanAttackTypes.AttackType.TCP_FIN
  }

  def getAttackType[A <: IterationResult](iterationResult: A, chance: Int) = iterationResult match {
    case SuspiciousMaimonScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) => MaimonScanAttack(old, analyzed, chance)
    case SuspiciousAckWinScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) => AckWinScanAttack(old, analyzed, chance)
    case SuspiciousFinScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) => FinScanAttack(old, analyzed, chance)
    case PortClosed(old: Seq[Packet], analyzed: Seq[Packet]) => PortScanAlert(old, analyzed, chance)
    case DidNotSendData(old: Seq[Packet], analyzed: Seq[Packet]) => PortScanAlert(old, analyzed, chance)
  }

  val logBase = 2

  def getClosedPortScore(threshold: Int, closedPorts: Int): Double = {
    if (closedPorts <= threshold) {
      0
    } else {
      ((log(closedPorts - (threshold - 1)) / scala.math.log(logBase)) - 1) / 10
    }
  }

  def incomingContainsInternetProtocol(packets: Seq[Packet], protocol: String) = {
    isSupportedInternetProtocol(protocol) && packets.exists(_.isIncoming)
  }

}
