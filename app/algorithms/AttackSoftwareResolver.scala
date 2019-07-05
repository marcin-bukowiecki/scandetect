package algorithms

import models.Packet
import utils.{ScanAttackTypes, _}

object AttackSoftwareResolver {

  val packetLength = Map(
    ScanAttackTypes.AttackType.UDP -> Map(
      8 -> Set(ScanningSoftware.ANGRY_IP_SCANNER),
      29 -> Set(ScanningSoftware.ZMAP),
      0 -> Set(ScanningSoftware.NMAP)
    )
  )

  val headerLength = Map(
    ScanAttackTypes.AttackType.TCP_SYN -> Map(
      32 -> Set(ScanningSoftware.ANGRY_IP_SCANNER),
      40 -> Set(ScanningSoftware.EVILSCAN),
      20 -> Set(ScanningSoftware.MASSCAN, ScanningSoftware.ZMAP),
      24 -> Set(ScanningSoftware.NMAP)
    ),
    ScanAttackTypes.AttackType.TCP_CONNECT -> Map(
      32 -> Set(ScanningSoftware.ANGRY_IP_SCANNER),
      40 -> Set(ScanningSoftware.NMAP),
      20 -> Set(ScanningSoftware.MASSCAN, ScanningSoftware.ZMAP)
    )
  )

  val windowLength = Map(
    ScanAttackTypes.AttackType.TCP_SYN -> Map(
      32 -> Set(ScanningSoftware.ANGRY_IP_SCANNER),
      8192 -> Set(ScanningSoftware.EVILSCAN),
      65535 -> Set(ScanningSoftware.ZMAP),
      1024 -> Set(ScanningSoftware.NMAP, ScanningSoftware.MASSCAN)
    ),
    ScanAttackTypes.AttackType.TCP_CONNECT -> Map(
      32 -> Set(ScanningSoftware.ANGRY_IP_SCANNER),
      29200 -> Set(ScanningSoftware.NMAP),
      1024 -> Set(ScanningSoftware.MASSCAN),
      65535 -> Set(ScanningSoftware.ZMAP)
    )
  )

  val dataField = Map(
    ScanAttackTypes.AttackType.ICMP -> Map(
      56 -> Set(ScanningSoftware.ANGRY_IP_SCANNER),
      12 -> Set(ScanningSoftware.ZMAP),
      0 -> Set(ScanningSoftware.NMAP)
    )
  )

  val attackTypes = Map(
    ScanAttackTypes.AttackType.TCP_SYN -> Set(ScanningSoftware.NMAP,
      ScanningSoftware.ZMAP,
      ScanningSoftware.ANGRY_IP_SCANNER,
      ScanningSoftware.EVILSCAN,
      ScanningSoftware.MASSCAN),
    ScanAttackTypes.AttackType.ICMP -> Set(ScanningSoftware.NMAP,
      ScanningSoftware.ZMAP,
      ScanningSoftware.ANGRY_IP_SCANNER),
    ScanAttackTypes.AttackType.IP -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.ARP -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.TCP_CONNECT -> Set(ScanningSoftware.NMAP,
      ScanningSoftware.ANGRY_IP_SCANNER),
    ScanAttackTypes.AttackType.TCP_NULL -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.TCP_MAIMON -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.TCP_ACK_WIN -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.TCP_ACK -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.TCP_XMAS -> Set(ScanningSoftware.NMAP),
    ScanAttackTypes.AttackType.UDP -> Set(ScanningSoftware.NMAP,
      ScanningSoftware.ANGRY_IP_SCANNER,
      ScanningSoftware.ZMAP)
  )

  def resolve(packets: Seq[Packet], attackType: String): Set[String] = {
    packets.head.protocol match {
      case Protocols.TCP =>
        attackType match {
          case ScanAttackTypes.AttackType.TCP_SYN =>
            val software = attackTypes(ScanAttackTypes.AttackType.TCP_SYN)
            if (software.size == 1) {
              software
            } else {
              tryToResolveMultipleSoftware(Protocols.TCP, packets, software)
            }
          case ScanAttackTypes.AttackType.TCP_CONNECT =>
            val software = attackTypes(ScanAttackTypes.AttackType.TCP_CONNECT)
            if (software.size == 1) {
              software
            } else {
              tryToResolveMultipleSoftware(Protocols.TCP, packets, software)
            }
          case _ => Set(Constants.UNKNOWN)
        }
      case _ => Set(Constants.UNKNOWN)
    }
  }

  def resolve(packets: Seq[Packet]): Set[String] = {
    packets.head.protocol match {
      case Protocols.UDP =>
        val software = attackTypes(ScanAttackTypes.AttackType.UDP)
        if (software.size == 1) {
          software
        } else {
          tryToResolveMultipleSoftware(Protocols.UDP, packets, software)
        }
      case Protocols.ICMP =>
        val software = attackTypes(ScanAttackTypes.AttackType.ICMP)
        if (software.size == 1) {
          software
        } else {
          tryToResolveMultipleSoftware(Protocols.ICMP, packets, software)
        }
      case _ => Set(Constants.UNKNOWN)
    }
  }

  def tryToResolveMultipleSoftware(protocol: String, packets: Seq[Packet], software: Set[String]): Set[String] = {
    protocol match {
      case Protocols.UDP =>
        packetLength(ScanAttackTypes.AttackType.UDP)
          .getOrElse(packets.head.length, Set(ScanningSoftware.NMAP))

      case Protocols.ICMP =>
        dataField(ScanAttackTypes.AttackType.ICMP)
          .getOrElse(packets.head.length, Set(ScanningSoftware.NMAP))

      case Protocols.TCP =>
        val hl = packets.head.info.getOrElse(PacketInfo.Tcp.HEADER_LENGTH, 0).toString

        val softwareUsed: Set[String] = headerLength(ScanAttackTypes.AttackType.TCP_SYN)
          .getOrElse(hl.toInt, Set())

        if (softwareUsed.size > 1 || softwareUsed.isEmpty) {
          val w = packets.head.info.getOrElse(PacketInfo.Tcp.WIN, 0).toString
          val newUsedSoftware = windowLength(ScanAttackTypes.AttackType.TCP_SYN)
            .getOrElse(w.toInt, Set(ScanningSoftware.NMAP))

          newUsedSoftware.intersect(softwareUsed)
        } else {
          softwareUsed
        }

      case _ => software
    }
  }

}
