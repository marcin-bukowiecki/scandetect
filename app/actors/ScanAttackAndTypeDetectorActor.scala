package actors

import java.util.Date

import akka.actor._
import akka.event.Logging
import algorithms._
import models.{Alert, Packet}
import repositories.{AlertRepositoryImpl, IterationResultHistoryRepository}
import utils._

import scala.concurrent.{ExecutionContext, Future}

object ScanAttackAndTypeDetectorActor {

  def props = Props[ScanAttackAndTypeDetectorActor]

}

class ScanAttackAndTypeDetectorActor(alertsService: AlertRepositoryImpl,
                                     iterationResultHistoryService: IterationResultHistoryRepository) extends Actor {

  val log = Logging(context.system, this)

  implicit val executionContext: ExecutionContext = context.system.dispatchers.lookup("software-detect-actor-context")

  override def receive = {
    case attackType@XmasScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) =>
      val incomingPacket = getIncomingPacket(attackType.all).get

      createAlert(
        ScanAttackTypes.ScanType.PORT_SCAN,
        ScanAttackTypes.AttackType.TCP_XMAS,
        incomingPacket.sourceAddress,
        Constants.EMPTY_STRING,
        AttackSoftwareResolver.attackTypes(ScanAttackTypes.AttackType.TCP_XMAS),
        incomingPacket.destinationPort,
        100
      ).map(alert => alertsService.create(alert))

    case attackType@TcpNullScanAttack(old: Seq[Packet], analyzed: Seq[Packet]) =>
      val incomingPacket = getIncomingPacket(attackType.all).get

      createAlert(
        ScanAttackTypes.ScanType.PORT_SCAN,
        ScanAttackTypes.AttackType.TCP_NULL,
        incomingPacket.sourceAddress,
        Constants.EMPTY_STRING,
        AttackSoftwareResolver.attackTypes(ScanAttackTypes.AttackType.TCP_NULL),
        incomingPacket.destinationPort,
        100
      ).map(alert => alertsService.create(alert))

    case attackType@AckWinScanAttack(old: Seq[Packet], analyzed: Seq[Packet], chance: Int) =>
      val incomingPacket = getIncomingPacket(attackType.all).get

      createAlert(
        ScanAttackTypes.ScanType.PORT_SCAN,
        ScanAttackTypes.AttackType.TCP_ACK_WIN,
        incomingPacket.sourceAddress,
        Constants.EMPTY_STRING,
        AttackSoftwareResolver.attackTypes(ScanAttackTypes.AttackType.TCP_ACK_WIN),
        incomingPacket.destinationPort,
        100
      ).map(alert => alertsService.create(alert))

    case alert@PortScanAlert(old: Seq[Packet], analyzed: Seq[Packet], chance: Int) =>
      val incomingPacket = getIncomingPacket(alert.all).get
      val protocol = incomingPacket.protocol

      protocol match {
        case Protocols.TCP =>
          matchTcpProtocolAttackPattern(incomingPacket.sourceAddress, incomingPacket.destinationPort, alert,
            ScanAttackTypes.ScanType.PORT_SCAN)
            .map(alert => alertsService.create(alert))

        case Protocols.UDP =>
          createAlert(
            ScanAttackTypes.ScanType.PORT_SCAN,
            ScanAttackTypes.AttackType.UDP,
            incomingPacket.sourceAddress,
            Constants.EMPTY_STRING,
            AttackSoftwareResolver.resolve(alert.all),
            incomingPacket.destinationPort,
            alert.chance
          ).map(alert => alertsService.create(alert))

        case _ => log.info("No scan alert matching.")
      }

    case networkScanAlert@NetworkScanAlert(old: Seq[Packet], analyzed: Seq[Packet]) =>
      val protocol = networkScanAlert.all.head.protocol

      val addressAndPort = getIncomingPacket(networkScanAlert.all)
        .map(p => (p.sourceAddress, p.destinationPort))
        .getOrElse((networkScanAlert.all.head.destinationAddress, networkScanAlert.all.head.sourcePort))

      val sourceAddress = addressAndPort._1
      val destinationPort = addressAndPort._2

      protocol match {
        case Protocols.TCP =>
          matchTcpProtocolAttackPattern(sourceAddress, destinationPort, networkScanAlert,
            ScanAttackTypes.ScanType.NETWORK_SCAN)
            .map(alert => alertsService.create(alert))

        case Protocols.UDP =>
          createAlert(
            ScanAttackTypes.ScanType.NETWORK_SCAN,
            ScanAttackTypes.AttackType.UDP,
            sourceAddress,
            Constants.EMPTY_STRING,
            AttackSoftwareResolver.resolve(networkScanAlert.all),
            destinationPort,
            100
          ).map(alert => alertsService.create(alert))

        case Protocols.SCTP_INIT =>
          createAlert(
            ScanAttackTypes.ScanType.NETWORK_SCAN,
            ScanAttackTypes.AttackType.SCTP_INIT,
            sourceAddress,
            Constants.EMPTY_STRING,
            AttackSoftwareResolver.resolve(networkScanAlert.all),
            destinationPort,
            100
          ).map(alert => alertsService.create(alert))

        case Protocols.IP4 | Protocols.IP6 =>
          createAlert(
            ScanAttackTypes.ScanType.NETWORK_SCAN,
            ScanAttackTypes.AttackType.IP,
            sourceAddress,
            Constants.EMPTY_STRING,
            AttackSoftwareResolver.resolve(networkScanAlert.all),
            PortUtils.NO_PORT,
            100
          ).map(alert => alertsService.create(alert))

        case Protocols.ICMP =>
          createAlert(
            ScanAttackTypes.ScanType.NETWORK_SCAN,
            ScanAttackTypes.AttackType.ICMP,
            sourceAddress,
            Constants.EMPTY_STRING,
            AttackSoftwareResolver.resolve(networkScanAlert.all),
            PortUtils.NO_PORT,
            100
          ).map(alert => alertsService.create(alert))

        case Protocols.ARP =>
          createAlert(
            ScanAttackTypes.ScanType.NETWORK_SCAN,
            ScanAttackTypes.AttackType.ARP,
            sourceAddress,
            Constants.EMPTY_STRING,
            AttackSoftwareResolver.resolve(networkScanAlert.all),
            PortUtils.NO_PORT,
            100
          ).map(alert => alertsService.create(alert))
      }
  }

  def matchTcpProtocolAttackPattern(sourceAddress: String, destinationPort: Int, iterationResult: IterationResult,
                                    scanType: String): Future[Alert] = {

    if (iterationResult.all.size >= 2 &&
      iterationResult.all.sliding(2).exists(ps => ps.head.containsOnlySynFlag && (ps.last.containsOnlyRstFlag
        || ps.last.containsOnlyRstAckFLags))) {

      createAlert(
        scanType,
        ScanAttackTypes.AttackType.TCP_SYN,
        sourceAddress,
        Constants.EMPTY_STRING,
        AttackSoftwareResolver.resolve(iterationResult.all, ScanAttackTypes.AttackType.TCP_SYN),
        destinationPort,
        getChance(iterationResult)
      )
    } else if (iterationResult.all.size >= 3 &&
      iterationResult.all.sliding(3).exists(ps => ps.head.containsOnlySynFlag && (ps.last.containsOnlyRstFlag
        || ps.last.containsOnlyRstAckFLags) && ps(2).containsOnlySynAckFlags)) {

      createAlert(
        scanType,
        ScanAttackTypes.AttackType.TCP_SYN,
        sourceAddress,
        Constants.EMPTY_STRING,
        AttackSoftwareResolver.resolve(iterationResult.all, ScanAttackTypes.AttackType.TCP_SYN),
        destinationPort,
        getChance(iterationResult)
      )
    } else if (iterationResult.all.size >= 4 &&
      iterationResult.all.sliding(4).exists(ps => ps.head.containsOnlySynFlag && (ps.last.containsOnlyRstFlag
        || ps.last.containsOnlyRstAckFLags) && ps(1).containsOnlySynAckFlags && ps(2).containsOnlyAckFlag)) {

      createAlert(
        scanType,
        ScanAttackTypes.AttackType.TCP_CONNECT,
        sourceAddress,
        Constants.EMPTY_STRING,
        AttackSoftwareResolver.resolve(iterationResult.all, ScanAttackTypes.AttackType.TCP_CONNECT),
        destinationPort,
        getChance(iterationResult)
      )
    } else {
      createAlert(
        scanType,
        ScanAttackTypes.AttackType.UNKNOWN,
        sourceAddress,
        Constants.EMPTY_STRING,
        Set(Constants.UNKNOWN),
        destinationPort,
        getChance(iterationResult)
      )
    }
  }

  def createAlert(scanType: String, attackType: String, sourceAddress: String, description: String,
                  softwareUsed: Set[String], destinationPort: Int, chance: Int): Future[Alert] = {
    getPortScanPorts(attackType, sourceAddress).map(result =>
      Alert(None,
        String.valueOf(new Date().getTime),
        scanType,
        attackType,
        sourceAddress,
        description,
        softwareUsed,
        Seq(destinationPort) ++ result,
        chance,
        read = false)
    )
  }

  def getIncomingPacket(packets: Seq[Packet]): Option[Packet] = {
    for (p <- packets) {
      if (p.isIncoming) {
        return Some(p)
      }
    }
    None
  }

  def getChance(iterationResult: IterationResult) = {
    iterationResult match {
      case alert@PortScanAlert(old: Seq[Packet], analyzed: Seq[Packet], chance: Int) => alert.chance
      case _ => 100
    }
  }

  def getPortScanPorts(attackType: String, sourceAddress: String): Future[Set[Int]] = {
    val f1 = iterationResultHistoryService.getPortScanPorts(sourceAddress)

    val f2 = if (attackType == ScanAttackTypes.AttackType.UDP) {
      iterationResultHistoryService
        .findByResultTypeAndSourceAddress(sourceAddress, Constants.IterationResultHistoryLabels.sendData)
        .map(_.map(_.port))
    } else {
      Future(Seq())
    }

    Future.sequence(Seq(f1, f2)).map(_.flatten.toSet.filter(_ != PortUtils.NO_PORT))
  }

}
