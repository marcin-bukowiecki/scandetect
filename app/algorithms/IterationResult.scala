package algorithms

import models.Packet

/**
  * Created by Marcin on 2016-12-29.
  */
abstract class IterationResult {
  val captured: Seq[Packet]
  val analyzed: Seq[Packet]

  val all = (captured ++ analyzed).sortBy(_.timestamp)
}

case class ContinueIteration(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class PortScanAlert(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

case class NetworkScanAlert(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class SuspiciousNetworkScan(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class RemoveFinePackets(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class TcpNullScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class XmasScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class PortClosed(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class FinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

case class SuspiciousFinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class AckWinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

case class SuspiciousAckWinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class MaimonScanAttack(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

case class SuspiciousMaimonScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class InitializingConnection(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class InitializingRemoveFinePackets(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class InitializingConnectionAndDataTransfer(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class SendData(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

case class DidNotSendData(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult