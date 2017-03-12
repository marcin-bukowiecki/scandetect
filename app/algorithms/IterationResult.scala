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

/**
  * Zdarzenia
  */

//Kontynuuj iteracje
case class ContinueIteration(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Alarm skanwoania portów
case class PortScanAlert(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult
//Alarm skanwoania sieci
case class NetworkScanAlert(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Podejrzane skanowanie sieci
case class SuspiciousNetworkScan(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Usuń pakiety
case class RemoveFinePackets(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Atak typu TCP Null
case class TcpNullScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Atak typu TCP Xmas
case class XmasScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Port zamknięty
case class PortClosed(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Atak typu TCP FIN
case class FinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

//Podejrzany atak typu TCP FIN
case class SuspiciousFinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Atak typu TCP ACK
case class AckWinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

//Podejrzany atak typu TCP ACK
case class SuspiciousAckWinScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Atak typu TCP Maimon
case class MaimonScanAttack(captured: Seq[Packet], analyzed: Seq[Packet], chance: Int) extends IterationResult

//Podejrzany atak typu TCP Maimon
case class SuspiciousMaimonScanAttack(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Inicjowanie połączenia
case class InitializingConnection(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Inicjowanie połączenia i usuń pakiety
case class InitializingRemoveFinePackets(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Inicjowanie połączenia i transmisja danych
case class InitializingConnectionAndDataTransfer(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Transmisja danych
case class SendData(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult

//Brak transmisji danych
case class DidNotSendData(captured: Seq[Packet], analyzed: Seq[Packet]) extends IterationResult