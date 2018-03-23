package utils

import algorithms._

object Constants {

  val INTEGER_ZERO = 0

  val INTEGER_ONE = 1

  val INTEGER_TWO = 2

  val EMPTY_STRING = ""

  val COMMA = ","

  val INFO_DELIM = "="

  val ZERO_AS_STRING = "0"

  val UNKNOWN = "UNKNOWN"

  val NO_HASHCODE: Long = -1L

  val ICMP_HASHCODE = 3L

  val ONE_SECOND_MILLIS = 1000

  val COLON = ":"

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

  val PORT_SCAN_CONTEXT_LABELS = Set(
    IterationResultHistoryLabels.didNotSendData,
    IterationResultHistoryLabels.portClosed,
    IterationResultHistoryLabels.suspiciousFinScanAttack,
    IterationResultHistoryLabels.suspiciousAckWinScanAttack,
    IterationResultHistoryLabels.suspiciousMaimonScanAttack
  )

  val OPEN_PORTS_COUNTER_LABELS = Set(
    IterationResultHistoryLabels.sendData,
    IterationResultHistoryLabels.removeFinePackets,
    IterationResultHistoryLabels.didNotSendData
  )

  val CLOSED_PORTS_COUNTER_LABELS = Set(
    IterationResultHistoryLabels.portClosed,
    IterationResultHistoryLabels.suspiciousFinScanAttack,
    IterationResultHistoryLabels.suspiciousAckWinScanAttack,
    IterationResultHistoryLabels.suspiciousMaimonScanAttack
  )

  object SettingsKeys {
    val DATABASE_URL = "DATABASE_URL"
    val DATABASE_USERNAME = "DATABASE_USERNAME"
    val DATABASE_PASSWORD = "DATABASE_PASSWORD"
    val HONEYPOT_DATABASE_URL = "HONEYPOT_DATABASE_URL"
    val HONEYPOT_DATABASE_USERNAME = "HONEYPOT_DATABASE_USERNAME"
    val HONEYPOT_DATABASE_PASSWORD = "HONEYPOT_DATABASE_PASSWORD"
    val CLOSED_PORT_THRESHOLD = "CLOSED_PORT_THRESHOLD"
    val USE_HONEYPOT = "USE_HONEYPOT"
  }

  object IterationResultHistoryLabels {
    val didNotSendData: String = DidNotSendData.getClass.getName.split("\\$").last
    val initializingConnection: String = InitializingConnection.getClass.getName.split("\\$").last
    val sendData: String = SendData.getClass.getName.split("\\$").last
    val initializingRemoveFinePackets: String = InitializingRemoveFinePackets.getClass.getName.split("\\$").last
    val portClosed: String = PortClosed.getClass.getName.split("\\$").last
    val suspiciousNetworkScan: String = SuspiciousNetworkScan.getClass.getName.split("\\$").last
    val removeFinePackets: String = RemoveFinePackets.getClass.getName.split("\\$").last
    val suspiciousFinScanAttack: String = SuspiciousFinScanAttack.getClass.getName.split("\\$").last
    val suspiciousAckWinScanAttack: String = SuspiciousAckWinScanAttack.getClass.getName.split("\\$").last
    val suspiciousMaimonScanAttack: String = SuspiciousMaimonScanAttack.getClass.getName.split("\\$").last
  }

}
