package utils

object AttackPatterns {

  val TIME_FRAMES_BETWEEN_PACKETS = Map(
    ScanAttackTypes.AttackType.TCP_MAIMON -> 1000L,
    ScanAttackTypes.AttackType.TCP_ACK -> 1000L,
    ScanAttackTypes.AttackType.TCP_FIN -> 1000L
  )

}
