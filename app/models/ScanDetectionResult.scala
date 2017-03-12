package models

import context.ScanDetectContext
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

case class ScanDetectionResult(sourceAddress: String,
                               packets: Seq[Packet],
                               scanScore: Int,
                               scannedPorts: Set[Int])

object AlertNotifier {
  /*
    def apply(scanDetectionResult: ScanDetectionResult): Unit = {
      checkForScanAttack(scanDetectionResult)
    }

    def checkForScanAttack(scanDetectionResult: ScanDetectionResult) = {
      Future {
        if (scanDetectionResult.scanScore > ScanDetectContext.Settings.portScanScoreAlertThreshold)
          null
      }
    }*/
}

