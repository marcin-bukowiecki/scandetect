package neuralnetwork

import algorithms.AlgorithmUtils

/**
  * Created by Marcin on 2016-12-27.
  */
class CheckingContext(val hostWasInitializingConnection: Boolean,
                      val sendData: Boolean,
                      val didNotSendData: Boolean,
                      val triedConnectToClosedPortAfterOpen: Boolean,
                      val closedPortsThresholdResult: CheckingContext.ThresholdResult,
                      val numberOfTransportedPacketsToOpenPorts: Int,
                      val usedClosedPorts: Set[Int],
                      val usedOpenPorts: Set[Int]) {

  def createWeights: Seq[Double] = {
    Seq(
      if (hostWasInitializingConnection) 1 else 3,
      if (sendData && didNotSendData) 2 else if (sendData && !didNotSendData) 1 else 3,
      if (triedConnectToClosedPortAfterOpen) 3 else 1,
      closedPortsThresholdResult match {
        case CheckingContext.AtThreshold(address: String, threshold: Int) => 2
        case CheckingContext.UnderThreshold(address: String, threshold: Int) => 1
        case CheckingContext.BeyondThreshold(address: String, threshold: Int) => 3
      },
      getNeighboringPortScanFactor,
      packetOpenPortFactor,
      closedPortsFactor
    )
  }

  def getNeighboringPortScanFactor: Double = {
    val sortedAllPorts = (usedClosedPorts ++ usedOpenPorts).toSeq.sorted

    if (sortedAllPorts.size > 1) {
      sortedAllPorts.sliding(2)
        .map(twoPackets => if((twoPackets.head + 1) == twoPackets.last) 1 else 0)
        .sum.toDouble / sortedAllPorts.size.toDouble
    } else {
      0
    }
  }

  def packetOpenPortFactor: Double = {
    if (numberOfTransportedPacketsToOpenPorts == 0) {
      0
    } else {
      2 * (usedOpenPorts.size.toDouble / numberOfTransportedPacketsToOpenPorts.toDouble)
    }
  }

  def closedPortsFactor: Double = {
    AlgorithmUtils.getClosedPortScore(closedPortsThresholdResult.threshold, usedClosedPorts.size)
  }

}

object CheckingContext {

  def apply(hostWasInitializingConnection: Boolean,
          sendData: Boolean,
          didNotSendData: Boolean,
          triedConnectToClosedPortAfterOpen: Boolean,
          closedPortsThresholdResult: CheckingContext.ThresholdResult,
          numberOfTransportedPacketsToOpenPorts: Int,
          usedClosedPorts: Set[Int],
          usedOpenPorts: Set[Int]): CheckingContext = {

    new CheckingContext(hostWasInitializingConnection,
      sendData,
      didNotSendData,
      triedConnectToClosedPortAfterOpen,
      closedPortsThresholdResult,
      numberOfTransportedPacketsToOpenPorts,
      usedClosedPorts,
      usedOpenPorts)
  }

  abstract class ThresholdResult {
    val address: String
    val threshold: Int
  }
  case class AtThreshold(address: String, threshold: Int) extends ThresholdResult
  case class UnderThreshold(address: String, threshold: Int) extends ThresholdResult
  case class BeyondThreshold(address: String, threshold: Int) extends ThresholdResult

}




