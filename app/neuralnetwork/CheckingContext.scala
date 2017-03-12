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

  /**
    * Inicjowanie wartości dla poszczególnych cech i współczynników
    *
    * @return sekwencja z odpowiednimi wartościami dla sieci neuronowej
    */
  def createWeights: Seq[Double] = {
    Seq(
      if (hostWasInitializingConnection) 1 else 3, //Inicjowanie połączenia
      if (sendData && didNotSendData) 2 else if (sendData && !didNotSendData) 1 else 3, //Transmisja danych
      if (triedConnectToClosedPortAfterOpen) 3 else 1, //Próba połaćzenia się z zamkniętym protem po otwartym
      closedPortsThresholdResult match { //Wartość progowa zamkniętych portów
        case CheckingContext.AtThreshold(address: String, threshold: Int) => 2
        case CheckingContext.UnderThreshold(address: String, threshold: Int) => 1
        case CheckingContext.BeyondThreshold(address: String, threshold: Int) => 3
      },
      getNeighboringPortScanFactor, //Współczynnik sąsiedztwa
      packetOpenPortFactor, //Współczynnik otwartych portów do liczby pakietów
      closedPortsFactor //Współczynnik liczby prób połaczeń z zamkniętymi portami
    )
  }

  /**
    * Metoda oblicza współczynnik sąsiedztwa
    *
    * @return obliczony współczynnik
    */
  def getNeighboringPortScanFactor: Double = {
    //sortowanie portów
    val sortedAllPorts = (usedClosedPorts ++ usedOpenPorts).toSeq.sorted

    if (sortedAllPorts.size > 1) {
      sortedAllPorts.sliding(2)
        .map(twoPackets => if((twoPackets.head + 1) == twoPackets.last) 1 else 0)
        .sum.toDouble / sortedAllPorts.size.toDouble
    } else {
      0
    }
  }

  /**
    * Metoda oblicza współczynnik otwartych portów do liczby pakietów
    *
    * @return obliczony współczynnik
    */
  def packetOpenPortFactor: Double = {
    if (numberOfTransportedPacketsToOpenPorts == 0) {
      0
    } else {
      2 * (usedOpenPorts.size.toDouble / numberOfTransportedPacketsToOpenPorts.toDouble)
    }
  }

  /**
    * Metoda oblicza współczynnik liczby prób połaczeń z zamkniętymi portami
    *
    * @return obliczony współczynnik
    */
  def closedPortsFactor: Double = {
    AlgorithmUtils.getClosedPortScore(closedPortsThresholdResult.threshold, usedClosedPorts.size)
  }

}

object CheckingContext {

  /**
    *  Budowanie obiektu kontekstu cech i współczynników
    */

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




