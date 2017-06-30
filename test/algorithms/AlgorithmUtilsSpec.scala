package algorithms

import models.Packet
import org.junit.runner.RunWith
import org.specs2.mutable.Specification
import org.specs2.runner.JUnitRunner
import utils.Direction

/**
  * Created by Marcin on 2016-10-29.
  */
@RunWith(classOf[JUnitRunner])
class AlgorithmUtilsSpec extends Specification {

  "isConnectionProtocol" should {
    "return true for TCP" in {
      AlgorithmUtils.isConnectionProtocol("TCP") must equalTo(true)
    }

    "return true for SCTP" in {
      AlgorithmUtils.isConnectionProtocol("SCTP") must equalTo(true)
    }

    "return false for UDP" in {
      AlgorithmUtils.isConnectionProtocol("UDP") must equalTo(false)
    }
  }

  "isInternetProtocol" should {
    "return true for ARP" in {
      AlgorithmUtils.isSupportedInternetProtocol("ARP") must equalTo(true)
    }

    "return true for IPv4" in {
      AlgorithmUtils.isSupportedInternetProtocol("IPv4") must equalTo(true)
    }

    "return true for IPv6" in {
      AlgorithmUtils.isSupportedInternetProtocol("IPv6") must equalTo(true)
    }

    "return true for ICMP" in {
      AlgorithmUtils.isSupportedInternetProtocol("ICMP") must equalTo(true)
    }

    "return false for TCP" in {
      AlgorithmUtils.isSupportedInternetProtocol("TCP") must equalTo(false)
    }
  }

  "isTransportProtocol" should {
    "return true for TCP" in {
      AlgorithmUtils.isSupportedTransportProtocol("TCP") must equalTo(true)
    }

    "return true for UDP" in {
      AlgorithmUtils.isSupportedTransportProtocol("UDP") must equalTo(true)
    }

    "return false for ICMP" in {
      AlgorithmUtils.isSupportedTransportProtocol("ICMP") must equalTo(false)
    }
  }

  "isInitializingConnection" should {
    "return true for given TCP packets" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("SYN"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 80, "192.168.1.6", 35123, Map(), Seq("SYN", "ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0)
      )

      AlgorithmUtils.isInitializingConnection("TCP", packets) must equalTo(true)
    }

    "return false for given TCP packets" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("ACK"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 80, "192.168.1.6", 35123, Map(), Seq("RST", "ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0)
      )

      AlgorithmUtils.isInitializingConnection("TCP", packets) must equalTo(false)
    }

    "return false for given UDP packet" in {
      val packets = Seq(
        Packet(null, 0, "UDP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq(), 123, 0, 0, Direction.INCOME.toString, 0)
      )

      AlgorithmUtils.isInitializingConnection("UDP", packets) must equalTo(false)
    }

    "return true for given SCTP packet" in {
      val packets = Seq(
        Packet(null, 0, "SCTP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("INIT"), 123, 0, 0, Direction.INCOME.toString, 0)
      )

      AlgorithmUtils.isInitializingConnection("SCTP", packets) must equalTo(true)
    }
  }

  "isConnectionClosed" should {
    "return true for given TCP packets" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("SYN"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.6", 80, "192.168.1.4", 35123, Map(), Seq("SYN","ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("ACK"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("RST","ACK"), 123, 0, 0, Direction.INCOME.toString, 0)
      )

      AlgorithmUtils.isConnectionClosed("TCP", packets) must equalTo(true)
    }
  }

  "isConnectionProperlyClosed" should {
    "return true for given TCP packets" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("SEQ","ACK"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.6", 80, "192.168.1.4", 35123, Map(), Seq("ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("FIN","ACK"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.6", 80, "192.168.1.4", 35123, Map(), Seq("FIN","ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.6", 80, "192.168.1.4", 35123, Map(), Seq("ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("RST"), 123, 0, 0, Direction.INCOME.toString, 0)
      )

      AlgorithmUtils.isConnectionProperlyClosed("TCP", packets) must equalTo(true)
    }
  }

  "didSendAnyData" should {
    "return false for given TCP packets" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("SYN"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.6", 80, "192.168.1.4", 35123, Map(), Seq("SYN", "ACK"), 123, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("ACK"), 123, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 80, Map(), Seq("RST", "ACK"), 123, 0, 0, Direction.INCOME.toString, 0)
      )

      AlgorithmUtils.didSendAnyData("TCP", packets) must equalTo(false)
    }
  }

  "port" should {
    "be closed for given 2 TCP packet" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 139,
          Map("SEQ" -> "0", "WIN" -> "1024", "WIN_SCALE" -> "-1"), Seq("SYN"), 111, 0, 0, Direction.INCOME.toString, 60),
        Packet(null, 0, "TCP", "192.168.1.6", 139, "192.168.1.4", 35123,
          Map("SEQ" -> "1", "WIN" -> "0", "WIN_SCALE" -> "-1"), Seq("RST", "ACK"), 111, 0, 0, Direction.OUTCOME.toString, 60)
      )

      AlgorithmUtils.isPortClosed("TCP", packets) must equalTo(true)
    }

    "be closed for given 2 TCP packet" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 139,
          Map("SEQ" -> "1", "WIN" -> "3072", "WIN_SCALE" -> "-1"), Seq("PSH", "ACK", "URG"), 111, 0, 0, Direction.INCOME.toString, 60),
        Packet(null, 0, "TCP", "192.168.1.6", 139, "192.168.1.4", 35123,
          Map("SEQ" -> "1", "WIN" -> "0", "WIN_SCALE" -> "-1"), Seq("RST"), 111, 0, 0, Direction.OUTCOME.toString, 54)
      )

      AlgorithmUtils.isPortClosed("TCP", packets) must equalTo(true)
    }
  }

  "score for closed ports" should {
    "be equal to 23%" in {
      val result = AlgorithmUtils.getClosedPortScore(11, 20)

      result.toString must startWith("23")
    }
  }

}
