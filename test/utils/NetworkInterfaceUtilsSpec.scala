package utils

import org.scalatest.{FlatSpec, GivenWhenThen}

/**
  * Created by Marcin on 2017-06-13.
  */
class NetworkInterfaceUtilsSpec extends FlatSpec with GivenWhenThen {

  "getReadableIPv4Address" should "return 192.168.1.4" in {
    Given("\"[INET4:192.168.1.4]\"")
    val result = NetworkInterfaceUtils.getReadableIPv4Address("[INET4:192.168.1.4]")

    Then("result should be equal to 192.168.1.4")
    assert(result equals "192.168.1.4")
  }

}
