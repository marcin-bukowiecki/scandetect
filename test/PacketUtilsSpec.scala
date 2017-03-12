import org.junit.runner.RunWith
import org.specs2.mutable.Specification
import org.specs2.runner.JUnitRunner
import utils.PacketUtils

@RunWith(classOf[JUnitRunner])
class PacketUtilsSpec extends Specification {

  "Method concatFlags" should {
    "return SYNACK String" in {
      val flags = Seq("SYN","ACK")

      val result = PacketUtils.concatFlags(flags)

      result must equalTo("SYNACK")
    }

    "return empty String" in {
      val flags = Seq()

      val result = PacketUtils.concatFlags(flags)

      result must equalTo("")
    }

    "return SYN String" in {
      val flags = Seq("SYN")

      val result = PacketUtils.concatFlags(flags)

      result must equalTo("SYN")
    }
  }

}
