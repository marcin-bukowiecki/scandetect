package utils

object PacketUtils {

  def concatFlags(flags: Seq[String]) = {
    flags.foldLeft("")((prev: String, next: String) => {
      prev + next
    })
  }

  def generateAdditionalHashcode(sourceAddress: String, destinationAddress: String, direction: String): Long = {
    if (direction == Direction.INCOME) {
      (sourceAddress + destinationAddress).hashCode
    } else {
      (destinationAddress + sourceAddress).hashCode
    }
  }

  def generateAdditionalHashcode(sourcePort: Int, destinationPort: Int, direction: String): Long = {
    if (direction == Direction.INCOME) {
      val s1 = "%05d".format(sourcePort)
      val s2 = "%05d".format(destinationPort)
      (s1 + s2).hashCode
    } else {
      val s1 = "%05d".format(destinationPort)
      val s2 = "%05d".format(sourcePort)
      (s1 + s2).hashCode
    }
  }

}

