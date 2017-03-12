package utils

object NetworkInterfaceUtils {

  def getReadableIPv4Address(address: String): String = {
    address.split(":")(1).dropRight(1).mkString
  }

}
