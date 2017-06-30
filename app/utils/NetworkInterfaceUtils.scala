package utils

object NetworkInterfaceUtils {

  def getReadableIPv4Address(address: String): String = {
    address
      .split(Constants.COLON)(Constants.INTEGER_ONE)
      .dropRight(Constants.INTEGER_ONE)
      .mkString
  }

}
