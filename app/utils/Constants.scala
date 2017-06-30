package utils

/**
  * Created by Marcin on 2016-09-14.
  */
object Constants {

  val EMPTY_STRING = ""

  val COMMA = ","

  val INFO_DELIM = "="

  val ZERO = "0"

  val UNKNOWN = "UNKNOWN"

  val NO_HASHCODE = -1L

  val ICMP_HASHCODE = 3L

  val ONE_SECOND = 1000

  val COLON = ":"

  val INTEGER_ONE = 1

  object SettingsKeys {
    val DATABASE_URL = "DATABASE_URL"
    val DATABASE_USERNAME = "DATABASE_USERNAME"
    val DATABASE_PASSWORD = "DATABASE_PASSWORD"
    val HONEYPOT_DATABASE_URL = "HONEYPOT_DATABASE_URL"
    val HONEYPOT_DATABASE_USERNAME = "HONEYPOT_DATABASE_USERNAME"
    val HONEYPOT_DATABASE_PASSWORD = "HONEYPOT_DATABASE_PASSWORD"
    val CLOSED_PORT_THRESHOLD = "CLOSED_PORT_THRESHOLD"
    val USE_HONEYPOT = "USE_HONEYPOT"
  }

  object Numbers {
    val ZERO = 0
  }

}
