package context

import com.google.inject.{ImplementedBy, Singleton}
import reactivemongo.api.{DefaultDB, MongoConnection, MongoDriver}
import utils.Constants.SettingsKeys

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent._
import scala.concurrent.duration._

@ImplementedBy(classOf[HoneypotMongoDBConnectionImpl])
trait  HoneypotMongoDBConnection {
  def database: Future[DefaultDB]
  def initConnection(scanDetectContext: ScanDetectContext)
  def closeConnection()
  def db: DefaultDB
}

@Singleton
class HoneypotMongoDBConnectionImpl extends HoneypotMongoDBConnection {

  var dataBaseConnection: Option[DefaultDB] = None

  override def database = Future {
    dataBaseConnection.getOrElse(throw new MongoDatabaseNotInitializedException("Honeypot MongoDB not initialized"))
  }

  def initConnection(scanDetectContext: ScanDetectContext) = {
    if (dataBaseConnection.isDefined) dataBaseConnection.get.connection.close()

    val password = scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.HONEYPOT_DATABASE_PASSWORD).toString
    val username = scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.HONEYPOT_DATABASE_USERNAME).toString

    val mongoPrefix = "mongodb://"

    val databaseName = scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.HONEYPOT_DATABASE_URL).toString.split("/").last

    val uri = if (password.isEmpty || username.isEmpty) {
      mongoPrefix + scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.HONEYPOT_DATABASE_URL).toString
    } else {
      mongoPrefix + username + ":" + password + "@" + scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.HONEYPOT_DATABASE_URL).toString
    }
    val driver = MongoDriver()
    val parsedUri = MongoConnection.parseURI(uri)
    val connection = parsedUri.map(result => driver.connection(result))
    val futureConnection = Future.fromTry(connection)
    val db = blocking {
      futureConnection.flatMap(_.database(databaseName))
    }

    try {
      this.dataBaseConnection = Some(Await.result(db, 60.seconds))
    } catch {
      case x: Throwable =>
        this.dataBaseConnection = None
    }
  }

  def closeConnection() = {
    this.dataBaseConnection.map(_.drop())
  }

  def db = {
    dataBaseConnection.getOrElse(throw new MongoDatabaseNotInitializedException("Honeypot MongoDB not initialized"))
  }

  class MongoDatabaseNotInitializedException(message: String) extends RuntimeException(message)

}
