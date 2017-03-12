package context

import com.google.inject.{ImplementedBy, Singleton}
import reactivemongo.api.{DefaultDB, MongoConnection, MongoDriver}
import utils.Constants.SettingsKeys

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent._
import scala.concurrent.duration._

/**
  * Created by Marcin on 2016-10-24.
  */
@ImplementedBy(classOf[MongoDBConnectionImpl])
trait MongoDBConnection {
  def database: Future[DefaultDB]
  def initConnection(scanDetectContext: ScanDetectContext)
  def db: DefaultDB
}

@Singleton
class MongoDBConnectionImpl extends MongoDBConnection {

  var dataBaseConnection: Option[DefaultDB] = None

  /*
  val uri = "mongodb://localhost:27017"
  val driver = MongoDriver()
  val parsedUri = MongoConnection.parseURI(uri)
  val connection = parsedUri.map(driver.connection(_))
  val futureConnection = Future.fromTry(connection)
  val db = blocking {
    futureConnection.flatMap(_.database("test"))
  }
*/

  override def database = Future {
    dataBaseConnection.getOrElse(throw new MongoDatabaseNotInitializedException("MongoDB not initialized"))
  }

  def initConnection(scanDetectContext: ScanDetectContext) = {
    if (dataBaseConnection.isDefined) dataBaseConnection.get.connection.close()

    val password = scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.DATABASE_PASSWORD).toString
    val username = scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.DATABASE_USERNAME).toString
    val databaseName = scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.DATABASE_URL).toString.split("/").last
    val mongoPrefix = "mongodb://"

    val uri = if (password.isEmpty || username.isEmpty) {
      mongoPrefix + scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.DATABASE_URL).toString
    } else {
      mongoPrefix + username + ":" + password + "@" + scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.DATABASE_URL).toString
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

  def db = {
    dataBaseConnection.getOrElse(throw new MongoDatabaseNotInitializedException("MongoDB not initialized"))
  }

  class MongoDatabaseNotInitializedException(message: String) extends RuntimeException(message)

}
