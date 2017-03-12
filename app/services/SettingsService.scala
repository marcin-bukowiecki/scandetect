package services

import akka.actor.ActorSystem
import com.google.inject.{Inject, Singleton}
import context.MongoDBConnection
import models.Settings
import reactivemongo.api.collections.bson.BSONCollection
import reactivemongo.bson.{BSONDocument, BSONDocumentReader, BSONDocumentWriter, Macros}
import utils.Constants.SettingsKeys

import scala.concurrent.{Await, ExecutionContext}
import scala.concurrent.duration._

/**
  * Created by Marcin on 2016-12-14.
  */
@Singleton
class SettingsService @Inject() (val mongoDBConnection: MongoDBConnection, val akkaSystem: ActorSystem) {

  implicit val executionContext: ExecutionContext = akkaSystem.dispatchers.lookup("settings-service-context")

  implicit def packetReader: BSONDocumentReader[Settings] = Macros.reader[Settings]
  implicit def packetWriter: BSONDocumentWriter[Settings] = Macros.writer[Settings]

  def settingsCollection = mongoDBConnection.database.map(_.collection[BSONCollection]("settings"))

  def validateSettings(): Boolean = {
    val query = BSONDocument(
      "key" -> BSONDocument(
        "$in" -> Seq(
          SettingsKeys.DATABASE_URL,
          SettingsKeys.DATABASE_USERNAME,
          SettingsKeys.DATABASE_PASSWORD,
          SettingsKeys.HONEYPOT_DATABASE_URL,
          SettingsKeys.CLOSED_PORT_THRESHOLD,
          SettingsKeys.USE_HONEYPOT,
          SettingsKeys.HONEYPOT_DATABASE_PASSWORD,
          SettingsKeys.HONEYPOT_DATABASE_USERNAME
        )
      )
    )

    val settings = Await.result(settingsCollection.flatMap(_.find(query).cursor[Settings]().collect[Seq]()), 5.seconds)

    settings.size == 8 && settings.map(_.key).toSet.size == 8
  }

  def loadSettings(): Seq[Settings] = {
    val query = BSONDocument(
      "key" -> BSONDocument(
        "$in" -> Seq(
          SettingsKeys.DATABASE_URL,
          SettingsKeys.DATABASE_USERNAME,
          SettingsKeys.DATABASE_PASSWORD,
          SettingsKeys.HONEYPOT_DATABASE_URL,
          SettingsKeys.CLOSED_PORT_THRESHOLD,
          SettingsKeys.USE_HONEYPOT,
          SettingsKeys.HONEYPOT_DATABASE_PASSWORD,
          SettingsKeys.HONEYPOT_DATABASE_USERNAME
        )
      )
    )

    Await.result(settingsCollection.flatMap(_.find(query).cursor[Settings]().collect[Seq]()), 5.seconds)
  }

  def saveSettings(databaseUrl: String, databasePassword: String, databaseUsername: String, useHoneypot: String,
                   honeypotDatabaseUrl: String, closedPortThreshold: String, honeypotDatabaseUsername: String,
                   honeypotDatabasePassword: String) = {

    var selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.DATABASE_URL
      )
    )

    var modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> databaseUrl)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.DATABASE_USERNAME
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> databaseUsername)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.DATABASE_PASSWORD
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> databasePassword)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.HONEYPOT_DATABASE_URL
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> honeypotDatabaseUrl)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.HONEYPOT_DATABASE_USERNAME
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> honeypotDatabaseUsername)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.HONEYPOT_DATABASE_PASSWORD
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> honeypotDatabasePassword)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.USE_HONEYPOT
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> useHoneypot)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)

    selector = BSONDocument(
      "key" -> BSONDocument(
        "$eq" -> SettingsKeys.CLOSED_PORT_THRESHOLD
      )
    )

    modifier = BSONDocument(
      "$set" -> BSONDocument(
        "value" -> closedPortThreshold)
    )

    Await.result(settingsCollection.flatMap(_.update(selector, modifier, upsert = true)), 5.seconds)
  }

}
