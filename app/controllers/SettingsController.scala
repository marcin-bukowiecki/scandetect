package controllers

import com.google.inject.{Inject, Singleton}
import context.ScanDetectContext
import play.api.mvc.{Action, Controller}
import play.api.libs.json.{JsBoolean, JsNumber, JsString, Json}
import repositories.{IterationResultHistoryRepositoryImpl, SettingsService}
import utils.Constants.SettingsKeys

import scala.concurrent.ExecutionContext.Implicits.global

/**
  * Created by Marcin on 2016-12-14.
  */
@Singleton
class SettingsController @Inject()(settingsService: SettingsService,
                                   scanDetectContext: ScanDetectContext,
                                   iterationResultHistoryService: IterationResultHistoryRepositoryImpl) extends Controller {

  def loadSettings = Action {
    if (settingsService.validateSettings()) {
      Ok(Json.toJson(
        settingsService.loadSettings()
      ))
    } else {
      Ok(Json.toJson(
        scanDetectContext.DefaultSettings.get()
      ))
    }
  }

  def saveSettings = Action {
    implicit request => {
      request.body.asJson.map { json =>
        val databaseUrl = (json \ "databaseUrl").as[String]
        val databaseUsername = (json \ "databaseUsername").as[String]
        val databasePassword = (json \ "databasePassword").as[String]
        val closedPortThreshold = (json \ "closedPortThreshold").get.asInstanceOf[JsNumber].value.toInt.toString
        val useHoneypot = (json \ "useHoneypot").get.asInstanceOf[JsBoolean].value.toString
        val honeypotDatabaseUrl = (json \ "honeypotDatabaseUrl").as[String]
        val honeypotDatabaseUsername = (json \ "honeypotDatabaseUsername").as[String]
        val honeypotDatabasePassword = (json \ "honeypotDatabasePassword").as[String]

        scanDetectContext.setSettings(
          Map(
            SettingsKeys.DATABASE_URL -> databaseUrl,
            SettingsKeys.DATABASE_USERNAME -> databaseUsername,
            SettingsKeys.DATABASE_PASSWORD -> databasePassword,
            SettingsKeys.HONEYPOT_DATABASE_URL -> honeypotDatabaseUrl,
            SettingsKeys.CLOSED_PORT_THRESHOLD -> closedPortThreshold,
            SettingsKeys.USE_HONEYPOT -> useHoneypot,
            SettingsKeys.HONEYPOT_DATABASE_PASSWORD -> honeypotDatabasePassword,
            SettingsKeys.HONEYPOT_DATABASE_USERNAME -> honeypotDatabaseUsername
          )
        )

        scanDetectContext.reloadDatabaseConnection()

        settingsService.saveSettings(databaseUrl, databasePassword, databaseUsername, useHoneypot, honeypotDatabaseUrl, closedPortThreshold, honeypotDatabaseUsername, honeypotDatabasePassword)

        Ok(Json.toJson(
          settingsService.loadSettings()
        ))
      }.getOrElse {
        BadRequest("Expecting Json data")
      }
    }
  }

  def connectToDatabase = Action {
    implicit request => {
      scanDetectContext.reloadDatabaseConnection()
      Ok("Done")
    }
  }

  def clearHistory = Action.async {
    iterationResultHistoryService.clearHistory().map(_ => Ok("Done"))
  }

}
