package controllers

import com.google.inject.{Inject, Singleton}
import context.{MongoDBConnection, ScanDetectContext}
import play.api.libs.json._
import play.api.mvc._
import services.{AlertsService, CaptureService, PacketService}
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import reactivemongo.api.DefaultDB

import scala.concurrent.{Await, Future, Promise}
import scala.concurrent.duration._
import scala.util.{Failure, Success}

/**
  * Created by Marcin on 2016-09-14.
  */
@Singleton
class IndexController @Inject() (captureService: CaptureService,
                                 scanDetectContext: ScanDetectContext,
                                 alertsService: AlertsService,
                                 packetService: PacketService,
                                 mongoDBConnection: MongoDBConnection) extends Controller {

  def index() = Action {
    Ok(views.html.index("Your new application is ready."))
  }

  def isRunning = Action {
    Ok(JsBoolean(captureService.allowCapturing.get()))
  }

  def startMonitoringPorts = Action {
    implicit request => {
      request.body.asJson.map { json =>
        val ignoredIps = (json \ "ignoredIps").as[Seq[String]]
        val networkInterface = (json \ "networkInterface").as[String]
        val useAsHoneypot = (json \ "runAsHoneypot").as[Boolean]
        captureService.setAddressesToIgnore(ignoredIps)
        scanDetectContext.useAsHoneypot = useAsHoneypot
        scanDetectContext.startCapturingPackets(networkInterface)
        Ok("Got JSON data")
      }.getOrElse {
        BadRequest("Expecting Json data")
      }
    }
      /*
    captureService.allowCapturing.set(true)
    Ok("Started monitoring ports")*/
  }

  def stopMonitoringPorts = Action {
    captureService.stopCapturing()
    scanDetectContext.stopCapturingPackets()
    Ok("Stopped monitoring ports")
  }

  def isDatabaseAvailable = Action {
    try {
      Await.result(alertsService.stub(), 5 seconds)
      Ok(JsBoolean(true))
    } catch {
      case x: Throwable => Ok(JsBoolean(false))
    }
  }

  def getCapturedPacketsCount = Action.async {
    packetService.getNumberOfPacketsInDatabase().map(number => Ok(JsString(number.toString())))
  }

  def getAnalyzedPacketsCount = Action.async {
    packetService.getNumberOfAnalyzedPacketsInDatabase().map(number => Ok(JsString(number.toString())))
  }

}
