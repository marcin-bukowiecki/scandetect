package controllers

import com.google.inject.{Inject, Singleton}
import context.{MongoDBConnection, ScanDetectContext}
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import play.api.libs.json._
import play.api.mvc._
import repositories.{AlertRepository, AlertRepositoryImpl, CaptureService, PacketRepositoryImpl}

import scala.concurrent.Await
import scala.concurrent.duration._

@Singleton
class IndexController @Inject() (captureService: CaptureService,
                                 scanDetectContext: ScanDetectContext,
                                 alertRepository: AlertRepository,
                                 packetService: PacketRepositoryImpl,
                                 mongoDBConnection: MongoDBConnection) extends Controller {

  def index() = Action {
    Ok(views.html.index("Your new application is ready."))
  }

  def isRunning = Action {
    Ok(JsBoolean(captureService.isCapturing()))
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
      Await.result(alertRepository.stub(), 5.seconds)
      Ok(JsBoolean(true))
    } catch {
      case x: Throwable => Ok(JsBoolean(false))
    }
  }

  def getCapturedPacketsCount = Action.async {
    packetService.getNumberOfPacketsInDatabase.map(number => Ok(JsString(String.valueOf(number))))
  }

  def getAnalyzedPacketsCount = Action.async {
    packetService.getNumberOfAnalyzedPacketsInDatabase.map(number => Ok(String.valueOf(number)))
  }

}
