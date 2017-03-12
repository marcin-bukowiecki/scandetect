package controllers

import akka.actor.ActorSystem
import akka.stream.Materializer
import com.google.inject.{Inject, Singleton}
import play.api.libs.json.Json
import services.AlertsService
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import play.api.mvc._
import utils.{Constants, ScanAttackTypes}

import scala.concurrent.Future

@Singleton
class AlertsController @Inject()(alertsService: AlertsService)(implicit materializer: Materializer, system: ActorSystem) extends Controller {

  def list = Action.async {
    alertsService.getAllAlertsAndGroupThem().flatMap(result => Future {
      Ok(Json.toJson(result))
    })
  }

  def removeAlert = Action.async {
    implicit request => {
      request.body.asJson.map { json =>
        val attackType = (json \ "attackType").as[String]
        val ipAttacker = (json \ "ipAttacker").as[String]
        val scanType = (json \ "scanType").as[String]

        val f = Future.sequence(
          attackType.split(Constants.COMMA).map(at => alertsService.removeAlert(at.trim, ipAttacker, scanType)).toSeq
        )

        f.flatMap(_ => Future {
          Ok("Alert removed")
        })
      }.getOrElse {
        Future {
          BadRequest("Did not get alert id")
        }
      }
    }
  }

}
