package controllers

import akka.actor.ActorSystem
import akka.stream.Materializer
import com.google.inject.{Inject, Singleton}
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import play.api.libs.json.Json
import play.api.mvc._
import repositories.AlertRepositoryImpl
import utils.Constants

import scala.concurrent.Future

@Singleton
class AlertsController @Inject()(alertsService: AlertRepositoryImpl)(implicit materializer: Materializer, system: ActorSystem) extends Controller {

  def list = Action.async {
    alertsService.getAllAlertsAndGroupThem.flatMap(result => Future {
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
