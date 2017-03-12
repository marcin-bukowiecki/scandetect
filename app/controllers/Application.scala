package controllers

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.stream.Materializer
import com.google.inject.Inject
import context.ScanDetectContext
import play.api.Logger
import play.api.mvc._
import services.{NetworkInterfaceService, PacketService}
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import play.api.libs.json.JsPath.json
import play.api.libs.streams.ActorFlow
import play.api.libs.json._

import scala.concurrent.Future


class Application @Inject()(packetService: PacketService,
                            networkInterfaceService: NetworkInterfaceService,
                            scanDetectContext: ScanDetectContext,
                            implicit val materializer: Materializer,
                            implicit val system: ActorSystem) extends Controller {

  def index = Action {
    Ok(views.html.index("Your new application is ready."))
  }

  def asyncCall = Action {
    val networkInterfaces = networkInterfaceService.getNetworkDevices()
    val result = networkInterfaceService.mapToJson(networkInterfaces)
    Ok(result)
  }

  def socket = WebSocket.accept[JsValue, JsValue] {
    implicit request  => {
      ActorFlow.actorRef(out => StatisticsWebSocketActor.props(packetService, out))

    }
  }

}

object StatisticsWebSocketActor {
  def props(packetService: PacketService, out: ActorRef) = Props(new StatisticsWebSocketActor(packetService, out))
}

class StatisticsWebSocketActor(packetService: PacketService, out: ActorRef) extends Actor {

  val log = Logger

  def receive = {
    case command: JsValue =>
      val commandString = (command \\ "command").head.asInstanceOf[JsString].value

      commandString match {
        case "getStats" =>
          val f_1 = packetService.getNumberOfPacketsInDatabase()
          val f_2 = packetService.getNumberOfAnalyzedPacketsInDatabase()

          Future.sequence(Seq(
            f_1,
            f_2
          )).map(result =>
            out ! Json.obj("numberOfCapturedPackets" -> result.head, "numberOfAnalyzedPackets" -> result.last)
          )
        case _ =>
      }
  }

  override def postStop() = {
    log.info("Closing websocket.")
  }
}