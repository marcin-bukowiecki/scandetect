package controllers

import com.google.inject.{Inject, Singleton}
import models.{AnalyzedPacketFilter, Packet}
import play.api.libs.json.Json
import play.api.mvc._
import repositories.PacketRepositoryImpl
import utils.PortUtils

import scala.concurrent.{Await, Future}
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.global

/**
  * Created by Marcin on 2016-12-12.
  */
@Singleton
class PacketsController @Inject()(packetService: PacketRepositoryImpl) extends Controller {

  implicit def packetWrites = Packet.PacketWriter

  def getCapturedPackets = Action {
    implicit request =>
      request.body.asJson.map { json =>
        val currentPage = (json \ "currentPage").as[Int]
        val protocol = (json \ "protocol").as[String]
        val sourceAddress = (json \ "sourceAddress").as[String]
        val destinationAddress = (json \ "destinationAddress").as[String]

        val sourcePort = try {
          (json \ "sourcePort").as[String].toInt
        } catch {
          case x: Throwable => PortUtils.NO_PORT
        }

        val destinationPort = try {
          (json \ "destinationPort").as[String].toInt
        } catch {
          case x: Throwable => PortUtils.NO_PORT
        }

        val length = try {
          (json \ "length").as[String].toInt
        } catch {
          case x: Throwable => PortUtils.NO_PORT
        }

        val packetFilter = AnalyzedPacketFilter(protocol.split(","), sourceAddress, destinationAddress, sourcePort, destinationPort, length)

        val list = Await.result(packetService.filterPackets(packetFilter), 10.seconds)
        val offset = (currentPage - 1) * 20
        val limit = offset + 20
        val jsArray = Json.toJson(list.slice(offset, limit))

        Ok(Json.obj("packets" -> jsArray, "numberOfPackets" -> list.size))
      }.getOrElse {
        BadRequest("Expecting Json data")
      }
  }

  def removeAllPackets = Action.async {
    packetService.removeAllPackets().map(result => {
      Ok("Done")
    })
  }

}
