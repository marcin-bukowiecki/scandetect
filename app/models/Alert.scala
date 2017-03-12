package models

import play.api.libs.json._
import reactivemongo.bson.BSONObjectID

case class Alert(_id: Option[BSONObjectID],
                 time: String,
                 scanType: String,
                 attackType: String,
                 ipAttacker: String,
                 description: String,
                 softwareUsed: Set[String],
                 scannedPorts: Seq[Int],
                 chance: Double,
                 read: Boolean
                )

object Alert {

  implicit object AlertReader extends Reads[Alert] {
    override def reads(json: JsValue): JsResult[Alert] = {
      try {
        val _id = (json \ "_id").as[BSONObjectID]
        val time = (json \ "time").as[String]
        val scanType = (json \ "scanType").as[String]
        val attackType = (json \ "attackType").as[String]
        val ipAttacker = (json \ "ipAttacker").as[String]
        val description = (json \ "description").as[String]
        val softwareUsed = (json \ "softwareUsed").as[Set[String]]
        val scannedPorts = (json \ "scannedPorts").as[Seq[Int]]
        val chance = (json \ "chance").as[Int]
        val read = (json \ "read").as[Boolean]

        JsSuccess(Alert(Option(_id), time, scanType, attackType, ipAttacker, description, softwareUsed, scannedPorts, chance, read))
      } catch {
        case e: Throwable => JsError(e.getMessage)
      }
    }
  }

  implicit object AlertWriter extends OWrites[Alert] {
    override def writes(alert: Alert) = Json.obj(
      "_id" -> alert._id.map(_.stringify),
      "time" -> alert.time,
      "scanType" -> alert.scanType,
      "attackType" -> alert.attackType,
      "ipAttacker" -> alert.ipAttacker,
      "description" -> alert.description,
      "softwareUsed" -> alert.softwareUsed,
      "scannedPorts" -> alert.scannedPorts,
      "chance" -> alert.chance,
      "read" -> alert.read
    )
  }

}
