package models

import play.api.libs.json._
import reactivemongo.bson.BSONObjectID

/**
  * Created by Marcin on 2016-12-12.
  */
case class Settings(_id: Option[BSONObjectID], key: String, value: String)

object Settings {

  implicit object SettingsReader extends Reads[Settings] {
    override def reads(json: JsValue): JsResult[Settings] = {
      try {
        val _id = (json \ "_id").as[BSONObjectID]
        val key = (json \ "key").as[String]
        val value = (json \ "value").as[String]

        JsSuccess(Settings(Option(_id), key, value))
      } catch {
        case e: Throwable => JsError(e.getMessage)
      }
    }
  }

  implicit object SettingsWriter extends OWrites[Settings] {
    override def writes(settings: Settings) = Json.obj(
      "_id" -> settings._id.getOrElse("-1").toString,
      "key" -> settings.key,
      "value" -> settings.value
    )
  }

}
