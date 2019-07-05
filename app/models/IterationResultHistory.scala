package models

import play.api.libs.json._
import reactivemongo.bson.{BSONDocument, BSONHandler, BSONObjectID, BSONString}

/**
  * Created by Marcin on 2016-12-16.
  */
object IterationResultInfo extends BSONHandler[BSONDocument, Map[String, String]] {

  override def read(bson: BSONDocument): Map[String, String] = {
    bson.elements.map {
      element => element.name.asInstanceOf[String] -> element.value.asInstanceOf[BSONString].as[String]
    }.toMap
  }

  override def write(doc: Map[String, String]): BSONDocument = {
    BSONDocument(doc.map(t => (t._1, BSONString(t._2))))
  }

}

case class IterationResultHistory(_id: Option[BSONObjectID],
                                  sourceAddress: String,
                                  flowKey: Long,
                                  additionalHash: Long,
                                  port: Int,
                                  info: Map[String, String],
                                  resultType: String) {

}

object IterationResultHistory {

  object InfoKeys {
    val INFO_KEYS = "NUMBER_OF_PACKETS"
  }

  implicit object IterationResultHistoryReader extends Reads[IterationResultHistory] {
    override def reads(json: JsValue): JsResult[IterationResultHistory] = {
      try {
        val _id = (json \ "_id").as[BSONObjectID]
        val sourceAddress = (json \ "sourceAddress").as[String]
        val flowKey = (json \ "flowKey").as[Long]
        val additionalHash = (json \ "additionalHash").as[Long]
        val info = (json \ "info").as[Map[String, String]]
        val resultType = (json \ "resultType").as[String]
        val port = (json \ "ports").as[Int]

        JsSuccess(IterationResultHistory(Option(_id), sourceAddress, flowKey, additionalHash, port, info, resultType))
      } catch {
        case e: Throwable => JsError(e.getMessage)
      }
    }
  }

  implicit object IterationResultHistoryWriter extends OWrites[IterationResultHistory] {
    override def writes(iterationResultHistory: IterationResultHistory) = Json.obj(
      "_id" -> iterationResultHistory._id.get,
      "sourceAddress" -> iterationResultHistory.sourceAddress,
      "flowKey" -> iterationResultHistory.flowKey,
      "additionalHash" -> iterationResultHistory.additionalHash,
      "info" -> iterationResultHistory.info,
      "resultType" -> iterationResultHistory.resultType,
      "port" -> iterationResultHistory.port
    )
  }

}


