import play.api.libs.json._
import reactivemongo.bson.BSONObjectID

import scala.util.Try

/**
  * Created by Marcin on 2016-09-29.
  */
package object models {

  implicit object BSONObjectIDFormat extends Format[BSONObjectID] {

    def writes(objectId: BSONObjectID): JsValue = JsString(objectId.toString())

    def reads(json: JsValue): JsResult[BSONObjectID] = json match {
      case JsString(x) => {
        val maybeOID: Try[BSONObjectID] = BSONObjectID.parse(x)
        if (maybeOID.isSuccess) JsSuccess(maybeOID.get) else {
          JsError("Expected BSONObjectID as JsString")
        }
      }
      case _ => JsError("Expected BSONObjectID as JsString")
    }
  }

}
