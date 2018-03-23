package repositories

import reactivemongo.api.collections.bson.BSONCollection

import scala.concurrent.Future

trait BaseRepository {

  def collection: Future[BSONCollection]

}
