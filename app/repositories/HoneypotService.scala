package repositories

import akka.actor.ActorSystem
import com.google.inject.{Inject, Singleton}
import context.HoneypotMongoDBConnection
import models.{IterationResultHistory, IterationResultInfo}
import play.api.Logger
import reactivemongo.api.collections.bson.BSONCollection
import reactivemongo.bson.{BSONDocument, BSONDocumentReader, BSONDocumentWriter, BSONHandler, Macros}

import scala.concurrent.{ExecutionContext, Future}

@Singleton
class HoneypotService @Inject()(val honeypotMongoDBConnection: HoneypotMongoDBConnection,
                                val akkaSystem: ActorSystem) {

  private val log = Logger

  implicit val honeypotServiceExecutionContext: ExecutionContext = akkaSystem.dispatchers.lookup("honeypot-service-context")

  def collection: Future[BSONCollection] = honeypotMongoDBConnection.database.map(_.collection[BSONCollection]("iteration_result_history"))

  implicit def iterationResultHistoryReader: BSONDocumentReader[IterationResultHistory] = Macros.reader[IterationResultHistory]

  implicit def iterationResultHistoryWriter: BSONDocumentWriter[IterationResultHistory] = Macros.writer[IterationResultHistory]

  implicit def infoMapReader: BSONHandler[BSONDocument, Map[String, String]] = IterationResultInfo

  def wasRegisteredByHoneypot(address: String): Future[Boolean] = {
    val query = BSONDocument(
      "sourceAddress" -> BSONDocument(
        "$eq" -> address
      )
    )

    collection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]()).map(_.nonEmpty)
  }
}
