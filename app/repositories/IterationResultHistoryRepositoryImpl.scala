package repositories

import akka.actor.ActorSystem
import com.google.inject.{ImplementedBy, Inject, Singleton}
import context.MongoDBConnection
import models.{IterationResultHistory, IterationResultInfo}
import reactivemongo.api.collections.bson.BSONCollection
import reactivemongo.bson.{BSONDocument, BSONDocumentReader, BSONDocumentWriter, BSONHandler, Macros}
import utils.Constants

import scala.concurrent.{ExecutionContext, Future}

@ImplementedBy(classOf[IterationResultHistoryRepositoryImpl])
trait IterationResultHistoryRepository extends BaseRepository {

  def create(iterationResultHistory: IterationResultHistory): Future[Unit]

  def findBySourceAddress(sourceAddress: String): Future[Seq[IterationResultHistory]]

  def getPortScanPorts(sourceAddress: String): Future[Set[Int]]

  def findByResultTypeAndSourceAddress(sourceAddress: String, resultType: String): Future[Seq[IterationResultHistory]]

  def findByResultType(resultType: String): Future[Seq[IterationResultHistory]]

  def clearHistory(): Future[Unit]

}

@Singleton
class IterationResultHistoryRepositoryImpl @Inject()(val mongoDBConnection: MongoDBConnection, val akkaSystem: ActorSystem) extends IterationResultHistoryRepository {

  implicit val iterationResultHistoryContext: ExecutionContext = akkaSystem.dispatchers.lookup("iteration-result-history-context")

  implicit def iterationResultHistoryReader: BSONDocumentReader[IterationResultHistory] = Macros.reader[IterationResultHistory]

  implicit def iterationResultHistoryWriter: BSONDocumentWriter[IterationResultHistory] = Macros.writer[IterationResultHistory]

  implicit def infoMapReader: BSONHandler[BSONDocument, Map[String, String]] = IterationResultInfo

  def collection: Future[BSONCollection] = mongoDBConnection.database.map(_.collection[BSONCollection]("iteration_result_history"))

  def create(iterationResultHistory: IterationResultHistory): Future[Unit] = {
    val f = collection.flatMap(_.insert(iterationResultHistory).map(_ => {}))
    f.onFailure { case e: Throwable => e.printStackTrace() }
    f
  }

  def findBySourceAddress(sourceAddress: String): Future[Seq[IterationResultHistory]] = {
    val query = BSONDocument(
      "sourceAddress" -> BSONDocument
      (
        "$eq" -> sourceAddress
      )
    )

    collection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]())
  }

  def getPortScanPorts(sourceAddress: String): Future[Set[Int]] = {
    findBySourceAddress(sourceAddress).map(rs => rs
      .filter(rt => Constants.PORT_SCAN_CONTEXT_LABELS.contains(rt.resultType)).map(_.port).toSet)
  }

  def findByResultTypeAndSourceAddress(sourceAddress: String, resultType: String): Future[Seq[IterationResultHistory]] = {
    val query = BSONDocument(
      "sourceAddress" -> BSONDocument
      (
        "$eq" -> sourceAddress
      ),
      "resultType" -> BSONDocument
      (
        "$eq" -> resultType
      )
    )

    collection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]())
  }

  def findByResultType(resultType: String): Future[Seq[IterationResultHistory]] = {
    val query = BSONDocument(
      "resultType" -> BSONDocument
      (
        "$eq" -> resultType
      )
    )

    collection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]())
  }

  def clearHistory(): Future[Unit] = {
    collection.flatMap(_.remove(BSONDocument())).map(_ => {})
  }

}