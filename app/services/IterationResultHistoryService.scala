package services

import akka.actor.ActorSystem
import algorithms.ScanDetectionAlgorithm
import com.google.inject.{Inject, Singleton}
import context.MongoDBConnection
import models.{IterationResultHistory, IterationResultInfo}
import reactivemongo.api.collections.bson.BSONCollection
import reactivemongo.bson.{BSONDocument, BSONDocumentReader, BSONDocumentWriter, BSONHandler, Macros}

import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration._

/**
  * Created by Marcin on 2016-12-16.
  */
@Singleton
class IterationResultHistoryService @Inject() (val mongoDBConnection: MongoDBConnection, val akkaSystem: ActorSystem) {

  implicit val iterationResultHistoryContext: ExecutionContext = akkaSystem.dispatchers.lookup("iteration-result-history-context")

  implicit def iterationResultHistoryReader: BSONDocumentReader[IterationResultHistory] = Macros.reader[IterationResultHistory]
  implicit def iterationResultHistoryWriter: BSONDocumentWriter[IterationResultHistory] = Macros.writer[IterationResultHistory]

  implicit def infoMapReader: BSONHandler[BSONDocument, Map[String, String]] = IterationResultInfo

  def iterationResultHistoryCollection = mongoDBConnection.database.map(_.collection[BSONCollection]("iteration_result_history"))

  def create(iterationResultHistory: IterationResultHistory): Future[Unit] = {
    val f = iterationResultHistoryCollection.flatMap(_.insert(iterationResultHistory).map(_ => {}))
    f.onFailure{case e: Throwable => e.printStackTrace()}
    f
  }

  def findBySourceAddress(sourceAddress: String): Future[Seq[IterationResultHistory]] = {
    val query = BSONDocument(
      "sourceAddress" -> BSONDocument
      (
        "$eq" -> sourceAddress
      )
    )

    iterationResultHistoryCollection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]())
  }

  def getPortScanPorts(sourceAddress: String): Future[Set[Int]] = {
    findBySourceAddress(sourceAddress).map(rs => rs
      .filter(rt => ScanDetectionAlgorithm.PORT_SCAN_CONTEXT_LABELS.contains(rt.resultType)).map(_.port).toSet)
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

    iterationResultHistoryCollection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]())
  }

  def findByResultType(resultType: String): Future[Seq[IterationResultHistory]] = {
    val query = BSONDocument(
      "resultType" -> BSONDocument
      (
        "$eq" -> resultType
      )
    )

    iterationResultHistoryCollection.flatMap(_.find(query).cursor[IterationResultHistory]().collect[Seq]())
  }

  def clearHistory(): Future[Unit] = {
    iterationResultHistoryCollection.flatMap(_.remove(BSONDocument())).map(_ => {})
  }

}