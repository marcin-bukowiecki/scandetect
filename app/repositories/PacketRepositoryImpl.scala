package repositories

import akka.actor.ActorSystem
import com.google.inject.{ImplementedBy, Inject, Singleton}
import context.MongoDBConnection
import models.{AnalyzedPacketFilter, Packet, PacketData}
import reactivemongo.api.collections.bson.BSONCollection
import reactivemongo.api.commands.{MultiBulkWriteResult, WriteResult}
import reactivemongo.bson.{BSONDocument, BSONDocumentReader, BSONDocumentWriter, BSONHandler, BSONObjectID, Macros}
import utils.{PortUtils, Protocols}

import scala.concurrent.{ExecutionContext, Future}

@ImplementedBy(classOf[PacketRepositoryImpl])
trait PacketRepository[T] {

  def create(packet: T): Future[Unit]
  def getAssociatedWithFlowKey(flowKey: Long, additionalHash: Long): Future[Seq[T]]
  def getToAnalyze(limit: Int): Future[Seq[T]]
  def removeMultiple(packetsToRemove: Seq[T]): Future[WriteResult]
  def markAsAnalyzed(packets: Seq[T]): Future[MultiBulkWriteResult]
  def markAsAnalyzedAndRemoveOld(packets: Seq[T]): Future[Unit]
  def removeByFlowKey(flowKey: Long): Future[WriteResult]
  def getAssociatedWithFlowKeyAndProtocol(flowKey: Long, protocol: String): Future[Seq[T]]
}

@Singleton
class PacketRepositoryImpl @Inject()(val mongoDBConnection: MongoDBConnection, val akkaSystem: ActorSystem) extends PacketRepository[Packet] {

  implicit val myExecutionContext: ExecutionContext = akkaSystem.dispatchers.lookup("packet-service-context")

  implicit def packetReader: BSONDocumentReader[Packet] = Macros.reader[Packet]
  implicit def packetWriter: BSONDocumentWriter[Packet] = Macros.writer[Packet]

  implicit def infoMapReader: BSONHandler[BSONDocument, Map[String, String]] = PacketData
  implicit def idReader: BSONHandler[BSONObjectID, Option[BSONObjectID]] = IdReader

  def packetsCollection: Future[BSONCollection] = mongoDBConnection.database.map(_.collection[BSONCollection]("capturedPackets"))
  def analyzedPacketsCollection: Future[BSONCollection] = mongoDBConnection.database.map(_.collection[BSONCollection]("analyzedPackets"))

  def create(packet: Packet): Future[Unit] = {
    val f = packetsCollection.flatMap(_.insert(packet).map(_ => {}))
    f.onFailure{case rs =>
      rs.printStackTrace()
      create(packet)
    }
    f
  }

  def getAssociatedWithFlowKey(flowKey: Long, additionalHash: Long): Future[Seq[Packet]] = {
    val query = BSONDocument(
        "flowKey" -> BSONDocument
        (
          "$eq" -> flowKey
        ),
        "additionalHash" -> BSONDocument
        (
          "$eq" -> additionalHash
        )
      )

    analyzedPacketsCollection.flatMap(_.find(query).cursor[Packet]().collect[Seq]())
  }

  def getAssociatedWithFlowKeyAndProtocol(flowKey: Long, protocol: String): Future[Seq[Packet]] = {
    val query = BSONDocument(
      "flowKey" -> BSONDocument
      (
        "$eq" -> flowKey
      ),
      "protocol" -> BSONDocument
      (
        "$eq" -> protocol
      )
    )

    analyzedPacketsCollection.flatMap(_.find(query).cursor[Packet]().collect[Seq]())
  }

  def getToAnalyze(limit: Int): Future[Seq[Packet]] = {
    val query = BSONDocument()
    packetsCollection.flatMap(_.find(query).cursor[Packet]().collect[Seq](limit))
  }

  def removeMultiple(packetsToRemove: Seq[Packet]): Future[WriteResult] = {
    val ids = packetsToRemove.map(_._id)

    val query = BSONDocument(
       "_id" -> BSONDocument(
         "$in" -> ids))

    val rs = packetsCollection.flatMap(_.remove(query))
    rs.onFailure{
      case ex => ex.printStackTrace()
    }
    rs
  }

  def removeMultipleAnalyzed(packetsToRemove: Seq[Packet]): Future[WriteResult] = {
    val ids = packetsToRemove.map(_._id)

    val query = BSONDocument(
      "_id" -> BSONDocument(
        "$in" -> ids))

    val rs = analyzedPacketsCollection.flatMap(_.remove(query))
    rs.onFailure{
      case ex => ex.printStackTrace()
    }
    rs
  }

  def removeAnalyzedByFlowKey(flowKey: Long): Future[WriteResult] = {
    val query = BSONDocument(
      "flowKey" -> BSONDocument(
        "$eq" -> flowKey))

    val rs = analyzedPacketsCollection.flatMap(_.remove(query))
    rs.onFailure{
      case ex => ex.printStackTrace()
    }
    rs
  }

  def markAsAnalyzed(packets: Seq[Packet]): Future[MultiBulkWriteResult] = {
    val docs = packets.toStream.map(p => packetWriter.write(p))
    val rs = analyzedPacketsCollection.flatMap[MultiBulkWriteResult](
      _.bulkInsert(docs, ordered = false)
    )
    rs.onFailure{
      case ex => ex.printStackTrace()
    }
    rs
  }

  def markAsAnalyzedAndRemoveOld(packets: Seq[Packet]): Future[Unit] = {
    markAsAnalyzed(packets).flatMap(_ => removeMultiple(packets).map(_ => ()))
  }

  def removeByFlowKey(flowKey: Long): Future[WriteResult] = {
    val query = BSONDocument(
      "flowKey" -> flowKey
    )

    val rs = packetsCollection.flatMap(_.remove(query))
    rs.onFailure{
      case ex => ex.printStackTrace()
    }
    rs
  }

  def getNumberOfPacketsInDatabase: Future[Int] = {
    packetsCollection.flatMap(_.count())
  }

  def getNumberOfAnalyzedPacketsInDatabase: Future[Int] = {
    analyzedPacketsCollection.flatMap(_.count())
  }

  def removeAllPackets(): Future[Unit] = {
    Future.sequence(Seq(
      packetsCollection.flatMap(_.remove(BSONDocument())),
      analyzedPacketsCollection.flatMap(_.remove(BSONDocument()))
    )).flatMap(rs => Future{})
  }

  def areThereMorePackets(flowKey: Long, additionalHash: Long): Future[Boolean] = {
    val query = BSONDocument(
      "flowKey" -> BSONDocument
      (
        "$eq" -> flowKey
      ),
      "additionalHash" -> BSONDocument
      (
        "$eq" -> additionalHash
      )
    )

    val f = packetsCollection.flatMap(_.count(Option(query))).map(result => result > 0)
    f.onFailure{case e: Throwable => e.printStackTrace()}
    f
  }

  def areThereMoreIcmpPackets(flowKey: Long): Future[Boolean] = {
    val query = BSONDocument(
      "flowKey" -> BSONDocument
      (
        "$eq" -> flowKey
      ),
      "protocol" -> BSONDocument
      (
        "$eq" -> Protocols.ICMP
      )
    )

    val f = packetsCollection.flatMap(_.count(Option(query))).map(result => result > 0)
    f.onFailure{case e: Throwable => e.printStackTrace()}
    f
  }

  def filterPackets(analyzedPacketFilter: AnalyzedPacketFilter): Future[Seq[Packet]] = {
    val protocolsToFilter = if (analyzedPacketFilter.protocols.size == 1 && analyzedPacketFilter.protocols.head.isEmpty) {
      Protocols.supportedProtocols
    } else {
      analyzedPacketFilter.protocols
    }

    val query = BSONDocument(
      "protocol" -> BSONDocument(
        "$in" -> protocolsToFilter
      ),
      "sourceAddress" -> BSONDocument(
        "$regex" -> analyzedPacketFilter.sourceAddress
      ),
      "destinationAddress" -> BSONDocument(
        "$regex" -> analyzedPacketFilter.destinationAddress
      )
    )

    analyzedPacketsCollection.flatMap(rs => {
      var queryBuilder = rs.find(query)
      queryBuilder = if(analyzedPacketFilter.sourcePort != PortUtils.NO_PORT) {
        queryBuilder.query(BSONDocument(
          "sourcePort" -> BSONDocument(
            "$eq" -> analyzedPacketFilter.sourcePort
          )
        ))
      } else {
        queryBuilder
      }
      queryBuilder = if (analyzedPacketFilter.destinationPort != PortUtils.NO_PORT) {
        queryBuilder.query(BSONDocument(
          "destinationPort" -> BSONDocument(
            "$eq" -> analyzedPacketFilter.destinationPort
          )
        ))
      } else {
        queryBuilder
      }
      queryBuilder = if (analyzedPacketFilter.length != PortUtils.NO_PORT) {
        queryBuilder.query(BSONDocument(
          "length" -> BSONDocument(
            "$eq" -> analyzedPacketFilter.length
          )
        ))
      } else {
        queryBuilder
      }

      queryBuilder.cursor[Packet]().collect[Seq]()
    })
  }

  object IdReader extends BSONHandler[BSONObjectID, Option[BSONObjectID]] {
    override def read(bson: BSONObjectID): Option[BSONObjectID] = {
      Option(bson)
    }

    override def write(t: Option[BSONObjectID]): BSONObjectID = {
      t.get
    }
  }

}
