import akka.actor.ActorSystem
import models.Packet
import org.junit.runner.RunWith
import org.specs2.mock.Mockito
import org.specs2.mutable.Specification
import org.specs2.runner.JUnitRunner
import algorithms.ScanDetectionAlgorithm
import context.{MongoDBConnection, ScanDetectContext}
import services.{AlertsService, PacketService}
import utils.Direction
import org.mockito.Mockito._
import reactivemongo.api.{DefaultDB, MongoConnection, MongoDriver}
import worker.ScanDetectWorker

import scala.concurrent.duration._
import scala.concurrent.{Await, Future}
import scala.concurrent.ExecutionContext.Implicits.global

/**
  * Created by Marcin on 2016-10-25.
  */
@RunWith(classOf[JUnitRunner])
class ScanDetectionAlgorithmSpec extends Specification with Mockito {

  object MongoDBConnectionTest extends MongoDBConnection {

    val uri = "mongodb://localhost:27017"
    val driver = MongoDriver()
    val parsedUri = MongoConnection.parseURI(uri)
    val connection = parsedUri.map(driver.connection(_))
    val futureConnection = Future.fromTry(connection)
    val dataBaseConnection = futureConnection.flatMap(_.database("test_db"))

    override def database: Future[DefaultDB] = dataBaseConnection

    override def initConnection(scanDetectContext: ScanDetectContext): Unit = {

    }

    override def db: DefaultDB = {
      null
    }
  }

  val ps = new PacketService(MongoDBConnectionTest, ActorSystem.create("packet-service-spec"))

  "ScanDetectionAlgorithm.detect() method" should {
    "detect TCP connect scan" in {
      val packets = Seq(
        Packet(null, 0, "TCP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("SYN"), 5000, 0, 0, Direction.INCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 5000, Map(), Seq("SYN", "ACK"), 5000, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(null, 0, "TCP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("RST"), 5000, 0, 0, Direction.INCOME.toString, 0)
      )

      val packetService = mock[PacketService]
      val alertService = new AlertsService(MongoDBConnectionTest, ActorSystem.create("alert-service-spec"))
      when(packetService.getToAnalyze(500)).thenReturn(Future(packets))
      when(packetService.getAssociatedWithFlowKey(411, 0)).thenReturn(Future(Seq()))
      when(packetService.markAsAnalyzedAndRemoveOld(packets)).thenReturn(Future[Unit]())

      val scanDetectionAlgorithm = new ScanDetectionAlgorithm(packetService,
        null,
        null,
        ActorSystem.create("scan-detection-algorithm-spec-context"))
      val scanDetectWorker = new ScanDetectWorker(packetService,
        scanDetectionAlgorithm,
        ActorSystem.create("scan-detection-algorithm-spec"),
        alertService, null)

      when(scanDetectionAlgorithm.fetchPacketsFromThisConnection("", 50000, 0)).thenReturn(Future(Seq()))

      Await.result(scanDetectionAlgorithm.detect(scanDetectWorker, packets)(0), 3 seconds)
      val rs = Await.result(alertService.list(), 3 seconds)
      Thread.sleep(3000)
      rs.size must equalTo(1)
    }
  }

}
