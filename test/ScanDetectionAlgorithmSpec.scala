import akka.actor.ActorSystem
import algorithms.ScanDetectionAlgorithm
import context.{MongoDBConnection, ScanDetectContext}
import models.Packet
import org.junit.runner.RunWith
import org.mockito.Mockito._
import org.specs2.mock.Mockito
import org.specs2.mutable.Specification
import org.specs2.runner.JUnitRunner
import reactivemongo.api.MongoConnection.ParsedURI
import reactivemongo.api.{DefaultDB, MongoConnection, MongoDriver}
import repositories.{AlertRepositoryImpl, HoneypotService, IterationResultHistoryRepository, PacketRepositoryImpl}
import utils.Direction
import worker.ScanDetectWorker

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import scala.concurrent.{Await, Future}
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class ScanDetectionAlgorithmSpec extends Specification with Mockito {

  object MongoDBConnectionTest extends MongoDBConnection {

    val uri: String = "mongodb://localhost:27017"
    val driver: MongoDriver = MongoDriver()
    val parsedUri: Try[ParsedURI] = MongoConnection.parseURI(uri)
    val connection: Try[MongoConnection] = parsedUri.map(driver.connection)
    val futureConnection: Future[MongoConnection] = Future.fromTry(connection)
    val dataBaseConnection: Future[DefaultDB] = futureConnection.flatMap(_.database("test_db"))

    override def database: Future[DefaultDB] = dataBaseConnection

    override def initConnection(scanDetectContext: ScanDetectContext): Unit = {

    }

    override def db: DefaultDB = {
      Await.result(dataBaseConnection, 5.seconds)
    }
  }

  private val mongoConnection = MongoDBConnectionTest

  //val ps =

  "ScanDetectionAlgorithm.detect() method" should {
    "detect TCP connect scan" in {
      val packets = Seq(
        Packet(None, 0, "TCP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("SYN"), 5000, 0, 0, Direction.INCOME.toString, 0),
        Packet(None, 0, "TCP", "192.168.1.4", 35123, "192.168.1.6", 5000, Map(), Seq("SYN", "ACK"), 5000, 0, 0, Direction.OUTCOME.toString, 0),
        Packet(None, 0, "TCP", "192.168.1.6", 35123, "192.168.1.4", 80, Map(), Seq("RST"), 5000, 0, 0, Direction.INCOME.toString, 0)
      )

      val iterationResultHistoryRepository =  mock[IterationResultHistoryRepository]
      val packetService = new PacketRepositoryImpl(mongoConnection, ActorSystem.create("packet-service-spec"))
      val alertService = new AlertRepositoryImpl(mongoConnection, ActorSystem.create("alert-service-spec"))
      val honeypotService = mock[HoneypotService]//new HoneypotService(mongoConnection, ActorSystem.create("honeypot-service-spec"))

      //when(packetService.getToAnalyze(500)).thenReturn(Future(packets))
      //when(packetService.getAssociatedWithFlowKey(411, 0)).thenReturn(Future(Seq()))
      //when(packetService.markAsAnalyzedAndRemoveOld(packets)).thenReturn(Future[Unit]())

      val scanDetectionAlgorithm = new ScanDetectionAlgorithm(
        packetService,
        iterationResultHistoryRepository,
        honeypotService,
        ActorSystem.create("scan-detection-algorithm-spec-context"))

      val scanDetectWorker = new ScanDetectWorker(packetService,
        scanDetectionAlgorithm,
        ActorSystem.create("scan-detection-algorithm-spec"),
        alertService,
        iterationResultHistoryRepository)

      when(scanDetectionAlgorithm.fetchPacketsFromThisConnection("TCP", 5000, 0)).thenReturn(Future(Seq()))

      Await.result(scanDetectionAlgorithm.detect(scanDetectWorker, packets).head, 3.seconds)
      Await.result(alertService.list(), 3.seconds).size must equalTo(1)
    }
  }

}
