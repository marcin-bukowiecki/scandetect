package services

import akka.actor.ActorSystem
import com.google.inject.{Inject, Singleton}
import context.MongoDBConnection
import models.Alert
import org.joda.time.format.DateTimeFormat
import reactivemongo.api.collections.bson.BSONCollection
import reactivemongo.bson.{BSONDocument, BSONDocumentReader, BSONDocumentWriter, Macros}
import play.api.Logger
import utils.ScanAttackTypes

import scala.concurrent.{ExecutionContext, Future}


@Singleton
class AlertsService @Inject() (val mongoDBConnection: MongoDBConnection, val akkaSystem: ActorSystem) {

  val log = Logger

  implicit val alertServiceExecutionContext: ExecutionContext = akkaSystem.dispatchers.lookup("alert-service-context")

  implicit def alertReader: BSONDocumentReader[Alert] = Macros.reader[Alert]
  implicit def alertWriter: BSONDocumentWriter[Alert] = Macros.writer[Alert]

  def collection = mongoDBConnection.database.map(_.collection[BSONCollection]("alerts"))

  def create(alert: Alert) = {
    log.info("Creating alert for: " + alert)
    collection.flatMap(_.insert(alert).map(_ => {}))
  }

  def list(): Future[Seq[Alert]] = {
    collection.flatMap(_.find(BSONDocument()).cursor[Alert]().collect[Seq]())
  }

  def findBySrcAddressAttackTypeAndScanType(srcAddress: String, scanType: String, attackType: String): Future[Seq[Alert]] = {
    val query = BSONDocument(
      "ipAttacker" -> BSONDocument (
        "$eq" -> srcAddress
      ),
      "scanType" -> BSONDocument (
        "$eq" -> scanType
      ),
      "attackType" -> BSONDocument (
        "$eq" -> attackType
      )
    )

    collection.flatMap(_.find(query).cursor[Alert]().collect[Seq]())
  }

  def list(from: String): Future[Seq[Alert]] = {
    val query = BSONDocument(
      "_id" -> BSONDocument(
        "$gt" -> from
      )
    )

    collection.flatMap(_.find(query).cursor[Alert]().collect[Seq]())
  }

  def setAsRead(alert: Alert) = {
    val selector = BSONDocument(
      "_id" -> BSONDocument(
        "$eq" -> alert._id))

    val modifier = BSONDocument(
      "$set" -> BSONDocument(
        "read" -> true
      )
    )

    collection.flatMap(_.update(selector, modifier).map(_ => {}))
  }

  def removeAlert(attackType: String, ipAttacker: String, scanType: String): Future[Unit] = {
    val selector = BSONDocument(
      "attackType" -> BSONDocument(
        "$eq" -> attackType
      ),
      "ipAttacker" -> BSONDocument(
        "$eq" -> ipAttacker
      ),
      "scanType" -> BSONDocument(
        "$eq" -> scanType
      )
    )

    collection.flatMap(_.remove(selector).map(_ => {}))
  }

  def getAllAlertsAndGroupThem(): Future[Seq[Alert]] = {
    collection.flatMap(_.find(BSONDocument()).cursor[Alert]().collect[Seq]()).map(alerts => {
      val sortedAlerts = alerts.sortBy(_.time)

      val gotTcpConnect = sortedAlerts.exists(_.attackType == ScanAttackTypes.AttackType.TCP_CONNECT)

      sortedAlerts.groupBy(a => if ((a.attackType == ScanAttackTypes.AttackType.TCP_CONNECT
        || a.attackType == ScanAttackTypes.AttackType.TCP_SYN) && gotTcpConnect) (a.ipAttacker, a.scanType,
        ScanAttackTypes.AttackType.TCP_SYN_OR_TCP_CONNECT)
      else (a.ipAttacker, a.scanType, a.attackType)).map(entry => {

        val alerts = entry._2
        val scannedPorts = alerts.flatMap(_.scannedPorts).distinct.sorted
        val softwareUsed = alerts.flatMap(_.softwareUsed).toSet
        val formattedTime = DateTimeFormat.forPattern("YYYY-MM-dd HH:mm").print(alerts.head.time.toLong)
        val chance = alerts.maxBy(_.chance).chance

        Alert(
          alerts.head._id,
          formattedTime,
          entry._1._2.toString,
          entry._1._3,
          entry._1._1,
          alerts.head.description,
          softwareUsed,
          scannedPorts,
          chance,
          alerts.head.read
        )

      }).toSeq
    })
  }

  def removeAlertByIpAndAttackType(ipAttacker: String, attackType: String): Future[Unit] = {
    val query = BSONDocument(
      "ipAttacker" -> BSONDocument(
        "$eq" -> ipAttacker
      ),
      "attackType" -> BSONDocument(
        "$eq" -> attackType
      )
    )

    collection.flatMap(_.remove(query).map(_ => {}))
  }

  def stub() = {
    collection.flatMap(_.find(BSONDocument()).cursor[Alert]().collect[Seq](1))
  }

}
