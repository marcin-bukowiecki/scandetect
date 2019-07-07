package worker

import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

import actors.ScanAttackAndTypeDetectorActor
import akka.actor.{ActorSystem, Props}
import akka.pattern.ask
import akka.util.Timeout
import algorithms._
import com.google.inject.{Inject, Singleton}
import context.ScanDetectContext
import models.Packet
import play.api.Logger
import repositories.{AlertRepositoryImpl, IterationResultHistoryRepository, IterationResultHistoryRepositoryImpl, PacketRepositoryImpl}
import utils.Constants
import utils.Constants.SettingsKeys

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.{Failure, Success}

@Singleton
class ScanDetectWorker @Inject()(packetService: PacketRepositoryImpl,
                                 scanDetectionAlgorithm: ScanDetectionAlgorithm,
                                 system: ActorSystem,
                                 alertsService: AlertRepositoryImpl,
                                 iterationResultHistoryRepository: IterationResultHistoryRepository) {

  implicit private val timeout = Timeout(5.seconds)

  private val log = Logger

  private val detectScanThreadPool = Executors.newFixedThreadPool(1)

  var scanDetectContext: ScanDetectContext = _

  val doWork = new AtomicBoolean(false)

  val scanAttackAndTypeDetectorActor = system.actorOf(Props(new ScanAttackAndTypeDetectorActor(alertsService,
    iterationResultHistoryRepository)))

  def setContext(scanDetectContext: ScanDetectContext) = {
    this.scanDetectContext = scanDetectContext
  }

  def start(): Unit = {
    doWork.set(true)
    detectScans()

    if (scanDetectContext.getSettingsValueOrUseDefault(SettingsKeys.USE_HONEYPOT).toString.toBoolean) {
      detectNetworkScans()
    }
  }

  def stop(): Unit = {
    doWork.set(false)
  }

  def detectScans(): Unit = {
    detectScanThreadPool.submit(new Runnable {
      override def run(): Unit = {
        if (doWork.get()) {
          packetService
            .getToAnalyze(500)
            .onComplete {
              case Success(rs) =>
                Future.sequence(
                  if (rs.nonEmpty) scanDetectionAlgorithm.detect(ScanDetectWorker.this, rs) else Seq()
                ).map(_ => {
                  detectScans()
                })
              case Failure(ex) => ex.printStackTrace()
            }
        }
      }
    })
  }

  def detectNetworkScans(): Unit = {
    if (doWork.get()) {
      iterationResultHistoryRepository
        .findByResultType(Constants.IterationResultHistoryLabels.suspiciousNetworkScan)
        .onComplete {
          case Success(rs) =>
            Future.sequence(
              if (rs.nonEmpty) scanDetectionAlgorithm.detectNetworkScans(this, rs) else Seq()
            ).map(_ => {
              detectNetworkScans()
            })
          case Failure(ex) => ex.printStackTrace()
        }
    }
  }

  def dispatch[A <: IterationResult](iterationResult: A): Any = {
    if (scanDetectContext.isHoneypot) {
      packetService.markAsAnalyzedAndRemoveOld(iterationResult.captured).map(_ =>
        scanAttackAndTypeDetectorActor ? NetworkScanAlert(iterationResult.captured, iterationResult.analyzed)
      )
    } else {
      iterationResult match {
        case RemoveFinePackets(old: Seq[Packet], analyzed: Seq[Packet]) =>
          packetService.removeMultiple(old).map(_ =>
            packetService.removeMultipleAnalyzed(analyzed)
          )
        case _ =>
          packetService.markAsAnalyzedAndRemoveOld(iterationResult.captured).map(_ =>
            iterationResult match {
              case r@ContinueIteration(old: Seq[Packet], analyzed: Seq[Packet]) =>
              case r => scanAttackAndTypeDetectorActor ? r
            }
          )
      }
    }
  }

}
