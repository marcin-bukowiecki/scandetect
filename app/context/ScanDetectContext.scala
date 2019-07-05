package context

import com.google.inject.{Inject, Singleton}
import java.lang.StringBuilder
import java.util

import models.Settings
import neuralnetwork.ScanDetectNeuralNetwork
import org.jnetpcap.{Pcap, PcapIf}
import play.api.Logger
import repositories.{CaptureService, SettingsService}
import utils.Constants.SettingsKeys
import worker.ScanDetectWorker

import scala.util.control.Breaks._
import scala.collection.JavaConverters._

@Singleton
class ScanDetectContext @Inject()(val captureService: CaptureService,
                                  val scanDetectWorker: ScanDetectWorker,
                                  val mongoDBConnection: MongoDBConnection,
                                  val settingsService: SettingsService,
                                  val honeypotMongoDBConnection: HoneypotMongoDBConnection) {

  private val log = Logger
  log.info("Initializing scan detect context.")

  private var loadedSettings = Map[String, Any]()

  var useAsHoneypot = false

  def reloadDatabaseConnection() = mongoDBConnection.initConnection(this)

  def reloadHoneypotConnection() = honeypotMongoDBConnection.initConnection(this)

  def initContext() = {
    scanDetectWorker.setContext(this)
    val devices = new util.ArrayList[PcapIf]()

    try {
      Pcap.findAllDevs(devices, new StringBuilder())
    } catch {
      case ex: Exception => ex.printStackTrace()
    }

    mongoDBConnection.initConnection(this)

    devices
  }

  def startCapturingPackets(networkInterface: String) = {
    log.info("Starting capturing packets.")
    val devices = new util.ArrayList[PcapIf]()

    val useHoneypot = getSettingsValueOrUseDefault(SettingsKeys.USE_HONEYPOT).toString.toBoolean

    if (useHoneypot) {
      honeypotMongoDBConnection.initConnection(this)
    }

    try {
      Pcap.findAllDevs(devices, new StringBuilder())
    } catch {
      case ex: UnsatisfiedLinkError => ex.printStackTrace()
    }

    var networkInterfaceToUse: PcapIf = null

    breakable {
      for (device: PcapIf <- devices.asScala) {
        if (device.getName == networkInterface) {
          networkInterfaceToUse = device
          break
        }
      }
    }

    if (networkInterfaceToUse == null) {
      log.info("Can not start detecting scans. No network device found.")
    } else {
      captureService.startCapturing(networkInterfaceToUse)

      log.info("Starting detecting scans.")
      scanDetectWorker.start()
    }
  }

  /*
  For debugging !!!
   */
  def startCapturingPackets() = {
    log.info("Starting capturing packets.")
    val devices = new util.ArrayList[PcapIf]()

    try {
      Pcap.findAllDevs(devices, new StringBuilder())
    } catch {
      case ex: UnsatisfiedLinkError => ex.printStackTrace()
    }

    captureService.startCapturing(devices.get(0))

    log.info("Starting detecting scans.")
    scanDetectWorker.start()
  }

  val networkInterfaces = initContext()
  /*
  For debugging !!!
   */
  //startCapturingPackets()

  def stopCapturingPackets() = {
    log.info("Stopping capturing packets.")
    scanDetectWorker.stop()
    honeypotMongoDBConnection.closeConnection()
  }

  def getAnalyzingPacketsNumber = 500

  object DefaultSettings {
    val databaseUrl = "localhost:27017/test"
    val databaseUsername = ""
    val databasePassword = ""
    val closedPortThreshold = 5
    val useHoneypot = false
    val honeypotDatabaseUrl = ""
    val honeypotDatabasePassword = ""
    val honeypotDatabaseUsername = ""

    def get(): Seq[Settings] = {
      Seq(
        Settings(None, SettingsKeys.DATABASE_URL, databaseUrl),
        Settings(None, SettingsKeys.CLOSED_PORT_THRESHOLD, closedPortThreshold.toString),
        Settings(None, SettingsKeys.USE_HONEYPOT, useHoneypot.toString),
        Settings(None, SettingsKeys.HONEYPOT_DATABASE_URL, honeypotDatabaseUrl),
        Settings(None, SettingsKeys.HONEYPOT_DATABASE_PASSWORD, honeypotDatabasePassword),
        Settings(None, SettingsKeys.HONEYPOT_DATABASE_USERNAME, honeypotDatabaseUsername),
        Settings(None, SettingsKeys.USE_HONEYPOT, useHoneypot.toString),
        Settings(None, SettingsKeys.DATABASE_PASSWORD, databasePassword),
        Settings(None, SettingsKeys.DATABASE_USERNAME, databaseUsername)
      )
    }
  }

  def getSettingsValueOrUseDefault(key: String): Any = {
    loadedSettings.getOrElse(key, key match {
      case SettingsKeys.CLOSED_PORT_THRESHOLD => DefaultSettings.closedPortThreshold
      case SettingsKeys.DATABASE_URL => DefaultSettings.databaseUrl
      case SettingsKeys.DATABASE_PASSWORD => DefaultSettings.databasePassword
      case SettingsKeys.DATABASE_USERNAME => DefaultSettings.databaseUsername
      case SettingsKeys.USE_HONEYPOT => DefaultSettings.useHoneypot
      case SettingsKeys.HONEYPOT_DATABASE_URL => DefaultSettings.honeypotDatabaseUrl
      case SettingsKeys.HONEYPOT_DATABASE_PASSWORD => DefaultSettings.honeypotDatabasePassword
      case SettingsKeys.HONEYPOT_DATABASE_USERNAME => DefaultSettings.honeypotDatabaseUsername
    })
  }

  var scanDetectNeuralNetwork = new ScanDetectNeuralNetwork

  def initNeuralNetworks() = {
    log.info("Initializing neural networks. This may take a while.")

    try {
      scanDetectNeuralNetwork.init()
    } catch {
      case e: Throwable =>
        log.error("Error while initializing neural networks.", e)
    }

    log.info("Initializing ended.")
  }

  initNeuralNetworks()

  def setSettings(settings: Map[String, Any]): Unit = {
    this.loadedSettings = settings
  }

  def isHoneypot = useAsHoneypot

  def loadSettings() = {
    if (settingsService.validateSettings()) setSettings(settingsService.loadSettings().map(row => row.key -> row.value).toMap)
  }

}
