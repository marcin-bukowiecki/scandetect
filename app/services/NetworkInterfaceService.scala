package services

import java.lang.StringBuilder
import java.util

import com.google.inject.{Inject, Singleton}
import context.ScanDetectContext
import models.{NetworkInterfaceAddress, NetworkInterface, NetworkInterfaceJson}

import scala.collection.JavaConverters._
import org.jnetpcap.{Pcap, PcapIf}
import play.api.libs.json._
import utils.{Constants, NetworkInterfaceUtils}

/**
  * Created by Marcin on 2016-09-14.
  */
@Singleton
class NetworkInterfaceService @Inject() (scanDetectContext: ScanDetectContext) {

  def getNetworkDevices() = {
    val errorBuffer = new StringBuilder()
    val devices = new util.ArrayList[PcapIf]()

    try {
      Pcap.findAllDevs(devices,  errorBuffer)
    } catch {
      case ex: UnsatisfiedLinkError => ex.printStackTrace()
    }

    scanDetectContext.networkInterfaces.asScala.map(interface => NetworkInterface(
      interface.getName,
      interface.getDescription,
      interface.getAddresses.asScala.map(
        address => NetworkInterfaceAddress(
          NetworkInterfaceUtils.getReadableIPv4Address(address.getAddr.toString),
          address.getNetmask.toString,
          address.getBroadaddr.toString,
          if (address.getDstaddr != null) address.getDstaddr.toString else Constants.EMPTY_STRING
        )
      ),
      interface.getFlags)
    )
  }

  def mapToJson(networkInterfaces: Seq[NetworkInterface]) = {
    Json.toJson(networkInterfaces.map(ni => NetworkInterfaceJson.networkInterfaceWrites.writes(ni)))
  }

}
