package repositories.handler

import org.jnetpcap.packet.{PcapPacket, PcapPacketHandler}
import repositories.CaptureService

object CaptureServicePacketHandler {

  def apply(captureService: CaptureService): CaptureServicePacketHandler = new CaptureServicePacketHandler(captureService)

}

class CaptureServicePacketHandler(val captureService: CaptureService) extends PcapPacketHandler[String] {

  override def nextPacket(pcapPacket: PcapPacket, interfaceAddress: String): Unit = {
    val packetToSave = captureService.createPacketToSave(pcapPacket, interfaceAddress)

    if (packetToSave.isDefined &&
      !captureService.getAddressesToIgnore.contains(packetToSave.get.sourceAddress) &&
      !captureService.getAddressesToIgnore.contains(packetToSave.get.destinationAddress)
    ) {
      if (!(captureService.networkInterfaceAddressesAsSet.contains(packetToSave.get.sourceAddress) ||
        captureService.networkInterfaceAddressesAsSet.contains(packetToSave.get.destinationAddress))) {
        return
      } else {
        captureService.packetService.create(packetToSave.get)
      }
    }
  }

}
