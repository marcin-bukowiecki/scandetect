package models

import play.api.libs.json._

/**
  * Created by Marcin on 2016-09-14.
  */

object NetworkInterfaceJson {

  def addressWrites = NetworkInterfaceAddressJson.addressWrites

  implicit val networkInterfaceWrites = new Writes[NetworkInterface] {
    def writes(networkInterface: NetworkInterface) = Json.obj(
      "name" -> networkInterface.name,
      "description" -> networkInterface.description,
      "addresses" -> JsArray(networkInterface.addresses.map(addressWrites.writes(_))),
      "flags" -> networkInterface.flags
    )
  }

}

case class NetworkInterface(name: String, description: String, addresses: Seq[NetworkInterfaceAddress], flags: Int)

object NetworkInterfaceAddressJson {

  implicit val addressWrites = new Writes[NetworkInterfaceAddress] {
    def writes(address: NetworkInterfaceAddress) = Json.obj(
      "address" -> address.address,
      "mask" -> address.mask,
      "broadcast" -> address.broadcast,
      "destinationAddress" -> address.destinationAddress
    )
  }

}

case class NetworkInterfaceAddress(address: String, mask: String, broadcast: String, destinationAddress: String)

