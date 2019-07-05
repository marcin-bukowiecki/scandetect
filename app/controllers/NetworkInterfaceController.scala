package controllers

import com.google.inject.{Inject, Singleton}
import play.api.mvc.{Action, Controller}
import repositories.NetworkInterfaceService

@Singleton
class NetworkInterfaceController @Inject()(networkInterfaceService: NetworkInterfaceService) extends Controller {

  def getNetworkInterfaces = Action {
    val networkInterfaces = networkInterfaceService.mapToJson(networkInterfaceService.getNetworkDevices())
    Ok(networkInterfaces)
  }

  def submitSelectedNetworkInterface = Action {
    implicit request => {
      Ok("test")
    }
  }

}
