package repositories

import context.MongoDBConnection
import models.Packet
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

/**
  * Created by Marcin on 2016-10-26.
  */
class PacketRepositoryImplTester(mongoDBConnection: MongoDBConnection = null) extends PacketRepositoryImpl(mongoDBConnection: MongoDBConnection, null) {

  override def create(packet: Packet): Future[Unit] = Future {}

}
