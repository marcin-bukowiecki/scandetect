package repositories.concurrent

import java.util.concurrent.{Executors, ThreadFactory}

import play.api.Logger
import utils.Constants

import scala.concurrent.ExecutionContext

class CaptureServiceExecutionContext extends ExecutionContext {

  private val log = Logger

  private val threadPool = Executors.newFixedThreadPool(Runtime.getRuntime.availableProcessors() * Constants.INTEGER_TWO)

  private val threadFactory = new ThreadFactory {
    override def newThread(r: Runnable): Thread = {
      val t = new Thread(r)
      t.setName("capturePacketThreadPool")
      t
    }
  }

  override def reportFailure(cause: Throwable): Unit = {
    log.error("Error while capturing packet", cause)
  }

  override def execute(runnable: Runnable): Unit = {
    threadPool.submit(threadFactory.newThread(runnable))
  }

}
