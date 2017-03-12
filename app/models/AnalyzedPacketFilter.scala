package models

/**
  * Created by Marcin on 2016-12-24.
  */
case class AnalyzedPacketFilter(protocols: Seq[String],
                               sourceAddress: String,
                               destinationAddress: String,
                               sourcePort: Int,
                               destinationPort: Int,
                               length: Int
                               )
