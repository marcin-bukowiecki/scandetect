name := "scandetect"

version := "1.0"

lazy val `scandetect` = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.8"

libraryDependencies ++= Seq( jdbc , cache , ws   , specs2 % Test )

unmanagedResourceDirectories in Test <+=  baseDirectory ( _ /"target/web/public/test" )  

resolvers += "scalaz-bintray" at "https://dl.bintray.com/scalaz/releases"

resolvers += "Typesafe repository releases" at "http://repo.typesafe.com/typesafe/releases/"

libraryDependencies ++= Seq( "org.reactivemongo" % "reactivemongo_2.11" % "0.12.0" )

libraryDependencies ++= Seq( "org.scalatestplus.play" %% "scalatestplus-play" % "1.5.0" % "test" )

libraryDependencies ++= Seq("mysql" % "mysql-connector-java" % "6.0.5" )

libraryDependencies += "nz.ac.waikato.cms.weka" % "weka-stable" % "3.8.3"
