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

libraryDependencies ++= Seq("org.deeplearning4j" % "deeplearning4j-core" % "1.0.0-beta4" )

libraryDependencies ++= Seq("org.nd4j" % "nd4j-native-platform" % "1.0.0-beta4" )

libraryDependencies ++= Seq("org.datavec" % "datavec-api" % "1.0.0-beta4" )

libraryDependencies ++= Seq("org.nd4j" % "nd4j-backend-impls" % "1.0.0-beta4" )

libraryDependencies ++= Seq("mysql" % "mysql-connector-java" % "6.0.5" )