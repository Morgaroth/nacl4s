
name := "nacl4s"

organization := "io.github.morgaroth"

version := "1.1.0"

scalaVersion := "2.11.11"

crossScalaVersions := Seq("2.10.5", scalaVersion.value, "2.12.4")

scalacOptions ++= Seq(
  "-encoding", "UTF-8",
  "-deprecation",
  "-unchecked",
  "-feature",
  "-Xfatal-warnings",
  "-Xlint",
  "-Xfuture",
  "-Yno-adapted-args",
  "-Ywarn-dead-code",
  "-Ywarn-numeric-widen"
) ++ (CrossVersion.partialVersion(scalaVersion.value) match {
  case Some((2, 11)) => Seq("-Ywarn-unused-import")
  case _ => Seq.empty
})

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.0.4" % "test" withSources(),
  "org.scalacheck" %% "scalacheck" % "1.13.4" % "test" withSources()
)

//coverageExcludedPackages := "com\\.emstlk\\.nacl4s\\.crypto\\.sign\\.Const;com\\.emstlk\\.nacl4s\\.benchmark"

licenses += ("MIT", url("http://opensource.org/licenses/MIT"))

bintrayVcsUrl := Some("https://github.com/Morgaroth/nacl4s")

enablePlugins(JmhPlugin)