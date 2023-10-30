ThisBuild / tlBaseVersion := "0.0"

ThisBuild / organization := "io.chrisdavenport"
ThisBuild / organizationName := "Christopher Davenport"
ThisBuild / developers := List(
  tlGitHubDev("christopherdavenport", "Christopher Davenport"),
  tlGitHubDev("armanbilge", "Arman Bilge"),
)
ThisBuild / tlCiReleaseBranches := Seq("main")
ThisBuild / tlSonatypeUseLegacyHost := true

val Scala213 = "2.13.12"
ThisBuild / crossScalaVersions := Seq(Scala213, "3.3.1")
ThisBuild / scalaVersion := Scala213

ThisBuild / githubWorkflowJavaVersions := Seq(JavaSpec.temurin("17"))

val http4sVersion = "0.23.23"

lazy val root = tlCrossRootProject.aggregate(runtime)

lazy val runtime = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("runtime"))
  .settings(
    name := "http4s-googleapis-runtime",
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-effect" % "3.5.2",
      "org.http4s" %%% "http4s-client" % http4sVersion,
      "org.http4s" %%% "http4s-circe" % http4sVersion,
    ),
  )
