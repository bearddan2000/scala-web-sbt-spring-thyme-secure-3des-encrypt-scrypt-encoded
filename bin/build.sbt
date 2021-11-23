lazy val root = (project in file("."))
  .settings(
    name := "spring-boot-scala-web",

    version := "1.0",

    scalaVersion := "2.11.8",

    libraryDependencies ++= Seq(
      "org.springframework.boot" % "spring-boot-starter-web" % "2.4.2",
      "org.springframework.boot" % "spring-boot-starter-thymeleaf" % "2.4.2",
      "org.thymeleaf.extras" % "thymeleaf-extras-springsecurity5" % "3.0.4.RELEASE",
      "org.springframework.boot" % "spring-boot-starter-websocket" % "2.4.2",
      "org.springframework.boot" % "spring-boot-starter-security" % "2.4.2",
      "org.springframework.security" % "spring-security-crypto" % "5.3.2.RELEASE",
      "org.springframework.security" % "spring-security-web" % "5.0.0.RELEASE",
      "org.springframework.security" % "spring-security-core" % "5.0.0.RELEASE",
      "org.springframework.security" % "spring-security-config" % "5.0.0.RELEASE",
      "commons-codec" % "commons-codec" % "1.15",
      "javax.xml.bind" % "jaxb-api" % "2.3.1",
      "org.bouncycastle" % "bcpkix-jdk15on" % "1.65",
      "org.webjars" % "webjars-locator-core" % "0.46",
      "org.webjars" % "bootstrap" % "3.3.7",
      "org.webjars" % "jquery" % "3.1.1-1"
     ),

    mainClass := Some("example.MyApp")
)
