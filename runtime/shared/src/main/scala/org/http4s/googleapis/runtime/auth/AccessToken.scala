package org.http4s
package googleapis.runtime.auth

import cats.data.EitherT
import cats.effect.kernel.Temporal
import cats.syntax.all._
import io.circe.Decoder
import org.http4s.circe.jsonOf

import scala.concurrent.duration._

sealed abstract class AccessToken private {
  def token: String
  def expiresAt: FiniteDuration
}

object AccessToken {
  private case class Impl(token: String, expiresAt: FiniteDuration) extends AccessToken {
    override def productPrefix = "AccessToken"
  }

  private def apply(token: String, expiresAt: FiniteDuration): AccessToken =
    Impl(token, expiresAt)

  implicit def entityDecoder[F[_]](implicit F: Temporal[F]): EntityDecoder[F, AccessToken] =
    jsonOf(F, Decoder.forProduct2("access_token", "expires_in")(Tuple2[String, Int](_, _)))
      .flatMapR { case (accessToken, expiresIn) =>
        EitherT.liftF {
          F.realTime.map { now =>
            AccessToken(accessToken, now + expiresIn.seconds)
          }
        }
      }
}
