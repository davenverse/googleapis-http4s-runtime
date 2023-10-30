package org.http4s
package googleapis.runtime.auth

import cats.data.EitherT
import cats.effect.kernel.Temporal
import cats.syntax.all._
import io.circe.Decoder
import org.http4s.circe.jsonOf
import scodec.bits.ByteVector

import scala.concurrent.duration._

trait OAuth2[F[_]] {
  def getAccessToken(
      clientEmail: String,
      privateKey: ByteVector,
      scopes: Seq[String],
  ): F[AccessToken]
}
