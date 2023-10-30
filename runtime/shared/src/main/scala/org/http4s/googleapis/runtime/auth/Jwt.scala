package org.http4s
package googleapis.runtime.auth

import cats.MonadThrow
import cats.effect.kernel.Clock
import cats.syntax.all._
import io.circe.JsonObject
import io.circe.syntax._
import scodec.bits._

import scala.concurrent.duration.FiniteDuration

sealed trait Jwt[F[_]] {
  def sign(
      payload: JsonObject,
      audience: String,
      issuer: String,
      expiresIn: FiniteDuration,
      privateKey: ByteVector,
  ): F[String]
}

abstract private[auth] class UnsealedJwt[F[_]: Clock](implicit F: MonadThrow[F])
    extends Jwt[F] {
  private[this] val header = asciiBytes"""{"alg":"RS256","typ":"JWT"}""".toBase64UrlNoPad

  def sign(
      payload: JsonObject,
      audience: String,
      issuer: String,
      expiresIn: FiniteDuration,
      privateKey: ByteVector,
  ) = for {
    iat <- Clock[F].realTime
    claim = JsonObject(
      "iss" := issuer,
      "aud" := audience,
      "exp" := (iat + expiresIn).toSeconds,
      "iat" := iat.toSeconds,
    )
    json = payload.asJsonObject.deepMerge(claim).asJson
    claim <- ByteVector.encodeAscii(json.noSpaces).liftTo[F].map(_.toBase64UrlNoPad)
    headerClaim <- ByteVector.encodeAscii(s"$header.$claim").liftTo[F]
    signature <- sign(headerClaim, privateKey).map(_.toBase64UrlNoPad)
  } yield s"$header.$claim.$signature"

  protected def sign(data: ByteVector, privateKey: ByteVector): F[ByteVector]
}
