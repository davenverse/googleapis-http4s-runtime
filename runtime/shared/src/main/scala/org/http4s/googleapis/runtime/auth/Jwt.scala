/*
 * Copyright (c) 2023 Christopher Davenport
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
