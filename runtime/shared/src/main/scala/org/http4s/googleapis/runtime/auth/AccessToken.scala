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
