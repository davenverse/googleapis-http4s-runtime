/*
 * Copyright 2024 Christopher Davenport
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.http4s
package googleapis.runtime.auth

import cats.Functor
import cats.data.EitherT
import cats.effect.Clock
import cats.effect.kernel.Temporal
import cats.syntax.all._
import io.circe.Decoder
import org.http4s.circe.jsonOf

import scala.concurrent.duration._

sealed abstract class AccessToken private {
  def token: String
  def expiresAt: FiniteDuration
  private[auth] def headerValue = Credentials.Token(AuthScheme.Bearer, token)
  private[auth] def withToken(token: String): AccessToken
  def expiresSoon[F[_]: Functor: Clock](in: FiniteDuration = 1.minute): F[Boolean] =
    Clock[F].realTime.map(now => expiresAt < now + in)
}

object AccessToken {
  private case class Impl(token: String, expiresAt: FiniteDuration) extends AccessToken {
    override def productPrefix = "AccessToken"
    override private[auth] def withToken(newToken: String): AccessToken =
      apply(newToken, expiresAt)
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
