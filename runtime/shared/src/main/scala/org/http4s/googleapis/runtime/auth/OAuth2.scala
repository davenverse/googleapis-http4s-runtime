/*
 * Copyright 2023 Christopher Davenport
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
