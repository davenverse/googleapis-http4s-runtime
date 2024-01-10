/*
 * Copyright 2024 Yoichiro Ito
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
package googleapis.runtime

import cats.effect.Temporal
import cats.effect.std.Env
import cats.syntax.all._
import fs2.io.file.Files
import fs2.io.file.Path

import scala.concurrent.duration._
import scala.util.control.NonFatal
trait GoogleEnvironmentDetection[F[_]] {

  /** Implements an algorithm to detect whether the code is running on Google Compute
    * Environment (GCE) or equivalent runtime. This algorithm can be disabled with environment
    * variable `NO_GCE_CHECK` set to `true`. In this case, the algorithm will always return
    * `false`
    *
    * @return
    *   `true` if currently running on Google Compute Environment (GCE) or equivalent runtime.
    *   Returns `false` if detection fails, platform is not supported or if detection disabled
    *   using the environment variable.
    * @see
    *   https://google.aip.dev/auth/4115 for more details.
    */
  def isOnGCE: F[Boolean]
}

object GoogleEnvironmentDetection {
  def apply[F[_]: Env: Files](
      met: ComputeMetadata[F],
  )(implicit F: Temporal[F]): GoogleEnvironmentDetection[F] =
    new GoogleEnvironmentDetection[F] {
      override def isOnGCE: F[Boolean] = for {
        noCheck <- Env[F].get("NO_GCE_CHECK")
        skip <- noCheck match {
          case None => F.pure(false)
          case Some(noCheck) => F.catchNonFatal(noCheck.toBoolean)
        }
        onGCE <- if (skip) F.pure(false) else pingN(3).orElse(detectFromSys)
      } yield onGCE

      def detectFromSys: F[Boolean] = {
        val linuxPath = Path("/sys/class/dmi/id/product_name")
        Files[F]
          .exists(linuxPath)
          .ifM(
            for {
              content <- Files[F].readUtf8(linuxPath).compile.string
              presence = content.startsWith("Google")
            } yield presence,
            F.pure(false),
          )
      }
      def pingN(max: Int, attempt: Int = 1): F[Boolean] =
        F.timeout(met.ping, 500.milliseconds).handleErrorWith {
          case NonFatal(e) => if (attempt < max) pingN(max, attempt + 1) else F.raiseError(e)
          case e => F.raiseError(e)
        }
    }
}
