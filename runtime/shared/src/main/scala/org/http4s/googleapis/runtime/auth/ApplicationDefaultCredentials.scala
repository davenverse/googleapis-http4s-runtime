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
package googleapis.runtime.auth
import cats.data.OptionT
import cats.effect.Concurrent
import cats.effect.Temporal
import cats.effect.std.Env
import cats.syntax.all._
import fs2.io.file.Files
import fs2.io.file.Path
import io.circe.parser

import client.Client

/** ApplicationDefaultCredentials is a strategy Google auth libraries use to detect and select
  * credentials based on environment or context.
  * @see
  *   https://google.aip.dev/auth/4110
  */
object ApplicationDefaultCredentials {

  /** create application default credentials
    * @see
    *   https://google.aip.dev/auth/4110#expected-behavior
    */
  def apply[F[_]: Env: Files](
      client: Client[F],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = for {
    localCredFile <- fromLocal
    credentials <- localCredFile match {
      case None => // Check workload credentials
        F.raiseError(
          new NotImplementedError("workload credentials lookup is not implemented yet"),
        )
      case Some(file) =>
        Oauth2Credentials[F](client, file)
    }
  } yield credentials

  private def fromLocal[F[_]: Env: Files](implicit
      F: Concurrent[F],
  ): F[Option[CredentialsFile]] =
    (OptionT(fromEnv) <+> OptionT(fromWellKnownPaths)).value

  /** lookup application default credentials at well known locations generated by gcloud CLI
    * @see
    *   https://google.aip.dev/auth/4113#guidance
    */
  private def fromWellKnownPaths[F[_]: Files](implicit
      F: Concurrent[F],
  ): F[Option[CredentialsFile]] = {
    val pathOnUnix: F[Path] =
      Files[F].userHome.map(_ / ".config" / "gcloud" / "application_default_credentials.json")
    val detectPlatform: F[String] = F.pure("TODO: Windows support")
    for {
      platform <- detectPlatform
      path <-
        if (platform == "windows")
          F.raiseError(new NotImplementedError("cannot lookup Google credentials on Windows"))
        else pathOnUnix
      file <- readCredentialsFile(path)
    } yield file
  }

  /** lookup application default credentials from GOOGLE_APPLICATION_CREDENTIALS environment
    * variable. GOOGLE_APPLICATION_CREDENTIALS should be a full path to credentials file.
    * @see
    *   https://google.aip.dev/auth/4110#environment-variables
    */
  private def fromEnv[F[_]: Env: Files](implicit
      F: Concurrent[F],
  ): F[Option[CredentialsFile]] = for {
    maybePath <- Env[F].get("GOOGLE_APPLICATION_CREDENTIALS")
    maybeFile <- maybePath.map(Path(_)).flatTraverse(readCredentialsFile(_))
  } yield maybeFile
  private def readCredentialsFile[F[_]: Files](
      path: Path,
  )(implicit F: Concurrent[F]): F[Option[CredentialsFile]] = for {
    exists <- Files[F].exists(path)
    file <-
      if (exists)
        Files[F]
          .readUtf8(path)
          .compile
          .string
          .flatMap(parseToCredentialsFile.andThen(F.fromEither))
          .map(_.some)
      else F.pure(none[CredentialsFile])
  } yield file

  private val parseToCredentialsFile = parser.parse.andThen(_.flatMap(_.as[CredentialsFile]))

}
