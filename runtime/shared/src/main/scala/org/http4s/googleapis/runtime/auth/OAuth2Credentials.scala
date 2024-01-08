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
import cats.data.OptionT
import cats.effect.Temporal
import cats.syntax.all._
import org.http4s.googleapis.runtime.auth.CredentialsFile.ExternalAccount
import org.http4s.googleapis.runtime.auth.CredentialsFile.ServiceAccount
import org.http4s.googleapis.runtime.auth.CredentialsFile.User

import scala.annotation.nowarn

import client.Client

object Oauth2Credentials {
  val DEFAULT_SCOPES = Seq("https://www.googleapis.com/auth/cloud-platform")

  /** setup GoogleCredentials from configuration file.
    *
    * @param credentialsFile
    *   Google credential file for authentication
    * @param scopesOverride
    *   optional OAuth2 scopes override. Default is `DEFAULT_SCOPES`.
    * @param quotaProjectOverride
    *   Quota project id from environment variables. According to
    *   https://google.aip.dev/auth/4110#environment-variables, the value from the environment
    *   variable will override any quota project that is present in the credential detected by
    *   the ADC mechanism.
    *
    * @see
    *   https://google.aip.dev/auth/4110#expected-behavior block 2(Load credentials), block 4(
    *   Determine auth flows) and block 5(Execute auth flows)
    */
  @nowarn
  def apply[F[_]](
      client: Client[F],
      credentialsFile: CredentialsFile,
      scopesOverride: Option[Seq[String]] = None,
      quotaProjectOverride: Option[String] = None,
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = {
    val _ = scopesOverride.getOrElse(DEFAULT_SCOPES)

    credentialsFile match {
      case _: User =>
        // user identity flow to exchange for an access token
        F.raiseError(
          new NotImplementedError("User credentials auth is not implemented"),
        )
      case _: ServiceAccount =>
        // self-signed JWT flow for an access token
        // https://google.aip.dev/auth/4111
        F.raiseError(
          new NotImplementedError("ServiceAccount credentials auth is not implemented"),
        )
      case _: ExternalAccount =>
        // external account flow to exchange for an access token
        // https://google.aip.dev/auth/4117
        F.raiseError(
          new NotImplementedError("ExternalAccount credentials auth is not implemented"),
        )
    }
  }

  @nowarn
  private def apply[F[_]](pid: String, refresh: F[AccessToken])(implicit
      F: Temporal[F],
  ): F[GoogleCredentials[F]] =
    for {
      cache <- F.ref(Option.empty[F[AccessToken]])
    } yield new GoogleCredentials[F] {
      val projectId = pid

      def get: F[AccessToken] = OptionT(cache.get)
        .semiflatMap(identity)
        .flatMapF { token =>
          for {
            expired <- token.expiresSoon()
          } yield Option.unless(expired)(token)
        }
        .getOrElseF {
          for {
            memo <- F.memoize(refresh)
            updated <- cache.tryUpdate(_ => Some(memo))
            token <-
              if (updated) memo
              else get

          } yield token
        }
    }
}
