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
import cats.effect.Temporal
import cats.syntax.all._
import fs2.io.IOException
import fs2.io.file.Files
import org.http4s.googleapis.runtime.auth.CredentialsFile.ExternalAccount.ExternalCredentialSource

import client.Client

/** External account credentials(A.K.A Workload Identity Federation) implementation to access
  * Google cloud resources from non-Google cloud platforms.
  *
  * @see
  *   https://google.aip.dev/auth/4117
  */
object ExternalAccountCredentials {

  /** Create Google credentials for external account. Internally, ExternalAccountCredentials has
    * the following variants
    *
    *   - IdentityPoolCredentials with and without service account impersonation from file or
    *     url source
    *   - AwsCredentials with service account impersonation
    *   - Plug-ableAuthCredentials
    *
    * @param externalAccount
    *   credentials file to create ExternalAccountCredentials
    * @param scopes
    */
  def apply[F[_]: Files](
      client: Client[F],
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = {
    val pid: F[String] = externalAccount.quota_project_id match {
      case Some(id) => F.pure(id)
      case None =>
        F.pure(
          "quota project id for external account is nullable." +
            "Perhaps, we need change GoogleCredentials#id signature.",
        )
    }

    for {
      id <- pid
      impersonationURL <- externalAccount.service_account_impersonation_url.traverse(
        Uri.fromString.andThen(F.fromEither),
      )
      // > check `credentials_source` to determine the necessary logic to retrieve the external credential
      credentials <-
        (externalAccount.credential_source, impersonationURL) match {
          case (_: ExternalCredentialSource.Aws, None) =>
            F.raiseError(
              new IOException("AWS credentials need service_account_impersonation_url"),
            )
          case (f: ExternalCredentialSource.File, impersonationURL) =>
            IdentityPoolCredentials.fromFile(
              client,
              id,
              impersonationURL,
              f,
              externalAccount,
              scopes,
            )
          case (u: ExternalCredentialSource.Url, impersonationURL) =>
            IdentityPoolCredentials.fromURL(
              client,
              id,
              impersonationURL,
              u,
              externalAccount,
              scopes,
            )
          case (_: ExternalCredentialSource.Aws, Some(_)) =>
            F.raiseError(new NotImplementedError("AwsCredentials is not implemented yet."))
        }
    } yield credentials
  }
}
