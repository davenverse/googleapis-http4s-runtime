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

import client.Client
import CredentialsFile.ExternalAccount.ExternalCredentialSource
import fs2.io.file.Files
import fs2.io.file.Path
import fs2.io.IOException

object IdentityPoolCredentials extends ExternalAccountSubjectTokenProvider {

  /** Create Google credentials from local file. The main use-case of this credentials is
    * Workload Identity Federation. This function may fail when no file is found at file source.
    */
  private[auth] def fromFile[F[_]: Files](
      client: Client[F],
      projectId: String,
      impersonationURL: Option[Uri],
      fileSource: ExternalCredentialSource.File,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = (fileSource, impersonationURL) match {
    case (file, Some(url)) =>
      withImpersonation(client, projectId, url, file, externalAccount, scopes)
    case (file, None) => withoutImpersonation(client, projectId, file, externalAccount, scopes)
  }

  /** Create Google credentials from remote source. The main use-case of this credentials is
    * Workload Identity Federation.
    */
  private[auth] def fromURL[F[_]](
      client: Client[F],
      projectId: String,
      impersonationURL: Option[Uri],
      urlSource: ExternalCredentialSource.Url,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = (urlSource, impersonationURL) match {
    case (u, Some(url)) => withImpersonation(client, projectId, url, u, externalAccount, scopes)
    case (u, None) => withoutImpersonation(client, projectId, u, externalAccount, scopes)
  }

  private def withoutImpersonation[F[_]: Files](
      client: Client[F],
      pid: String,
      fileSource: ExternalCredentialSource.File,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = fileSource match {
    case ExternalCredentialSource.File(file, format) =>
      F.ifM(Files[F].exists(Path(file)))(
        F.unit,
        F.raiseError(new IOException(s"$file not found")),
      ).flatMap(_ =>
        withoutImpersonation(
          client,
          pid,
          subjectTokenFromFile(file, format),
          externalAccount,
          scopes,
        ),
      )
  }
  private def withoutImpersonation[F[_]](
      client: Client[F],
      pid: String,
      urlSource: ExternalCredentialSource.Url,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = urlSource match {
    case ExternalCredentialSource.Url(url, headers, format) =>
      F.fromEither(Uri.fromString(url))
        .flatMap(url =>
          withoutImpersonation(
            client,
            pid,
            subjectTokenFromUrl(client, url, headers, format),
            externalAccount,
            scopes,
          ),
        )
  }

  /** The shared routine to fetch external credentials without service account impersonation.
    *
    * @param id
    *   GCP project id
    * @param retrieveSubjectToken
    *   abstract platform specific actions to retrieve subject token for token exchange
    * @param externalAccount
    *   configuration for external account credentials generation
    * @param scopes
    *   scopes for authorization
    *
    * @return
    *   a sts token for authorization skipping impersonation flow
    */
  private def withoutImpersonation[F[_]](
      client: Client[F],
      pid: String,
      retrieveSubjectToken: F[String],
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = for {
    // TODO: implement cache logic
    _ <- F.ref(Option.empty[AccessToken])
  } yield new GoogleCredentials[F] {
    def projectId: String = pid
    def get: F[AccessToken] = for {
      sbjTkn <- retrieveSubjectToken
      tkn <- GoogleOAuth2TokenExchange[F](client)
        .stsToken(sbjTkn, externalAccount, scopes)
      // If impersonation url is not available, end the flow and just use the STS access token for authorization.
    } yield tkn
  }

  private def withImpersonation[F[_]: Files](
      client: Client[F],
      id: String,
      impersonationURL: Uri,
      fileSource: ExternalCredentialSource.File,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = fileSource match {
    case ExternalCredentialSource.File(file, format) =>
      F.ifM(Files[F].exists(Path(file)))(
        F.unit,
        F.raiseError(new IOException(s"$file not found")),
      ).flatMap(_ =>
        withImpersonation(
          client,
          id,
          impersonationURL,
          subjectTokenFromFile(file, format),
          externalAccount,
          scopes,
        ),
      )
  }
  private def withImpersonation[F[_]](
      client: Client[F],
      id: String,
      impersonationURL: Uri,
      urlSource: ExternalCredentialSource.Url,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] = urlSource match {
    case ExternalCredentialSource.Url(tknURL, headers, format) =>
      F.fromEither(Uri.fromString(tknURL))
        .flatMap(tknURL =>
          withImpersonation(
            client,
            id,
            impersonationURL,
            subjectTokenFromUrl(client, tknURL, headers, format),
            externalAccount,
            scopes,
          ),
        )
  }

  /** The shared routine to fetch external credentials with service account impersonation
    *
    * @param id
    *   GCP project id
    * @param retrieveSubjectToken
    *   abstract platform specific actions to retrieve subject token for token exchange
    * @param externalAccount
    *   configuration for external account credentials generation
    * @param scopes
    *   scopes for authorization
    * @return
    *   authorization token with impersonation
    */
  private def withImpersonation[F[_]](
      client: Client[F],
      id: String,
      impersonationURL: Uri,
      retrieveSubjectToken: F[String],
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] =
    ImpersonatedCredentials(
      client,
      id,
      impersonationURL,
      retrieveSubjectToken,
      externalAccount,
      scopes,
    )
}
