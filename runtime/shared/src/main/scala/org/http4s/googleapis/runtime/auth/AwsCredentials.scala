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
import cats.MonadThrow
import cats.data.Validated.Invalid
import cats.data.Validated.Valid
import cats.effect.Temporal
import cats.effect.std.Env
import cats.syntax.all._
import CredentialsFile.ExternalAccount.ExternalCredentialSource
import client.Client
object AwsCredentials extends AwsSubjectTokenProvider {

  /** @param id
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
  def apply[F[_]: Env](
      client: Client[F],
      id: String,
      impersonationURL: Uri,
      aws: ExternalCredentialSource.Aws,
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] =
    for {
      urls <- validateSource(aws)
      (r_cred_verification_url, maybe_url, maybe_region_url, maybe_imdsv2_sess_t_url) = urls
      credentials <- ImpersonatedCredentials(
        client,
        id,
        impersonationURL,
        retrieveSubjectTokenForAWS(
          client,
          externalAccount.audience,
          maybe_imdsv2_sess_t_url,
          maybe_region_url,
          r_cred_verification_url,
          maybe_url,
        ),
        externalAccount,
        scopes,
      )
    } yield credentials

  /** Validate the host for the url, regional_url and imdsv2_session_token_url fields if they
    * are provided. The host should either be 169.254.169.254 or fd00:ec2::254.
    */
  private def validateSource[F[_]](
      aws: ExternalCredentialSource.Aws,
  )(implicit F: MonadThrow[F]) = {
    def pureFrom3[S, T, U](s: T, t: T, u: U) = F.pure((s, t, u))
    val parseURLToVNec = Uri.fromString.andThen(_.toValidatedNec)
    val validUrlsIfExist = (
      aws.url.traverse(parseURLToVNec),
      aws.region_url.traverse(parseURLToVNec),
      aws.imdsv2_session_token_url.traverse(parseURLToVNec),
    ).traverseN(pureFrom3)
    for {
      regional_cred_verification_url <- F.fromEither(
        Uri.fromString(aws.regional_cred_verification_url),
      )
      validUrlsIfExist <- validUrlsIfExist
      urls <- validUrlsIfExist match {
        case Invalid(errors) =>
          F.raiseError(
            new IllegalArgumentException(
              errors.map(_.message).mkString_("\n"),
            ),
          )
        case Valid((maybe_sec_creds_url, maybe_region_url, maybe_imdsv2_sess_t_url)) =>
          F.pure((maybe_sec_creds_url, maybe_region_url, maybe_imdsv2_sess_t_url))
      }
    } yield (
      regional_cred_verification_url,
      urls._1, // maybe_sec_creds_url
      urls._2, // maybe_region_url
      urls._3, // maybe_imdsv2_sess_t_url
    )
  }
}
