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
import cats.data.EitherT
import cats.data.OptionT
import cats.data.Validated.Invalid
import cats.data.Validated.Valid
import cats.effect.Concurrent
import cats.effect.Temporal
import cats.effect.std.Env
import cats.syntax.all._
import fs2.io.IOException
import io.circe.Decoder
import org.http4s.headers.Accept

import circe.jsonOf
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

      region = lookupAwsRegion(client, maybe_region_url)
      secCredsSource = lookupSecurityCredentials(client)(maybe_url)
      signingProps <- F.both(region, secCredsSource)
      (region, ((kid, secAccessKey), sessTkn)) = signingProps
      credentials <- ImpersonatedCredentials(
        client,
        id,
        impersonationURL,
        retrieveSubjectTokenForAWS(client, externalAccount.audience, r_cred_verification_url),
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

  /** Check the environment variables in the following order (AWS_REGION and then the
    * AWS_DEFAULT_REGION) to determine the AWS region.
    *
    * If found, skip using the AWS metadata server to determine this value.
    *
    * If the region environment variables are not provided, use the region_url to determine the
    * current AWS region. The API returns the zone name, e.g. us-east-1d. The region should be
    * determined by stripping the last character, e.g. us-east-1.
    * @return
    *   aws region
    */
  private def lookupAwsRegion[F[_]: Env](
      client: Client[F],
      regionURL: Option[Uri],
  )(implicit F: Concurrent[F]) = EitherT
    .fromOptionM(
      awsRegionFromEnv,
      F.fromOption(
        regionURL,
        new IOException("Neither region_url nor AWS region from environment variable is found."),
      ).flatMap(fetchAwsRegion(client)),
    )
    .merge[String]

  private def awsRegionFromEnv[F[_]: Env: MonadThrow]: F[Option[String]] =
    (OptionT(Env[F].get("AWS_REGION")) <+> OptionT(
      Env[F].get("AWS_DEFAULT_REGION"),
    )).value

  private def fetchAwsRegion[F[_]: Concurrent](client: Client[F])(uri: Uri) =
    client.expect[String](uri).map(_.dropRight(1))

  /** Check the environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and the optional
    * AWS_SESSION_TOKEN for the AWS security credentials. If found, skip using the AWS metadata
    * server to determine these values.
    *
    * If url is available and the security credentials environment variables are not provided:
    * Call url to retrieve the attached AWS IAM role name to the current instance. Call
    * url/$ROLE_NAME to get the access key, secret key and security token needed to sign the
    * GetCallerIdentity request.
    *
    * @return
    *   (AwsAccessKeyId,AwsSecretAccessKey) with optional AWS_SESSION_TOKEN. These values are
    *   temporary credentials typically last for several hours.
    */
  private def lookupSecurityCredentials[F[_]: Env](client: Client[F])(
      maybeURL: Option[Uri],
  )(implicit F: Concurrent[F]): F[((String, String), Option[String])] = EitherT
    .fromOptionM(
      lookupSecurityCredentialsEnvVars,
      F.fromOption(
        maybeURL,
        new IOException(
          "Neither url nor AWS security credential from environment variables is found",
        ),
      ).flatMap(fetchAwsSecurityCredentials(client)),
    )
    .merge

  /** @return
    *   (AwsAccessKeyId,AwsSecretAccessKey) with optional AWS_SESSION_TOKEN.
    */
  private def lookupSecurityCredentialsEnvVars[F[_]: Env](implicit
      F: MonadThrow[F],
  ): F[Option[((String, String), Option[String])]] = {
    val required = OptionT(Env[F].get("AWS_ACCESS_KEY_ID"))
      .product(OptionT(Env[F].get("AWS_SECRET_ACCESS_KEY")))
    val optional = OptionT.liftF(Env[F].get("AWS_SESSION_TOKEN"))
    required.product(optional).value
  }

  /** @return
    *   (AwsAccessKeyId,AwsSecretAccessKey) with optional AWS_SESSION_TOKEN.
    */
  private def fetchAwsSecurityCredentials[F[_]: Concurrent](
      client: Client[F],
  )(uri: Uri): F[((String, String), Option[String])] =
    for {
      awsRoleName <- client.expect[String](uri)
      awsSecCreds <- client.expect[AwsSecurityCredentials](
        Request[F](
          uri = uri / awsRoleName,
        ).putHeaders(Accept(MediaType.application.json)),
      )
    } yield ((awsSecCreds.AccessKeyId, awsSecCreds.SecretAccessKey), None)
}

/** Interface defining the AWS security-credentials endpoint response.
  */
private case class AwsSecurityCredentials(
    Code: String,
    LastUpdated: String,
    Type: String,
    AccessKeyId: String,
    SecretAccessKey: String,
    Token: String,
    Expiration: String,
)
private object AwsSecurityCredentials {
  implicit def ev2[F[_]: Concurrent]: EntityDecoder[F, AwsSecurityCredentials] = jsonOf
  implicit val ev: Decoder[AwsSecurityCredentials] = Decoder.forProduct7(
    "Code",
    "LastUpdated",
    "Type",
    "AccessKeyId",
    "SecretAccessKey",
    "Token",
    "Expiration",
  )(AwsSecurityCredentials(_, _, _, _, _, _, _))
}
