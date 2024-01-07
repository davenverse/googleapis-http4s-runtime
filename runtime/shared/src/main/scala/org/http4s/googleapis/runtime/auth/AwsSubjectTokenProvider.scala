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
import cats.effect.Concurrent
import cats.effect.std.Env
import cats.syntax.all._
import fs2.io.IOException
import io.circe.Decoder
import io.circe.Json
import io.circe.Printer
import io.circe.syntax._
import org.http4s.headers.Accept

import java.net.URLEncoder

import circe.jsonOf
import client.Client
private[auth] trait AwsSubjectTokenProvider {
  def retrieveSubjectTokenForAWS[F[_]: Env](
      client: Client[F],
      audience: String,
      maybe_region_uri: Option[Uri],
      maybe_imdsv2_sess_t_url: Option[Uri],
      r_cred_verification_url: Uri,
      maybe_uri: Option[Uri],
  )(implicit F: Concurrent[F]): F[String] = {
    val imdsv2SessHeaders = mkImdsv2SessTokenHeaders(client, maybe_imdsv2_sess_t_url)
    for {
      pair <- F.both(
        lookupAwsRegion(client, maybe_region_uri, imdsv2SessHeaders),
        lookupSecurityCredentials(client, maybe_uri, imdsv2SessHeaders),
      )
      (region, secCreds) = pair
      r_cred_v_url_with_region_substituted <-
        F.fromEither(
          Uri.fromString(
            r_cred_verification_url.renderString.replace("{region}", region),
          ),
        )
      _ = ("x-goog-cloud-target-resource" -> audience)
      // signature <-  signer(r_cred_v_url_with_region_substituted,..).sign
      json = mkSbjTkn(???, r_cred_v_url_with_region_substituted, audience)
      // Generate signed request to AWS STS GetCallerIdentity API.
    } yield URLEncoder.encode(Printer.noSpaces.print(json), "UTF-8")
  }

  // TODO: cache
  /** Create HTTP headers for AWS metadata server if `imdsv2SessTokenURL` is present.
    *
    * > AWS IDMSv2 introduced a requirement for a session token to be present with the requests
    * made to metadata endpoints. This requirement is to help prevent SSRF attacks. Presence of
    * "imdsv2_session_token_url" in Credential Source of config file will trigger a flow with
    * session token, else there will not be a session token with the metadata requests. Both
    * flows work for IDMS v1 and v2. But if IDMSv2 is enabled, then if session token is not
    * present, Unauthorized exception will be thrown.
    *
    * @see
    *   https://github.com/googleapis/google-auth-library-java/blob/ab872812d0f6e9ad7598ba4c4c503d5bff6c2a2b/oauth2_http/java/com/google/auth/oauth2/AwsCredentials.java#L229
    */
  private def mkImdsv2SessTokenHeaders[F[_]: Concurrent](
      client: Client[F],
      imdsv2SessTokenURL: Option[Uri],
  ): F[Headers] = imdsv2SessTokenURL
    .traverse(u =>
      client.expect[String](
        Request[F](method = Method.PUT, uri = u)
          .putHeaders("x-aws-ec2-metadata-token-ttl-seconds" -> "300"),
      ),
    )
    .map(_.fold(Headers.empty)(tkn => Headers("x-aws-ec2-metadata-token" -> tkn)))

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
      mkImdsv2SessTokenHeaders: F[Headers],
  )(implicit F: Concurrent[F]) = EitherT
    .fromOptionM(
      awsRegionFromEnv,
      F.fromOption(
        regionURL,
        new IOException(
          "Unable to determine the AWS region. Neither region_url nor AWS region from environment variable is found.",
        ),
      ).flatMap(fetchAwsRegion(client)(_, mkImdsv2SessTokenHeaders)),
    )
    .merge[String]

  private def awsRegionFromEnv[F[_]: Env: MonadThrow]: F[Option[String]] =
    (OptionT(Env[F].get("AWS_REGION")) <+> OptionT(
      Env[F].get("AWS_DEFAULT_REGION"),
    )).value

  private def fetchAwsRegion[F[_]: Concurrent](
      client: Client[F],
  )(uri: Uri, mkImdsv2SessTokenHeaders: F[Headers]) =
    mkImdsv2SessTokenHeaders.flatMap(headers =>
      client.expect[String](Request[F](uri = uri, headers = headers)).map(_.dropRight(1)),
    )

  /** Check the environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and the optional
    * AWS_SESSION_TOKEN for the AWS security credentials. If found, skip using the AWS metadata
    * server to determine these values.
    *
    * If url is available and the security credentials environment variables are not provided:
    * Call url to retrieve the attached AWS IAM role name to the current instance. Call
    * url/$ROLE_NAME to get the access key, secret key and security token needed to sign the
    * GetCallerIdentity request.
    *
    * @param maybeURL
    *   a url to fetch AwsSecurityCredentials
    * @param imdsv2SessTokenURL
    *   a url to fetch session token
    * @return
    *   (AwsAccessKeyId,AwsSecretAccessKey) with optional AWS_SESSION_TOKEN. These values are
    *   temporary credentials typically last for several hours.
    */
  private def lookupSecurityCredentials[F[_]: Env](
      client: Client[F],
      maybeURL: Option[Uri],
      mkImdsv2SessTokenHeaders: F[Headers],
  )(implicit F: Concurrent[F]): F[((String, String), Option[String])] = EitherT
    .fromOptionM(
      lookupSecurityCredentialsEnvVars,
      F.fromOption(
        maybeURL,
        new IOException(
          "Neither url nor AWS security credential from environment variables is found",
        ),
      ).flatMap(fetchAwsSecurityCredentials(client)(_, mkImdsv2SessTokenHeaders)),
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

  /** fetch AwsSecurityCredentials from metadata server
    *
    * @param uri
    *   a url to fetch AwsSecurityCredentials
    * @param imdsv2SessTokenURL
    *   a url to fetch session token
    *
    * @return
    *   (AwsAccessKeyId,AwsSecretAccessKey) with optional AWS_SESSION_TOKEN.
    */
  private def fetchAwsSecurityCredentials[F[_]](
      client: Client[F],
  )(uri: Uri, imdsv2SessTokenHeaders: F[Headers])(implicit
      F: Concurrent[F],
  ): F[((String, String), Option[String])] =
    for {
      imdsv2SessHeaders <- imdsv2SessTokenHeaders
      // Retrieve the IAM role that is attached to the VM. This is required to retrieve the AWS
      // security credentials.
      awsRoleName <- client.expect[String](Request[F](uri = uri, headers = imdsv2SessHeaders))
      // Retrieve the AWS security credentials by calling the endpoint specified by the credential
      // source.
      awsSecCreds <- client.expect[AwsSecurityCredentials](
        Request[F](
          uri = uri / awsRoleName,
        ).putHeaders(Accept(MediaType.application.json))
          .putHeaders(imdsv2SessHeaders),
      )
    } yield ((awsSecCreds.AccessKeyId, awsSecCreds.SecretAccessKey), None)

  private def mkSbjTkn(
      signature: Signature,
      rCredVUrlWithRegionSubstituted: Uri,
      audience: String,
  ): Json = Json.obj(
    "url" ->
      rCredVUrlWithRegionSubstituted.renderString.asJson,
    "method" -> signature.httpMethod.asJson,
    // The GCP STS endpoint expects the headers to be formatted as:
    // [
    //   {key: 'x-amz-date', value: '...'},
    //   {key: 'Authorization', value: '...'},
    //   ...
    // ]
    "headers" -> Json.fromValues(
      signature.canonicalHeaders.map(header =>
        Json.obj(
          "key" -> header._1.toString.asJson,
          "value" -> header._2.toString.asJson,
        ),
      ) ++ Seq(
        Json.obj(
          "key" -> "x-goog-cloud-target-resource".asJson,
          // The full, canonical resource name of the workload identity pool
          // provider, with or without the HTTPS prefix.
          // Including this header as part of the signature is recommended to
          // ensure data integrity.
          "value" -> audience.asJson,
        ),
        Json.obj(
          "key" -> "Authorization".asJson,
          "value" -> signature.authorizationHeader.asJson,
        ),
      ),
    ),
  )
  // The spec says
  // > For the AWS token, STS requires a special header `x-goog-cloud-endpoint`
  // > to recognize that the token is for a specific workload identity provider.
  // However, both Node.js and Java implementation seem to ignore this spec.
  // suppress warnings for now
  private[auth] def requestOverride[F[_]]: Request[F] => Request[F] =
    _.putHeaders("x-goog-cloud-endpoint" -> "???")

  /** @param signature
    * @param rCredVUrlWithRegionSubstituted
    *   regional credential verification url with region substituted
    * @param audience
    *   The full, canonical resource name of the workload identity pool provider, with or
    *   without the HTTPS prefix.
    *
    * @return
    *   subject token in JSON format
    */
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

private case class Signature(
    canonicalHeaders: Map[String, String],
    authorizationHeader: String,
    audience: String,
    region: String,
    httpMethod: String,
)
