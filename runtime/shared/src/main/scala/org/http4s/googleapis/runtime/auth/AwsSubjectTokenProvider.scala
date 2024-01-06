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
import io.circe.Json
import io.circe.syntax._
import io.circe.Printer
import io.circe.Decoder
import cats.Applicative
private[auth] trait AwsSubjectTokenProvider {

  // The spec says
  // > For the AWS token, STS requires a special header `x-goog-cloud-endpoint`
  // > to recognize that the token is for a specific workload identity provider.
  // However, both Node.js and Java implementation seem to ignore this spec.
  // suppress warnings for now
  private[auth] def requestOverride[F[_]]: Request[F] => Request[F] =
    _.putHeaders("x-goog-cloud-endpoint" -> "???")

  /** @param headers
    *   request option headers from AWS STS GetCallerIdentity API
    * @param audience
    *   The full, canonical resource name of the workload identity pool provider, with or
    *   without the HTTPS prefix.
    *
    * @return
    *   subject token in JSON format
    */
  private def mkSbjTkn(headers: Map[String, String], audience: String): Json = Json.obj(
    "url" -> headers("url").asJson,
    "method" -> headers("method").asJson,
    // The GCP STS endpoint expects the headers to be formatted as:
    // [
    //   {key: 'x-amz-date', value: '...'},
    //   {key: 'Authorization', value: '...'},
    //   ...
    // ]
    "headers" -> Json.fromValues(
      headers.map(header =>
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
      ),
    ),
  )
  private[auth] def retrieveSubjectTokenForAWS[F[_]](
      audience: String,
      r_cred_verification_url: Uri,
  )(implicit F: Applicative[F]): F[String] = {
    // memonize AwsRequestSigner
    // getAwsRoleName
    // getAwsSecurityCredentials
    // Generate signed request to AWS STS GetCallerIdentity API.
    val json = mkSbjTkn(???, audience)
    // encodeURIComponent and then
    F.pure(
      Printer.noSpaces.print(json),
    )
  }
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
