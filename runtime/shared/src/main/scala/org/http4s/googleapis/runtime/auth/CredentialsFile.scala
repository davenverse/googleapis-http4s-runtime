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
import cats.syntax.all._
import io.circe.Decoder
import io.circe.generic.semiauto.deriveDecoder

/** [[CredentialsFile]] represents Google application credentials file variants.
  *
  * CredentialsFile is one of the following;
  *
  *   - [[CredentialsFile.ServiceAccount]]: service account credentials file containing
  *     __sensitive__ private key associated with a service account
  *   - [[CredentialsFile.User]]: This file contains __sensitive__ oauth2 client secret and
  *     refresh_token.
  *   - [[CredentialsFile.ExternalAccount]]: This file contains only non-sensitive information.
  *     This file is mainly for workload identity federation.
  */
sealed trait CredentialsFile extends Product with Serializable {
  def getQuotaProjectId: Option[String] = this match {
    case sa: CredentialsFile.ServiceAccount => sa.quota_project_id
    case u: CredentialsFile.User => u.quota_project_id
    case ea: CredentialsFile.ExternalAccount => ea.quota_project_id
  }
}

object CredentialsFile {
  final implicit val ev: Decoder[CredentialsFile] =
    deriveDecoder[ServiceAccount].widen[CredentialsFile] <+> deriveDecoder[User]
      .widen[CredentialsFile] <+> deriveDecoder[ExternalAccount].widen[CredentialsFile]
    /** service account credentials file containing __sensitive__ private key.
      */
  final case class ServiceAccount(
      project_id: String,
      client_email: String,
      private val private_key_id: String,
      private[auth] val private_key: String, // SecretValue,
      private val token_url: String,
      // #[serde(skip)]
      scopes: Seq[String],
      quota_project_id: Option[String],
  ) extends CredentialsFile

  /** This file contains __sensitive__ oauth2 client secret and refresh token
    */
  final case class User(
      private val client_secret: String, // SecretValue,
      client_id: String,
      private val refresh_token: String, // SecretValue,
      quota_project_id: Option[String],
  ) extends CredentialsFile

  /** @param credential_source
    *   This determines the source to obtain subject token. The value is either Url or File to
    *   get subject token from.
    */
  final case class ExternalAccount(
      audience: String,
      subject_token_type: String,
      token_url: String,
      service_account_impersonation_url: Option[String],
      service_account_impersonation: Option[ServiceAccountImpersonationSettings],
      quota_project_id: Option[String],
      credential_source: ExternalAccount.ExternalCredentialSource,
      // #[serde(skip)]
      scopes: Seq[String],
  ) extends CredentialsFile

  object ExternalAccount {
    sealed trait ExternalCredentialSource
    // #[serde(untagged)]
    object ExternalCredentialSource {
      implicit val ev: Decoder[ExternalCredentialSource] =
        deriveDecoder[Url]
          .widen[ExternalCredentialSource] <+> deriveDecoder[File]
          .widen[ExternalCredentialSource]
      case class Url(
          url: String,
          headers: Option[Map[String, String /*SecretValue*/ ]],
          format: Option[ExternalCredentialUrlFormat],
      ) extends ExternalCredentialSource
      case class File(
          file: String,
          format: Option[ExternalCredentialUrlFormat],
      ) extends ExternalCredentialSource
      // AWS external source implementation example https://github.com/googleapis/google-auth-library-nodejs/blob/4bbd13fbf9081e004209d0ffc336648cff0c529e/src/auth/awsclient.ts
    }

    /** Internally tagged union of the following two variants;
      *
      *   - `{"type": "json", "subject_token_field_name": "<string>"}`
      *   - `{"type": "text"}`
      */
    sealed trait ExternalCredentialUrlFormat
    object ExternalCredentialUrlFormat {
      implicit val ev: Decoder[ExternalCredentialUrlFormat] =
        Decoder
          .withReattempt(cursor =>
            cursor.downField("type").as[String] match {
              case Right("json") =>
                cursor.downField("subject_token_field_name").as[String].map(Json(_))
              case Right("text") => Right(Text)
              case Right(value) =>
                Left(
                  io.circe.DecodingFailure(
                    s"Unexpected descriminator value `type`=$value for ExternalCredentialUrlFormat",
                    cursor.history,
                  ),
                )
              case Left(e) => Left(e)
            },
          )
          .widen[ExternalCredentialUrlFormat]

      /** This variant indicates token value is JSON format.
        * @param subject_token_field_name
        *   This value is used to lookup token value from JSON object in token RPC response
        */
      case class Json(subject_token_field_name: String) extends ExternalCredentialUrlFormat

      /** This variant indicates token value is plain-text format.
        */
      case object Text extends ExternalCredentialUrlFormat
    }
  }
  case class ServiceAccountImpersonationSettings(token_lifetime_seconds: Option[Long /*u64*/ ])
  object ServiceAccountImpersonationSettings {
    implicit val ev: Decoder[ServiceAccountImpersonationSettings] = deriveDecoder
  }
}
