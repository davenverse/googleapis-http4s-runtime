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

import cats.effect.Concurrent
import cats.effect.Temporal
import cats.syntax.all._
import fs2.io.file.Files
import fs2.io.file.Path
import io.circe.Decoder
import io.circe.Json
import io.circe.JsonObject
import io.circe.generic.semiauto.deriveDecoder
import io.circe.parser
import org.http4s.circe.jsonEncoderOf
import org.http4s.circe.jsonOf
import org.http4s.headers.Authorization

import CredentialsFile.ExternalAccount.ExternalCredentialSource._
import CredentialsFile.ExternalAccount.ExternalCredentialUrlFormat
import CredentialsFile.ExternalAccount.ExternalCredentialUrlFormat.{Json => JsonFmt}
import CredentialsFile.ExternalAccount.ExternalCredentialUrlFormat.Text
import client.Client
trait GoogleOAuth2TokenExchange[F[_]] {
  def subjectToken(externalAccount: CredentialsFile.ExternalAccount): F[String]
  def stsToken(
      sbjToken: String,
      externalAccount: CredentialsFile.ExternalAccount,
  ): F[AccessToken]
}

object GoogleOAuth2TokenExchange {
  def apply[F[_]: Files: Temporal](client: Client[F]) =
    new GoogleOAuth2TokenExchange[F] {
      private val je: EntityEncoder[F, JsonObject] = jsonEncoderOf[F, JsonObject]
      def subjectToken(externalAccount: CredentialsFile.ExternalAccount): F[String] =
        externalAccount.credential_source match {
          case Url(url, headers, format) => subjectTokenFromUrl(client, url, headers, format)
          case File(file, format) => subjectTokenFromFile(file, format)
        }
      def stsToken(
          sbjToken: String,
          externalAccount: CredentialsFile.ExternalAccount,
      ): F[AccessToken] = {
        val scopes =
          externalAccount.service_account_impersonation_url.fold(externalAccount.scopes)(_ =>
            Seq("https://www.googleapis.com/auth/cloud-platform"),
          )
        val req = Request[F](uri = Uri.unsafeFromString(externalAccount.token_url))
          .withEntity(
            JsonObject(
              "grant_type" -> Json.fromString(
                "urn:ietf:params:oauth:grant-type:token-exchange",
              ),
              "audience" -> Json.fromString(externalAccount.audience),
              "requested_token_type" -> Json.fromString(
                "urn:ietf:params:oauth:token-type:access_token",
              ),
              "subject_token_type" -> Json.fromString(externalAccount.subject_token_type),
              "subject_token" -> Json.fromString(sbjToken),
              "scope" -> Json.fromString(scopes.mkString(" ")),
            ),
          )(je)
        val stsTkn = client.expect[AccessToken](req)

        externalAccount.service_account_impersonation_url match {
          case None => stsTkn
          case Some(url) =>
            val req = Request[F]()
              .withUri(Uri.unsafeFromString(url))
              .withMethod(Method.POST)
              .withEntity(
                JsonObject(
                  "scopes" -> Json.fromString(externalAccount.scopes.mkString(",")),
                ),
              )(je)
            val bearer = (tkn: AccessToken) => Credentials.Token(AuthScheme.Bearer, tkn.token)
            for {
              tkn <- stsTkn
              iamTkn <- client.expect[IamCredentialsTokenResponse](
                req.withHeaders(Authorization(bearer(tkn))),
              )

            } yield tkn.withToken(iamTkn.accessToken)
        }
      }
    }
  private def subjectTokenFromUrl[F[_]](
      client: Client[F],
      url: String,
      headers: Option[Map[String, String]],
      format: Option[ExternalCredentialUrlFormat],
  )(implicit F: Concurrent[F]) = {
    val headerList = headers.getOrElse(Map.empty).toList
    val hs = Headers(headerList)
    val uri = Uri.unsafeFromString(url)
    val req = Request[F](uri = uri).putHeaders(hs)
    format match {
      case None | Some(Text) => client.expect[String](req)
      case Some(JsonFmt(subjectTokenFieldName)) =>
        val dec = Decoder.forProduct1[String, String](subjectTokenFieldName)(identity)
        client.expect[String](req)(jsonOf(F, dec))
    }
  }
  private def subjectTokenFromFile[F[_]: Files](
      file: String,
      format: Option[ExternalCredentialUrlFormat],
  )(implicit F: Concurrent[F]) = for {
    tokenOrJson <- Files[F].readUtf8(Path(file)).compile.string
    tkn <- format match {
      case None | Some(Text) => F.pure(tokenOrJson)
      case Some(JsonFmt(subjectTokenFieldName)) =>
        val dec = Decoder.forProduct1[String, String](subjectTokenFieldName)(identity)
        F.fromEither(parser.parse(tokenOrJson).flatMap(dec.decodeJson(_)))
    }
  } yield tkn
}

/** @param accessToken
  *   access token
  * @param expireTime
  *   DateTime string in utc
  */
private[auth] case class IamCredentialsTokenResponse(
    accessToken: String, // SecretValue,
    expireTime: String,
)

object IamCredentialsTokenResponse {
  implicit def ed[F[_]: Concurrent]: EntityDecoder[F, IamCredentialsTokenResponse] =
    jsonOf[F, IamCredentialsTokenResponse]
  implicit val ev: Decoder[IamCredentialsTokenResponse] = deriveDecoder
}
