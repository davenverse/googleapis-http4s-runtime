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
import io.circe.Json
import io.circe.JsonObject
import org.http4s.circe.jsonEncoderOf

import googleapis.runtime.auth.CredentialsFile.ExternalAccount
import client.Client
trait GoogleOAuth2TokenExchange[F[_]] {

  /** Exchanges the external credential for a Google Cloud access token.
    * @param subjectToken
    *   retrieved external credentials
    * @param scopes
    *   a list of OAuth scopes that specify the desired scopes of the requested security token
    *   in the context of the service or resource where the token should be used. If service
    *   account impersonation is used, the cloud platform or IAM scope should be passed.
    * @param requestOverride
    *   A hack to support Secure Token Service that requires dedicated handling. For example,
    *   AWS STS requires `x-goog-cloud-endpoint` header.
    * @return
    *   the access token returned by the Security Token Service
    */
  def stsToken(
      subjectToken: String,
      externalAccount: ExternalAccount,
      scopes: Seq[String],
      requestOverride: Request[F] => Request[F] = identity,
  ): F[AccessToken]
}

object GoogleOAuth2TokenExchange {
  def apply[F[_]: Temporal](client: Client[F]) =
    new GoogleOAuth2TokenExchange[F] {
      private val je: EntityEncoder[F, JsonObject] = jsonEncoderOf[F, JsonObject]
      def stsToken(
          subjectToken: String,
          externalAccount: ExternalAccount,
          scopes: Seq[String],
          requestOverride: Request[F] => Request[F] = identity,
      ): F[AccessToken] = {
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
              "subject_token" -> Json.fromString(subjectToken),
              "scope" -> Json.fromString(scopes.mkString(" ")),
            ),
          )(je)
        client.expect[AccessToken](requestOverride(req))
      }
    }
}
