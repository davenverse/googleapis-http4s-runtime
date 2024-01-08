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

import client.Client
import syntax.all._

private[auth] trait GoogleOAuth2RefreshToken[F[_]] {

  /** calls Google authorization backend with the refresh token, client ID and client secret in
    * the gcloud default credentials
    *
    * @param clientId
    *   in the gcloud default credentials
    * @param clientSecret
    *   the gcloud default credentials
    * @param refreshToken
    *   in the gcloud default credentials
    */
  def getAccessToken(
      clientId: String,
      clientSecret: String,
      refreshToken: String,
      scopes: Seq[String],
  ): F[AccessToken]
}

private[auth] object GoogleOAuth2RefreshToken {
  def apply[F[_]: Temporal](client: Client[F]): GoogleOAuth2RefreshToken[F] = {
    val TOKEN_URL = uri"https://oauth2.googleapis.com/token"
    val GRANT_TYPE = "refresh_token"
    new GoogleOAuth2RefreshToken[F] {
      def getAccessToken(
          clientId: String,
          clientSecret: String,
          refreshToken: String,
          scopes: Seq[String],
      ): F[AccessToken] =
        client.expect[AccessToken](
          Request[F](uri = TOKEN_URL).withEntity(
            UrlForm(
              "client_id" -> clientId,
              "client_secret" -> clientSecret,
              "grant_type" -> GRANT_TYPE,
              // The refresh token is not included in the response from google's server,
              // so it always uses the specified refresh token from the file.
              "refresh_token" -> refreshToken,
            ),
          ),
        )
    }
  }
}
