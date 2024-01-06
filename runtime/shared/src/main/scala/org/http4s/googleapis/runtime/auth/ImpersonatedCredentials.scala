package org.http4s
package googleapis.runtime.auth
import cats.effect.Concurrent
import cats.effect.Temporal
import cats.syntax.all._
import io.circe.Decoder
import io.circe.Json
import io.circe.JsonObject
import io.circe.generic.semiauto.deriveDecoder
import org.http4s.circe.jsonEncoderOf
import org.http4s.circe.jsonOf

import client.Client
import headers.Authorization

object ImpersonatedCredentials {
  private final val PLATFORM_SCOPES = Seq("https://www.googleapis.com/auth/cloud-platform")
  // private final val IAM_SCOPES = Seq("https://www.googleapis.com/auth/iam")
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
  def apply[F[_]](
      client: Client[F],
      id: String,
      impersonationURL: Uri,
      retrieveSubjectToken: F[String],
      externalAccount: CredentialsFile.ExternalAccount,
      scopes: Seq[String],
  )(implicit F: Temporal[F]): F[GoogleCredentials[F]] =
    for {
      // TODO: implement cache logic
      _ <- F.ref(Option.empty[AccessToken])
    } yield new GoogleCredentials[F] {
      def projectId: String = id
      def get: F[AccessToken] =
        for {
          sbjTkn <- retrieveSubjectToken
          // > If service account impersonation is used, the cloud platform or IAM scope should be passed to STS
          stsTkn <- GoogleOAuth2TokenExchange[F](client).stsToken(
            sbjTkn,
            externalAccount,
            PLATFORM_SCOPES,
          )
          // TODO: use service_account_impersonation.token_lifetime_seconds to set token cache life cycle

          // > and then customer provided scopes should be passed in the IamCredentials call
          req = Request[F]()
            .withMethod(Method.POST)
            .withHeaders(Authorization(stsTkn.headerValue))
            .withUri(impersonationURL)
            .withEntity(
              JsonObject(
                "scopes" -> Json
                  .fromString(scopes.mkString(",")),
              ), // If there's service_account_impersonation.token_lifetime_seconds, it needs to be passed here.
            )(jsonEncoderOf[F, JsonObject])
          iamTkn <- client.expect[IamCredentialsTokenResponse](req)
        } yield stsTkn.withToken(iamTkn.accessToken)
    }
}

/** @param accessToken
  *   access token
  * @param expireTime
  *   DateTime string in utc
  */
private case class IamCredentialsTokenResponse(
    accessToken: String, // SecretValue,
    expireTime: String,
)

private object IamCredentialsTokenResponse {
  implicit def ed[F[_]: Concurrent]: EntityDecoder[F, IamCredentialsTokenResponse] =
    jsonOf[F, IamCredentialsTokenResponse]
  implicit val ev: Decoder[IamCredentialsTokenResponse] = deriveDecoder
}
