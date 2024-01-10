package org.http4s
package googleapis.runtime.auth

import cats.effect.Temporal
import cats.effect.std.Env
import cats.syntax.all._
import org.http4s.googleapis.runtime.ComputeMetadata

import client.Client

object ComputeEngineCredentials {
  def apply[F[_]: Env](client: Client[F], scopes: Set[String])(implicit
      F: Temporal[F],
  ): F[GoogleCredentials[F]] =
    for {
      met <- ComputeMetadata(client, scopes)
      pid <- met.getProjectId
      credentials <- Oauth2Credentials(Some(pid), met.getAccessToken)
    } yield credentials
}
