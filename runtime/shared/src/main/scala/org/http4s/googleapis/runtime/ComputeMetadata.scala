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
package googleapis.runtime

import cats.effect.kernel.Temporal
import org.http4s.client.Client
import org.http4s.googleapis.runtime.auth.AccessToken
import org.http4s.syntax.all._
import org.typelevel.ci._

trait ComputeMetadata[F[_]] {
  def getProjectId: F[String]
  def getZone: F[String]
  def getInstanceId: F[String]
  def getClusterName: F[String]
  def getContainerName: F[String]
  def getNamespaceId: F[String]
  def getAccessToken: F[AccessToken]
}

object ComputeMetadata {
  def apply[F[_]: Temporal](client: Client[F]): ComputeMetadata[F] =
    new ComputeMetadata[F] {
      val headers = Headers(Header.Raw(ci"Metadata-Flavor", "Google"))
      val baseUri: Uri = uri"http://metadata.google.internal/computeMetadata/v1"
      def mkRequest(path: String) = Request[F](uri = baseUri / path, headers = headers)

      def get(path: String) = client.expect[String](mkRequest(path))

      val getProjectId = get("project/project-id")
      val getZone = get("instance/zone")
      val getInstanceId = get("instance/id")
      val getClusterName = get("instance/attributes/cluster-name")
      val getContainerName = get("instance/attributes/container-name")
      val getNamespaceId = get("instance/attributes/namespace-id")
      val getAccessToken = client.expect("instance/service-accounts/default/token")
    }
}
Metadata/v1"
      def mkRequest(path: String) = Request[F](uri = baseUri / path, headers = headers)

      def get(path: String) = client.expect[String](mkRequest(path))

      val getProjectId = get("project/project-id")
      val getZone = get("instance/zone")
      val getInstanceId = get("instance/id")
      val getClusterName = get("instance/attributes/cluster-name")
      val getContainerName = get("instance/attributes/container-name")
      val getNamespaceId = get("instance/attributes/namespace-id")
      val getAccessToken = client.expect("instance/service-accounts/default/token")
    }
}
