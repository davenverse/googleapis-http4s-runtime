/*
 * Copyright (c) 2023 Christopher Davenport
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
