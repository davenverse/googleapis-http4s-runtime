

package org.http4s
package googleapis.runtime

trait GoogleEnvironmentDetection {
    def isOnGCE[F[_]]: F[Boolean] = ???
}
