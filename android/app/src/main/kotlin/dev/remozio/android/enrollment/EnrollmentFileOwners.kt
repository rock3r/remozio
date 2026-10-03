package dev.remozio.android.enrollment

/** Reserve before opening a channel: closing a competing channel can release another process-local lock. */
internal object EnrollmentFileOwners {
    private val held = mutableMapOf<String, Any>()
    @Synchronized fun acquire(canonicalPath: String): AutoCloseable {
        check(canonicalPath !in held) { "Enrollment store already open" }
        val token = Any()
        held[canonicalPath] = token
        return AutoCloseable {
            synchronized(this) { if (held[canonicalPath] === token) held.remove(canonicalPath) }
        }
    }
}
