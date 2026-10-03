package dev.remozio.android.enrollment

import org.junit.Test
import kotlin.test.*

class EnrollmentFileOwnersTest {
    @Test fun rejectsOverlappingOwnersAndStaleCloseCannotReleaseTheReplacement() {
        val path = "/synthetic/enrollment-one"
        val first = EnrollmentFileOwners.acquire(path)
        try { assertFailsWith<IllegalStateException> { EnrollmentFileOwners.acquire(path) } }
        finally { first.close() }
        EnrollmentFileOwners.acquire(path).use {
            first.close()
            assertFailsWith<IllegalStateException> { EnrollmentFileOwners.acquire(path) }
        }
        EnrollmentFileOwners.acquire(path).close()
    }

    @Test fun separateArchivesHaveIndependentOwnership() {
        EnrollmentFileOwners.acquire("/synthetic/enrollment-a").use {
            EnrollmentFileOwners.acquire("/synthetic/enrollment-b").use {
                assertFailsWith<IllegalStateException> { EnrollmentFileOwners.acquire("/synthetic/enrollment-a") }
            }
        }
    }
}
