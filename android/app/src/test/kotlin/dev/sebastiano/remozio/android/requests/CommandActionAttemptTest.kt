package dev.sebastiano.remozio.android.requests

import org.junit.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CommandActionAttemptTest {
    @Test fun replacementRejectsTheOldTicket() {
        val attempts = CommandActionAttempt()
        val first = attempts.begin()
        assertTrue(attempts.owns(first))
        val second = attempts.begin()
        assertFalse(attempts.owns(first))
        assertTrue(attempts.owns(second))
    }

    @Test fun invalidationRejectsLateCallbacksAfterAnotherAttemptBegins() {
        val attempts = CommandActionAttempt()
        val cancelled = attempts.begin()
        attempts.invalidate()
        assertFalse(attempts.owns(cancelled))
        val next = attempts.begin()
        assertFalse(attempts.owns(cancelled))
        assertTrue(attempts.owns(next))
    }
}
