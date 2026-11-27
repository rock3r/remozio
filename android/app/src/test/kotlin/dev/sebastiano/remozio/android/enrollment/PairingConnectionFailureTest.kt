package dev.sebastiano.remozio.android.enrollment

import java.io.IOException
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PairingConnectionFailureTest {
    private val connecting = PairingScreenState(PairingPhase.CONNECTING)
    private val refusal = IOException("Missing pairing transcript")

    @Test fun failedRePairWithSuccessfulCleanupOffersConditionalGuidance() {
        val state = connecting.connectionFailed(refusal, isRePair = true, cleanupSucceeded = true)
        assertEquals(PairingPhase.RE_PAIR_FAILED, state.phase)
        assertFalse(state.mayHaveSavedSetup)
    }

    @Test fun ordinaryFailureAndUncertainCleanupKeepTheirExistingMessages() {
        val ordinary = connecting.connectionFailed(refusal, isRePair = false, cleanupSucceeded = true)
        assertEquals(PairingPhase.FAILED, ordinary.phase)
        assertFalse(ordinary.mayHaveSavedSetup)

        val incomplete = connecting.connectionFailed(refusal, isRePair = true, cleanupSucceeded = false)
        assertEquals(PairingPhase.FAILED, incomplete.phase)
        assertTrue(incomplete.mayHaveSavedSetup)
    }

    @Test fun pendingAndExpiredRePairKeepTheirOwnStates() {
        val pending = connecting.connectionFailed(RePairAlreadyPending(), isRePair = true, cleanupSucceeded = true)
        assertEquals(PairingPhase.RECOVERY_PENDING, pending.phase)
        val expired = connecting.connectionFailed(PairingDeadlineExpired(), isRePair = true, cleanupSucceeded = true)
        assertEquals(PairingPhase.EXPIRED, expired.phase)
    }
}
