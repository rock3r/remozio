package dev.sebastiano.remozio.android.enrollment

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.Test

class PairingWindowProtectionTest {
    @Test fun onlyLiveComparisonPhasesRequireProtectedWindows() {
        assertEquals(setOf(PairingPhase.COMPARING, PairingPhase.PREPARING, PairingPhase.BIOMETRIC),
            PairingPhase.entries.filter { requiresPairingWindowProtection(it, preview = false) }.toSet())
        assertTrue(PairingPhase.entries.none { requiresPairingWindowProtection(it, preview = true) })
    }

    @Test fun aSignerCannotLaunchAPromptBeforeWindowProtectionSucceeds() {
        val window = PairingWindowProtection()
        val signer = Any()
        assertNull(window.startBiometrics(PairingPhase.BIOMETRIC, true, signer) { fail("Prompt launched before protection") })
        assertFalse(window.canMatch(PairingPhase.COMPARING, true))
    }

    @Test fun aWindowWithoutCaptureProtectionCannotConfirmOrLaunch() {
        val window = PairingWindowProtection()
        window.protect(secure = false) { fail("The comparison window is missing or insecure") }
        assertEquals(PairingWindowProtection.State.UNAVAILABLE, window.state)
        assertFalse(window.canMatch(PairingPhase.COMPARING, true))
        assertNull(window.startBiometrics(PairingPhase.BIOMETRIC, true, Any()) { fail("Prompt launched without capture protection") })
    }

    @Test fun anOverlayRejectionCannotConfirmOrLaunch() {
        val window = PairingWindowProtection()
        window.protect(secure = true) { throw SecurityException("Overlay protection rejected") }
        assertEquals(PairingWindowProtection.State.UNAVAILABLE, window.state)
        assertFalse(window.canMatch(PairingPhase.COMPARING, true))
        assertNull(window.startBiometrics(PairingPhase.BIOMETRIC, true, Any()) { fail("Prompt launched without overlay protection") })
    }

    @Test fun matchRequiresTheCodeAndTheComparingPhase() {
        val window = readyWindow()
        for (phase in PairingPhase.entries) {
            assertFalse(window.canMatch(phase, false))
            assertEquals(phase == PairingPhase.COMPARING, window.canMatch(phase, true))
        }
    }

    @Test fun onlyTheCurrentComparisonSignerCanLaunchInBiometricPhase() {
        val window = readyWindow()
        val signer = Any()
        val prompt = Any()
        for (phase in PairingPhase.entries.filter { it != PairingPhase.BIOMETRIC }) {
            assertNull(window.startBiometrics(phase, true, signer) { fail("Prompt launched from the wrong phase") })
        }
        assertNull(window.startBiometrics(PairingPhase.BIOMETRIC, false, signer) { fail("Prompt launched without a code") })
        assertNull(window.startBiometrics(PairingPhase.BIOMETRIC, true, null as Any?) { fail("Prompt launched without a signer") })
        assertSame(prompt, window.startBiometrics(PairingPhase.BIOMETRIC, true, signer) {
            assertSame(signer, it)
            prompt
        })
    }

    @Test fun aReplacementWindowMustPassItsOwnChecks() {
        val old = readyWindow()
        val replacement = PairingWindowProtection()
        old.revoke()
        old.protect(secure = true) { fail("A disposed window regained protection") }
        for (window in listOf(old, replacement)) {
            assertFalse(window.canMatch(PairingPhase.COMPARING, true))
            assertNull(window.startBiometrics(PairingPhase.BIOMETRIC, true, Any()) { fail("Prompt launched with old protection") })
        }
        replacement.protect(secure = true) {}
        assertTrue(replacement.canMatch(PairingPhase.COMPARING, true))
        assertFalse(old.canMatch(PairingPhase.COMPARING, true))
    }

    private fun readyWindow() = PairingWindowProtection().apply { protect(secure = true) {} }
}
