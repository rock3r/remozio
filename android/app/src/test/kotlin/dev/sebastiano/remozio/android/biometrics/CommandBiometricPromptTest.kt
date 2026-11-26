package dev.sebastiano.remozio.android.biometrics

import android.hardware.biometrics.BiometricPrompt
import dev.remozio.protocol.ApprovalMessage
import dev.remozio.protocol.ApprovalMessageType
import dev.remozio.protocol.SigningPurpose
import java.security.Signature
import org.junit.Test
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.fail

class CommandBiometricPromptTest {
    private val token = Any()
    private val biometric = BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC
    private val signature = Signature.getInstance("SHA256withECDSA")
    private val carrier = ApprovalMessage(1u, ApprovalMessageType.DECISION,
        SigningPurpose.BIOMETRIC_AUTHORIZATION, byteArrayOf(1), ByteArray(64))

    @Test fun aCurrentBiometricSuccessSignsWithTheReturnedObject() {
        val result = commandBiometricSuccess(token, token, true, biometric, { signature }) {
            assertSame(signature, it)
            carrier
        }
        assertSame(carrier, assertIs<CommandBiometricResult.Signed>(result).message)
    }

    @Test fun cancellationAndReplacementIgnoreLateSuccess() {
        for (active in listOf(null, Any())) {
            val result = commandBiometricSuccess(token, active, true, biometric,
                { fail("A late callback read its signature") }) {
                fail("A late callback reached the signer")
            }
            assertNull(result)
        }
    }

    @Test fun deviceCredentialAndStoppedActivityCannotReachTheSigner() {
        val credential = BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL
        for ((started, type) in listOf(true to credential, false to biometric)) {
            val result = commandBiometricSuccess(token, token, started, type,
                { fail("An ineligible callback read its signature") }) {
                fail("An ineligible callback reached the signer")
            }
            assertSame(CommandBiometricResult.Unavailable, result)
        }
    }

    @Test fun missingSignatureAndSignerFailureReportUnavailable() {
        val missing = commandBiometricSuccess(token, token, true, biometric, { null }) {
            fail("A callback without a signature reached the signer")
        }
        assertSame(CommandBiometricResult.Unavailable, missing)
        val failure = commandBiometricSuccess(token, token, true, biometric, { signature }) {
            throw IllegalStateException("The request is no longer pending")
        }
        assertSame(CommandBiometricResult.Unavailable, failure)
    }
}
