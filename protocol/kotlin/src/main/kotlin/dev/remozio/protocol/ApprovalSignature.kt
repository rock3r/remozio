package dev.remozio.protocol

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.Signature
import java.security.SignatureException
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidKeySpecException

/** Verify with the public key and context selected from trusted enrollment and retained request state. */
object ApprovalSignature {
    fun verify(
        signature: ByteArray,
        publicKey: ByteArray,
        wireVersion: ULong,
        messageType: ApprovalMessageType,
        purpose: SigningPurpose,
        canonicalPayload: ByteArray,
        payloadLimits: CborLimits,
        inputLimits: CborLimits,
    ): Boolean {
        val input = SigningInput.make(wireVersion, messageType, purpose, canonicalPayload, payloadLimits, inputLimits)
        if (signature.size != 64 || publicKey.size != 65) return false
        val pointBytes = publicKey.copyOf()
        val rawSignature = signature.copyOf()
        if (pointBytes[0] != 4.toByte()) return false
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val r = BigInteger(1, rawSignature.copyOfRange(0, 32))
        val s = BigInteger(1, rawSignature.copyOfRange(32, 64))
        if (r.signum() == 0 || s.signum() == 0 || r >= parameters.order || s >= parameters.order) return false
        val x = BigInteger(1, pointBytes.copyOfRange(1, 33))
        val y = BigInteger(1, pointBytes.copyOfRange(33, 65))
        val derR = r.toByteArray()
        val derS = s.toByteArray()
        val der = byteArrayOf(0x30, (4 + derR.size + derS.size).toByte(), 0x02, derR.size.toByte()) +
            derR + byteArrayOf(0x02, derS.size.toByte()) + derS
        return try {
            val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), parameters))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(input)
                verify(der)
            }
        } catch (_: InvalidKeySpecException) {
            false
        } catch (_: InvalidKeyException) {
            false
        } catch (_: SignatureException) {
            false
        }
    }
}
