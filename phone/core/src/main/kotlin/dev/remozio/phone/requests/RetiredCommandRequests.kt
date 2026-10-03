package dev.remozio.phone.requests

/**
 * Exact terminal-request membership for one trusted enrollment incarnation. No probabilistic matches or eviction.
 * Reads are bounded to one 32-byte digest. Remember must durably commit before returning and reject conflicting digests.
 * Storage failure must throw; it must never look like an absent ID. The enrollment owns this store after a successful add.
 * This is a local suppression index, not an audit log, current trust proof, or the Mac's durable consumption ledger.
 */
interface RetiredCommandRequests : AutoCloseable {
    fun lookup(requestID: ByteArray): ByteArray?
    fun remember(requestID: ByteArray, requestDigest: ByteArray)
}
