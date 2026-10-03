package dev.remozio.android.audit

import android.content.Context
import dev.remozio.android.enrollment.AndroidEnrollmentStore
import dev.remozio.phone.audit.AuditEvidenceLimits
import dev.remozio.phone.audit.AuditPageLimits
import dev.remozio.protocol.CborLimits

/** Decoder limits only. This reader never selects retention or prunes an archive. */
internal fun androidStoredAuditReader(context: Context): StoredAuditReader {
    val app = context.applicationContext
    val protocol = AuditPageLimits(
        batch = CborLimits(1_048_576, 8, 131_072),
        record = CborLimits(4096, 4, 64),
        signing = CborLimits(1_050_624, 8, 32),
        maximumRecords = 2048,
        history = CborLimits(16_384, 8, 256),
        descriptor = CborLimits(4096, 4, 64),
    )
    return StoredAuditReader(
        openEnrollments = { AndroidEnrollmentStore.openExisting(app, 1024, 16_777_216) },
        openCache = { binding, maximumBytes ->
            AndroidAuditCache.openExisting(app, binding, protocol,
                AuditEvidenceLimits(maximumProofs = 4096, maximumBytes = maximumBytes.toLong(),
                    maximumRecords = 50_000, maximumEpochs = 4096),
                CborLimits(maximumBytes, 8, 65_536))
        },
    )
}
