package dev.remozio.phone.enrollment

/** Creates synthetic active records for consumers' tests. This source set is excluded from application artifacts. */
fun EncryptedEnrollmentStore.activateSyntheticEnrollment(
    recordID: ByteArray, expectedRevision: ULong, replacingRecordID: ByteArray? = null,
): EnrollmentSnapshot = activate(recordID, expectedRevision, replacingRecordID)
