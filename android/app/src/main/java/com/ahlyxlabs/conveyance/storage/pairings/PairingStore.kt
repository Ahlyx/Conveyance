package com.ahlyxlabs.conveyance.storage.pairings

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Thin accessor over [PairingDao]. A stable seam for Phase 10.5's pairing
 * ceremony and the session layer; no ceremony logic lives here.
 */
@Singleton
class PairingStore @Inject constructor(
    private val dao: PairingDao,
) {
    suspend fun save(pairing: PairingEntity) = dao.upsert(pairing)

    suspend fun get(pcIdPub: ByteArray): PairingEntity? = dao.get(pcIdPub)

    suspend fun all(): List<PairingEntity> = dao.all()

    /** @return true if a row was removed. */
    suspend fun remove(pcIdPub: ByteArray): Boolean = dao.delete(pcIdPub) > 0

    /** @return true if a paired row was updated. */
    suspend fun touchLastSession(pcIdPub: ByteArray, timestamp: Long): Boolean =
        dao.touchLastSession(pcIdPub, timestamp) > 0
}
