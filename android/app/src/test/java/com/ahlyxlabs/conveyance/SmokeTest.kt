package com.ahlyxlabs.conveyance

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Phase 10.0 has no logic to test. This exists so the `test` task and
 * its CI step are real rather than vacuous, and so the JVM-unit-test
 * wiring (deps, source set, runner, generated BuildConfig) is proven
 * before any code needs it.
 */
class SmokeTest {

    @Test
    fun applicationIdIsTheSpecPackage() {
        assertEquals("com.ahlyxlabs.conveyance", BuildConfig.APPLICATION_ID)
    }
}
