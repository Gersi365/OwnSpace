[Reading 56 lines from start (total: 56 lines, 0 remaining)]

package com.privateworkspace.prw

import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidKeyCustodyStateTest {
    @Test
    fun clean_first_run_requires_every_piece_of_established_state_to_be_absent() {
        assertEquals(
            AndroidIdentityState.FirstRun,
            classifyAndroidIdentityState(
                markerExists = false,
                aliasExists = false,
                expectedSpkiDigestExists = false,
                spkiDigestMatches = false,
            ),
        )
    }

    @Test
    fun established_state_requires_marker_alias_and_matching_spki_digest() {
        assertEquals(
            AndroidIdentityState.Established,
            classifyAndroidIdentityState(
                markerExists = true,
                aliasExists = true,
                expectedSpkiDigestExists = true,
                spkiDigestMatches = true,
            ),
        )
    }

    @Test
    fun every_partial_or_mismatched_state_requires_fresh_reenrollment() {
        val cases = listOf(
            booleanArrayOf(true, false, true, false),
            booleanArrayOf(false, true, false, false),
            booleanArrayOf(true, true, false, false),
            booleanArrayOf(true, true, true, false),
            booleanArrayOf(false, false, true, false),
            booleanArrayOf(false, true, true, true),
        )

        cases.forEach { state ->
            assertEquals(
                AndroidIdentityState.ReenrollmentRequired,
                classifyAndroidIdentityState(
                    markerExists = state[0],
                    aliasExists = state[1],
                    expectedSpkiDigestExists = state[2],
                    spkiDigestMatches = state[3],
                ),
            )
        }
    }
}

[executed on device: OWS (2e7ebe3b-518e-4a6a-b7f3-214616d73d77)]