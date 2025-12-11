package com.mahbub.detectvirtualdevicekmp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import com.mahbub.detectvirtualdevicekmp.detect.DetectionSignal
import com.mahbub.detectvirtualdevicekmp.detect.DetectionScoring

class ComposeAppCommonTest {

    @Test
    fun example() {
        assertEquals(3, 1 + 2)
    }

    @Test
    fun scoringAggregatesSignals() {
        val signals = listOf(
            DetectionSignal("a", "fp", true, 2),
            DetectionSignal("b", "hardware", true, 3),
            DetectionSignal("c", "model", false, 2)
        )
        val report = DetectionScoring.aggregate(signals)
        assertTrue(report.isEmulatorOrSimulator)
        assertEquals(5, report.confidence)
    }
}
