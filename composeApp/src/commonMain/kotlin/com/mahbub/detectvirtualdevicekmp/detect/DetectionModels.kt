package com.mahbub.detectvirtualdevicekmp.detect

data class DetectionSignal(
    val id: String,
    val description: String,
    val triggered: Boolean,
    val weight: Int
)

data class DetectionReport(
    val isEmulatorOrSimulator: Boolean,
    val confidence: Int,
    val signals: List<DetectionSignal>
)

object DetectionScoring {
    fun aggregate(signals: List<DetectionSignal>): DetectionReport {
        val score = signals.filter { it.triggered }.sumOf { it.weight }
        val confidence = score.coerceIn(0, 10)
        val isEmu = confidence >= 4
        return DetectionReport(isEmulatorOrSimulator = isEmu, confidence = confidence, signals = signals)
    }
}

