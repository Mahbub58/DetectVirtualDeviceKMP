package com.mahbub.detectvirtualdevicekmp.detect

expect object VirtualDetector {
    fun collectSignals(): List<DetectionSignal>
    fun collectSignalsWithContext(context: Any?): List<DetectionSignal>
}

fun evaluateVirtualEnvironment(): DetectionReport {
    return DetectionScoring.aggregate(VirtualDetector.collectSignals())
}

fun evaluateVirtualEnvironment(context: Any?): DetectionReport {
    return DetectionScoring.aggregate(VirtualDetector.collectSignalsWithContext(context))
}
