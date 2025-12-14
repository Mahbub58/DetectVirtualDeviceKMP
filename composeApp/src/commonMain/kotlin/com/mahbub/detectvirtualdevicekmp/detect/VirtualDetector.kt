package com.mahbub.detectvirtualdevicekmp.detect

expect object VirtualDetector {
    fun collectSignals(context: Any?): List<DetectionSignal>
    fun collectSignalsWithContext(context: Any?): List<DetectionSignal>
}

fun evaluateVirtualEnvironment(context: Any?): DetectionReport {
    return DetectionScoring.aggregate(VirtualDetector.collectSignals(context))
}

fun evaluateVirtualEnvironmentContext(context: Any?): DetectionReport {
    return DetectionScoring.aggregate(VirtualDetector.collectSignalsWithContext(context))
}
