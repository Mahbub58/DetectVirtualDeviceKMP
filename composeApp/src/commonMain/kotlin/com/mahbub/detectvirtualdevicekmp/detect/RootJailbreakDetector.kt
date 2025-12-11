package com.mahbub.detectvirtualdevicekmp.detect

expect object RootJailbreakDetector {
    fun collectSignals(): List<DetectionSignal>
    fun collectSignalsWithContext(context: Any?): List<DetectionSignal>
}

fun evaluateRootOrJailbreak(): DetectionReport {
    return DetectionScoring.aggregate(RootJailbreakDetector.collectSignals())
}

fun evaluateRootOrJailbreak(context: Any?): DetectionReport {
    return DetectionScoring.aggregate(RootJailbreakDetector.collectSignalsWithContext(context))
}

