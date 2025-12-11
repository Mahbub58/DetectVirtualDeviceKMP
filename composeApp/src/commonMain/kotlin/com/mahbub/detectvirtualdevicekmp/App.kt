package com.mahbub.detectvirtualdevicekmp

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeContentPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.ui.tooling.preview.Preview
import com.mahbub.detectvirtualdevicekmp.detect.evaluateVirtualEnvironment
import com.mahbub.detectvirtualdevicekmp.detect.evaluateRootOrJailbreak
import com.mahbub.detectvirtualdevicekmp.detect.evaluateVirtualEnvironmentContext
import com.mahbub.detectvirtualdevicekmp.detect.getPlatformContext


@Composable
@Preview
fun App() {
    MaterialTheme {
        val ctx = remember { getPlatformContext() }
        val reportContextCheck = remember { evaluateVirtualEnvironmentContext(ctx) }
        val rootReportContextCheck = remember { evaluateRootOrJailbreak(ctx) }
        val report = remember { evaluateVirtualEnvironment() }
        val rootReport = remember { evaluateRootOrJailbreak() }
        Scaffold { it ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .safeContentPadding()
                    .padding(it),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text("Virtual: ${report.isEmulatorOrSimulator} (confidence=${report.confidence})")
                Text("Root/Jailbreak: ${rootReport.isEmulatorOrSimulator} (confidence=${rootReport.confidence})")

                Text("Virtual(Context): ${reportContextCheck.isEmulatorOrSimulator} (confidence=${reportContextCheck.confidence})")
                Text("Root/Jailbreak(Context): ${rootReportContextCheck.isEmulatorOrSimulator} (confidence=${rootReportContextCheck.confidence})")
            }
        }
    }
}
