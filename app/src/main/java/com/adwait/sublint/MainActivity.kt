package com.adwait.sublint

import android.content.Context
import android.net.ConnectivityManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import com.adwait.sublint.ui.theme.SublintTheme
import com.sublint.android.AndroidWifiNetworkResolver
import com.sublint.core.classifier.BannerClassifier
import com.sublint.core.coordinator.LanScanCoordinator
import com.sublint.core.network.JavaSocketProber
import com.sublint.core.scanner.SubnetHostEnumerator
import com.sublint.ui.ScanScreen
import com.sublint.ui.SublintViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: SublintViewModel by viewModels {
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val wifiResolver = AndroidWifiNetworkResolver(connectivityManager)
        val socketProber = JavaSocketProber()
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = socketProber
        )
        SublintViewModel.provideFactory(wifiResolver, coordinator)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val uiState by viewModel.uiState.collectAsState()

            // Keep screen on during active scan, clear when idle
            LaunchedEffect(uiState.isScanning) {
                if (uiState.isScanning) {
                    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                }
            }

            SublintTheme {
                ScanScreen(viewModel = viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshNetworkState()
    }

    override fun onStop() {
        super.onStop()
        // Enforce foreground-only policy: cancel active scan on app backgrounding
        viewModel.cancelScan()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }
}
