package dev.alsatianconsulting.pocketpcap

import android.Manifest
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import dev.alsatianconsulting.pocketpcap.ui.navigation.AppNavGraph
import dev.alsatianconsulting.pocketpcap.ui.theme.PocketPcapTheme

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        // Refresh capabilities after permissions granted/denied
        viewModel.refresh(probeRoot = false)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        requestRuntimePermissions()

        setContent {
            PocketPcapTheme {
                androidx.compose.material3.Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = dev.alsatianconsulting.pocketpcap.ui.theme.WarmBg900,
                ) {
                    AppNavGraph(viewModel = viewModel)
                }
            }
        }
    }

    private fun requestRuntimePermissions() {
        val perms = buildList {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }.toTypedArray()
        permissionLauncher.launch(perms)
    }
}
