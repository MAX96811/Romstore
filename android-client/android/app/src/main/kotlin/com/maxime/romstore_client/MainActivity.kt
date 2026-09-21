package com.maxime.romstore_client

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.InputStreamReader

// Shizuku bridge: Android 13 blocks apps from other apps' Android/data, where
// the emulators keep their saves. Shizuku lends us a shell-uid process (the
// same access adb has), which is the only non-root way to reach them.
class MainActivity : FlutterActivity() {
    private var pendingPermissionResult: MethodChannel.Result? = null

    // romstore://shop?platform=nds. Held here because Flutter asks for it
    // after its first frame, which is later than onCreate.
    private var launchLink: String? = null
    private var linkChannel: MethodChannel? = null

    private val permissionListener =
        Shizuku.OnRequestPermissionResultListener { _, grantResult ->
            pendingPermissionResult?.success(grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED)
            pendingPermissionResult = null
        }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        Shizuku.addRequestPermissionResultListener(permissionListener)

        // Downloads run in a foreground service so they survive leaving the
        // app; Flutter only enqueues and listens.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "romstore/downloads")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "enqueue" -> {
                        val intent = Intent(this, DownloadService::class.java)
                            .setAction(DownloadService.ACTION_ENQUEUE)
                            .putExtra("jobs", call.argument<String>("jobs") ?: "[]")
                        startForegroundService(intent)
                        result.success(true)
                    }
                    "cancel" -> {
                        startForegroundService(
                            Intent(this, DownloadService::class.java)
                                .setAction(DownloadService.ACTION_CANCEL)
                                .putExtra("id", call.argument<String>("id"))
                        )
                        result.success(true)
                    }
                    "cancelAll" -> {
                        startForegroundService(
                            Intent(this, DownloadService::class.java)
                                .setAction(DownloadService.ACTION_CANCEL_ALL)
                        )
                        result.success(true)
                    }
                    "state" -> result.success(DownloadService.snapshot())
                    else -> result.notImplemented()
                }
            }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, "romstore/downloads/events")
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, sink: EventChannel.EventSink?) {
                    DownloadService.events = { payload -> sink?.success(payload) }
                }

                override fun onCancel(arguments: Any?) {
                    DownloadService.events = null
                }
            })

        // Android 13+ hides the progress notification without this. The
        // download itself does not depend on it, so a refusal is not fatal.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1001)
        }

        launchLink = intent?.dataString
        linkChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "romstore/link")
        linkChannel!!.setMethodCallHandler { call, result ->
            when (call.method) {
                // Consumed once: a later rebuild should not jump the user back
                // to the platform they arrived on.
                "consumeInitialLink" -> {
                    result.success(launchLink)
                    launchLink = null
                }
                else -> result.notImplemented()
            }
        }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "romstore/shizuku")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "ping" -> result.success(try { Shizuku.pingBinder() } catch (e: Throwable) { false })
                    "hasPermission" -> result.success(
                        try { Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED }
                        catch (e: Throwable) { false }
                    )
                    "requestPermission" -> {
                        try {
                            if (Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED) {
                                result.success(true)
                            } else {
                                pendingPermissionResult = result
                                Shizuku.requestPermission(1000)
                            }
                        } catch (e: Throwable) { result.success(false) }
                    }
                    "exec" -> {
                        val cmd = call.argument<String>("cmd") ?: ""
                        Thread {
                            try {
                                val method = Shizuku::class.java.getDeclaredMethod(
                                    "newProcess",
                                    Array<String>::class.java,
                                    Array<String>::class.java,
                                    String::class.java
                                )
                                method.isAccessible = true
                                val proc = method.invoke(null, arrayOf("sh", "-c", cmd), null, null) as Process
                                val out = BufferedReader(InputStreamReader(proc.inputStream)).readText()
                                val err = BufferedReader(InputStreamReader(proc.errorStream)).readText()
                                val code = proc.waitFor()
                                runOnUiThread { result.success(mapOf("code" to code, "out" to out, "err" to err)) }
                            } catch (e: Throwable) {
                                runOnUiThread { result.error("EXEC", e.toString(), null) }
                            }
                        }.start()
                    }
                    else -> result.notImplemented()
                }
            }
    }

    // Launched again while already running (singleTop), e.g. tapping a second
    // platform's shop tile: hand the new link straight to Flutter.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val link = intent.dataString ?: return
        if (linkChannel == null) launchLink = link else linkChannel!!.invokeMethod("link", link)
    }

    override fun onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionListener)
        super.onDestroy()
    }
}
