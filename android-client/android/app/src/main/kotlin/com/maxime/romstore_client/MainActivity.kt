package com.maxime.romstore_client

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.InputStreamReader

// Shizuku bridge: Android 13 blocks apps from other apps' Android/data, where
// the emulators keep their saves. Shizuku lends us a shell-uid process (the
// same access adb has), which is the only non-root way to reach them.
class MainActivity : FlutterActivity() {
    private var pendingPermissionResult: MethodChannel.Result? = null

    private val permissionListener =
        Shizuku.OnRequestPermissionResultListener { _, grantResult ->
            pendingPermissionResult?.success(grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED)
            pendingPermissionResult = null
        }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        Shizuku.addRequestPermissionResultListener(permissionListener)
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

    override fun onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionListener)
        super.onDestroy()
    }
}
