package com.maxime.romstore_client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

// Downloads that outlive the screen.
//
// Flutter's own HTTP work dies with the UI isolate, so leaving the app (or
// Cocoon reclaiming the foreground) used to abandon a half-written ROM. A
// foreground service keeps the process alive and the progress visible in the
// notification shade, which is what you want when a Switch title is several
// gigabytes over Wi-Fi.
//
// Files stream straight to their place in the ROM tree via a .part file, and
// resume with a Range request, so an interrupted 4GB download costs seconds
// rather than starting over.
class DownloadService : Service() {

    companion object {
        const val ACTION_ENQUEUE = "romstore.ENQUEUE"
        const val ACTION_CANCEL = "romstore.CANCEL"
        const val ACTION_CANCEL_ALL = "romstore.CANCEL_ALL"

        private const val CHANNEL_ID = "romstore_downloads"
        private const val NOTIFICATION_ID = 4711

        // State the UI reads. Kept in the app's own folder on shared storage so
        // it survives the process being killed: Flutter reconciles from this on
        // next launch and finishes anything that completed while it was gone.
        private const val STATE_FILE = "/storage/emulated/0/ROMs/.romstore/downloads.json"

        private val queue = ConcurrentLinkedQueue<Job>()
        private val cancelled = HashSet<String>()
        private val running = AtomicBoolean(false)

        // Set while Flutter is attached; progress is mirrored here so the UI can
        // animate without polling.
        @Volatile
        var events: ((Map<String, Any?>) -> Unit)? = null

        @Volatile
        private var current: Job? = null

        private val done = LinkedHashMap<String, JSONObject>()

        fun snapshot(): String {
            val array = JSONArray()
            current?.let { array.put(it.toJson("running")) }
            queue.forEach { array.put(it.toJson("queued")) }
            done.values.forEach { array.put(it) }
            return array.toString()
        }
    }

    data class Job(
        val id: String, // the game's relPath, which is also its identity in Flutter
        val url: String,
        val cookie: String,
        val dest: String,
        val title: String,
        val total: Long
    ) {
        fun toJson(state: String, received: Long = 0, error: String? = null): JSONObject =
            JSONObject()
                .put("id", id)
                .put("title", title)
                .put("dest", dest)
                .put("total", total)
                .put("received", received)
                .put("state", state)
                .apply { if (error != null) put("error", error) }
    }

    private val main = Handler(Looper.getMainLooper())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "Downloads",
                    NotificationManager.IMPORTANCE_LOW // silent: this runs while playing
                )
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CANCEL -> intent.getStringExtra("id")?.let { id ->
                synchronized(cancelled) { cancelled.add(id) }
                queue.removeAll { it.id == id }
                publish(id, 0, 0, "cancelled", null)
            }
            ACTION_CANCEL_ALL -> {
                synchronized(cancelled) { current?.let { cancelled.add(it.id) } }
                queue.forEach { publish(it.id, 0, it.total, "cancelled", null) }
                queue.clear()
            }
            ACTION_ENQUEUE -> {
                val jobs = JSONArray(intent.getStringExtra("jobs") ?: "[]")
                for (i in 0 until jobs.length()) {
                    val j = jobs.getJSONObject(i)
                    val job = Job(
                        id = j.getString("id"),
                        url = j.getString("url"),
                        cookie = j.optString("cookie"),
                        dest = j.getString("dest"),
                        title = j.optString("title", j.getString("id")),
                        total = j.optLong("total", 0)
                    )
                    synchronized(cancelled) { cancelled.remove(job.id) }
                    queue.add(job)
                    publish(job.id, 0, job.total, "queued", null)
                }
            }
        }

        startForeground(NOTIFICATION_ID, notification("Downloading", "Starting…", 0, 0))
        if (running.compareAndSet(false, true)) {
            Thread { workLoop() }.start()
        }
        return START_STICKY
    }

    private fun workLoop() {
        try {
            while (true) {
                val job = queue.poll() ?: break
                if (isCancelled(job.id)) continue
                current = job
                try {
                    download(job)
                    // Cleared before recording, so a finished job is not also
                    // listed as the one in flight when the state file is written.
                    current = null
                    record(job.toJson("done", job.total))
                    publish(job.id, job.total, job.total, "done", null)
                } catch (e: Throwable) {
                    current = null
                    val state = if (isCancelled(job.id)) "cancelled" else "failed"
                    record(job.toJson(state, 0, e.message))
                    publish(job.id, 0, job.total, state, e.message)
                } finally {
                    current = null
                }
            }
        } finally {
            running.set(false)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun isCancelled(id: String): Boolean = synchronized(cancelled) { cancelled.contains(id) }

    private fun download(job: Job) {
        val target = File(job.dest)
        target.parentFile?.mkdirs()
        val part = File("${job.dest}.part")

        // Resume whatever a previous run managed to write.
        var already = if (part.exists()) part.length() else 0L
        val connection = (URL(job.url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000
            readTimeout = 30000
            if (job.cookie.isNotEmpty()) setRequestProperty("Cookie", job.cookie)
            if (already > 0) setRequestProperty("Range", "bytes=$already-")
        }

        connection.connect()
        val code = connection.responseCode
        if (code == HttpURLConnection.HTTP_OK && already > 0) {
            // Server ignored the range: start over rather than corrupt the file.
            already = 0
            part.delete()
        } else if (code != HttpURLConnection.HTTP_OK && code != HttpURLConnection.HTTP_PARTIAL) {
            throw IllegalStateException("HTTP $code")
        }

        val total = if (job.total > 0) job.total else connection.contentLengthLong + already

        RandomAccessFile(part, "rw").use { out ->
            out.seek(already)
            connection.inputStream.use { input ->
                val buffer = ByteArray(1 shl 16)
                var received = already
                var lastPublished = 0L
                while (true) {
                    if (isCancelled(job.id)) throw InterruptedException("cancelled")
                    val read = input.read(buffer)
                    if (read <= 0) break
                    out.write(buffer, 0, read)
                    received += read

                    // Notifications and channel messages are far more expensive
                    // than the copy itself; 300ms keeps the bar smooth without
                    // making the download slower than the network.
                    val now = System.currentTimeMillis()
                    if (now - lastPublished > 300) {
                        lastPublished = now
                        publish(job.id, received, total, "running", null)
                        notifyProgress(job.title, received, total)
                    }
                }
            }
        }

        if (isCancelled(job.id)) throw InterruptedException("cancelled")
        if (target.exists()) target.delete()
        if (!part.renameTo(target)) throw IllegalStateException("could not move into place")
    }

    private fun record(entry: JSONObject) {
        done[entry.getString("id")] = entry
        try {
            val file = File(STATE_FILE)
            file.parentFile?.mkdirs()
            file.writeText(snapshot())
        } catch (_: Throwable) {
            // Shared storage is best-effort here; the live channel still works.
        }
    }

    private fun publish(id: String, received: Long, total: Long, state: String, error: String?) {
        val payload = mapOf(
            "id" to id,
            "received" to received,
            "total" to total,
            "state" to state,
            "error" to error
        )
        main.post { events?.invoke(payload) }
    }

    private fun notifyProgress(title: String, received: Long, total: Long) {
        val percent = if (total > 0) ((received * 100) / total).toInt() else 0
        val text = if (total > 0) "$percent%  ·  ${queue.size} waiting" else "${received / 1048576} MB"
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, notification(title, text, percent, total))
    }

    private fun notification(title: String, text: String, percent: Int, total: Long): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .setProgress(100, percent, total <= 0)
            .build()
    }
}
