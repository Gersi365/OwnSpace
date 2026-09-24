package com.privateworkspace.prw

internal const val MAX_REMOTE_TERMINAL_BYTES = 60_000
internal const val MAX_TERMINAL_DIMENSION = 1_000
internal const val MAX_TERMINAL_TRANSCRIPT_CHARS = 262_144

internal enum class TerminalProfileView(val nativeCode: Int) {
    PosixShell(0),
    BashShell(1),
}

internal enum class TerminalLifecycleView {
    Closed,
    Opening,
    Open,
    Closing,
    Failed,
}

internal interface TerminalCommandEncoder {
    fun open(sessionId: Long, profile: TerminalProfileView, columns: Int, rows: Int): ByteArray
    fun input(sessionId: Long, bytes: ByteArray): ByteArray
    fun resize(sessionId: Long, columns: Int, rows: Int): ByteArray
    fun read(sessionId: Long, maximumBytes: Int): ByteArray
    fun close(sessionId: Long): ByteArray
}

internal object NativeTerminalCommandEncoder : TerminalCommandEncoder {
    override fun open(sessionId: Long, profile: TerminalProfileView, columns: Int, rows: Int): ByteArray =
        NativeBridge.terminalOpenPayload(sessionId, profile.nativeCode, columns, rows)

    override fun input(sessionId: Long, bytes: ByteArray): ByteArray =
        NativeBridge.terminalInputPayload(sessionId, bytes)

    override fun resize(sessionId: Long, columns: Int, rows: Int): ByteArray =
        NativeBridge.terminalResizePayload(sessionId, columns, rows)

    override fun read(sessionId: Long, maximumBytes: Int): ByteArray =
        NativeBridge.terminalReadPayload(sessionId, maximumBytes)

    override fun close(sessionId: Long): ByteArray = NativeBridge.terminalClosePayload(sessionId)
}

internal data class TerminalUiState(
    val lifecycle: TerminalLifecycleView = TerminalLifecycleView.Closed,
    val sessionId: Long? = null,
    val profile: TerminalProfileView = TerminalProfileView.PosixShell,
    val columns: Int = 80,
    val rows: Int = 24,
    val transcript: String = "",
    val lastPayloadBytes: Int = 0,
    val detail: String = "No terminal session",
)

internal class TerminalSessionController(
    private val encoder: TerminalCommandEncoder,
    private val transcriptLimitChars: Int = MAX_TERMINAL_TRANSCRIPT_CHARS,
) {
    private var current = TerminalUiState()

    init {
        require(transcriptLimitChars > 0)
    }

    fun state(): TerminalUiState = current

    fun requestOpen(
        sessionId: Long,
        profile: TerminalProfileView,
        columns: Int,
        rows: Int,
    ): Boolean {
        if (current.lifecycle != TerminalLifecycleView.Closed || sessionId <= 0) return false
        if (!validGeometry(columns, rows)) return false
        val payload = runCatching { encoder.open(sessionId, profile, columns, rows) }.getOrNull()
            ?: return false
        if (payload.isEmpty()) return false
        current = TerminalUiState(
            lifecycle = TerminalLifecycleView.Opening,
            sessionId = sessionId,
            profile = profile,
            columns = columns,
            rows = rows,
            lastPayloadBytes = payload.size,
            detail = "Terminal open intent encoded; awaiting authoritative acceptance",
        )
        return true
    }

    fun applyAuthoritativeOpen(sessionId: Long): Boolean {
        if (current.lifecycle != TerminalLifecycleView.Opening || current.sessionId != sessionId) return false
        current = current.copy(
            lifecycle = TerminalLifecycleView.Open,
            detail = "Disposable authoritative open accepted",
        )
        return true
    }

    fun sendInput(bytes: ByteArray): Boolean {
        val sessionId = current.sessionId ?: return false
        if (current.lifecycle != TerminalLifecycleView.Open) return false
        if (bytes.isEmpty() || bytes.size > MAX_REMOTE_TERMINAL_BYTES) return false
        val payload = runCatching { encoder.input(sessionId, bytes) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(
            lastPayloadBytes = payload.size,
            detail = "Terminal input intent encoded; no remote output fabricated locally",
        )
        return true
    }

    fun requestRead(maximumBytes: Int): Boolean {
        val sessionId = current.sessionId ?: return false
        if (current.lifecycle != TerminalLifecycleView.Open) return false
        if (maximumBytes !in 1..MAX_REMOTE_TERMINAL_BYTES) return false
        val payload = runCatching { encoder.read(sessionId, maximumBytes) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(
            lastPayloadBytes = payload.size,
            detail = "Terminal output-read intent encoded",
        )
        return true
    }

    fun applyAuthoritativeOutput(bytes: ByteArray): Boolean {
        if (current.lifecycle != TerminalLifecycleView.Open) return false
        if (bytes.size > MAX_REMOTE_TERMINAL_BYTES) return false
        val combined = current.transcript + bytes.toString(Charsets.UTF_8)
        val bounded = if (combined.length <= transcriptLimitChars) {
            combined
        } else {
            combined.takeLast(transcriptLimitChars)
        }
        current = current.copy(
            transcript = bounded,
            detail = "Disposable authoritative terminal output applied",
        )
        return true
    }

    fun resize(columns: Int, rows: Int): Boolean {
        val sessionId = current.sessionId ?: return false
        if (current.lifecycle != TerminalLifecycleView.Open || !validGeometry(columns, rows)) return false
        val payload = runCatching { encoder.resize(sessionId, columns, rows) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(
            columns = columns,
            rows = rows,
            lastPayloadBytes = payload.size,
            detail = "Terminal resize intent encoded",
        )
        return true
    }

    fun requestClose(): Boolean {
        val sessionId = current.sessionId ?: return false
        if (current.lifecycle != TerminalLifecycleView.Open) return false
        val payload = runCatching { encoder.close(sessionId) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(
            lifecycle = TerminalLifecycleView.Closing,
            lastPayloadBytes = payload.size,
            detail = "Terminal close intent encoded; awaiting authoritative completion",
        )
        return true
    }

    fun applyAuthoritativeClosed(sessionId: Long): Boolean {
        if (current.lifecycle != TerminalLifecycleView.Closing || current.sessionId != sessionId) return false
        current = current.copy(
            lifecycle = TerminalLifecycleView.Closed,
            sessionId = null,
            lastPayloadBytes = 0,
            detail = "Disposable authoritative close completed",
        )
        return true
    }

    fun fail(detail: String): Boolean {
        if (current.lifecycle == TerminalLifecycleView.Closed) return false
        current = current.copy(lifecycle = TerminalLifecycleView.Failed, detail = detail)
        return true
    }

    private fun validGeometry(columns: Int, rows: Int): Boolean =
        columns in 1..MAX_TERMINAL_DIMENSION && rows in 1..MAX_TERMINAL_DIMENSION
}
