package com.privateworkspace.prw

import java.security.MessageDigest

internal const val MAX_REMOTE_FILE_CHUNK_BYTES = 60_000
internal const val MAX_REMOTE_DIRECTORY_ENTRIES = 4_096
internal const val MAX_REMOTE_ENTRY_NAME_BYTES = 255
internal const val MAX_REMOTE_TRANSFER_BYTES = 1_073_741_824L
internal const val MAX_DISPOSABLE_TRANSFER_MEMORY_BYTES = 1_048_576

internal enum class RemoteEntryTypeView { RegularFile, Directory, SymbolicLink, Other }

internal data class RemoteDirectoryEntryView(val name: String, val type: RemoteEntryTypeView)

internal data class BrowserUiState(
    val path: String = "",
    val entries: List<RemoteDirectoryEntryView> = emptyList(),
    val pendingPath: String? = null,
    val lastPayloadBytes: Int = 0,
)

internal enum class UploadLifecycleView { Idle, Planning, Ready, Transferring, Finalizing, Completed, Failed, Aborted }

internal data class UploadUiState(
    val lifecycle: UploadLifecycleView = UploadLifecycleView.Idle,
    val transferId: String? = null,
    val destination: String? = null,
    val totalBytes: Long = 0,
    val acknowledgedBytes: Long = 0,
    val sha256: ByteArray = byteArrayOf(),
    val source: ByteArray = byteArrayOf(),
    val pendingChunkBytes: Int = 0,
    val abortPending: Boolean = false,
    val lastPayloadBytes: Int = 0,
) {
    fun progress(): Float = if (totalBytes == 0L) 0f else (acknowledgedBytes.toDouble() / totalBytes.toDouble()).toFloat()
}

internal enum class DownloadLifecycleView { Idle, Ready, Transferring, Completed, Failed }

internal data class DownloadUiState(
    val lifecycle: DownloadLifecycleView = DownloadLifecycleView.Idle,
    val path: String? = null,
    val expectedBytes: Long? = null,
    val acknowledgedBytes: Long = 0,
    val received: ByteArray = byteArrayOf(),
    val pendingRequestBytes: Int = 0,
    val lastPayloadBytes: Int = 0,
) {
    fun progress(): Float? = expectedBytes?.let { total ->
        if (total == 0L) 0f else (acknowledgedBytes.toDouble() / total.toDouble()).toFloat()
    }
}

internal data class RemoteFilesUiState(
    val browser: BrowserUiState = BrowserUiState(),
    val upload: UploadUiState = UploadUiState(),
    val download: DownloadUiState = DownloadUiState(),
)

internal interface FileCommandEncoder {
    fun list(path: String): ByteArray
    fun stat(path: String): ByteArray
    fun uploadBegin(transferId: String, destination: String, totalBytes: Long, sha256: ByteArray): ByteArray
    fun uploadResume(transferId: String, destination: String, totalBytes: Long, sha256: ByteArray): ByteArray
    fun uploadChunk(transferId: String, offset: Long, chunk: ByteArray): ByteArray
    fun uploadFinalize(transferId: String): ByteArray
    fun uploadAbort(transferId: String): ByteArray
    fun download(path: String, offset: Long, requestedBytes: Int): ByteArray
}

internal object NativeFileCommandEncoder : FileCommandEncoder {
    override fun list(path: String) = NativeBridge.fileListPayload(path.encodeToByteArray())
    override fun stat(path: String) = NativeBridge.fileStatPayload(path.encodeToByteArray())
    override fun uploadBegin(transferId: String, destination: String, totalBytes: Long, sha256: ByteArray) =
        NativeBridge.uploadBeginPayload(transferId.encodeToByteArray(), destination.encodeToByteArray(), totalBytes, sha256)
    override fun uploadResume(transferId: String, destination: String, totalBytes: Long, sha256: ByteArray) =
        NativeBridge.uploadResumePayload(transferId.encodeToByteArray(), destination.encodeToByteArray(), totalBytes, sha256)
    override fun uploadChunk(transferId: String, offset: Long, chunk: ByteArray) =
        NativeBridge.uploadChunkPayload(transferId.encodeToByteArray(), offset, chunk)
    override fun uploadFinalize(transferId: String) = NativeBridge.uploadFinalizePayload(transferId.encodeToByteArray())
    override fun uploadAbort(transferId: String) = NativeBridge.uploadAbortPayload(transferId.encodeToByteArray())
    override fun download(path: String, offset: Long, requestedBytes: Int) =
        NativeBridge.downloadChunkPayload(path.encodeToByteArray(), offset, requestedBytes)
}

internal class RemoteFilesController(private val encoder: FileCommandEncoder) {
    private var current = RemoteFilesUiState()
    fun state(): RemoteFilesUiState = current

    fun requestList(path: String): Boolean {
        val payload = runCatching { encoder.list(path) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(browser = current.browser.copy(pendingPath = path, lastPayloadBytes = payload.size))
        return true
    }

    fun applyAuthoritativeDirectorySnapshot(path: String, entries: List<RemoteDirectoryEntryView>): Boolean {
        if (current.browser.pendingPath != path || entries.size > MAX_REMOTE_DIRECTORY_ENTRIES) return false
        if (entries.any { !validEntryName(it.name) }) return false
        current = current.copy(browser = BrowserUiState(path = path, entries = entries.toList()))
        return true
    }

    fun prepareUpload(transferId: String, destination: String, source: ByteArray): Boolean {
        if (!validTransferId(transferId) || source.size > MAX_DISPOSABLE_TRANSFER_MEMORY_BYTES) return false
        val digest = MessageDigest.getInstance("SHA-256").digest(source)
        current = current.copy(
            upload = UploadUiState(
                lifecycle = UploadLifecycleView.Ready,
                transferId = transferId,
                destination = destination,
                totalBytes = source.size.toLong(),
                sha256 = digest,
                source = source.copyOf(),
            ),
        )
        return true
    }

    fun requestUploadBegin(resume: Boolean): Boolean {
        val upload = current.upload
        val id = upload.transferId ?: return false
        val destination = upload.destination ?: return false
        if (upload.lifecycle !in setOf(UploadLifecycleView.Ready, UploadLifecycleView.Failed)) return false
        val payload = runCatching {
            if (resume) encoder.uploadResume(id, destination, upload.totalBytes, upload.sha256)
            else encoder.uploadBegin(id, destination, upload.totalBytes, upload.sha256)
        }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(upload = upload.copy(lifecycle = UploadLifecycleView.Planning, lastPayloadBytes = payload.size))
        return true
    }

    fun applyAuthoritativeUploadOffset(offset: Long): Boolean {
        val upload = current.upload
        if (upload.lifecycle != UploadLifecycleView.Planning || offset !in 0..upload.totalBytes) return false
        current = current.copy(upload = upload.copy(lifecycle = UploadLifecycleView.Transferring, acknowledgedBytes = offset))
        return true
    }

    fun sendNextUploadChunk(): Boolean {
        val upload = current.upload
        val id = upload.transferId ?: return false
        if (upload.lifecycle != UploadLifecycleView.Transferring || upload.pendingChunkBytes != 0) return false
        if (upload.acknowledgedBytes >= upload.totalBytes) return false
        val start = upload.acknowledgedBytes.toInt()
        val count = minOf(MAX_REMOTE_FILE_CHUNK_BYTES, upload.source.size - start)
        val chunk = upload.source.copyOfRange(start, start + count)
        val payload = runCatching { encoder.uploadChunk(id, upload.acknowledgedBytes, chunk) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(upload = upload.copy(pendingChunkBytes = count, lastPayloadBytes = payload.size))
        return true
    }

    fun applyAuthoritativeUploadChunkOffset(offset: Long): Boolean {
        val upload = current.upload
        if (upload.lifecycle != UploadLifecycleView.Transferring || upload.pendingChunkBytes == 0) return false
        val expected = upload.acknowledgedBytes + upload.pendingChunkBytes
        if (offset != expected || offset > upload.totalBytes) return false
        current = current.copy(upload = upload.copy(acknowledgedBytes = offset, pendingChunkBytes = 0))
        return true
    }

    fun requestUploadFinalize(): Boolean {
        val upload = current.upload
        val id = upload.transferId ?: return false
        if (upload.lifecycle != UploadLifecycleView.Transferring || upload.pendingChunkBytes != 0 || upload.acknowledgedBytes != upload.totalBytes) return false
        val payload = runCatching { encoder.uploadFinalize(id) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(upload = upload.copy(lifecycle = UploadLifecycleView.Finalizing, lastPayloadBytes = payload.size))
        return true
    }

    fun applyAuthoritativeUploadFinalized(): Boolean {
        val upload = current.upload
        if (upload.lifecycle != UploadLifecycleView.Finalizing) return false
        current = current.copy(upload = upload.copy(lifecycle = UploadLifecycleView.Completed))
        return true
    }

    fun markUploadFailed(): Boolean {
        val upload = current.upload
        if (upload.lifecycle in setOf(UploadLifecycleView.Idle, UploadLifecycleView.Completed, UploadLifecycleView.Aborted)) return false
        current = current.copy(upload = upload.copy(lifecycle = UploadLifecycleView.Failed, pendingChunkBytes = 0, abortPending = false))
        return true
    }

    fun requestUploadAbort(): Boolean {
        val upload = current.upload
        val id = upload.transferId ?: return false
        if (upload.lifecycle in setOf(UploadLifecycleView.Idle, UploadLifecycleView.Completed, UploadLifecycleView.Aborted) || upload.abortPending) return false
        val payload = runCatching { encoder.uploadAbort(id) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(upload = upload.copy(abortPending = true, lastPayloadBytes = payload.size))
        return true
    }

    fun applyAuthoritativeUploadAborted(): Boolean {
        val upload = current.upload
        if (!upload.abortPending) return false
        current = current.copy(upload = upload.copy(lifecycle = UploadLifecycleView.Aborted, abortPending = false, pendingChunkBytes = 0))
        return true
    }

    fun prepareDownload(path: String, expectedBytes: Long?): Boolean {
        if (expectedBytes != null && expectedBytes !in 0..MAX_REMOTE_TRANSFER_BYTES) return false
        current = current.copy(download = DownloadUiState(lifecycle = DownloadLifecycleView.Ready, path = path, expectedBytes = expectedBytes))
        return true
    }

    fun requestDownloadChunk(requestedBytes: Int = MAX_REMOTE_FILE_CHUNK_BYTES): Boolean {
        val download = current.download
        val path = download.path ?: return false
        if (download.lifecycle !in setOf(DownloadLifecycleView.Ready, DownloadLifecycleView.Transferring) || download.pendingRequestBytes != 0) return false
        if (requestedBytes !in 1..MAX_REMOTE_FILE_CHUNK_BYTES) return false
        val payload = runCatching { encoder.download(path, download.acknowledgedBytes, requestedBytes) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(download = download.copy(lifecycle = DownloadLifecycleView.Transferring, pendingRequestBytes = requestedBytes, lastPayloadBytes = payload.size))
        return true
    }

    fun applyAuthoritativeDownloadChunk(chunk: ByteArray): Boolean {
        val download = current.download
        if (download.lifecycle != DownloadLifecycleView.Transferring || download.pendingRequestBytes == 0) return false
        if (chunk.size > download.pendingRequestBytes || chunk.size > MAX_REMOTE_FILE_CHUNK_BYTES) return false
        if (chunk.isEmpty()) {
            val complete = download.expectedBytes == null || download.acknowledgedBytes == download.expectedBytes
            current = current.copy(download = download.copy(lifecycle = if (complete) DownloadLifecycleView.Completed else DownloadLifecycleView.Failed, pendingRequestBytes = 0))
            return complete
        }
        if (download.received.size + chunk.size > MAX_DISPOSABLE_TRANSFER_MEMORY_BYTES) return false
        val newOffset = download.acknowledgedBytes + chunk.size
        if (download.expectedBytes != null && newOffset > download.expectedBytes) return false
        current = current.copy(download = download.copy(acknowledgedBytes = newOffset, received = download.received + chunk, pendingRequestBytes = 0))
        return true
    }

    private fun validTransferId(value: String): Boolean = value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun validEntryName(value: String): Boolean {
        val bytes = value.encodeToByteArray()
        return bytes.isNotEmpty() && bytes.size <= MAX_REMOTE_ENTRY_NAME_BYTES && value != "." && value != ".." && '/' !in value && '\\' !in value && '\u0000' !in value
    }
}
