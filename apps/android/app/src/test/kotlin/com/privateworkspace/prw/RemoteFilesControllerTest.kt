package com.privateworkspace.prw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteFilesControllerTest {
    private class FakeEncoder : FileCommandEncoder {
        override fun list(path: String) = byteArrayOf(2)
        override fun stat(path: String) = byteArrayOf(3)
        override fun uploadBegin(transferId: String, destination: String, totalBytes: Long, sha256: ByteArray) = byteArrayOf(6)
        override fun uploadResume(transferId: String, destination: String, totalBytes: Long, sha256: ByteArray) = byteArrayOf(7)
        override fun uploadChunk(transferId: String, offset: Long, chunk: ByteArray) = byteArrayOf(8)
        override fun uploadFinalize(transferId: String) = byteArrayOf(9)
        override fun uploadAbort(transferId: String) = byteArrayOf(10)
        override fun download(path: String, offset: Long, requestedBytes: Int) = byteArrayOf(11)
    }

    private val id = "abababababababababababababababab"

    @Test fun browser_request_does_not_fabricate_entries() {
        val controller = RemoteFilesController(FakeEncoder())
        assertTrue(controller.requestList(""))
        assertTrue(controller.state().browser.entries.isEmpty())
        assertEquals("", controller.state().browser.pendingPath)
        val entries = listOf(RemoteDirectoryEntryView("Documents", RemoteEntryTypeView.Directory))
        assertTrue(controller.applyAuthoritativeDirectorySnapshot("", entries))
        assertEquals(entries, controller.state().browser.entries)
        assertFalse(controller.applyAuthoritativeDirectorySnapshot("", List(MAX_REMOTE_DIRECTORY_ENTRIES + 1) { RemoteDirectoryEntryView("x$it", RemoteEntryTypeView.RegularFile) }))
    }

    @Test fun upload_progress_moves_only_on_exact_authoritative_acknowledgement() {
        val controller = RemoteFilesController(FakeEncoder())
        val source = ByteArray(70_000) { 1 }
        assertTrue(controller.prepareUpload(id, "uploads/demo.bin", source))
        assertTrue(controller.requestUploadBegin(resume = false))
        assertEquals(0L, controller.state().upload.acknowledgedBytes)
        assertTrue(controller.applyAuthoritativeUploadOffset(0))
        assertTrue(controller.sendNextUploadChunk())
        assertEquals(0L, controller.state().upload.acknowledgedBytes)
        assertEquals(60_000, controller.state().upload.pendingChunkBytes)
        assertFalse(controller.applyAuthoritativeUploadChunkOffset(59_999))
        assertTrue(controller.applyAuthoritativeUploadChunkOffset(60_000))
        assertTrue(controller.sendNextUploadChunk())
        assertTrue(controller.applyAuthoritativeUploadChunkOffset(70_000))
        assertEquals(70_000L, controller.state().upload.acknowledgedBytes)
    }

    @Test fun finalize_and_abort_do_not_forge_authoritative_completion() {
        val controller = RemoteFilesController(FakeEncoder())
        assertTrue(controller.prepareUpload(id, "uploads/demo.bin", byteArrayOf(1, 2, 3)))
        assertTrue(controller.requestUploadBegin(resume = false))
        assertTrue(controller.applyAuthoritativeUploadOffset(0))
        assertFalse(controller.requestUploadFinalize())
        assertTrue(controller.sendNextUploadChunk())
        assertTrue(controller.applyAuthoritativeUploadChunkOffset(3))
        assertTrue(controller.requestUploadFinalize())
        assertEquals(UploadLifecycleView.Finalizing, controller.state().upload.lifecycle)
        assertTrue(controller.applyAuthoritativeUploadFinalized())
        assertEquals(UploadLifecycleView.Completed, controller.state().upload.lifecycle)

        val second = RemoteFilesController(FakeEncoder())
        assertTrue(second.prepareUpload(id, "uploads/abort.bin", byteArrayOf(9)))
        assertTrue(second.requestUploadBegin(resume = false))
        assertTrue(second.applyAuthoritativeUploadOffset(0))
        assertTrue(second.requestUploadAbort())
        assertEquals(UploadLifecycleView.Transferring, second.state().upload.lifecycle)
        assertTrue(second.state().upload.abortPending)
        assertTrue(second.applyAuthoritativeUploadAborted())
        assertEquals(UploadLifecycleView.Aborted, second.state().upload.lifecycle)
    }

    @Test fun resume_reuses_plan_and_authoritative_offset() {
        val controller = RemoteFilesController(FakeEncoder())
        val source = ByteArray(80_000) { 2 }
        assertTrue(controller.prepareUpload(id, "uploads/resume.bin", source))
        val digest = controller.state().upload.sha256.copyOf()
        assertTrue(controller.requestUploadBegin(resume = false))
        assertTrue(controller.applyAuthoritativeUploadOffset(0))
        assertTrue(controller.sendNextUploadChunk())
        assertTrue(controller.applyAuthoritativeUploadChunkOffset(60_000))
        assertTrue(controller.markUploadFailed())
        assertTrue(controller.requestUploadBegin(resume = true))
        assertEquals(id, controller.state().upload.transferId)
        assertEquals("uploads/resume.bin", controller.state().upload.destination)
        assertTrue(digest.contentEquals(controller.state().upload.sha256))
        assertTrue(controller.applyAuthoritativeUploadOffset(60_000))
        assertEquals(60_000L, controller.state().upload.acknowledgedBytes)
    }

    @Test fun download_progress_and_eof_are_authoritative() {
        val controller = RemoteFilesController(FakeEncoder())
        assertTrue(controller.prepareDownload("downloads/demo.bin", 3))
        assertTrue(controller.requestDownloadChunk(3))
        assertEquals(0L, controller.state().download.acknowledgedBytes)
        assertTrue(controller.applyAuthoritativeDownloadChunk(byteArrayOf(1, 2, 3)))
        assertEquals(3L, controller.state().download.acknowledgedBytes)
        assertTrue(controller.requestDownloadChunk(1))
        assertTrue(controller.applyAuthoritativeDownloadChunk(byteArrayOf()))
        assertEquals(DownloadLifecycleView.Completed, controller.state().download.lifecycle)

        val premature = RemoteFilesController(FakeEncoder())
        assertTrue(premature.prepareDownload("downloads/short.bin", 3))
        assertTrue(premature.requestDownloadChunk(3))
        assertFalse(premature.applyAuthoritativeDownloadChunk(byteArrayOf()))
        assertEquals(DownloadLifecycleView.Failed, premature.state().download.lifecycle)
    }
}
