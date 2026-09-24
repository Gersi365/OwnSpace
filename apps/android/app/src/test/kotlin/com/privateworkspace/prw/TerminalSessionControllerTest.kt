package com.privateworkspace.prw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TerminalSessionControllerTest {
    private class FakeEncoder : TerminalCommandEncoder {
        var inputCalls = 0
        override fun open(sessionId: Long, profile: TerminalProfileView, columns: Int, rows: Int) = byteArrayOf(12)
        override fun input(sessionId: Long, bytes: ByteArray): ByteArray {
            inputCalls += 1
            return byteArrayOf(13)
        }
        override fun resize(sessionId: Long, columns: Int, rows: Int) = byteArrayOf(14)
        override fun read(sessionId: Long, maximumBytes: Int) = byteArrayOf(15)
        override fun close(sessionId: Long) = byteArrayOf(16)
    }

    @Test fun open_request_does_not_forge_open_state() {
        val controller = TerminalSessionController(FakeEncoder())
        assertTrue(controller.requestOpen(147, TerminalProfileView.PosixShell, 80, 24))
        assertEquals(TerminalLifecycleView.Opening, controller.state().lifecycle)
        assertTrue(controller.applyAuthoritativeOpen(147))
        assertEquals(TerminalLifecycleView.Open, controller.state().lifecycle)
    }

    @Test fun input_is_only_accepted_while_open_and_does_not_fabricate_output() {
        val encoder = FakeEncoder()
        val controller = TerminalSessionController(encoder)
        assertFalse(controller.sendInput("pwd\n".encodeToByteArray()))
        assertTrue(controller.requestOpen(147, TerminalProfileView.BashShell, 80, 24))
        assertTrue(controller.applyAuthoritativeOpen(147))
        assertTrue(controller.sendInput("pwd\n".encodeToByteArray()))
        assertEquals(1, encoder.inputCalls)
        assertEquals("", controller.state().transcript)
        assertFalse(controller.sendInput(byteArrayOf()))
        assertFalse(controller.sendInput(ByteArray(MAX_REMOTE_TERMINAL_BYTES + 1)))
    }

    @Test fun read_resize_and_close_respect_state_and_bounds() {
        val controller = TerminalSessionController(FakeEncoder())
        assertTrue(controller.requestOpen(147, TerminalProfileView.PosixShell, 80, 24))
        assertFalse(controller.requestRead(4096))
        assertTrue(controller.applyAuthoritativeOpen(147))
        assertFalse(controller.requestRead(0))
        assertFalse(controller.requestRead(MAX_REMOTE_TERMINAL_BYTES + 1))
        assertTrue(controller.requestRead(4096))
        assertFalse(controller.resize(0, 24))
        assertFalse(controller.resize(1001, 24))
        assertTrue(controller.resize(120, 40))
        assertTrue(controller.requestClose())
        assertEquals(TerminalLifecycleView.Closing, controller.state().lifecycle)
        assertFalse(controller.sendInput("ignored".encodeToByteArray()))
        assertTrue(controller.applyAuthoritativeClosed(147))
        assertEquals(TerminalLifecycleView.Closed, controller.state().lifecycle)
    }

    @Test fun transcript_is_bounded_and_only_authoritative_output_is_applied() {
        val controller = TerminalSessionController(FakeEncoder(), transcriptLimitChars = 8)
        assertTrue(controller.requestOpen(147, TerminalProfileView.PosixShell, 80, 24))
        assertTrue(controller.applyAuthoritativeOpen(147))
        assertTrue(controller.applyAuthoritativeOutput("123456789".encodeToByteArray()))
        assertEquals("23456789", controller.state().transcript)
        assertFalse(controller.applyAuthoritativeOutput(ByteArray(MAX_REMOTE_TERMINAL_BYTES + 1)))
    }

    @Test fun failed_session_does_not_silently_reopen() {
        val controller = TerminalSessionController(FakeEncoder())
        assertTrue(controller.requestOpen(147, TerminalProfileView.PosixShell, 80, 24))
        assertTrue(controller.fail("disposable failure"))
        assertEquals(TerminalLifecycleView.Failed, controller.state().lifecycle)
        assertFalse(controller.requestOpen(148, TerminalProfileView.BashShell, 80, 24))
    }
}
