package com.privateworkspace.prw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionControllerTest {
    @Test fun legal_bootstrap_path_is_explicit() {
        val controller = ConnectionController()
        assertTrue(controller.transition(ConnectionState.Connecting))
        assertTrue(controller.transition(ConnectionState.Authenticating))
        assertTrue(controller.transition(ConnectionState.Connected))
        assertEquals(ConnectionState.Connected, controller.state.value)
    }

    @Test fun illegal_jump_to_connected_fails_closed() {
        val controller = ConnectionController()
        assertFalse(controller.transition(ConnectionState.Connected))
        assertEquals(ConnectionState.Disconnected, controller.state.value)
    }

    @Test fun disconnect_is_two_step_from_connected() {
        val controller = ConnectionController()
        assertTrue(controller.transition(ConnectionState.Connecting))
        assertTrue(controller.transition(ConnectionState.Authenticating))
        assertTrue(controller.transition(ConnectionState.Connected))
        assertTrue(controller.transition(ConnectionState.Disconnecting))
        assertTrue(controller.transition(ConnectionState.Disconnected))
    }
}
