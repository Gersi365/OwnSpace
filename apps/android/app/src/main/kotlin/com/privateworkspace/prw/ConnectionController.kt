package com.privateworkspace.prw

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

internal class ConnectionController {
    private val mutableState = MutableStateFlow(ConnectionState.Disconnected)
    val state: StateFlow<ConnectionState> = mutableState.asStateFlow()

    fun transition(target: ConnectionState): Boolean {
        val current = mutableState.value
        if (!isAllowed(current, target)) return false
        mutableState.value = target
        return true
    }

    companion object {
        internal fun isAllowed(from: ConnectionState, to: ConnectionState): Boolean = when (from) {
            ConnectionState.Disconnected -> to == ConnectionState.Connecting
            ConnectionState.Connecting -> to in setOf(
                ConnectionState.Authenticating,
                ConnectionState.Disconnected,
                ConnectionState.Error,
            )
            ConnectionState.Authenticating -> to in setOf(
                ConnectionState.Connected,
                ConnectionState.Disconnected,
                ConnectionState.Error,
            )
            ConnectionState.Connected -> to in setOf(
                ConnectionState.Suspended,
                ConnectionState.Disconnecting,
                ConnectionState.Error,
            )
            ConnectionState.Suspended -> to in setOf(
                ConnectionState.Connecting,
                ConnectionState.Disconnecting,
                ConnectionState.Error,
            )
            ConnectionState.Disconnecting -> to == ConnectionState.Disconnected
            ConnectionState.Error -> to in setOf(
                ConnectionState.Disconnected,
                ConnectionState.Connecting,
            )
        }
    }
}
