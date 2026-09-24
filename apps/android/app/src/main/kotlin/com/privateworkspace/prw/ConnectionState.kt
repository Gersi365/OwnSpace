package com.privateworkspace.prw

internal enum class ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Suspended,
    Disconnecting,
    Error,
}
