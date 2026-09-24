package com.privateworkspace.prw

internal enum class ForwardLifecycleView {
    Closed,
    Opening,
    Active,
    Closing,
    Failed,
}

internal enum class LoopbackFamilyView(val code: Int) {
    Ipv4(0),
    Ipv6(1),
}

internal enum class ReachabilityView(val code: Int) {
    Unknown(0),
    Reachable(1),
    Unreachable(2),
}

internal enum class ConnectivityPathView {
    Offline,
    LocalDirect,
    InternetDirect,
    Relay,
}

internal data class ForwardingUiState(
    val lifecycle: ForwardLifecycleView = ForwardLifecycleView.Closed,
    val forwardId: Long? = null,
    val family: LoopbackFamilyView = LoopbackFamilyView.Ipv4,
    val bindPort: Int = 0,
    val targetAddress: String = "",
    val targetPort: Int = 0,
    val lastPayloadBytes: Int = 0,
)

internal data class PrivateDnsUiState(
    val requestedEnabled: Boolean = false,
    val validated: Boolean = true,
    val deviceNaming: Boolean = false,
    val deviceDomain: String = "",
    val resolverAddress: String = "",
    val resolverPort: Int = 0,
    val splitDomain: String = "",
    val osApplied: Boolean = false,
)

internal data class NetworkManagementUiState(
    val forwarding: ForwardingUiState = ForwardingUiState(),
    val selectedPath: ConnectivityPathView = ConnectivityPathView.Offline,
    val privateDns: PrivateDnsUiState = PrivateDnsUiState(),
)

internal interface NetworkCommandEncoder {
    fun forwardOpen(
        forwardId: Long,
        family: LoopbackFamilyView,
        bindPort: Int,
        targetAddress: String,
        targetPort: Int,
    ): ByteArray

    fun forwardClose(forwardId: Long): ByteArray

    fun selectedPath(
        local: ReachabilityView,
        internet: ReachabilityView,
        relay: ReachabilityView,
    ): Int

    fun validatePrivateDns(
        enabled: Boolean,
        deviceNaming: Boolean,
        deviceDomain: String,
        resolverAddress: String,
        resolverPort: Int,
        splitDomain: String,
    ): Boolean
}

internal object NativeNetworkCommandEncoder : NetworkCommandEncoder {
    override fun forwardOpen(
        forwardId: Long,
        family: LoopbackFamilyView,
        bindPort: Int,
        targetAddress: String,
        targetPort: Int,
    ): ByteArray = NativeBridge.forwardOpenPayload(
        forwardId,
        family.code,
        bindPort,
        targetAddress.encodeToByteArray(),
        targetPort,
    )

    override fun forwardClose(forwardId: Long): ByteArray =
        NativeBridge.forwardClosePayload(forwardId)

    override fun selectedPath(
        local: ReachabilityView,
        internet: ReachabilityView,
        relay: ReachabilityView,
    ): Int = NativeBridge.connectivitySelectedPath(local.code, internet.code, relay.code)

    override fun validatePrivateDns(
        enabled: Boolean,
        deviceNaming: Boolean,
        deviceDomain: String,
        resolverAddress: String,
        resolverPort: Int,
        splitDomain: String,
    ): Boolean = NativeBridge.validatePrivateDnsConfig(
        enabled,
        deviceNaming,
        deviceDomain.encodeToByteArray(),
        resolverAddress.encodeToByteArray(),
        resolverPort,
        splitDomain.encodeToByteArray(),
    )
}

internal class NetworkManagementController(private val encoder: NetworkCommandEncoder) {
    private var current = NetworkManagementUiState()

    fun state(): NetworkManagementUiState = current

    fun requestForwardOpen(
        forwardId: Long,
        family: LoopbackFamilyView,
        bindPort: Int,
        targetAddress: String,
        targetPort: Int,
    ): Boolean {
        if (current.forwarding.lifecycle !in setOf(ForwardLifecycleView.Closed, ForwardLifecycleView.Failed)) {
            return false
        }
        val payload = runCatching {
            encoder.forwardOpen(forwardId, family, bindPort, targetAddress, targetPort)
        }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(
            forwarding = ForwardingUiState(
                lifecycle = ForwardLifecycleView.Opening,
                forwardId = forwardId,
                family = family,
                bindPort = bindPort,
                targetAddress = targetAddress,
                targetPort = targetPort,
                lastPayloadBytes = payload.size,
            ),
        )
        return true
    }

    fun applyAuthoritativeForwardOpen(forwardId: Long): Boolean {
        val forward = current.forwarding
        if (forward.lifecycle != ForwardLifecycleView.Opening || forward.forwardId != forwardId) return false
        current = current.copy(forwarding = forward.copy(lifecycle = ForwardLifecycleView.Active))
        return true
    }

    fun requestForwardClose(): Boolean {
        val forward = current.forwarding
        val id = forward.forwardId ?: return false
        if (forward.lifecycle != ForwardLifecycleView.Active) return false
        val payload = runCatching { encoder.forwardClose(id) }.getOrNull() ?: return false
        if (payload.isEmpty()) return false
        current = current.copy(
            forwarding = forward.copy(
                lifecycle = ForwardLifecycleView.Closing,
                lastPayloadBytes = payload.size,
            ),
        )
        return true
    }

    fun applyAuthoritativeForwardClosed(forwardId: Long): Boolean {
        val forward = current.forwarding
        if (forward.lifecycle != ForwardLifecycleView.Closing || forward.forwardId != forwardId) return false
        current = current.copy(forwarding = ForwardingUiState())
        return true
    }

    fun applyAuthoritativeForwardFailure(forwardId: Long): Boolean {
        val forward = current.forwarding
        if (forward.forwardId != forwardId || forward.lifecycle == ForwardLifecycleView.Closed) return false
        current = current.copy(forwarding = forward.copy(lifecycle = ForwardLifecycleView.Failed))
        return true
    }

    fun applyAuthoritativeConnectivitySnapshot(
        local: ReachabilityView,
        internet: ReachabilityView,
        relay: ReachabilityView,
    ): Boolean {
        val code = runCatching { encoder.selectedPath(local, internet, relay) }.getOrNull() ?: return false
        val selected = when (code) {
            0 -> ConnectivityPathView.Offline
            1 -> ConnectivityPathView.LocalDirect
            2 -> ConnectivityPathView.InternetDirect
            3 -> ConnectivityPathView.Relay
            else -> return false
        }
        current = current.copy(selectedPath = selected)
        return true
    }

    fun validatePrivateDnsDraft(
        enabled: Boolean,
        deviceNaming: Boolean,
        deviceDomain: String,
        resolverAddress: String,
        resolverPort: Int,
        splitDomain: String,
    ): Boolean {
        val accepted = runCatching {
            encoder.validatePrivateDns(
                enabled,
                deviceNaming,
                deviceDomain,
                resolverAddress,
                resolverPort,
                splitDomain,
            )
        }.getOrDefault(false)
        if (!accepted) return false
        current = current.copy(
            privateDns = PrivateDnsUiState(
                requestedEnabled = enabled,
                validated = true,
                deviceNaming = deviceNaming,
                deviceDomain = deviceDomain,
                resolverAddress = resolverAddress,
                resolverPort = resolverPort,
                splitDomain = splitDomain,
                osApplied = false,
            ),
        )
        return true
    }
}
