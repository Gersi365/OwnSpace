package com.privateworkspace.prw

import androidx.lifecycle.ViewModel
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class EnrollmentPresentationState {
    NotReady,
    Ready,
    ProofValidated,
    Error,
}

internal data class PrwUiState(
    val connectionState: ConnectionState = ConnectionState.Disconnected,
    val identityReady: Boolean = false,
    val nativeBridgeReady: Boolean = false,
    val bootstrapValidated: Boolean = false,
    val enrollmentState: EnrollmentPresentationState = EnrollmentPresentationState.NotReady,
    val devices: List<DeviceSnapshot> = emptyList(),
    val pendingRevocationDeviceId: String? = null,
    val terminal: TerminalUiState = TerminalUiState(),
    val files: RemoteFilesUiState = RemoteFilesUiState(),
    val network: NetworkManagementUiState = NetworkManagementUiState(),
    val detail: String = "Development bootstrap only — no production endpoint",
)

internal class MainViewModel(
    private val custody: AndroidKeyCustody = AndroidKeyCustody(),
    private val controller: ConnectionController = ConnectionController(),
    private val deviceManagement: DeviceManagementController = DeviceManagementController(),
    private val terminalController: TerminalSessionController = TerminalSessionController(NativeTerminalCommandEncoder),
    private val fileController: RemoteFilesController = RemoteFilesController(NativeFileCommandEncoder),
    private val networkController: NetworkManagementController = NetworkManagementController(NativeNetworkCommandEncoder),
) : ViewModel() {
    private val mutableUiState = MutableStateFlow(PrwUiState())
    val uiState: StateFlow<PrwUiState> = mutableUiState.asStateFlow()

    fun validateLocalBootstrap() {
        if (!controller.transition(ConnectionState.Connecting)) return
        publish("Preparing non-exportable Android identity")
        runCatching {
            check(NativeBridge.protocolVersion() == 1)
            val spki = custody.ensureDeviceIdentitySpki()
            check(custody.deviceIdentityIsNonExportable())
            controller.transition(ConnectionState.Authenticating)
            publish("Validating typed local session proof")
            val nonce = ByteArray(32).also(SecureRandom()::nextBytes)
            val request = BootstrapRequest(
                workspaceId = "phase145-development-workspace",
                userId = "phase145-development-user",
                deviceId = "phase145-android-device",
                sessionId = "phase145-local-session",
                publicSpki = spki,
                nonce = nonce,
            ).encode()
            val canonical = NativeBridge.canonicalSessionMessage(request)
            check(canonical.isNotEmpty())
            val signature = custody.signCanonicalSessionProof(canonical)
            check(NativeBridge.verifySessionSignature(request, signature))
            check(controller.transition(ConnectionState.Connected))
        }.onSuccess {
            mutableUiState.value = mutableUiState.value.copy(
                connectionState = ConnectionState.Connected,
                identityReady = true,
                nativeBridgeReady = true,
                bootstrapValidated = true,
                detail = "Local authenticated bootstrap validated; remote production networking remains disabled",
            )
        }.onFailure { error ->
            controller.transition(ConnectionState.Error)
            mutableUiState.value = mutableUiState.value.copy(
                connectionState = ConnectionState.Error,
                identityReady = runCatching { custody.deviceIdentityIsNonExportable() }.getOrDefault(false),
                nativeBridgeReady = runCatching { NativeBridge.protocolVersion() == 1 }.getOrDefault(false),
                bootstrapValidated = false,
                detail = error.message ?: "Local bootstrap failed closed",
            )
        }
    }

    fun validateLocalEnrollmentProof() {
        mutableUiState.value = mutableUiState.value.copy(
            enrollmentState = EnrollmentPresentationState.Ready,
            detail = "Preparing disposable typed enrollment proof; no enrollment authority is contacted",
        )
        runCatching {
            check(NativeBridge.protocolVersion() == 1)
            val spki = custody.ensureDeviceIdentitySpki()
            check(custody.deviceIdentityIsNonExportable())
            val nonce = ByteArray(32).also(SecureRandom()::nextBytes)
            val request = EnrollmentProofRequest(
                enrollmentId = "phase146-local-enrollment",
                workspaceId = "phase146-development-workspace",
                userId = "phase146-development-user",
                deviceId = "phase146-android-device",
                publicSpki = spki,
                nonce = nonce,
            ).encode()
            val canonical = NativeBridge.canonicalEnrollmentMessage(request)
            check(canonical.isNotEmpty())
            val signature = custody.signCanonicalEnrollmentProof(canonical)
            check(NativeBridge.verifyEnrollmentSignature(request, signature))
        }.onSuccess {
            mutableUiState.value = mutableUiState.value.copy(
                identityReady = true,
                nativeBridgeReady = true,
                enrollmentState = EnrollmentPresentationState.ProofValidated,
                detail = "Disposable enrollment proof validated locally; authoritative enrollment remains unchanged",
            )
        }.onFailure { error ->
            mutableUiState.value = mutableUiState.value.copy(
                enrollmentState = EnrollmentPresentationState.Error,
                detail = error.message ?: "Enrollment proof failed closed",
            )
        }
    }

    fun loadDisposableDeviceSnapshots() {
        val accepted = deviceManagement.applyAuthoritativeSnapshot(
            listOf(
                DeviceSnapshot("phase146-android-device", DeviceLifecycleView.Enrolled),
                DeviceSnapshot("phase146-pending-device", DeviceLifecycleView.PendingEnrollment),
            ),
        )
        check(accepted)
        publishDeviceState("Loaded disposable authoritative device snapshots; no production registry contacted")
    }

    fun requestRevocation(deviceId: String) {
        val accepted = deviceManagement.requestRevocation(deviceId)
        publishDeviceState(
            if (accepted) {
                "Revocation intent pending for $deviceId; authoritative lifecycle remains Enrolled"
            } else {
                "Revocation intent rejected by current authoritative lifecycle/pending state"
            },
        )
    }

    fun requestDisposableTerminal(profile: TerminalProfileView): Boolean {
        val accepted = terminalController.requestOpen(DISPOSABLE_TERMINAL_SESSION_ID, profile, 80, 24)
        publishTerminalState(
            if (accepted) {
                "Disposable terminal open intent encoded; no production endpoint contacted"
            } else {
                "Terminal open intent rejected by local bounded lifecycle"
            },
        )
        return accepted
    }

    fun acceptDisposableTerminalOpen(): Boolean {
        val accepted = terminalController.applyAuthoritativeOpen(DISPOSABLE_TERMINAL_SESSION_ID)
        publishTerminalState(
            if (accepted) "Disposable terminal open acceptance applied" else "Terminal open acceptance rejected",
        )
        return accepted
    }

    fun sendDisposableTerminalInput(text: String): Boolean {
        val accepted = terminalController.sendInput(text.encodeToByteArray())
        publishTerminalState(
            if (accepted) "Terminal input payload encoded through existing PRWC bridge" else "Terminal input rejected",
        )
        return accepted
    }

    fun requestDisposableTerminalRead(): Boolean {
        val accepted = terminalController.requestRead(4096)
        publishTerminalState(
            if (accepted) "Bounded terminal read payload encoded" else "Terminal read request rejected",
        )
        return accepted
    }

    fun injectDisposableTerminalOutput(): Boolean {
        val accepted = terminalController.applyAuthoritativeOutput(
            "phase147 disposable remote output\n".encodeToByteArray(),
        )
        publishTerminalState(
            if (accepted) "Disposable authoritative output applied" else "Terminal output rejected",
        )
        return accepted
    }

    fun resizeDisposableTerminal(columns: Int, rows: Int): Boolean {
        val accepted = terminalController.resize(columns, rows)
        publishTerminalState(if (accepted) "Terminal resize payload encoded" else "Terminal resize rejected")
        return accepted
    }

    fun requestDisposableTerminalClose(): Boolean {
        val accepted = terminalController.requestClose()
        publishTerminalState(
            if (accepted) "Terminal close intent encoded; awaiting disposable completion" else "Terminal close rejected",
        )
        return accepted
    }

    fun acceptDisposableTerminalClosed(): Boolean {
        val accepted = terminalController.applyAuthoritativeClosed(DISPOSABLE_TERMINAL_SESSION_ID)
        publishTerminalState(
            if (accepted) "Disposable terminal close completed" else "Terminal close completion rejected",
        )
        return accepted
    }

    fun requestDisposableRootFiles(): Boolean {
        val accepted = fileController.requestList("")
        publishFilesState(if (accepted) "Root file-list intent encoded; no entries fabricated" else "File-list intent rejected")
        return accepted
    }

    fun applyDisposableRootFiles(): Boolean {
        val accepted = fileController.applyAuthoritativeDirectorySnapshot(
            "",
            listOf(
                RemoteDirectoryEntryView("Documents", RemoteEntryTypeView.Directory),
                RemoteDirectoryEntryView("example.txt", RemoteEntryTypeView.RegularFile),
                RemoteDirectoryEntryView("link-visible-not-followed", RemoteEntryTypeView.SymbolicLink),
            ),
        )
        publishFilesState(if (accepted) "Disposable authoritative directory snapshot applied" else "Directory snapshot rejected")
        return accepted
    }

    fun prepareDisposableUpload(): Boolean {
        val accepted = fileController.prepareUpload(
            "abababababababababababababababab",
            "uploads/phase148-demo.txt",
            "phase148 disposable upload payload\n".encodeToByteArray(),
        )
        publishFilesState(if (accepted) "Disposable upload plan prepared" else "Upload plan rejected")
        return accepted
    }

    fun requestDisposableUploadBegin(resume: Boolean = false): Boolean {
        val accepted = fileController.requestUploadBegin(resume)
        publishFilesState(if (accepted) "Upload begin/resume intent encoded; progress unchanged" else "Upload begin/resume rejected")
        return accepted
    }

    fun acknowledgeDisposableUploadPlan(): Boolean {
        val offset = if (fileController.state().upload.lifecycle == UploadLifecycleView.Planning) fileController.state().upload.acknowledgedBytes else 0L
        val accepted = fileController.applyAuthoritativeUploadOffset(offset)
        publishFilesState(if (accepted) "Disposable authoritative upload offset applied" else "Upload offset acknowledgement rejected")
        return accepted
    }

    fun sendDisposableUploadChunk(): Boolean {
        val accepted = fileController.sendNextUploadChunk()
        publishFilesState(if (accepted) "Upload chunk intent encoded; acknowledged progress unchanged" else "Upload chunk rejected")
        return accepted
    }

    fun acknowledgeDisposableUploadChunk(): Boolean {
        val upload = fileController.state().upload
        val accepted = fileController.applyAuthoritativeUploadChunkOffset(upload.acknowledgedBytes + upload.pendingChunkBytes)
        publishFilesState(if (accepted) "Disposable authoritative upload chunk acknowledgement applied" else "Upload chunk acknowledgement rejected")
        return accepted
    }

    fun finalizeDisposableUpload(): Boolean {
        val accepted = fileController.requestUploadFinalize()
        publishFilesState(if (accepted) "Upload finalize intent encoded; completion not forged" else "Upload finalize rejected")
        return accepted
    }

    fun completeDisposableUpload(): Boolean {
        val accepted = fileController.applyAuthoritativeUploadFinalized()
        publishFilesState(if (accepted) "Disposable authoritative upload finalize applied" else "Upload finalize acknowledgement rejected")
        return accepted
    }

    fun prepareDisposableDownload(): Boolean {
        val expected = "phase148 disposable download\n".encodeToByteArray().size.toLong()
        val accepted = fileController.prepareDownload("downloads/phase148-demo.txt", expected)
        publishFilesState(if (accepted) "Disposable download prepared" else "Download plan rejected")
        return accepted
    }

    fun requestDisposableDownloadChunk(): Boolean {
        val accepted = fileController.requestDownloadChunk()
        publishFilesState(if (accepted) "Download chunk intent encoded; progress unchanged" else "Download request rejected")
        return accepted
    }

    fun applyDisposableDownloadChunk(): Boolean {
        val accepted = fileController.applyAuthoritativeDownloadChunk("phase148 disposable download\n".encodeToByteArray())
        publishFilesState(if (accepted) "Disposable authoritative download bytes applied" else "Download chunk rejected")
        return accepted
    }

    fun applyDisposableDownloadEof(): Boolean {
        val accepted = fileController.applyAuthoritativeDownloadChunk(byteArrayOf())
        publishFilesState(if (accepted) "Disposable authoritative EOF completed download" else "Download EOF rejected")
        return accepted
    }

    fun requestDisposableForwardOpen(): Boolean {
        val accepted = networkController.requestForwardOpen(
            DISPOSABLE_FORWARD_ID,
            LoopbackFamilyView.Ipv4,
            41_149,
            "127.0.0.1",
            22,
        )
        publishNetworkState(if (accepted) "Forward-open intent encoded; no socket opened" else "Forward-open intent rejected")
        return accepted
    }

    fun applyDisposableForwardOpen(): Boolean {
        val accepted = networkController.applyAuthoritativeForwardOpen(DISPOSABLE_FORWARD_ID)
        publishNetworkState(if (accepted) "Disposable authoritative forward-open acknowledgement applied" else "Forward-open acknowledgement rejected")
        return accepted
    }

    fun requestDisposableForwardClose(): Boolean {
        val accepted = networkController.requestForwardClose()
        publishNetworkState(if (accepted) "Forward-close intent encoded; completion not forged" else "Forward-close intent rejected")
        return accepted
    }

    fun applyDisposableForwardClosed(): Boolean {
        val accepted = networkController.applyAuthoritativeForwardClosed(DISPOSABLE_FORWARD_ID)
        publishNetworkState(if (accepted) "Disposable authoritative forward-close acknowledgement applied" else "Forward-close acknowledgement rejected")
        return accepted
    }

    fun applyDisposableConnectivitySnapshot(): Boolean {
        val accepted = networkController.applyAuthoritativeConnectivitySnapshot(
            ReachabilityView.Unreachable,
            ReachabilityView.Reachable,
            ReachabilityView.Reachable,
        )
        publishNetworkState(if (accepted) "Disposable authoritative connectivity snapshot selected existing path" else "Connectivity snapshot rejected")
        return accepted
    }

    fun validateDisposablePrivateDns(): Boolean {
        val accepted = networkController.validatePrivateDnsDraft(
            enabled = true,
            deviceNaming = true,
            deviceDomain = "prw.internal",
            resolverAddress = "127.0.0.1",
            resolverPort = 53,
            splitDomain = "dev.internal",
        )
        publishNetworkState(if (accepted) "Private-DNS draft validated; OS resolver remains unchanged" else "Private-DNS draft rejected")
        return accepted
    }

    fun validateDisabledPrivateDns(): Boolean {
        val accepted = networkController.validatePrivateDnsDraft(
            enabled = false,
            deviceNaming = false,
            deviceDomain = "",
            resolverAddress = "",
            resolverPort = 0,
            splitDomain = "",
        )
        publishNetworkState(if (accepted) "Private-DNS disabled draft validated; connectivity remains independent" else "Disabled DNS draft rejected")
        return accepted
    }

    fun disconnect() {
        val current = controller.state.value
        if (current == ConnectionState.Connected || current == ConnectionState.Suspended) {
            check(controller.transition(ConnectionState.Disconnecting))
            check(controller.transition(ConnectionState.Disconnected))
        } else if (current == ConnectionState.Error) {
            check(controller.transition(ConnectionState.Disconnected))
        }
        mutableUiState.value = mutableUiState.value.copy(
            connectionState = controller.state.value,
            bootstrapValidated = false,
            detail = "Development bootstrap only — no production endpoint",
        )
    }

    private fun publish(detail: String) {
        mutableUiState.value = mutableUiState.value.copy(
            connectionState = controller.state.value,
            detail = detail,
        )
    }

    private fun publishDeviceState(detail: String) {
        val deviceState = deviceManagement.state()
        mutableUiState.value = mutableUiState.value.copy(
            devices = deviceState.devices,
            pendingRevocationDeviceId = deviceState.pendingRevocationDeviceId,
            detail = detail,
        )
    }

    private fun publishFilesState(detail: String) {
        mutableUiState.value = mutableUiState.value.copy(files = fileController.state(), detail = detail)
    }

    private fun publishNetworkState(detail: String) {
        mutableUiState.value = mutableUiState.value.copy(
            network = networkController.state(),
            detail = detail,
        )
    }

    private fun publishTerminalState(detail: String) {
        mutableUiState.value = mutableUiState.value.copy(
            terminal = terminalController.state(),
            detail = detail,
        )
    }

    companion object {
        private const val DISPOSABLE_TERMINAL_SESSION_ID = 147_001L
        private const val DISPOSABLE_FORWARD_ID = 149_001L
    }
}
