package com.privateworkspace.prw

internal object NativeBridge {
    init {
        System.loadLibrary("prw_android_adapter")
    }

    @JvmStatic external fun protocolVersion(): Int
    @JvmStatic external fun roundTripControlFrame(frame: ByteArray): ByteArray
    @JvmStatic external fun canonicalSessionMessage(request: ByteArray): ByteArray
    @JvmStatic external fun verifySessionSignature(request: ByteArray, signature: ByteArray): Boolean
    @JvmStatic external fun canonicalEnrollmentMessage(request: ByteArray): ByteArray
    @JvmStatic external fun verifyEnrollmentSignature(request: ByteArray, signature: ByteArray): Boolean
    @JvmStatic external fun terminalOpenPayload(sessionId: Long, profileCode: Int, columns: Int, rows: Int): ByteArray
    @JvmStatic external fun terminalInputPayload(sessionId: Long, input: ByteArray): ByteArray
    @JvmStatic external fun terminalResizePayload(sessionId: Long, columns: Int, rows: Int): ByteArray
    @JvmStatic external fun terminalReadPayload(sessionId: Long, maximumBytes: Int): ByteArray
    @JvmStatic external fun terminalClosePayload(sessionId: Long): ByteArray
    @JvmStatic external fun isTerminalPayload(payload: ByteArray): Boolean
    @JvmStatic external fun fileListPayload(path: ByteArray): ByteArray
    @JvmStatic external fun fileStatPayload(path: ByteArray): ByteArray
    @JvmStatic external fun uploadBeginPayload(transferId: ByteArray, destination: ByteArray, totalBytes: Long, sha256: ByteArray): ByteArray
    @JvmStatic external fun uploadResumePayload(transferId: ByteArray, destination: ByteArray, totalBytes: Long, sha256: ByteArray): ByteArray
    @JvmStatic external fun uploadChunkPayload(transferId: ByteArray, offset: Long, chunk: ByteArray): ByteArray
    @JvmStatic external fun uploadFinalizePayload(transferId: ByteArray): ByteArray
    @JvmStatic external fun uploadAbortPayload(transferId: ByteArray): ByteArray
    @JvmStatic external fun downloadChunkPayload(path: ByteArray, offset: Long, requestedBytes: Int): ByteArray
    @JvmStatic external fun isFileTransferPayload(payload: ByteArray): Boolean
    @JvmStatic external fun forwardOpenPayload(forwardId: Long, familyCode: Int, bindPort: Int, targetAddress: ByteArray, targetPort: Int): ByteArray
    @JvmStatic external fun forwardClosePayload(forwardId: Long): ByteArray
    @JvmStatic external fun isForwardingPayload(payload: ByteArray): Boolean
    @JvmStatic external fun connectivitySelectedPath(localObservation: Int, internetObservation: Int, relayObservation: Int): Int
    @JvmStatic external fun validatePrivateDnsConfig(enabled: Boolean, deviceNaming: Boolean, deviceDomain: ByteArray, resolverAddress: ByteArray, resolverPort: Int, splitDomain: ByteArray): Boolean
}
