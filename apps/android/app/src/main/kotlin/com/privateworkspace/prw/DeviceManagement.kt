package com.privateworkspace.prw

internal enum class DeviceLifecycleView {
    PendingEnrollment,
    Enrolled,
    Revoked,
}

internal data class DeviceSnapshot(
    val deviceId: String,
    val lifecycle: DeviceLifecycleView,
)

internal data class DeviceManagementState(
    val devices: List<DeviceSnapshot> = emptyList(),
    val pendingRevocationDeviceId: String? = null,
)

internal class DeviceManagementController {
    private var current = DeviceManagementState()

    fun state(): DeviceManagementState = current

    fun applyAuthoritativeSnapshot(devices: List<DeviceSnapshot>): Boolean {
        if (devices.size > MAX_DEVICES) return false
        val ids = HashSet<String>()
        for (device in devices) {
            val bytes = device.deviceId.toByteArray(Charsets.UTF_8)
            if (bytes.isEmpty() || bytes.size > MAX_DEVICE_ID_BYTES || !ids.add(device.deviceId)) {
                return false
            }
        }
        val pending = current.pendingRevocationDeviceId?.takeIf { deviceId ->
            devices.any { it.deviceId == deviceId && it.lifecycle == DeviceLifecycleView.Enrolled }
        }
        current = DeviceManagementState(devices = devices.toList(), pendingRevocationDeviceId = pending)
        return true
    }

    fun requestRevocation(deviceId: String): Boolean {
        if (current.pendingRevocationDeviceId != null) return false
        val device = current.devices.singleOrNull { it.deviceId == deviceId } ?: return false
        if (device.lifecycle != DeviceLifecycleView.Enrolled) return false
        current = current.copy(pendingRevocationDeviceId = deviceId)
        return true
    }

    companion object {
        private const val MAX_DEVICES = 256
        private const val MAX_DEVICE_ID_BYTES = 1024
    }
}
