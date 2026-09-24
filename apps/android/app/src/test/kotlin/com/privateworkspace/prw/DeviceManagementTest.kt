package com.privateworkspace.prw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceManagementTest {
    @Test fun revocation_intent_does_not_forge_authoritative_lifecycle() {
        val controller = DeviceManagementController()
        assertTrue(controller.applyAuthoritativeSnapshot(listOf(DeviceSnapshot("device-1", DeviceLifecycleView.Enrolled))))
        assertTrue(controller.requestRevocation("device-1"))
        assertEquals(DeviceLifecycleView.Enrolled, controller.state().devices.single().lifecycle)
        assertEquals("device-1", controller.state().pendingRevocationDeviceId)
        assertFalse(controller.requestRevocation("device-1"))
    }

    @Test fun only_enrolled_device_may_request_revocation() {
        val controller = DeviceManagementController()
        assertTrue(controller.applyAuthoritativeSnapshot(listOf(
            DeviceSnapshot("pending", DeviceLifecycleView.PendingEnrollment),
            DeviceSnapshot("revoked", DeviceLifecycleView.Revoked),
        )))
        assertFalse(controller.requestRevocation("pending"))
        assertFalse(controller.requestRevocation("revoked"))
        assertNull(controller.state().pendingRevocationDeviceId)
    }

    @Test fun authoritative_revoked_snapshot_clears_pending_intent() {
        val controller = DeviceManagementController()
        assertTrue(controller.applyAuthoritativeSnapshot(listOf(DeviceSnapshot("device-1", DeviceLifecycleView.Enrolled))))
        assertTrue(controller.requestRevocation("device-1"))
        assertTrue(controller.applyAuthoritativeSnapshot(listOf(DeviceSnapshot("device-1", DeviceLifecycleView.Revoked))))
        assertEquals(DeviceLifecycleView.Revoked, controller.state().devices.single().lifecycle)
        assertNull(controller.state().pendingRevocationDeviceId)
    }

    @Test fun duplicate_device_identifiers_fail_without_mutation() {
        val controller = DeviceManagementController()
        val baseline = listOf(DeviceSnapshot("device-1", DeviceLifecycleView.Enrolled))
        assertTrue(controller.applyAuthoritativeSnapshot(baseline))
        assertFalse(controller.applyAuthoritativeSnapshot(listOf(
            DeviceSnapshot("device-1", DeviceLifecycleView.Enrolled),
            DeviceSnapshot("device-1", DeviceLifecycleView.Revoked),
        )))
        assertEquals(baseline, controller.state().devices)
    }
}
