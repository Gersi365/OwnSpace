package com.privateworkspace.prw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

internal class NetworkManagementControllerTest {
    private class FakeEncoder : NetworkCommandEncoder {
        var openPayload = byteArrayOf(1, 2, 3)
        var closePayload = byteArrayOf(4, 5)
        var selectedPathCode = 0
        var dnsAccepted = true

        override fun forwardOpen(
            forwardId: Long,
            family: LoopbackFamilyView,
            bindPort: Int,
            targetAddress: String,
            targetPort: Int,
        ): ByteArray = openPayload

        override fun forwardClose(forwardId: Long): ByteArray = closePayload

        override fun selectedPath(
            local: ReachabilityView,
            internet: ReachabilityView,
            relay: ReachabilityView,
        ): Int = selectedPathCode

        override fun validatePrivateDns(
            enabled: Boolean,
            deviceNaming: Boolean,
            deviceDomain: String,
            resolverAddress: String,
            resolverPort: Int,
            splitDomain: String,
        ): Boolean = dnsAccepted
    }

    @Test
    fun forwarding_requires_explicit_authoritative_acknowledgements() {
        val encoder = FakeEncoder()
        val controller = NetworkManagementController(encoder)

        assertTrue(controller.requestForwardOpen(149001, LoopbackFamilyView.Ipv4, 4149, "127.0.0.1", 22))
        assertEquals(ForwardLifecycleView.Opening, controller.state().forwarding.lifecycle)
        assertFalse(controller.requestForwardClose())
        assertTrue(controller.applyAuthoritativeForwardOpen(149001))
        assertEquals(ForwardLifecycleView.Active, controller.state().forwarding.lifecycle)
        assertTrue(controller.requestForwardClose())
        assertEquals(ForwardLifecycleView.Closing, controller.state().forwarding.lifecycle)
        assertTrue(controller.applyAuthoritativeForwardClosed(149001))
        assertEquals(ForwardLifecycleView.Closed, controller.state().forwarding.lifecycle)
    }

    @Test
    fun empty_forward_payload_fails_without_fabricating_state() {
        val encoder = FakeEncoder().also { it.openPayload = byteArrayOf() }
        val controller = NetworkManagementController(encoder)
        assertFalse(controller.requestForwardOpen(149001, LoopbackFamilyView.Ipv4, 4149, "127.0.0.1", 22))
        assertEquals(ForwardLifecycleView.Closed, controller.state().forwarding.lifecycle)
    }

    @Test
    fun connectivity_changes_only_through_authoritative_snapshot_application() {
        val encoder = FakeEncoder().also { it.selectedPathCode = 2 }
        val controller = NetworkManagementController(encoder)
        assertEquals(ConnectivityPathView.Offline, controller.state().selectedPath)
        assertTrue(
            controller.applyAuthoritativeConnectivitySnapshot(
                ReachabilityView.Unreachable,
                ReachabilityView.Reachable,
                ReachabilityView.Reachable,
            ),
        )
        assertEquals(ConnectivityPathView.InternetDirect, controller.state().selectedPath)
    }

    @Test
    fun dns_validation_never_claims_operating_system_application() {
        val encoder = FakeEncoder()
        val controller = NetworkManagementController(encoder)
        assertTrue(
            controller.validatePrivateDnsDraft(
                true,
                true,
                "prw.internal",
                "127.0.0.1",
                53,
                "dev.internal",
            ),
        )
        val dns = controller.state().privateDns
        assertTrue(dns.requestedEnabled)
        assertTrue(dns.validated)
        assertFalse(dns.osApplied)

        encoder.dnsAccepted = false
        assertFalse(controller.validatePrivateDnsDraft(true, true, "BAD", "", 0, ""))
        assertEquals(dns, controller.state().privateDns)
    }
}
