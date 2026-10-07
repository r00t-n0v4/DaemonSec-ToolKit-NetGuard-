package com.netguard.core

import java.net.DatagramSocket
import java.net.Socket

/**
 * Lets non-service modules mark their sockets so their traffic bypasses the
 * VPN (otherwise an active session would tunnel the app's own scans back into
 * itself and, with TCP unforwarded, break them entirely). The VpnService
 * registers the real protect() implementations when it establishes; before
 * that, protecting is a no-op (no VPN → nothing to bypass).
 */
object SocketProtector {
    @Volatile var protectSocketImpl: ((Socket) -> Unit)? = null
    @Volatile var protectDatagramImpl: ((DatagramSocket) -> Unit)? = null

    fun protect(socket: Socket) {
        try { protectSocketImpl?.invoke(socket) } catch (_: Exception) {}
    }

    fun protectDatagram(socket: DatagramSocket) {
        try { protectDatagramImpl?.invoke(socket) } catch (_: Exception) {}
    }
}