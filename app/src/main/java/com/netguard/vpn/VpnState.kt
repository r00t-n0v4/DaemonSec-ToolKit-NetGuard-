package com.netguard.vpn

import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Process-wide VPN running state. The service flips it on establish/death;
 * the UI observes it so the Monitor tab can offer direct Disconnect/Enable
 * controls and stay truthful even after an app relaunch while the tunnel
 * (START_STICKY) keeps running.
 */
object VpnState {
    val active = MutableStateFlow(false)
}