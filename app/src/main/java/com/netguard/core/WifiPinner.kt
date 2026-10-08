package com.netguard.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.DatagramSocket
import java.net.Socket

/**
 * Pins sockets to the WiFi [Network] instead of trusting the process default.
 *
 * Why this exists: a phone can have WiFi AND cellular (LTE, often ROAMING)
 * connected at the same time. Socket.bind(null) + connect() then resolves via
 * the per-UID routing rules, which on this device sent app sockets into the
 * cellular agent — where 192.168.2.x is unroutable and the packets vanish.
 * (Symptom seen on-device: ARP/host discovery worked because ARP is L2 on
 * wlan0, while every TCP connect and the public-IP HTTP fetch timed out.)
 *
 * Bind-before-connect to the WiFi network forces the kernel to route those
 * sockets over wlan0 and use its routing table (LAN + default via AP) —
 * both requirements for port probing and public-IP lookup to work.
 */
object WifiPinner {

    @Volatile private var wifiNetwork: Network? = null

    /** Call from Application.onCreate and refresh on WiFi connect/reconnect. */
    @Synchronized
    fun refresh(context: Context) {
        wifiNetwork = try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.allNetworks.firstOrNull { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
        } catch (_: Exception) {
            null
        }
    }

    val hasWifi: Boolean get() = wifiNetwork != null

    /**
     * Bind a TCP socket to the WiFi network (bind-before-connect — required
     * order for per-network binding). Falls back silently when WiFi is gone;
     * the default-network path remains.
     */
    fun bindTcp(socket: Socket) {
        try {
            wifiNetwork?.bindSocket(socket)
        } catch (_: Exception) {
            // Network dropped between refresh and bind: leave default routing.
        }
    }

    /** Bind a UDP socket to the WiFi network (mDNS/SSDP listeners, QUIC-style probes). */
    fun bindUdp(socket: DatagramSocket) {
        try {
            wifiNetwork?.bindSocket(socket)
        } catch (_: Exception) {
        }
    }

    /**
     * HttpURLConnection bound to the WiFi network (RDAP/AbuseIPDB/idify class
     * lookups that use the platform HTTP stack instead of OkHttp).
     */
    fun openHttpConnection(url: java.net.URL): java.net.HttpURLConnection? = try {
        wifiNetwork?.openConnection(url) as? java.net.HttpURLConnection
    } catch (_: Exception) {
        null
    }
}