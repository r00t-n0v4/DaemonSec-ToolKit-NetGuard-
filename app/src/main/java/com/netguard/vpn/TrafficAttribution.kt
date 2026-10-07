package com.netguard.vpn

/**
 * Best-effort per-app attribution for TUN flows.
 *
 * Honest limitation: since Android 10 (Q), an app reading /proc/net/tcp|udp
 * only sees ITS OWN sockets — every other app's rows are filtered out by the
 * kernel (no hidden API needed, it's a procfs access control). So: flows
 * originated by NetGuard itself resolve to com.netguard, everything else
 * returns null. The field stays in the data model so a rooted build (or a
 * future API) can fill it in without a schema change.
 */
object TrafficAttribution {

    private const val SELF_PACKAGE = "com.netguard"

    private fun myUid(): Int = android.os.Process.myUid()

    /** Reads the local-port -> uid mapping for this app's own sockets only. */
    private fun ownLocalPorts(): Map<Int, Int> {
        val out = HashMap<Int, Int>()
        val me = myUid()
        for (table in listOf("/proc/net/tcp", "/proc/net/udp")) {
            try {
                java.io.File(table).readLines().drop(1).forEach { line ->
                    val cols = line.trim().split(Regex("\\s+"))
                    // sl local_address rem_address ... uid ...
                    if (cols.size >= 8) {
                        val port = cols[1].substringAfter(":").toIntOrNull(16) ?: return@forEach
                        val uid = cols[7].toIntOrNull() ?: return@forEach
                        if (uid == me) out[port] = uid
                    }
                }
            } catch (_: Exception) {
            }
        }
        return out
    }

    /**
     * Attribution for a TUN flow keyed by its source (originating) port.
     * Returns the package name only for NetGuard's own flows; null otherwise.
     */
    fun attributablePackage(srcPort: Int): String? =
        if (ownLocalPorts().containsKey(srcPort)) SELF_PACKAGE else null
}