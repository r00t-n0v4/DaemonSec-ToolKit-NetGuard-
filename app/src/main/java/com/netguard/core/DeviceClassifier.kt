package com.netguard.core

/**
 * Shared device-type classifier used across BLE, WiFi AP SSIDs, and
 * mDNS/SSDP hostnames — so a Bravia TV groups the same whether it was heard
 * as an access point, an advertisement, or a Cast beacon. Name rules win;
 * Bluetooth company IDs / service UUIDs fill in for unnamed devices.
 */
object DeviceClassifier {

    const val CAT_FLIPPER = "Flipper Zero"
    const val CAT_TRACKER = "Trackers"
    const val CAT_GLASSES = "Meta/AR Glasses"
    const val CAT_AUDIO = "Headphones/Audio"
    const val CAT_TV = "TV/Media"
    const val CAT_WEARABLE = "Wearables"
    const val CAT_VEHICLE = "Vehicle"
    const val CAT_DEVBOARD = "Dev Boards (ESP32/nRF)"
    const val CAT_COMPUTER = "Phones/Computers"
    const val CAT_HID = "HID/Input/Remotes"
    const val CAT_HIDDEN = "Hidden Networks"
    const val CAT_THISPHONE = "This Phone"
    const val CAT_GATEWAY = "Gateway/Router"
    const val CAT_OTHER = "Other"

    /** Display order for grouped views. */
    val CATEGORY_ORDER = listOf(
        CAT_THISPHONE, CAT_GATEWAY,
        CAT_FLIPPER, CAT_TRACKER, CAT_GLASSES, CAT_AUDIO, CAT_TV,
        CAT_WEARABLE, CAT_HID, CAT_VEHICLE, CAT_DEVBOARD, CAT_COMPUTER,
        CAT_HIDDEN, CAT_OTHER
    )

    /**
     * Hardware MAC signature table — strongest signal, survives renames
     * (a Flipper advertising as "R4v3n" still wears its OUI). 80:E1:26 is
     * the Flipper Zero BLE MAC prefix (observed empirically: both flipper
     * test devices wear it regardless of advertised name).
     */
    private val MAC_OUI_RULES: List<Pair<String, String>> = listOf(
        "80:E1:26" to CAT_FLIPPER
    )

    private fun classifyMac(mac: String?): String? {
        if (mac.isNullOrBlank()) return null
        val oui = mac.uppercase().replace("-", ":").take(8)
        return MAC_OUI_RULES.firstOrNull { it.first == oui }?.second
    }

    private val NAME_RULES: List<Pair<Regex, String>> = listOf(
        Regex("flipper|marauder", RegexOption.IGNORE_CASE) to CAT_FLIPPER,
        Regex("ray-?ban|meta|quest|story|wayfarer|hololens|viture|rokid|xreal", RegexOption.IGNORE_CASE) to CAT_GLASSES,
        Regex("airpods?|buds|beats|bose|jbl|headphone|headset|earbud|earphone|soundcore|liberty|sesh|wh-1000|wf-1000|tozo|mifo|sonos|homepod|echo|nest audio|speaker|soundbar", RegexOption.IGNORE_CASE) to CAT_AUDIO,
        Regex("bravia|roku|fire ?tv|firestick|chromecast|\\bcast\\b|shield|webos|tizen|google ?tv|vizio|\\btcl\\b|hisense|smart ?tv|samsung.*tv|apple ?tv|projector|denon|yamaha.*av|onkyo", RegexOption.IGNORE_CASE) to CAT_TV,
        Regex("tile|airtag|smart ?tag|chipolo|nomad|pebblebee", RegexOption.IGNORE_CASE) to CAT_TRACKER,
        Regex("watch|fitbit|oura|\\bring\\b|pebble|amazfit|garmin|mi band|band [0-9]", RegexOption.IGNORE_CASE) to CAT_WEARABLE,
        Regex("tesla|\\bbmw\\b|\\bjeep\\b|\\bcar\\b|vehicle|model [3y]|ioniq|\\bleaf\\b|carlinkit", RegexOption.IGNORE_CASE) to CAT_VEHICLE,
        Regex("esp32|esp8266|nrf52?|adafruit|nucleo|bluefruit|feather|raspberry|\\bpico\\b|mcu|marauder|wifi dev", RegexOption.IGNORE_CASE) to CAT_DEVBOARD,
        Regex("iphone|ipad|macbook|galaxy s|pixel [3-9]|thinkpad|xps|desktop|notebook|surface|win ?book|\\blap\\b|laptop", RegexOption.IGNORE_CASE) to CAT_COMPUTER,
        Regex("keyboard|mouse|remote|\\bhid\\b|trackpad|airturn", RegexOption.IGNORE_CASE) to CAT_HID
    )

    // Bluetooth SIG company identifiers useful for classification
    private const val COMPANY_APPLE = 0x004C
    private const val COMPANY_MICROSOFT = 0x0006
    private const val COMPANY_SAMSUNG = 0x0075
    private const val COMPANY_GOOGLE = 0x00E0

    private val TRACKER_SERVICE_UUIDS = setOf(
        "0000fd6f-0000-1000-8000-00805f9b34fb",   // Chipolo
        "0000fe2c-0000-1000-8000-00805f9b34fb"    // Samsung SmartTag
    )
    private val AUDIO_SERVICE_UUIDS = setOf(
        "0000110b", "0000110c", "0000110e", "0000110f", "0000111e", "0000111f", "0000110a"
    )

    /** Full classifier: hardware MAC OUI first, then name, UUIDs, mfg IDs. */
    fun categorize(
        name: String?,
        serviceUuids: List<String>,
        companies: List<Int> = emptyList(),
        appleFindMyBeacon: Boolean = false,
        mac: String? = null
    ): String {
        classifyMac(mac)?.let { return it }
        if (appleFindMyBeacon) return CAT_TRACKER
        if (!name.isNullOrBlank()) {
            NAME_RULES.firstOrNull { it.first.containsMatchIn(name) }?.let { return it.second }
        }
        val uuids = serviceUuids.map { it.lowercase() }
        uuids.firstOrNull { u -> TRACKER_SERVICE_UUIDS.any { t -> u.startsWith(t.take(8)) } }?.let { return CAT_TRACKER }
        uuids.firstOrNull { u -> u.startsWith("0000fe9f") }?.let { return CAT_GLASSES } // Google AR beacon
        uuids.firstOrNull { u -> AUDIO_SERVICE_UUIDS.any { a -> u.startsWith(a) } }?.let { return CAT_AUDIO }
        uuids.firstOrNull { it.startsWith("00001812") }?.let { return CAT_HID } // HID over GATT

        companies.firstOrNull { c ->
            when (c) {
                COMPANY_MICROSOFT, COMPANY_SAMSUNG, COMPANY_GOOGLE -> true
                else -> false
            }
        }?.let { return CAT_COMPUTER }
        if (companies.contains(COMPANY_APPLE)) return CAT_COMPUTER // Apple generic; Find My handled above

        return CAT_OTHER
    }

    /** Vendor-string classifier for ARP/scan results ("Raspberry Pi Trading"). */
    fun classifyVendor(vendor: String?): String? =
        vendor?.let { v -> NAME_RULES.firstOrNull { it.first.containsMatchIn(v) }?.second }

    /**
     * OS inference for a LAN host from signals an unrooted phone can see:
     * open-port pattern, grabbed service banners (SSH/HTTP/FTP announce
     * product+OS), OUI vendor, and hostname. Output is a HINT for reports
     * ("likely Windows (RDP+SMB)") — TCP-stack fingerprinting beyond this
     * needs raw sockets, which non-rooted Android forbids.
     */
    fun guessOs(
        openPorts: Collection<Int>,
        banners: Map<Int, String> = emptyMap(),
        vendor: String? = null,
        hostname: String? = null
    ): String? {
        val h = hostname?.lowercase() ?: ""
        val v = vendor?.lowercase() ?: ""
        val texts = (banners.values.joinToString(" ") + " " + h).lowercase()

        // banner-direct OS strings beat everything
        when {
            texts.contains("ubuntu") -> return "Linux (Ubuntu)"
            texts.contains("debian") -> return "Linux (Debian)"
            texts.contains("freebsd") -> return "FreeBSD"
            texts.contains("busybox") -> return "Linux (embedded/BusyBox)"
            texts.contains("mikrotik") || texts.contains("routeros") -> return "RouterOS (MikroTik)"
            texts.contains("windows") || texts.contains("iis/") -> return "Windows"
        }

        // port-pattern inferences
        val portOs = when {
            3389 in openPorts -> "Windows (RDP open)"
            445 in openPorts && 139 in openPorts -> "Windows (SMB/NetBIOS)"
            445 in openPorts -> "Windows or Samba (SMB)"
            548 in openPorts -> "macOS (AFP open)"
            5555 in openPorts -> "Android (ADB exposed!)"
            9100 in openPorts -> "printer (JetDirect)"
            else -> null
        }
        if (portOs != null) return portOs

        // vendor / hostname hints
        return when {
            v.contains("apple") -> "macOS/iOS device (Apple)"
            v.contains("raspberry") -> "Linux (Raspberry Pi)"
            v.contains("google") -> "Android/Google device"
            v.contains("synology") || v.contains("qnap") -> "Linux NAS"
            h.contains("iphone") || h.contains("ipad") || h.contains("mbp") || h.contains("macbook") -> "macOS/iOS device"
            h.contains("android") || h.contains("pixel") || h.contains("galaxy") -> "Android"
            22 in openPorts -> "Linux/Unix (SSH)"
            80 in openPorts || 443 in openPorts -> "runs a web service"
            else -> null
        }
    }

    /** True if the category should render in the red/alerted style. */
    fun isAlertCategory(category: String): Boolean =
        category == CAT_TRACKER || category == CAT_FLIPPER

    /**
     * Reads the category of any finding row by decoding its payload:
     * WifiAp.category / BleDevice.category / Host.category, else null.
     * Falls back to hardware MAC classification (payload's bssid/address/mac
     * field) when the stored category says "Other" — so rows stored before a
     * classifier upgrade still group correctly (Flipper OUI beats stale data).
     */
    fun categoryOfEntity(json: String): String? = try {
        val stored: String? = when {
            json.contains("WifiAp") -> kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
                .decodeFromString(Finding.WifiAp.serializer(), json).category
            json.contains("BleDevice") -> kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
                .decodeFromString(Finding.BleDevice.serializer(), json).category
            json.contains("Finding.Host") -> kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
                .decodeFromString(Finding.Host.serializer(), json).category
            else -> null
        }
        if (stored != null && stored != CAT_OTHER) {
            stored
        } else {
            // Hardware-MAC fallback (Flipper OUI etc.) beats a stale "Other" verdict
            val mac = Regex("\"(?:bssid|address|mac)\"\\s*:\\s*\"([0-9a-fA-F:-]{11,17})\"")
                .find(json)?.groupValues?.get(1)
            classifyMac(mac) ?: stored
        }
    } catch (_: Exception) {
        null
    }
}