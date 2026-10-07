package com.netguard.net

import com.netguard.core.SocketProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * HTTP client whose sockets are marked with VpnService.protect() when a VPN
 * session is active, so recon/OSINT traffic bypasses the TUN instead of
 * dying in the observe-only TCP path. Outside a session, protection is a
 * no-op and this behaves like any normal client.
 */
object ProtectedHttp {

    private val lock = Any()
    @Volatile private var cached: OkHttpClient? = null

    val client: OkHttpClient
        get() = cached ?: synchronized(lock) { cached ?: build().also { cached = it } }

    private fun build(): OkHttpClient {
        val tm = defaultTrustManager()
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(tm), SecureRandom())
        return OkHttpClient.Builder()
            .socketFactory(ProtectedPlainSocketFactory())
            .sslSocketFactory(ProtectedSslSocketFactory(ctx.socketFactory), tm)
            .connectTimeout(java.time.Duration.ofSeconds(15))
            .readTimeout(java.time.Duration.ofSeconds(25))
            .build()
    }

    private fun defaultTrustManager(): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as java.security.KeyStore?)
        return factory.trustManagers.first { it is X509TrustManager } as X509TrustManager
    }

    // --- politeness: global min-interval between outgoing requests ---

    private val throttleMutex = Mutex()
    @Volatile private var lastRequestAt = 0L

    suspend fun throttle(minIntervalMs: Long = 120) {
        throttleMutex.withLock {
            val now = System.currentTimeMillis()
            val wait = lastRequestAt + minIntervalMs - now
            if (wait > 0) delay(wait)
            lastRequestAt = System.currentTimeMillis()
        }
    }

    /** GET helper returning (httpCode, body) or null on transport failure. */
    suspend fun get(
        url: String,
        headers: Map<String, String> = emptyMap(),
        minIntervalMs: Long = 120
    ): Pair<Int, String>? = withContext(Dispatchers.IO) {
        throttle(minIntervalMs)
        runCatching {
            val builder = Request.Builder().url(url).get()
            headers.forEach { (k, v) -> builder.header(k, v) }
            client.newCall(builder.build()).execute().use { resp ->
                resp.code to (resp.body?.string() ?: "")
            }
        }.getOrNull()
    }
}

/** Plain sockets: bind + protect BEFORE connect, so the VPN excludes them. */
class ProtectedPlainSocketFactory : SocketFactory() {

    private fun newProtectedSocket(): Socket = Socket().also {
        it.bind(null)
        SocketProtector.protect(it)
    }

    override fun createSocket(): Socket = newProtectedSocket()

    override fun createSocket(host: String, port: Int): Socket =
        newProtectedSocket().apply { connect(InetSocketAddress(host, port), 15000) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        newProtectedSocket().apply {
            bind(InetSocketAddress(localHost, localPort))
            connect(InetSocketAddress(host, port), 15000)
        }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        createSocket(host.hostAddress ?: host.toString(), port)

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        createSocket(address.hostAddress ?: address.toString(), port, localAddress, localPort)
}

/**
 * TLS sockets: obtain a plain protected + connected socket first, then let
 * the platform's SSLSocketFactory layer TLS on top of it.
 */
class ProtectedSslSocketFactory(private val base: SSLSocketFactory) : SSLSocketFactory() {

    private fun protectedConnected(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        val raw = Socket()
        raw.bind(if (localHost != null) InetSocketAddress(localHost, localPort) else null)
        SocketProtector.protect(raw)
        raw.connect(InetSocketAddress(host, port), 15000)
        return raw
    }

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
        base.createSocket(s, host, port, autoClose)

    override fun createSocket(host: String, port: Int): Socket =
        base.createSocket(protectedConnected(host, port, null, 0), host, port, true)

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        base.createSocket(protectedConnected(host, port, localHost, localPort), host, port, true)

    override fun createSocket(host: InetAddress, port: Int): Socket =
        base.createSocket(protectedConnected(host.hostAddress ?: host.toString(), port, null, 0),
            host.hostAddress ?: host.toString(), port, true)

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        base.createSocket(
            protectedConnected(address.hostAddress ?: address.toString(), port, localAddress, localPort),
            address.hostAddress ?: address.toString(), port, true
        )

    override fun getDefaultCipherSuites(): Array<String> = base.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = base.supportedCipherSuites
}