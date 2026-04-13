package com.example.etc.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Locale
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import kotlin.math.max
import kotlin.math.min

internal class UpstreamDnsResolver(
    private val vpnService: VpnService
) {
    private data class UpstreamCandidate(
        val network: Network?,
        val dnsServer: InetAddress
    )

    private data class QueryResult(
        val candidate: UpstreamCandidate,
        val response: ByteArray? = null,
        val error: Exception? = null
    )

    private data class CachedResponse(
        val response: ByteArray,
        val expiresAtMs: Long
    )

    private val connectivityManager =
        vpnService.getSystemService(ConnectivityManager::class.java)
    private val queryExecutor: ExecutorService = Executors.newFixedThreadPool(MAX_PARALLEL_QUERIES)
    private val responseCache = object : LinkedHashMap<String, CachedResponse>(MAX_CACHE_ENTRIES, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedResponse>?): Boolean {
            return size > MAX_CACHE_ENTRIES
        }
    }
    private val candidateCooldownUntilMs = mutableMapOf<String, Long>()

    @Volatile
    private var privateDnsWarningLogged = false

    fun resolve(rawQuery: ByteArray): ByteArray? {
        val queryKey = buildQueryKey(rawQuery)
        val candidates = findDnsCandidates()
        Log.i(LOG_TAG, "Upstream resolver candidates=${candidates.joinToString(",") { candidateLabel(it) }}")

        val liveResponse = queryCandidatesParallel(rawQuery, candidates)
        if (liveResponse != null) {
            cacheResponseIfEligible(queryKey, liveResponse)
            return liveResponse
        }

        val cachedResponse = readCachedResponse(queryKey, rawQuery)
        if (cachedResponse != null) {
            return cachedResponse
        }

        Log.w(LOG_TAG, "Upstream resolver returned null response")
        return null
    }

    fun close() {
        queryExecutor.shutdownNow()
    }

    private fun queryCandidatesParallel(rawQuery: ByteArray, candidates: List<UpstreamCandidate>): ByteArray? {
        if (candidates.isEmpty()) {
            return null
        }

        val completion = ExecutorCompletionService<QueryResult>(queryExecutor)
        val futures = mutableListOf<Future<QueryResult>>()
        val submitted = candidates.size

        for (index in 0 until submitted) {
            val candidate = candidates[index]
            futures += completion.submit(
                Callable {
                    try {
                        QueryResult(
                            candidate = candidate,
                            response = querySingleCandidate(candidate, rawQuery)
                        )
                    } catch (e: Exception) {
                        QueryResult(
                            candidate = candidate,
                            error = e
                        )
                    }
                }
            )
        }

        for (index in 0 until submitted) {
            val future = try {
                completion.take()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return null
            }

            val result = try {
                future.get()
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Upstream query future failed: ${e.message}")
                continue
            }

            val response = result.response
            if (response != null) {
                markCandidateSuccess(result.candidate)
                Log.i(
                    LOG_TAG,
                    "Upstream response from ${result.candidate.dnsServer.hostAddress} len=${response.size}"
                )
                futures.forEach { queued ->
                    if (queued !== future) {
                        queued.cancel(true)
                    }
                }
                return response
            }

            markCandidateFailure(result.candidate, result.error)
        }

        return null
    }

    private fun querySingleCandidate(candidate: UpstreamCandidate, rawQuery: ByteArray): ByteArray {
        val dnsServer = candidate.dnsServer
        DatagramSocket().use { socket ->
            if (candidate.network != null) {
                candidate.network.bindSocket(socket)
            } else if (!vpnService.protect(socket)) {
                throw IOException("protect(socket) failed for ${dnsServer.hostAddress}")
            }

            socket.soTimeout = SINGLE_QUERY_TIMEOUT_MS
            socket.connect(InetSocketAddress(dnsServer, DNS_PORT))
            socket.send(DatagramPacket(rawQuery, rawQuery.size))

            val responseBuffer = ByteArray(MAX_DNS_PACKET_SIZE)
            val response = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(response)
            return response.data.copyOf(response.length)
        }
    }

    private fun markCandidateSuccess(candidate: UpstreamCandidate) {
        val host = candidateHost(candidate)
        synchronized(candidateCooldownUntilMs) {
            candidateCooldownUntilMs.remove(host)
        }
    }

    private fun markCandidateFailure(candidate: UpstreamCandidate, error: Exception?) {
        val host = candidateHost(candidate)
        val message = error?.message ?: "unknown"
        Log.w(LOG_TAG, "Upstream query failed for $host: $message")
        if (message.contains("timed out", ignoreCase = true)) {
            synchronized(candidateCooldownUntilMs) {
                candidateCooldownUntilMs[host] = System.currentTimeMillis() + CANDIDATE_COOLDOWN_MS
            }
        }
    }

    private fun findDnsCandidates(): List<UpstreamCandidate> {
        val all = mutableListOf<UpstreamCandidate>()
        val seenHosts = linkedSetOf<String>()

        val manager = connectivityManager
        if (manager != null) {
            val networks = try {
                manager.allNetworks.toList()
            } catch (_: SecurityException) {
                emptyList()
            } catch (_: Exception) {
                emptyList()
            }

            networks.forEach { network ->
                val capabilities = try {
                    manager.getNetworkCapabilities(network)
                } catch (_: Exception) {
                    null
                } ?: return@forEach

                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return@forEach
                }

                val linkProperties = try {
                    manager.getLinkProperties(network)
                } catch (_: Exception) {
                    null
                } ?: return@forEach

                if (!privateDnsWarningLogged && linkProperties.isPrivateDnsActive) {
                    privateDnsWarningLogged = true
                    val privateDnsName = linkProperties.privateDnsServerName?.takeIf { it.isNotBlank() }
                    Log.w(
                        LOG_TAG,
                        "Private DNS is active on network ${network.hashCode()}" +
                            (privateDnsName?.let { " hostname=$it" } ?: "") +
                            ". Host mapping only intercepts DNS seen by this VPN."
                    )
                }

                linkProperties.dnsServers.forEach { dns ->
                    val host = dns.hostAddress ?: return@forEach
                    if (host == VPN_DNS_ADDRESS) {
                        return@forEach
                    }
                    if (seenHosts.add(host)) {
                        all.add(UpstreamCandidate(network = network, dnsServer = dns))
                    }
                }
            }
        }

        val fallback = listOf("1.1.1.1", "8.8.8.8").mapNotNull { value ->
            try {
                InetAddress.getByName(value)
            } catch (_: Exception) {
                null
            }
        }

        fallback.forEach { dns ->
            val host = dns.hostAddress ?: return@forEach
            if (host == VPN_DNS_ADDRESS) {
                return@forEach
            }
            if (seenHosts.add(host)) {
                all.add(UpstreamCandidate(network = null, dnsServer = dns))
            }
        }

        return prioritizeCandidates(all)
    }

    private fun prioritizeCandidates(candidates: List<UpstreamCandidate>): List<UpstreamCandidate> {
        val now = System.currentTimeMillis()
        val cooldownSnapshot = synchronized(candidateCooldownUntilMs) { candidateCooldownUntilMs.toMap() }
        return candidates.sortedBy { candidate ->
            val host = candidateHost(candidate)
            val until = cooldownSnapshot[host] ?: 0L
            if (until <= now) 0L else max(1L, until - now)
        }
    }

    private fun buildQueryKey(rawQuery: ByteArray): String? {
        val parsed = DnsPacketCodec.parseQuery(rawQuery) ?: return null
        val normalizedDomain = parsed.questionName.trim().lowercase(Locale.US).trimEnd('.')
        val questionClass = parsed.questionClass and 0x7FFF
        return "$normalizedDomain|${parsed.questionType}|$questionClass"
    }

    private fun cacheResponseIfEligible(queryKey: String?, response: ByteArray) {
        if (queryKey == null || response.size < 12) {
            return
        }

        val rCode = response[3].toInt() and 0x0F
        if (rCode != 0) {
            return
        }

        val ttlSeconds = extractMinimumTtlSeconds(response) ?: DEFAULT_CACHE_TTL_SECONDS
        val clampedTtlSeconds = min(MAX_CACHE_TTL_SECONDS, max(MIN_CACHE_TTL_SECONDS, ttlSeconds))
        val expiresAtMs = System.currentTimeMillis() + (clampedTtlSeconds * 1000L)
        synchronized(responseCache) {
            responseCache[queryKey] = CachedResponse(response = response.copyOf(), expiresAtMs = expiresAtMs)
        }
    }

    private fun readCachedResponse(queryKey: String?, rawQuery: ByteArray): ByteArray? {
        if (queryKey == null) {
            return null
        }

        val now = System.currentTimeMillis()
        val cached = synchronized(responseCache) {
            responseCache[queryKey]
        } ?: return null

        if (cached.expiresAtMs < now) {
            val staleAgeMs = now - cached.expiresAtMs
            if (staleAgeMs > STALE_CACHE_GRACE_MS) {
                synchronized(responseCache) {
                    responseCache.remove(queryKey)
                }
                return null
            }
            Log.w(LOG_TAG, "Serving stale cached DNS response for $queryKey ageMs=$staleAgeMs")
        } else {
            Log.i(LOG_TAG, "Serving cached DNS response for $queryKey")
        }

        return withQueryTransactionId(cached.response, rawQuery)
    }

    private fun withQueryTransactionId(response: ByteArray, rawQuery: ByteArray): ByteArray {
        if (response.size < 2 || rawQuery.size < 2) {
            return response.copyOf()
        }
        return response.copyOf().also { patched ->
            patched[0] = rawQuery[0]
            patched[1] = rawQuery[1]
        }
    }

    private fun extractMinimumTtlSeconds(packet: ByteArray): Int? {
        if (packet.size < DNS_HEADER_SIZE) {
            return null
        }

        val qdCount = readU16(packet, 4)
        val anCount = readU16(packet, 6)
        val nsCount = readU16(packet, 8)
        val arCount = readU16(packet, 10)
        var offset = DNS_HEADER_SIZE

        repeat(qdCount) {
            offset = skipName(packet, offset) ?: return null
            if (offset + 4 > packet.size) {
                return null
            }
            offset += 4
        }

        val totalRecords = anCount + nsCount + arCount
        if (totalRecords <= 0) {
            return null
        }

        var minTtl: Int? = null
        repeat(totalRecords) {
            offset = skipName(packet, offset) ?: return minTtl
            if (offset + 10 > packet.size) {
                return minTtl
            }

            val ttl = readU32(packet, offset + 4)
            val rdLength = readU16(packet, offset + 8)
            offset += 10
            if (offset + rdLength > packet.size) {
                return minTtl
            }
            offset += rdLength

            val ttlInt = if (ttl > Int.MAX_VALUE.toLong()) Int.MAX_VALUE else ttl.toInt()
            minTtl = if (minTtl == null) ttlInt else min(minTtl!!, ttlInt)
        }

        return minTtl
    }

    private fun skipName(packet: ByteArray, startOffset: Int): Int? {
        var offset = startOffset
        var steps = 0
        while (true) {
            if (offset >= packet.size || steps > 64) {
                return null
            }
            val length = packet[offset].toInt() and 0xFF
            if (length == 0) {
                return offset + 1
            }
            if (length and 0xC0 == 0xC0) {
                if (offset + 1 >= packet.size) {
                    return null
                }
                return offset + 2
            }
            if (length and 0xC0 != 0) {
                return null
            }
            val next = offset + 1 + length
            if (next > packet.size) {
                return null
            }
            offset = next
            steps += 1
        }
    }

    private fun readU16(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }

    private fun readU32(buffer: ByteArray, offset: Int): Long {
        return ((buffer[offset].toLong() and 0xFF) shl 24) or
            ((buffer[offset + 1].toLong() and 0xFF) shl 16) or
            ((buffer[offset + 2].toLong() and 0xFF) shl 8) or
            (buffer[offset + 3].toLong() and 0xFF)
    }

    private fun candidateHost(candidate: UpstreamCandidate): String {
        return candidate.dnsServer.hostAddress ?: "unknown"
    }

    private fun candidateLabel(candidate: UpstreamCandidate): String {
        val host = candidateHost(candidate)
        val networkPart = candidate.network?.let { "net=${it.hashCode()}" } ?: "protected"
        val cooldownUntil = synchronized(candidateCooldownUntilMs) { candidateCooldownUntilMs[host] ?: 0L }
        val cooldown = max(0L, cooldownUntil - System.currentTimeMillis())
        return if (cooldown > 0L) "$host($networkPart,cooldownMs=$cooldown)" else "$host($networkPart)"
    }

    companion object {
        private const val LOG_TAG = "DNS_HOST_MAP_TRACE"
        private const val DNS_PORT = 53
        private const val VPN_DNS_ADDRESS = "10.9.0.1"
        private const val SINGLE_QUERY_TIMEOUT_MS = 2000
        private const val MAX_PARALLEL_QUERIES = 4
        private const val MAX_DNS_PACKET_SIZE = 4096
        private const val DNS_HEADER_SIZE = 12
        private const val MAX_CACHE_ENTRIES = 256
        private const val MIN_CACHE_TTL_SECONDS = 20
        private const val DEFAULT_CACHE_TTL_SECONDS = 120
        private const val MAX_CACHE_TTL_SECONDS = 300
        private const val STALE_CACHE_GRACE_MS = 120_000L
        private const val CANDIDATE_COOLDOWN_MS = 20_000L
    }
}
