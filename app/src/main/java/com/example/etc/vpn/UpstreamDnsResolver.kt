package com.example.etc.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import com.example.etc.data.HostRuleStore
import java.io.IOException
import java.net.BindException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.concurrent.CancellationException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.math.max
import kotlin.math.min

internal class UpstreamDnsResolver(
    private val vpnService: VpnService
) {
    private class UdpTruncatedException : IOException("UDP DNS response truncated (TC=1)")

    private data class InFlightQuery(
        val future: Future<QueryResult>,
        val task: CandidateQueryTask
    )

    private data class UpstreamCandidate(
        val network: Network?,
        val dnsServer: InetAddress,
        val priority: Int
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

    private inner class CandidateQueryTask(
        private val candidate: UpstreamCandidate,
        private val rawQuery: ByteArray,
        private val udpAttemptLimit: Int
    ) : Callable<QueryResult> {
        @Volatile
        private var cancelled = false

        @Volatile
        private var udpSocket: DatagramSocket? = null

        @Volatile
        private var tcpSocket: Socket? = null

        override fun call(): QueryResult {
            return try {
                val response = querySingleCandidate(
                    candidate = candidate,
                    rawQuery = rawQuery,
                    maxUdpAttempts = udpAttemptLimit,
                    onUdpSocketCreated = { socket -> udpSocket = socket },
                    onTcpSocketCreated = { socket -> tcpSocket = socket }
                )
                QueryResult(candidate = candidate, response = response)
            } catch (e: Exception) {
                if (cancelled || isCancellationLike(e)) {
                    QueryResult(candidate = candidate, error = CancellationException("candidate canceled"))
                } else {
                    QueryResult(candidate = candidate, error = e)
                }
            } finally {
                udpSocket = null
                tcpSocket = null
            }
        }

        fun cancel() {
            cancelled = true
            try {
                udpSocket?.close()
            } catch (_: Exception) {
                // Best effort cancel.
            }
            try {
                tcpSocket?.close()
            } catch (_: Exception) {
                // Best effort cancel.
            }
        }
    }

    private val connectivityManager =
        vpnService.getSystemService(ConnectivityManager::class.java)
    private val queryExecutor: ExecutorService = Executors.newFixedThreadPool(MAX_PARALLEL_QUERIES)
    private val systemFallbackExecutor: ExecutorService =
        Executors.newFixedThreadPool(SYSTEM_FALLBACK_PARALLELISM)
    private val responseCache = object : LinkedHashMap<String, CachedResponse>(MAX_CACHE_ENTRIES, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedResponse>?): Boolean {
            return size > MAX_CACHE_ENTRIES
        }
    }
    private val candidateCooldownUntilMs = mutableMapOf<String, Long>()
    private val candidateConsecutiveFailures = mutableMapOf<String, Int>()
    private val candidateSuccessCount = mutableMapOf<String, Int>()
    private val candidateTcpDisabledUntilMs = mutableMapOf<String, Long>()
    private val createdAtMs = System.currentTimeMillis()

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

        val systemFallbackTimeoutMs = if (candidates.isEmpty()) {
            SYSTEM_FALLBACK_TIMEOUT_EMPTY_MS
        } else {
            SYSTEM_FALLBACK_TIMEOUT_MS
        }
        val systemFallback = awaitSystemFallback(
            future = submitSystemFallback(rawQuery),
            timeoutMs = systemFallbackTimeoutMs
        )
        if (systemFallback != null) {
            cacheResponseIfEligible(queryKey, systemFallback)
            return systemFallback
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
        systemFallbackExecutor.shutdownNow()
    }

    private fun submitSystemFallback(rawQuery: ByteArray): Future<ByteArray?>? {
        return try {
            systemFallbackExecutor.submit<ByteArray?> { resolveUsingSystemDns(rawQuery) }
        } catch (_: RejectedExecutionException) {
            null
        }
    }

    private fun awaitSystemFallback(future: Future<ByteArray?>?, timeoutMs: Long): ByteArray? {
        if (future == null) {
            return null
        }
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            future.cancel(true)
            Log.w(LOG_TAG, "System DNS fallback timed out after ${timeoutMs}ms")
            null
        } catch (e: Exception) {
            future.cancel(true)
            Log.w(LOG_TAG, "System DNS fallback failed: ${e.message}")
            null
        }
    }

    private fun queryCandidatesParallel(rawQuery: ByteArray, candidates: List<UpstreamCandidate>): ByteArray? {
        if (candidates.isEmpty()) {
            return null
        }

        var start = 0
        while (start < candidates.size) {
            val end = min(start + MAX_PARALLEL_QUERIES, candidates.size)
            val batch = candidates.subList(start, end)
            val response = queryCandidateBatch(rawQuery, batch)
            if (response != null) {
                return response
            }
            start = end
        }

        return null
    }

    private fun queryCandidateBatch(
        rawQuery: ByteArray,
        batch: List<UpstreamCandidate>
    ): ByteArray? {
        val completion = ExecutorCompletionService<QueryResult>(queryExecutor)
        val inFlight = mutableListOf<InFlightQuery>()

        batch.forEach { candidate ->
            val task = CandidateQueryTask(
                candidate = candidate,
                rawQuery = rawQuery,
                udpAttemptLimit = computeUdpAttemptLimit(candidate, batch.size)
            )
            val future = completion.submit(task)
            inFlight += InFlightQuery(future = future, task = task)
        }

        for (index in batch.indices) {
            val future = try {
                completion.take()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                cancelInFlight(inFlight, except = null)
                return null
            }

            val result = try {
                future.get()
            } catch (_: CancellationException) {
                continue
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Upstream query future failed: ${e.message}")
                continue
            }

            if (result.error is CancellationException) {
                continue
            }

            val response = result.response
            if (response != null) {
                markCandidateSuccess(result.candidate)
                Log.i(
                    LOG_TAG,
                    "Upstream response from ${result.candidate.dnsServer.hostAddress} len=${response.size}"
                )
                cancelInFlight(inFlight, except = future)
                return response
            }

            markCandidateFailure(result.candidate, result.error)
        }

        cancelInFlight(inFlight, except = null)
        return null
    }

    private fun cancelInFlight(
        inFlight: List<InFlightQuery>,
        except: Future<QueryResult>?
    ) {
        inFlight.forEach { item ->
            if (item.future === except) {
                return@forEach
            }
            item.task.cancel()
            item.future.cancel(true)
        }
    }

    private fun querySingleCandidate(
        candidate: UpstreamCandidate,
        rawQuery: ByteArray,
        maxUdpAttempts: Int,
        onUdpSocketCreated: ((DatagramSocket) -> Unit)? = null,
        onTcpSocketCreated: ((Socket) -> Unit)? = null
    ): ByteArray {
        var udpError: Exception? = null
        repeat(maxUdpAttempts) { attempt ->
            try {
                return querySingleCandidateUdp(candidate, rawQuery, onUdpSocketCreated)
            } catch (e: Exception) {
                if (isCancellationLike(e)) {
                    throw CancellationException("UDP query canceled")
                }
                udpError = e
                val isLastAttempt = attempt == maxUdpAttempts - 1
                if (!isTimeoutLike(e) || isLastAttempt) {
                    return@repeat
                }
            }
        }

        val finalUdpError = udpError ?: IOException("UDP query failed")

        if (!shouldTryTcpFallback(candidate, finalUdpError)) {
            throw finalUdpError
        }

        Log.w(
            LOG_TAG,
            "UDP upstream failed for ${candidateHost(candidate)} (${finalUdpError.message}), trying TCP fallback"
        )

        try {
            val tcpResponse = querySingleCandidateTcp(candidate, rawQuery, onTcpSocketCreated)
            synchronized(candidateCooldownUntilMs) {
                candidateTcpDisabledUntilMs.remove(candidateHost(candidate))
            }
            return tcpResponse
        } catch (tcpError: Exception) {
            if (isTcpRefusedLike(tcpError)) {
                temporarilyDisableTcpFallback(candidate)
            }
            tcpError.addSuppressed(finalUdpError)
            throw tcpError
        }
    }

    private fun computeUdpAttemptLimit(candidate: UpstreamCandidate, batchSize: Int): Int {
        return when {
            hasCandidateSuccess(candidate) -> UDP_RETRY_ATTEMPTS_FOR_WARM_CANDIDATE
            batchSize > 1 -> 1
            isWithinStartupWarmupWindow() -> UDP_RETRY_ATTEMPTS_DURING_STARTUP
            else -> 1
        }
    }

    private fun querySingleCandidateUdp(
        candidate: UpstreamCandidate,
        rawQuery: ByteArray,
        onSocketCreated: ((DatagramSocket) -> Unit)? = null
    ): ByteArray {
        val dnsServer = candidate.dnsServer
        DatagramSocket().use { socket ->
            onSocketCreated?.invoke(socket)
            if (candidate.network != null) {
                candidate.network.bindSocket(socket)
            } else {
                if (!protectUdpIfPossible(socket, dnsServer)) {
                    throw IOException("protect(udp) failed for ${dnsServer.hostAddress}")
                }
            }

            socket.soTimeout = SINGLE_QUERY_TIMEOUT_MS
            socket.connect(InetSocketAddress(dnsServer, DNS_PORT))
            socket.send(DatagramPacket(rawQuery, rawQuery.size))

            val responseBuffer = ByteArray(MAX_DNS_PACKET_SIZE)
            val response = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(response)
            val payload = response.data.copyOf(response.length)
            if (isTruncatedDnsResponse(payload)) {
                throw UdpTruncatedException()
            }
            return payload
        }
    }

    private fun querySingleCandidateTcp(
        candidate: UpstreamCandidate,
        rawQuery: ByteArray,
        onSocketCreated: ((Socket) -> Unit)? = null
    ): ByteArray {
        val dnsServer = candidate.dnsServer
        Socket().use { socket ->
            onSocketCreated?.invoke(socket)
            if (candidate.network != null) {
                candidate.network.bindSocket(socket)
            } else {
                if (!protectTcpIfPossible(socket, dnsServer)) {
                    throw IOException("protect(tcp) failed for ${dnsServer.hostAddress}")
                }
            }

            socket.soTimeout = TCP_QUERY_TIMEOUT_MS
            socket.connect(InetSocketAddress(dnsServer, DNS_PORT), TCP_CONNECT_TIMEOUT_MS)

            val output = socket.getOutputStream()
            val input = socket.getInputStream()

            val queryLength = rawQuery.size
            if (queryLength <= 0 || queryLength > MAX_DNS_PACKET_SIZE) {
                throw IOException("Invalid DNS query length=$queryLength")
            }

            output.write((queryLength ushr 8) and 0xFF)
            output.write(queryLength and 0xFF)
            output.write(rawQuery)
            output.flush()

            val lengthHi = input.read()
            val lengthLo = input.read()
            if (lengthHi < 0 || lengthLo < 0) {
                throw IOException("TCP DNS response length prefix missing")
            }
            val responseLength = (lengthHi shl 8) or lengthLo
            if (responseLength <= 0 || responseLength > MAX_DNS_PACKET_SIZE) {
                throw IOException("Invalid TCP DNS response length=$responseLength")
            }

            val response = ByteArray(responseLength)
            readFully(input, response)
            return response
        }
    }

    private fun markCandidateSuccess(candidate: UpstreamCandidate) {
        val host = candidateHost(candidate)
        synchronized(candidateCooldownUntilMs) {
            candidateCooldownUntilMs.remove(host)
            candidateConsecutiveFailures.remove(host)
            candidateSuccessCount[host] = (candidateSuccessCount[host] ?: 0) + 1
            candidateTcpDisabledUntilMs.remove(host)
        }
    }

    private fun markCandidateFailure(candidate: UpstreamCandidate, error: Exception?) {
        if (error != null && isCancellationLike(error)) {
            return
        }
        val host = candidateHost(candidate)
        val message = error?.message ?: "unknown"
        val isTimeoutLike = error != null && isTimeoutLike(error)
        val isBindLike = error != null && isBindLike(error)
        val isRefusedLike = error != null && isTcpRefusedLike(error)

        val failureCount: Int
        val hasSuccess: Boolean
        val inStartupWarmupWindow = isWithinStartupWarmupWindow()
        synchronized(candidateCooldownUntilMs) {
            failureCount = (candidateConsecutiveFailures[host] ?: 0) + 1
            candidateConsecutiveFailures[host] = failureCount
            hasSuccess = (candidateSuccessCount[host] ?: 0) > 0
        }

        val cooldownMs = when {
            isTimeoutLike || isBindLike -> {
                if (hasSuccess) {
                    if (failureCount >= WARM_PATH_FAILURE_THRESHOLD) {
                        if (candidate.priority == PRIORITY_CUSTOM) {
                            CUSTOM_WARM_PATH_COOLDOWN_MS
                        } else {
                            WARM_PATH_COOLDOWN_MS
                        }
                    } else {
                        0L
                    }
                } else {
                    if (inStartupWarmupWindow && failureCount <= STARTUP_WARMUP_FAILURE_THRESHOLD) {
                        0L
                    } else if (failureCount >= COLD_START_FAILURE_THRESHOLD) {
                        CANDIDATE_LONG_COOLDOWN_MS
                    } else {
                        CANDIDATE_COOLDOWN_MS
                    }
                }
            }

            isRefusedLike -> {
                temporarilyDisableTcpFallback(candidate)
                if (hasSuccess) 0L else CANDIDATE_COOLDOWN_MS
            }

            else -> 0L
        }
        if (cooldownMs > 0L) {
            synchronized(candidateCooldownUntilMs) {
                candidateCooldownUntilMs[host] = System.currentTimeMillis() + cooldownMs
            }
        }

        val errorLabel = when {
            isTimeoutLike -> "Poll timed out"
            isBindLike -> "bind failed"
            isRefusedLike -> "Connection refused"
            else -> message
        }
        Log.w(
            LOG_TAG,
            "Upstream query failed for $host: $errorLabel (failures=$failureCount${if (cooldownMs > 0L) ", cooldownMs=$cooldownMs" else ""})"
        )
    }

    private fun findDnsCandidates(): List<UpstreamCandidate> {
        val all = mutableListOf<UpstreamCandidate>()
        val seenHosts = linkedSetOf<String>()

        val manager = connectivityManager
        val activeNetwork = if (manager != null) {
            try {
                manager.activeNetwork
            } catch (_: Exception) {
                null
            }
        } else {
            null
        }
        val sortedNetworks = if (manager != null) {
            val networks = try {
                manager.allNetworks.toList()
            } catch (_: SecurityException) {
                emptyList()
            } catch (_: Exception) {
                emptyList()
            }
            networks.sortedWith(
                compareByDescending<Network> { network -> network == activeNetwork }
            )
        } else {
            emptyList()
        }
        val eligibleNetworks = mutableListOf<Network>()

        if (manager != null) {
            sortedNetworks.forEach { network ->
                val capabilities = try {
                    manager.getNetworkCapabilities(network)
                } catch (_: Exception) {
                    null
                } ?: return@forEach

                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return@forEach
                }
                if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    return@forEach
                }
                eligibleNetworks.add(network)
            }
        }
        val preferredNetwork = eligibleNetworks.firstOrNull()

        val customResolvers = HostRuleStore.loadCustomDnsServers(vpnService).mapNotNull { value ->
            try {
                InetAddress.getByName(value)
            } catch (_: Exception) {
                null
            }
        }
        customResolvers.forEach { dns ->
            val host = dns.hostAddress ?: return@forEach
            if (host == VPN_DNS_ADDRESS) {
                return@forEach
            }
            if (seenHosts.add(host)) {
                all.add(
                    UpstreamCandidate(
                        network = preferredNetwork,
                        dnsServer = dns,
                        priority = PRIORITY_CUSTOM
                    )
                )
            }
        }

        if (manager != null) {
            eligibleNetworks.forEach { network ->
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
                        all.add(
                            UpstreamCandidate(
                                network = network,
                                dnsServer = dns,
                                priority = PRIORITY_NETWORK_DISCOVERED
                            )
                        )
                    }
                }
            }
        }

        val extraResolvers = NETWORK_FALLBACK_DNS

        if (preferredNetwork != null) {
            extraResolvers.forEach { dns ->
                val host = dns.hostAddress ?: return@forEach
                if (host == VPN_DNS_ADDRESS) {
                    return@forEach
                }
                if (seenHosts.add(host)) {
                    all.add(
                        UpstreamCandidate(
                            network = preferredNetwork,
                            dnsServer = dns,
                            priority = PRIORITY_ACTIVE_NETWORK_FALLBACK
                        )
                    )
                }
            }
        }

        // Always keep protected fallback resolvers so DNS still works when network-bound discovery fails.
        extraResolvers.forEach { dns ->
            val host = dns.hostAddress ?: return@forEach
            if (host == VPN_DNS_ADDRESS) {
                return@forEach
            }
            if (seenHosts.add(host)) {
                all.add(
                    UpstreamCandidate(
                        network = null,
                        dnsServer = dns,
                        priority = PRIORITY_PROTECTED_FALLBACK
                    )
                )
            }
        }

        return prioritizeCandidates(all)
    }

    private fun prioritizeCandidates(candidates: List<UpstreamCandidate>): List<UpstreamCandidate> {
        if (candidates.isEmpty()) {
            return emptyList()
        }

        val now = System.currentTimeMillis()
        val (cooldownSnapshot, failureSnapshot, successSnapshot) = synchronized(candidateCooldownUntilMs) {
            Triple(
                candidateCooldownUntilMs.toMap(),
                candidateConsecutiveFailures.toMap(),
                candidateSuccessCount.toMap()
            )
        }
        val withCooldown = candidates.sortedWith(
            compareBy<UpstreamCandidate>(
                { candidate ->
                    val host = candidateHost(candidate)
                    val until = cooldownSnapshot[host] ?: 0L
                    if (until <= now) 0 else 1
                },
                { candidate ->
                    val host = candidateHost(candidate)
                    -(successSnapshot[host] ?: 0)
                },
                { candidate ->
                    val host = candidateHost(candidate)
                    failureSnapshot[host] ?: 0
                },
                { candidate ->
                    val host = candidateHost(candidate)
                    val until = cooldownSnapshot[host] ?: 0L
                    if (until <= now) 0L else max(1L, until - now)
                },
                { candidate ->
                    candidate.priority
                }
            )
        )

        val ready = withCooldown.filter { candidate ->
            val host = candidateHost(candidate)
            (cooldownSnapshot[host] ?: 0L) <= now
        }
        val customCandidates = withCooldown.filter { candidate ->
            candidate.priority == PRIORITY_CUSTOM
        }
        val nearestCustomCandidate = customCandidates.minByOrNull { candidate ->
            val host = candidateHost(candidate)
            val until = cooldownSnapshot[host] ?: 0L
            if (until <= now) 0L else until - now
        }

        if (ready.isNotEmpty()) {
            val readyCustom = ready.filter { candidate ->
                candidate.priority == PRIORITY_CUSTOM
            }
            if (readyCustom.isNotEmpty()) {
                val selected = LinkedHashSet<UpstreamCandidate>()
                selected.add(readyCustom.first())
                ready.forEach { candidate ->
                    if (selected.size >= WARM_READY_CANDIDATE_COUNT) {
                        return@forEach
                    }
                    selected.add(candidate)
                }
                return selected.toList()
            }

            if (nearestCustomCandidate != null) {
                val selected = LinkedHashSet<UpstreamCandidate>()
                selected.add(ready.first())
                selected.add(nearestCustomCandidate)
                return selected.toList()
            }

            return ready.take(BOOTSTRAP_CANDIDATE_COUNT)
        }

        // No resolver is currently ready.
        // If a custom DNS server is configured, keep probing it so mapped/custom behavior
        // recovers quickly instead of returning an empty candidate set.
        if (nearestCustomCandidate != null) {
            return listOf(nearestCustomCandidate)
        }

        // No custom resolver exists; only probe cooled resolvers near expiry.
        val coolingWithSuccess = withCooldown.filter { candidate ->
            val host = candidateHost(candidate)
            val hasSuccess = (successSnapshot[host] ?: 0) > 0
            val cooldownUntil = cooldownSnapshot[host] ?: 0L
            hasSuccess && cooldownUntil > now
        }
        val nextProbe = coolingWithSuccess.firstOrNull()
        if (nextProbe != null) {
            val remainingMs = (cooldownSnapshot[candidateHost(nextProbe)] ?: 0L) - now
            if (remainingMs <= NEAR_COOLDOWN_PROBE_MS) {
                return listOf(nextProbe)
            }
        }

        return emptyList()
    }

    private fun resolveUsingSystemDns(rawQuery: ByteArray): ByteArray? {
        val parsed = DnsPacketCodec.parseQuery(rawQuery) ?: return null
        val questionClass = parsed.questionClass and 0x7FFF
        if (questionClass != DnsPacketCodec.CLASS_IN) {
            return null
        }
        if (parsed.questionType != DnsPacketCodec.TYPE_A && parsed.questionType != DnsPacketCodec.TYPE_ANY) {
            return null
        }

        val host = parsed.questionName.trim().trimEnd('.')
        if (host.isBlank()) {
            return null
        }

        val manager = connectivityManager ?: return null
        val activeNetwork = try {
            manager.activeNetwork
        } catch (_: Exception) {
            null
        }
        val networks = try {
            manager.allNetworks.toList()
        } catch (_: Exception) {
            emptyList()
        }.sortedWith(compareByDescending<Network> { it == activeNetwork })

        for (network in networks) {
            val capabilities = try {
                manager.getNetworkCapabilities(network)
            } catch (_: Exception) {
                null
            } ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                continue
            }
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                continue
            }

            try {
                val resolved = network.getAllByName(host)
                val ipv4 = resolved.firstOrNull { address -> address.address.size == 4 }?.address ?: continue
                Log.i(LOG_TAG, "System DNS fallback resolved $host via net=${network.hashCode()}")
                return DnsPacketCodec.buildAResponse(parsed, ipv4)
            } catch (_: Exception) {
                // Try next network.
            }
        }

        return null
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
            minTtl = minTtl?.let { current -> min(current, ttlInt) } ?: ttlInt
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

    private fun protectUdpIfPossible(socket: DatagramSocket, dnsServer: InetAddress): Boolean {
        try {
            if (!vpnService.protect(socket)) {
                Log.w(LOG_TAG, "protect(udp) returned false for ${dnsServer.hostAddress}")
                return false
            }
        } catch (e: Exception) {
            Log.w(LOG_TAG, "protect(udp) threw for ${dnsServer.hostAddress}: ${e.message}")
            return false
        }
        return true
    }

    private fun protectTcpIfPossible(socket: Socket, dnsServer: InetAddress): Boolean {
        try {
            if (!vpnService.protect(socket)) {
                Log.w(LOG_TAG, "protect(tcp) returned false for ${dnsServer.hostAddress}")
                return false
            }
        } catch (e: Exception) {
            Log.w(LOG_TAG, "protect(tcp) threw for ${dnsServer.hostAddress}: ${e.message}")
            return false
        }
        return true
    }

    private fun isTimeoutLike(error: Exception): Boolean {
        val message = error.message?.lowercase(Locale.US).orEmpty()
        return error is SocketTimeoutException || message.contains("timed out")
    }

    private fun isBindLike(error: Exception): Boolean {
        val message = error.message?.lowercase(Locale.US).orEmpty()
        return error is BindException || message.contains("bind failed")
    }

    private fun isTcpRefusedLike(error: Exception): Boolean {
        val message = error.message?.lowercase(Locale.US).orEmpty()
        return message.contains("connection refused") || message.contains("econnrefused")
    }

    private fun shouldTryTcpFallback(candidate: UpstreamCandidate, udpError: Exception): Boolean {
        if (udpError is UdpTruncatedException) {
            return !isTcpFallbackDisabled(candidate)
        }
        if (isTimeoutLike(udpError)) {
            return false
        }
        if (isTcpRefusedLike(udpError)) {
            temporarilyDisableTcpFallback(candidate)
            return false
        }
        return !isTcpFallbackDisabled(candidate)
    }

    private fun isTcpFallbackDisabled(candidate: UpstreamCandidate): Boolean {
        val host = candidateHost(candidate)
        val now = System.currentTimeMillis()
        synchronized(candidateCooldownUntilMs) {
            val until = candidateTcpDisabledUntilMs[host] ?: return false
            if (until <= now) {
                candidateTcpDisabledUntilMs.remove(host)
                return false
            }
            return true
        }
    }

    private fun temporarilyDisableTcpFallback(candidate: UpstreamCandidate) {
        val host = candidateHost(candidate)
        synchronized(candidateCooldownUntilMs) {
            candidateTcpDisabledUntilMs[host] = System.currentTimeMillis() + TCP_FALLBACK_DISABLE_MS
        }
    }

    private fun hasCandidateSuccess(candidate: UpstreamCandidate): Boolean {
        val host = candidateHost(candidate)
        synchronized(candidateCooldownUntilMs) {
            return (candidateSuccessCount[host] ?: 0) > 0
        }
    }

    private fun isWithinStartupWarmupWindow(): Boolean {
        return System.currentTimeMillis() - createdAtMs <= STARTUP_WARMUP_WINDOW_MS
    }

    private fun isTruncatedDnsResponse(packet: ByteArray): Boolean {
        if (packet.size < DNS_HEADER_SIZE) {
            return false
        }
        val flags = readU16(packet, 2)
        return (flags and 0x0200) != 0
    }

    private fun isCancellationLike(error: Exception): Boolean {
        if (error is CancellationException) {
            return true
        }
        val message = error.message?.lowercase(Locale.US).orEmpty()
        if (message.contains("interrupted")) {
            return true
        }
        if (message.contains("socket closed") || message.contains("socket is closed")) {
            return true
        }
        if (message.contains("bad file descriptor") || message.contains("ebadf")) {
            return true
        }
        return false
    }

    private fun readFully(input: java.io.InputStream, output: ByteArray) {
        var offset = 0
        while (offset < output.size) {
            val read = input.read(output, offset, output.size - offset)
            if (read < 0) {
                throw IOException("Unexpected EOF while reading TCP DNS response")
            }
            offset += read
        }
    }

    private fun candidateLabel(candidate: UpstreamCandidate): String {
        val host = candidateHost(candidate)
        val networkPart = candidate.network?.let { "net=${it.hashCode()}" } ?: "protected"
        val sourcePart = when (candidate.priority) {
            PRIORITY_CUSTOM -> "custom"
            PRIORITY_NETWORK_DISCOVERED -> "network"
            PRIORITY_ACTIVE_NETWORK_FALLBACK -> "active_fallback"
            PRIORITY_PROTECTED_FALLBACK -> "protected_fallback"
            else -> "unknown"
        }
        val (cooldownUntil, failures, successes) = synchronized(candidateCooldownUntilMs) {
            Triple(
                candidateCooldownUntilMs[host] ?: 0L,
                candidateConsecutiveFailures[host] ?: 0,
                candidateSuccessCount[host] ?: 0
            )
        }
        val cooldown = max(0L, cooldownUntil - System.currentTimeMillis())
        return if (cooldown > 0L) {
            "$host($networkPart,source=$sourcePart,cooldownMs=$cooldown,failures=$failures,successes=$successes)"
        } else {
            "$host($networkPart,source=$sourcePart,failures=$failures,successes=$successes)"
        }
    }

    companion object {
        private const val LOG_TAG = "DNS_HOST_MAP_TRACE"
        private const val DNS_PORT = 53
        private const val VPN_DNS_ADDRESS = "10.9.0.1"
        private const val SINGLE_QUERY_TIMEOUT_MS = 1500
        private const val TCP_CONNECT_TIMEOUT_MS = 1200
        private const val TCP_QUERY_TIMEOUT_MS = 1500
        private const val MAX_PARALLEL_QUERIES = 4
        private const val BOOTSTRAP_CANDIDATE_COUNT = 2
        private const val WARM_READY_CANDIDATE_COUNT = 2
        private val NETWORK_FALLBACK_DNS = listOf(
            InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)),
            InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)),
            InetAddress.getByAddress(byteArrayOf(9, 9, 9, 9))
        )
        private const val PRIORITY_CUSTOM = 0
        private const val PRIORITY_NETWORK_DISCOVERED = 10
        private const val PRIORITY_ACTIVE_NETWORK_FALLBACK = 20
        private const val PRIORITY_PROTECTED_FALLBACK = 30
        private const val MAX_DNS_PACKET_SIZE = 4096
        private const val DNS_HEADER_SIZE = 12
        private const val MAX_CACHE_ENTRIES = 256
        private const val MIN_CACHE_TTL_SECONDS = 20
        private const val DEFAULT_CACHE_TTL_SECONDS = 120
        private const val MAX_CACHE_TTL_SECONDS = 300
        private const val STALE_CACHE_GRACE_MS = 120_000L
        private const val CANDIDATE_COOLDOWN_MS = 20_000L
        private const val CANDIDATE_LONG_COOLDOWN_MS = 120_000L
        private const val COLD_START_FAILURE_THRESHOLD = 3
        private const val WARM_PATH_FAILURE_THRESHOLD = 3
        private const val WARM_PATH_COOLDOWN_MS = 5_000L
        private const val CUSTOM_WARM_PATH_COOLDOWN_MS = 2_000L
        private const val NEAR_COOLDOWN_PROBE_MS = 1_500L
        private const val TCP_FALLBACK_DISABLE_MS = 600_000L
        private const val STARTUP_WARMUP_WINDOW_MS = 20_000L
        private const val STARTUP_WARMUP_FAILURE_THRESHOLD = 2
        private const val UDP_RETRY_ATTEMPTS_DURING_STARTUP = 2
        private const val UDP_RETRY_ATTEMPTS_FOR_WARM_CANDIDATE = 2
        private const val SYSTEM_FALLBACK_PARALLELISM = 2
        private const val SYSTEM_FALLBACK_TIMEOUT_MS = 4000L
        private const val SYSTEM_FALLBACK_TIMEOUT_EMPTY_MS = 6000L
    }
}
