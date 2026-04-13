package com.example.etc.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

internal class UpstreamDnsResolver(
    private val vpnService: VpnService
) {
    private data class UpstreamCandidate(
        val network: Network?,
        val dnsServer: InetAddress
    )

    private val connectivityManager =
        vpnService.getSystemService(ConnectivityManager::class.java)
    private var privateDnsWarningLogged = false

    fun resolve(rawQuery: ByteArray): ByteArray? {
        val candidates = findDnsCandidates()
        Log.i(LOG_TAG, "Upstream resolver candidates=${candidates.joinToString(",") { candidateLabel(it) }}")
        for (candidate in candidates) {
            val dnsServer = candidate.dnsServer
            try {
                DatagramSocket().use { socket ->
                    if (candidate.network != null) {
                        candidate.network.bindSocket(socket)
                    } else {
                        if (!vpnService.protect(socket)) {
                            Log.w(LOG_TAG, "protect(socket) failed for ${dnsServer.hostAddress}")
                            return@use
                        }
                    }

                    socket.soTimeout = 2000
                    socket.connect(InetSocketAddress(dnsServer, DNS_PORT))
                    socket.send(DatagramPacket(rawQuery, rawQuery.size))

                    val responseBuffer = ByteArray(4096)
                    val response = DatagramPacket(responseBuffer, responseBuffer.size)
                    socket.receive(response)
                    Log.i(LOG_TAG, "Upstream response from ${dnsServer.hostAddress} len=${response.length}")
                    return response.data.copyOf(response.length)
                }
            } catch (e: Exception) {
                // Try next DNS candidate.
                Log.w(LOG_TAG, "Upstream query failed for ${dnsServer.hostAddress}: ${e.message}")
            }
        }
        Log.w(LOG_TAG, "Upstream resolver returned null response")
        return null
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

                val dnsServers = try {
                    manager.getLinkProperties(network)?.dnsServers.orEmpty()
                } catch (_: Exception) {
                    emptyList()
                }

                val linkProperties = try {
                    manager.getLinkProperties(network)
                } catch (_: Exception) {
                    null
                }
                if (!privateDnsWarningLogged && linkProperties?.isPrivateDnsActive == true) {
                    privateDnsWarningLogged = true
                    val privateDnsName = linkProperties.privateDnsServerName?.takeIf { it.isNotBlank() }
                    Log.w(
                        LOG_TAG,
                        "Private DNS is active on network ${network.hashCode()}" +
                            (privateDnsName?.let { " hostname=$it" } ?: "") +
                            ". Host mapping only intercepts DNS seen by this VPN."
                    )
                }

                dnsServers.forEach { dns ->
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

        return all
    }

    private fun candidateLabel(candidate: UpstreamCandidate): String {
        val host = candidate.dnsServer.hostAddress ?: "?"
        val networkPart = candidate.network?.let { "net=${it.hashCode()}" } ?: "protected"
        return "$host($networkPart)"
    }

    companion object {
        private const val LOG_TAG = "DNS_HOST_MAP_TRACE"
        private const val DNS_PORT = 53
        private const val VPN_DNS_ADDRESS = "10.9.0.1"
    }
}
