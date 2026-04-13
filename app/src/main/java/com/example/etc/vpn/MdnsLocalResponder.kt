package com.example.etc.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiManager
import android.util.Log
import com.example.etc.data.HostRuleStore
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

internal class MdnsLocalResponder(
    private val context: Context,
    private val vpnService: VpnService
) {
    private val running = AtomicBoolean(false)
    private var workerThread: Thread? = null
    private var socket: MulticastSocket? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)

    fun start() {
        if (!running.compareAndSet(false, true)) {
            Log.i(LOG_TAG, "MdnsLocalResponder already running")
            return
        }

        workerThread = Thread(
            { runLoop() },
            "dns-host-mapper-mdns-responder"
        ).apply { start() }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) {
            return
        }

        workerThread?.interrupt()
        workerThread = null

        val currentSocket = socket
        socket = null
        if (currentSocket != null) {
            try {
                currentSocket.close()
            } catch (_: Exception) {
                // Ignore close race.
            }
        }

        val lock = multicastLock
        multicastLock = null
        if (lock != null && lock.isHeld) {
            try {
                lock.release()
            } catch (_: Exception) {
                // Ignore release race.
            }
        }

        Log.i(LOG_TAG, "MdnsLocalResponder stopped")
    }

    private fun runLoop() {
        try {
            acquireMulticastLock()

            val mdnsGroupV4 = InetAddress.getByName(MDNS_GROUP_IPV4)
            val mdnsGroupV6 = InetAddress.getByName(MDNS_GROUP_IPV6)
            val localSocket = MulticastSocket(null).apply {
                reuseAddress = true
                bind(InetSocketAddress(MDNS_PORT))
                soTimeout = 1000
                timeToLive = 255
            }

            val selectedNetwork = selectNonVpnNetwork()
            val selectedNetworkInterface = selectedNetwork?.let { getNetworkInterface(it) }

            val boundToNetwork = selectedNetwork?.let { network ->
                try {
                    network.bindSocket(localSocket)
                    true
                } catch (e: Exception) {
                    Log.w(LOG_TAG, "MdnsLocalResponder bindSocket failed: ${e.message}")
                    false
                }
            } ?: false

            if (!boundToNetwork) {
                if (!vpnService.protect(localSocket)) {
                    Log.w(LOG_TAG, "MdnsLocalResponder protect(socket) failed")
                }
            }

            if (selectedNetworkInterface != null) {
                try {
                    localSocket.networkInterface = selectedNetworkInterface
                } catch (e: Exception) {
                    Log.w(LOG_TAG, "MdnsLocalResponder set networkInterface failed: ${e.message}")
                }
                try {
                    localSocket.joinGroup(
                        InetSocketAddress(mdnsGroupV4, MDNS_PORT),
                        selectedNetworkInterface
                    )
                } catch (e: Exception) {
                    Log.w(LOG_TAG, "MdnsLocalResponder joinGroup(interface) failed: ${e.message}")
                    @Suppress("DEPRECATION")
                    localSocket.joinGroup(mdnsGroupV4)
                }

                try {
                    localSocket.joinGroup(
                        InetSocketAddress(mdnsGroupV6, MDNS_PORT),
                        selectedNetworkInterface
                    )
                    Log.i(LOG_TAG, "MdnsLocalResponder joined IPv6 group $MDNS_GROUP_IPV6")
                } catch (e: Exception) {
                    Log.w(LOG_TAG, "MdnsLocalResponder join IPv6 group failed: ${e.message}")
                }
            } else {
                @Suppress("DEPRECATION")
                localSocket.joinGroup(mdnsGroupV4)
                try {
                    @Suppress("DEPRECATION")
                    localSocket.joinGroup(mdnsGroupV6)
                    Log.i(LOG_TAG, "MdnsLocalResponder joined IPv6 group $MDNS_GROUP_IPV6 (default iface)")
                } catch (e: Exception) {
                    Log.w(LOG_TAG, "MdnsLocalResponder join IPv6 group (default iface) failed: ${e.message}")
                }
            }
            socket = localSocket

            Log.i(
                LOG_TAG,
                "MdnsLocalResponder listening on $MDNS_GROUP_IPV4:$MDNS_PORT " +
                    "network=${selectedNetwork?.hashCode() ?: "none"} iface=${selectedNetworkInterface?.name ?: "default"}"
            )

            val buffer = ByteArray(2048)
            var nextAnnounceAt = 0L
            while (running.get()) {
                val now = System.currentTimeMillis()
                if (now >= nextAnnounceAt) {
                    announceLocalRules(localSocket, mdnsGroupV4, mdnsGroupV6)
                    nextAnnounceAt = now + ANNOUNCE_INTERVAL_MS
                }

                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    localSocket.receive(packet)
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: Exception) {
                    if (running.get()) {
                        Log.w(LOG_TAG, "MdnsLocalResponder receive failed")
                    }
                    break
                }

                val queryBytes = packet.data.copyOf(packet.length)
                val query = DnsPacketCodec.parseQuery(queryBytes) ?: continue

                val domain = HostRuleStore.normalizeDomain(query.questionName)
                val questionClass = query.questionClass and 0x7FFF
                Log.i(
                    LOG_TAG,
                    "MdnsLocalResponder rx domain=$domain type=${query.questionType} class=$questionClass from=${packet.address.hostAddress}:${packet.port}"
                )
                if (questionClass != DnsPacketCodec.CLASS_IN) {
                    continue
                }

                val mappedAddress = HostRuleStore.resolveIpv4(context, domain) ?: continue
                val responseBytes = when (query.questionType) {
                    DnsPacketCodec.TYPE_A, DnsPacketCodec.TYPE_ANY ->
                        DnsPacketCodec.buildMdnsAResponse(query, mappedAddress)

                    DnsPacketCodec.TYPE_AAAA ->
                        DnsPacketCodec.buildMdnsEmptyResponse(query)

                    else -> null
                } ?: continue

                try {
                    val questionClassRaw = query.questionClass
                    val wantsUnicastResponse = (questionClassRaw and 0x8000) != 0
                    val responseAddress = when {
                        wantsUnicastResponse -> packet.address
                        packet.address is Inet6Address -> mdnsGroupV6
                        else -> mdnsGroupV4
                    }
                    val responsePort = if (wantsUnicastResponse) packet.port else MDNS_PORT

                    val responsePacket = DatagramPacket(
                        responseBytes,
                        responseBytes.size,
                        responseAddress,
                        responsePort
                    )
                    localSocket.send(responsePacket)
                    Log.i(
                        LOG_TAG,
                        "MdnsLocalResponder answered domain=$domain to ${responseAddress.hostAddress}:$responsePort unicast=$wantsUnicastResponse"
                    )
                } catch (_: Exception) {
                    Log.w(LOG_TAG, "MdnsLocalResponder send failed for $domain")
                }
            }

            try {
                @Suppress("DEPRECATION")
                localSocket.leaveGroup(mdnsGroupV4)
            } catch (_: Exception) {
                // Ignore leave race.
            }
            try {
                @Suppress("DEPRECATION")
                localSocket.leaveGroup(mdnsGroupV6)
            } catch (_: Exception) {
                // Ignore leave race.
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "MdnsLocalResponder fatal error", e)
        } finally {
            stop()
        }
    }

    private fun acquireMulticastLock() {
        val wifiManager = context.applicationContext.getSystemService(WifiManager::class.java)
        if (wifiManager == null) {
            Log.w(LOG_TAG, "MdnsLocalResponder no WifiManager")
            return
        }

        val lock = wifiManager.createMulticastLock("dns-host-mapper-mdns-lock").apply {
            setReferenceCounted(false)
        }
        try {
            lock.acquire()
            multicastLock = lock
            Log.i(LOG_TAG, "MdnsLocalResponder multicast lock acquired")
        } catch (e: Exception) {
            Log.w(LOG_TAG, "MdnsLocalResponder multicast lock acquire failed: ${e.message}")
        }
    }

    private fun selectNonVpnNetwork(): Network? {
        val manager = connectivityManager ?: return null
        val networks = try {
            manager.allNetworks
        } catch (_: Exception) {
            return null
        }

        return networks.firstOrNull { network ->
            val capabilities = try {
                manager.getNetworkCapabilities(network)
            } catch (_: Exception) {
                null
            } ?: return@firstOrNull false

            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    private fun getNetworkInterface(network: Network): NetworkInterface? {
        val manager = connectivityManager ?: return null
        val interfaceName = try {
            manager.getLinkProperties(network)?.interfaceName
        } catch (_: Exception) {
            null
        } ?: return null

        return try {
            NetworkInterface.getByName(interfaceName)
        } catch (_: Exception) {
            null
        }
    }

    private fun announceLocalRules(
        socket: MulticastSocket,
        mdnsGroupV4: InetAddress,
        mdnsGroupV6: InetAddress
    ) {
        val localRules = HostRuleStore.loadRules(context)
            .filter { it.domain.endsWith(".local") }

        localRules.forEach { rule ->
            val mappedAddress = HostRuleStore.parseIpv4(rule.ip) ?: return@forEach
            val announcement = DnsPacketCodec.buildMdnsAAnnouncement(rule.domain, mappedAddress) ?: return@forEach
            sendAnnouncement(socket, mdnsGroupV4, announcement)
            sendAnnouncement(socket, mdnsGroupV6, announcement)
            Log.i(LOG_TAG, "MdnsLocalResponder announced domain=${rule.domain} ip=${rule.ip}")
        }
    }

    private fun sendAnnouncement(socket: MulticastSocket, groupAddress: InetAddress, payload: ByteArray) {
        try {
            socket.send(
                DatagramPacket(
                    payload,
                    payload.size,
                    groupAddress,
                    MDNS_PORT
                )
            )
        } catch (_: Exception) {
            Log.w(LOG_TAG, "MdnsLocalResponder announcement send failed to ${groupAddress.hostAddress}")
        }
    }

    companion object {
        private const val LOG_TAG = "DNS_HOST_MAP_TRACE"
        private const val MDNS_GROUP_IPV4 = "224.0.0.251"
        private const val MDNS_GROUP_IPV6 = "ff02::fb"
        private const val MDNS_PORT = 5353
        private const val ANNOUNCE_INTERVAL_MS = 5000L
    }
}
