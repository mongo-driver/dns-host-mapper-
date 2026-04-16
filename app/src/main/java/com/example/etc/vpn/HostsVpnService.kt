package com.example.etc.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.example.etc.data.HostRuleStore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicLong

class HostsVpnService : VpnService() {
    private data class TunnelUdpPacket(
        val ipVersion: Int,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val payload: ByteArray
    )

    private var tunnelInterface: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null
    private var upstreamResolver: UpstreamDnsResolver? = null
    private var mdnsLocalResponder: MdnsLocalResponder? = null
    private var ipv6PacketCounter = 0
    private val sessionCounter = AtomicLong(0L)

    @Volatile
    private var active = false

    @Volatile
    private var activeSessionId = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(LOG_TAG, "onStartCommand action=${intent?.action ?: "null"} active=$active")
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }

            ACTION_QUERY_STATE -> {
                val running = active && tunnelInterface != null
                Log.i(LOG_TAG, "State query requested, running=$running")
                publishVpnState(running)
                if (!running) {
                    stopSelf()
                }
                return START_NOT_STICKY
            }

            ACTION_START, null -> startVpnIfNeeded()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        Log.i(LOG_TAG, "onDestroy")
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(LOG_TAG, "onRevoke")
        stopSelf()
    }

    private fun startVpnIfNeeded() {
        if (active) {
            Log.i(LOG_TAG, "startVpnIfNeeded ignored, already active")
            return
        }

        Log.i(LOG_TAG, "startVpnIfNeeded building tunnel")
        val builder = Builder()
            .setSession("DNS Host Mapper")
            .setMtu(VPN_MTU)
            .addAddress(VPN_CLIENT_ADDRESS, 32)
            .addAddress(VPN_CLIENT_ADDRESS_V6, 128)
            .addDnsServer(VPN_DNS_ADDRESS)
            .addDnsServer(VPN_DNS_ADDRESS_V6)
            .addRoute(VPN_DNS_ADDRESS, 32)
            .addRoute(VPN_DNS_ADDRESS_V6, 128)
            .addRoute(MDNS_MULTICAST_ADDRESS, 32)
            .addRoute(MDNS_MULTICAST_ADDRESS_V6, 128)

        val iface = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(LOG_TAG, "builder.establish failed", e)
            null
        } ?: run {
            Log.e(LOG_TAG, "builder.establish returned null")
            publishVpnState(false)
            stopSelf()
            return
        }

        tunnelInterface = iface
        val sessionId = sessionCounter.incrementAndGet()
        activeSessionId = sessionId
        upstreamResolver = UpstreamDnsResolver(this)
        mdnsLocalResponder = MdnsLocalResponder(this, this).also { it.start() }
        active = true
        publishVpnState(true)
        Log.i(LOG_TAG, "VPN established and active session=$sessionId")

        tunnelThread = Thread(
            { runTunnelLoop(sessionId, iface) },
            "dns-host-mapper-vpn-loop"
        ).apply { start() }
    }

    private fun runTunnelLoop(sessionId: Long, iface: ParcelFileDescriptor) {
        try {
            FileInputStream(iface.fileDescriptor).use { input ->
                FileOutputStream(iface.fileDescriptor).use { output ->
                    val packetBuffer = ByteArray(VPN_MTU * 2)
                    while (active && activeSessionId == sessionId) {
                        val readBytes = try {
                            input.read(packetBuffer)
                        } catch (e: Exception) {
                            Log.w(LOG_TAG, "Tunnel read failed/closed", e)
                            break
                        }

                        if (readBytes <= 0) {
                            continue
                        }

                        val response = handleDnsPacket(packetBuffer, readBytes) ?: continue
                        try {
                            output.write(response)
                        } catch (e: IOException) {
                            // Interface can be closed while stopping VPN.
                            Log.w(LOG_TAG, "Tunnel write failed/closed", e)
                            break
                        }
                    }
                }
            }
        } finally {
            if (activeSessionId == sessionId) {
                active = false
                activeSessionId = 0L
                publishVpnState(false)
            }
            closeTunnelInterface(iface)
            Log.i(LOG_TAG, "runTunnelLoop finished session=$sessionId")
        }
    }

    private fun handleDnsPacket(packet: ByteArray, packetLength: Int): ByteArray? {
        val udpPacket = parseTunnelUdpPacket(packet, packetLength) ?: run {
            if (packetLength > 0) {
                val version = (packet[0].toInt() ushr 4) and 0x0F
                if (version == 6) {
                    ipv6PacketCounter += 1
                    if (ipv6PacketCounter <= 5 || ipv6PacketCounter % 50 == 0) {
                        val nextHeader = if (packetLength > 6) {
                            packet[6].toInt() and 0xFF
                        } else {
                            -1
                        }
                        Log.i(
                            LOG_TAG,
                            "Observed unhandled IPv6 packet in tunnel (count=$ipv6PacketCounter, nextHeader=$nextHeader)."
                        )
                    }
                }
            }
            return null
        }
        val isDnsQuery = udpPacket.destinationPort == DNS_PORT
        val isMdnsQuery = udpPacket.destinationPort == MDNS_PORT && (
            isMdnsMulticastDestination(udpPacket.destinationAddress) ||
                isMdnsMulticastDestinationV6(udpPacket.destinationAddress)
            )

        if (!isDnsQuery && !isMdnsQuery) {
            return null
        }

        val dnsQuery = udpPacket.payload
        if (dnsQuery.toString(Charsets.US_ASCII).contains("hasan.local", ignoreCase = true)) {
            Log.i(
                LOG_TAG,
                "Raw payload contains hasan.local ipVersion=${udpPacket.ipVersion} dstPort=${udpPacket.destinationPort}"
            )
        }
        val parsedQuery = DnsPacketCodec.parseQuery(dnsQuery) ?: return null
        val normalizedDomain = HostRuleStore.normalizeDomain(parsedQuery.questionName)
        val questionClass = parsedQuery.questionClass and 0x7FFF
        Log.i(
            LOG_TAG,
            "Query domain=$normalizedDomain type=${queryTypeName(parsedQuery.questionType)} class=$questionClass sourcePort=${udpPacket.sourcePort} mode=${if (isMdnsQuery) "mDNS" else "DNS"}"
        )

        if (!isMdnsQuery &&
            questionClass == DnsPacketCodec.CLASS_IN &&
            parsedQuery.questionType == DnsPacketCodec.TYPE_PTR
        ) {
            Log.i(LOG_TAG, "PTR query for $normalizedDomain handled locally with empty response")
            val ptrEmptyResponse = DnsPacketCodec.buildEmptyResponse(parsedQuery)
            return if (udpPacket.ipVersion == 6) {
                Ipv6PacketCodec.buildUdpIpv6Packet(
                    sourceAddress = udpPacket.destinationAddress,
                    destinationAddress = udpPacket.sourceAddress,
                    sourcePort = udpPacket.destinationPort,
                    destinationPort = udpPacket.sourcePort,
                    payload = ptrEmptyResponse
                )
            } else {
                Ipv4PacketCodec.buildUdpIpv4Packet(
                    sourceAddress = udpPacket.destinationAddress,
                    destinationAddress = udpPacket.sourceAddress,
                    sourcePort = udpPacket.destinationPort,
                    destinationPort = udpPacket.sourcePort,
                    payload = ptrEmptyResponse
                )
            }
        }

        val mappedAddress = HostRuleStore.resolveIpv4(this, normalizedDomain)
        val dnsResponsePayload = when {
            mappedAddress != null && questionClass == DnsPacketCodec.CLASS_IN -> {
                when (parsedQuery.questionType) {
                    DnsPacketCodec.TYPE_A, DnsPacketCodec.TYPE_ANY -> {
                        Log.i(
                            LOG_TAG,
                            "Mapped hit for $normalizedDomain -> ${mappedAddress.joinToString(".") { (it.toInt() and 0xFF).toString() }} mode=${if (isMdnsQuery) "mDNS" else "DNS"}"
                        )
                        if (isMdnsQuery) {
                            DnsPacketCodec.buildMdnsAResponse(parsedQuery, mappedAddress)
                        } else {
                            DnsPacketCodec.buildAResponse(parsedQuery, mappedAddress)
                        }
                    }

                    DnsPacketCodec.TYPE_AAAA -> {
                        Log.i(
                            LOG_TAG,
                            "Mapped domain $normalizedDomain asked AAAA -> returning empty answer mode=${if (isMdnsQuery) "mDNS" else "DNS"}"
                        )
                        if (isMdnsQuery) {
                            DnsPacketCodec.buildMdnsEmptyResponse(parsedQuery)
                        } else {
                            DnsPacketCodec.buildEmptyResponse(parsedQuery)
                        }
                    }

                    else -> {
                        Log.i(
                            LOG_TAG,
                            "Mapped domain $normalizedDomain asked ${queryTypeName(parsedQuery.questionType)} -> returning empty answer mode=${if (isMdnsQuery) "mDNS" else "DNS"}"
                        )
                        if (isMdnsQuery) {
                            DnsPacketCodec.buildMdnsEmptyResponse(parsedQuery)
                        } else {
                            DnsPacketCodec.buildEmptyResponse(parsedQuery)
                        }
                    }
                }
            }

            else -> {
                if (isMdnsQuery) {
                    Log.i(LOG_TAG, "mDNS query miss for $normalizedDomain (no map), ignoring")
                    return null
                }
                Log.i(LOG_TAG, "Forwarding DNS query upstream for $normalizedDomain")
                val upstream = upstreamResolver?.resolve(dnsQuery)
                if (upstream == null) {
                    val shouldReturnEmpty = parsedQuery.questionType != DnsPacketCodec.TYPE_A &&
                        parsedQuery.questionType != DnsPacketCodec.TYPE_ANY
                    if (shouldReturnEmpty) {
                        Log.w(
                            LOG_TAG,
                            "Upstream DNS failed for $normalizedDomain type=${queryTypeName(parsedQuery.questionType)}, returning empty answer"
                        )
                        DnsPacketCodec.buildEmptyResponse(parsedQuery)
                    } else {
                        Log.w(LOG_TAG, "Upstream DNS failed for $normalizedDomain, returning SERVFAIL")
                        DnsPacketCodec.buildServFail(parsedQuery)
                    }
                } else {
                    upstream
                }
            }
        }

        val sourceAddress = if (isMdnsQuery) {
            if (udpPacket.ipVersion == 6) VPN_DNS_ADDRESS_V6_BYTES else VPN_DNS_ADDRESS_BYTES
        } else {
            udpPacket.destinationAddress
        }
        val sourcePort = if (isMdnsQuery) MDNS_PORT else udpPacket.destinationPort

        return if (udpPacket.ipVersion == 6) {
            Ipv6PacketCodec.buildUdpIpv6Packet(
                sourceAddress = sourceAddress,
                destinationAddress = udpPacket.sourceAddress,
                sourcePort = sourcePort,
                destinationPort = udpPacket.sourcePort,
                payload = dnsResponsePayload,
                hopLimit = if (isMdnsQuery) 255 else 64
            )
        } else {
            Ipv4PacketCodec.buildUdpIpv4Packet(
                sourceAddress = sourceAddress,
                destinationAddress = udpPacket.sourceAddress,
                sourcePort = sourcePort,
                destinationPort = udpPacket.sourcePort,
                payload = dnsResponsePayload
            )
        }
    }

    private fun stopVpn() {
        Log.i(LOG_TAG, "stopVpn called")
        active = false
        activeSessionId = 0L
        tunnelThread?.interrupt()
        tunnelThread = null
        closeTunnelInterface()
        upstreamResolver?.close()
        upstreamResolver = null
        mdnsLocalResponder?.stop()
        mdnsLocalResponder = null
        publishVpnState(false)
    }

    private fun closeTunnelInterface(target: ParcelFileDescriptor? = tunnelInterface) {
        val iface = target ?: return
        synchronized(this) {
            if (tunnelInterface === iface) {
                tunnelInterface = null
            }
        }
        try {
            iface.close()
        } catch (e: Exception) {
            // Ignore close errors/races.
            Log.w(LOG_TAG, "closeTunnelInterface failed", e)
        }
    }

    private fun isMdnsMulticastDestination(address: ByteArray): Boolean {
        return address.size == 4 && address[0] == MDNS_MULTICAST_ADDRESS_BYTES[0] &&
            address[1] == MDNS_MULTICAST_ADDRESS_BYTES[1] &&
            address[2] == MDNS_MULTICAST_ADDRESS_BYTES[2] &&
            address[3] == MDNS_MULTICAST_ADDRESS_BYTES[3]
    }

    private fun isMdnsMulticastDestinationV6(address: ByteArray): Boolean {
        if (address.size != 16) {
            return false
        }
        for (i in 0 until 16) {
            if (address[i] != MDNS_MULTICAST_ADDRESS_V6_BYTES[i]) {
                return false
            }
        }
        return true
    }

    private fun parseTunnelUdpPacket(packet: ByteArray, packetLength: Int): TunnelUdpPacket? {
        val ipv4 = Ipv4PacketCodec.parseUdpPacket(packet, packetLength)
        if (ipv4 != null) {
            return TunnelUdpPacket(
                ipVersion = 4,
                sourceAddress = ipv4.sourceAddress,
                destinationAddress = ipv4.destinationAddress,
                sourcePort = ipv4.sourcePort,
                destinationPort = ipv4.destinationPort,
                payload = ipv4.payload
            )
        }

        val ipv6 = Ipv6PacketCodec.parseUdpPacket(packet, packetLength)
        if (ipv6 != null) {
            return TunnelUdpPacket(
                ipVersion = 6,
                sourceAddress = ipv6.sourceAddress,
                destinationAddress = ipv6.destinationAddress,
                sourcePort = ipv6.sourcePort,
                destinationPort = ipv6.destinationPort,
                payload = ipv6.payload
            )
        }

        return null
    }

    private fun publishVpnState(running: Boolean) {
        Log.i(LOG_TAG, "publishVpnState running=$running")
        HostRuleStore.setVpnRunning(this, running)
        val updateIntent = Intent(ACTION_VPN_STATE_CHANGED).apply {
            setPackage(packageName)
            putExtra(EXTRA_VPN_RUNNING, running)
        }
        sendBroadcast(updateIntent)
    }

    private fun queryTypeName(type: Int): String {
        return when (type) {
            DnsPacketCodec.TYPE_A -> "A"
            DnsPacketCodec.TYPE_PTR -> "PTR"
            DnsPacketCodec.TYPE_AAAA -> "AAAA"
            DnsPacketCodec.TYPE_SVCB -> "SVCB"
            DnsPacketCodec.TYPE_HTTPS -> "HTTPS"
            DnsPacketCodec.TYPE_ANY -> "ANY"
            else -> type.toString()
        }
    }

    companion object {
        private const val LOG_TAG = "DNS_HOST_MAP_TRACE"
        const val ACTION_START = "com.example.etc.action.START_VPN"
        const val ACTION_STOP = "com.example.etc.action.STOP_VPN"
        const val ACTION_QUERY_STATE = "com.example.etc.action.QUERY_VPN_STATE"
        const val ACTION_VPN_STATE_CHANGED = "com.example.etc.action.VPN_STATE_CHANGED"
        const val EXTRA_VPN_RUNNING = "vpn_running"

        private const val DNS_PORT = 53
        private const val MDNS_PORT = 5353
        private const val VPN_MTU = 1500
        private const val VPN_CLIENT_ADDRESS = "10.9.0.2"
        private const val VPN_CLIENT_ADDRESS_V6 = "fd00:10:9::2"
        private const val VPN_DNS_ADDRESS = "10.9.0.1"
        private val VPN_DNS_ADDRESS_BYTES = byteArrayOf(10, 9, 0, 1)
        private const val VPN_DNS_ADDRESS_V6 = "fd00:10:9::1"
        private val VPN_DNS_ADDRESS_V6_BYTES = byteArrayOf(
            0xFD.toByte(), 0x00, 0x10, 0x09,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        )
        private const val MDNS_MULTICAST_ADDRESS = "224.0.0.251"
        private val MDNS_MULTICAST_ADDRESS_BYTES =
            byteArrayOf(224.toByte(), 0, 0, 251.toByte())
        private const val MDNS_MULTICAST_ADDRESS_V6 = "ff02::fb"
        private val MDNS_MULTICAST_ADDRESS_V6_BYTES = byteArrayOf(
            0xFF.toByte(), 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xFB.toByte()
        )
    }
}
