package com.example.etc.vpn

internal data class ParsedUdpIpv6Packet(
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray
)

internal object Ipv6PacketCodec {
    private const val IPV6_HEADER_LENGTH = 40
    private const val UDP_HEADER_LENGTH = 8
    private const val NEXT_HEADER_UDP = 17
    private const val NEXT_HEADER_HOP_BY_HOP = 0
    private const val NEXT_HEADER_ROUTING = 43
    private const val NEXT_HEADER_FRAGMENT = 44
    private const val NEXT_HEADER_ESP = 50
    private const val NEXT_HEADER_AH = 51
    private const val NEXT_HEADER_DESTINATION_OPTIONS = 60
    private const val MAX_EXTENSION_HEADERS = 8

    fun parseUdpPacket(packet: ByteArray, packetLength: Int): ParsedUdpIpv6Packet? {
        if (packetLength < IPV6_HEADER_LENGTH) {
            return null
        }

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 6) {
            return null
        }

        val payloadLength = readU16(packet, 4)
        if (payloadLength < UDP_HEADER_LENGTH || IPV6_HEADER_LENGTH + payloadLength > packetLength) {
            return null
        }

        val udp = locateUdpHeader(packet, packetLength, payloadLength) ?: return null
        val udpOffset = udp.udpOffset
        val sourcePort = readU16(packet, udpOffset)
        val destinationPort = readU16(packet, udpOffset + 2)
        val udpLength = readU16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_LENGTH || udpLength > udp.availablePayloadLength) {
            return null
        }

        val payloadStart = udpOffset + UDP_HEADER_LENGTH
        val payloadEnd = udpOffset + udpLength
        if (payloadEnd > packetLength || payloadStart > payloadEnd) {
            return null
        }

        val sourceAddress = packet.copyOfRange(8, 24)
        val destinationAddress = packet.copyOfRange(24, 40)
        val payload = packet.copyOfRange(payloadStart, payloadEnd)

        return ParsedUdpIpv6Packet(
            sourceAddress = sourceAddress,
            destinationAddress = destinationAddress,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            payload = payload
        )
    }

    private data class UdpHeaderLocation(
        val udpOffset: Int,
        val availablePayloadLength: Int
    )

    private fun locateUdpHeader(
        packet: ByteArray,
        packetLength: Int,
        payloadLength: Int
    ): UdpHeaderLocation? {
        var nextHeader = packet[6].toInt() and 0xFF
        var cursor = IPV6_HEADER_LENGTH
        var remainingPayload = payloadLength
        var extensionCount = 0

        while (nextHeader != NEXT_HEADER_UDP) {
            if (extensionCount >= MAX_EXTENSION_HEADERS) {
                return null
            }

            when (nextHeader) {
                NEXT_HEADER_HOP_BY_HOP,
                NEXT_HEADER_ROUTING,
                NEXT_HEADER_DESTINATION_OPTIONS -> {
                    if (remainingPayload < 8 || cursor + 2 > packetLength) {
                        return null
                    }
                    val headerLength = ((packet[cursor + 1].toInt() and 0xFF) + 1) * 8
                    if (headerLength <= 0 || headerLength > remainingPayload || cursor + headerLength > packetLength) {
                        return null
                    }
                    nextHeader = packet[cursor].toInt() and 0xFF
                    cursor += headerLength
                    remainingPayload -= headerLength
                }

                NEXT_HEADER_FRAGMENT -> {
                    if (remainingPayload < 8 || cursor + 8 > packetLength) {
                        return null
                    }
                    val fragmentInfo = readU16(packet, cursor + 2)
                    val fragmentOffset = (fragmentInfo and 0xFFF8) ushr 3
                    if (fragmentOffset != 0) {
                        // Non-first fragments do not carry UDP header.
                        return null
                    }
                    nextHeader = packet[cursor].toInt() and 0xFF
                    cursor += 8
                    remainingPayload -= 8
                }

                NEXT_HEADER_AH -> {
                    if (remainingPayload < 12 || cursor + 2 > packetLength) {
                        return null
                    }
                    val headerLength = ((packet[cursor + 1].toInt() and 0xFF) + 2) * 4
                    if (headerLength <= 0 || headerLength > remainingPayload || cursor + headerLength > packetLength) {
                        return null
                    }
                    nextHeader = packet[cursor].toInt() and 0xFF
                    cursor += headerLength
                    remainingPayload -= headerLength
                }

                NEXT_HEADER_ESP -> {
                    return null
                }

                else -> {
                    return null
                }
            }

            extensionCount += 1
        }

        if (remainingPayload < UDP_HEADER_LENGTH || cursor + UDP_HEADER_LENGTH > packetLength) {
            return null
        }

        return UdpHeaderLocation(
            udpOffset = cursor,
            availablePayloadLength = remainingPayload
        )
    }

    fun buildUdpIpv6Packet(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
        hopLimit: Int = 64
    ): ByteArray {
        if (sourceAddress.size != 16 || destinationAddress.size != 16) {
            return ByteArray(0)
        }

        val udpLength = UDP_HEADER_LENGTH + payload.size
        val totalLength = IPV6_HEADER_LENGTH + udpLength
        val packet = ByteArray(totalLength)

        packet[0] = 0x60.toByte() // Version 6, traffic class + flow label = 0.
        packet[1] = 0x00
        packet[2] = 0x00
        packet[3] = 0x00
        writeU16(packet, 4, udpLength)
        packet[6] = NEXT_HEADER_UDP.toByte()
        packet[7] = (hopLimit and 0xFF).toByte()

        sourceAddress.copyInto(packet, destinationOffset = 8)
        destinationAddress.copyInto(packet, destinationOffset = 24)

        val udpOffset = IPV6_HEADER_LENGTH
        writeU16(packet, udpOffset, sourcePort)
        writeU16(packet, udpOffset + 2, destinationPort)
        writeU16(packet, udpOffset + 4, udpLength)
        writeU16(packet, udpOffset + 6, 0)
        payload.copyInto(packet, destinationOffset = udpOffset + UDP_HEADER_LENGTH)

        val checksum = computeUdpChecksum(packet, udpOffset, udpLength, sourceAddress, destinationAddress)
        writeU16(packet, udpOffset + 6, checksum)

        return packet
    }

    private fun computeUdpChecksum(
        packet: ByteArray,
        udpOffset: Int,
        udpLength: Int,
        sourceAddress: ByteArray,
        destinationAddress: ByteArray
    ): Int {
        var sum = 0L

        fun addWord(value: Int) {
            sum += (value and 0xFFFF).toLong()
            while (sum ushr 16 != 0L) {
                sum = (sum and 0xFFFF) + (sum ushr 16)
            }
        }

        for (i in 0 until 16 step 2) {
            addWord(((sourceAddress[i].toInt() and 0xFF) shl 8) or (sourceAddress[i + 1].toInt() and 0xFF))
            addWord(((destinationAddress[i].toInt() and 0xFF) shl 8) or (destinationAddress[i + 1].toInt() and 0xFF))
        }

        addWord((udpLength ushr 16) and 0xFFFF)
        addWord(udpLength and 0xFFFF)
        addWord(NEXT_HEADER_UDP)

        var cursor = udpOffset
        val end = udpOffset + udpLength
        while (cursor + 1 < end) {
            addWord(((packet[cursor].toInt() and 0xFF) shl 8) or (packet[cursor + 1].toInt() and 0xFF))
            cursor += 2
        }

        if (cursor < end) {
            addWord((packet[cursor].toInt() and 0xFF) shl 8)
        }

        var checksum = sum.inv().toInt() and 0xFFFF
        if (checksum == 0) {
            checksum = 0xFFFF
        }
        return checksum
    }

    private fun readU16(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }

    private fun writeU16(buffer: ByteArray, offset: Int, value: Int) {
        buffer[offset] = ((value ushr 8) and 0xFF).toByte()
        buffer[offset + 1] = (value and 0xFF).toByte()
    }
}
