package com.example.etc.vpn

internal data class ParsedUdpIpv4Packet(
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray
)

internal object Ipv4PacketCodec {
    private const val IPV4_HEADER_MIN_LENGTH = 20
    private const val UDP_HEADER_LENGTH = 8
    private const val PROTOCOL_UDP = 17

    fun parseUdpPacket(packet: ByteArray, packetLength: Int): ParsedUdpIpv4Packet? {
        if (packetLength < IPV4_HEADER_MIN_LENGTH) {
            return null
        }

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) {
            return null
        }

        val ihlWords = packet[0].toInt() and 0x0F
        val ipHeaderLength = ihlWords * 4
        if (ipHeaderLength < IPV4_HEADER_MIN_LENGTH || packetLength < ipHeaderLength + UDP_HEADER_LENGTH) {
            return null
        }

        if ((packet[9].toInt() and 0xFF) != PROTOCOL_UDP) {
            return null
        }

        val totalLength = readU16(packet, 2)
        if (totalLength < ipHeaderLength + UDP_HEADER_LENGTH || totalLength > packetLength) {
            return null
        }

        val udpOffset = ipHeaderLength
        val sourcePort = readU16(packet, udpOffset)
        val destinationPort = readU16(packet, udpOffset + 2)
        val udpLength = readU16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_LENGTH) {
            return null
        }

        val payloadStart = udpOffset + UDP_HEADER_LENGTH
        val payloadEnd = udpOffset + udpLength
        if (payloadEnd > totalLength || payloadStart > payloadEnd) {
            return null
        }

        val sourceAddress = packet.copyOfRange(12, 16)
        val destinationAddress = packet.copyOfRange(16, 20)
        val payload = packet.copyOfRange(payloadStart, payloadEnd)

        return ParsedUdpIpv4Packet(
            sourceAddress = sourceAddress,
            destinationAddress = destinationAddress,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            payload = payload
        )
    }

    fun buildUdpIpv4Packet(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray
    ): ByteArray {
        if (sourceAddress.size != 4 || destinationAddress.size != 4) {
            return ByteArray(0)
        }

        val totalLength = IPV4_HEADER_MIN_LENGTH + UDP_HEADER_LENGTH + payload.size
        val packet = ByteArray(totalLength)

        packet[0] = 0x45.toByte() // IPv4 + 5x32-bit words.
        packet[1] = 0x00
        writeU16(packet, 2, totalLength)
        writeU16(packet, 4, 0)
        writeU16(packet, 6, 0)
        packet[8] = 64 // TTL
        packet[9] = PROTOCOL_UDP.toByte()
        writeU16(packet, 10, 0) // Filled by checksum.

        sourceAddress.copyInto(packet, destinationOffset = 12)
        destinationAddress.copyInto(packet, destinationOffset = 16)

        val udpOffset = IPV4_HEADER_MIN_LENGTH
        writeU16(packet, udpOffset, sourcePort)
        writeU16(packet, udpOffset + 2, destinationPort)
        writeU16(packet, udpOffset + 4, UDP_HEADER_LENGTH + payload.size)
        writeU16(packet, udpOffset + 6, 0) // UDP checksum optional for IPv4.

        payload.copyInto(packet, destinationOffset = udpOffset + UDP_HEADER_LENGTH)

        val headerChecksum = computeIpv4Checksum(packet, 0, IPV4_HEADER_MIN_LENGTH)
        writeU16(packet, 10, headerChecksum)

        return packet
    }

    private fun computeIpv4Checksum(buffer: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var cursor = offset

        while (cursor < offset + length) {
            val word = ((buffer[cursor].toInt() and 0xFF) shl 8) or (buffer[cursor + 1].toInt() and 0xFF)
            sum += word
            while (sum ushr 16 != 0) {
                sum = (sum and 0xFFFF) + (sum ushr 16)
            }
            cursor += 2
        }

        return sum.inv() and 0xFFFF
    }

    private fun readU16(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }

    private fun writeU16(buffer: ByteArray, offset: Int, value: Int) {
        buffer[offset] = ((value ushr 8) and 0xFF).toByte()
        buffer[offset + 1] = (value and 0xFF).toByte()
    }
}
