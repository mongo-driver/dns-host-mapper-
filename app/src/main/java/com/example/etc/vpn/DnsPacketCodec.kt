package com.example.etc.vpn

import java.io.ByteArrayOutputStream

internal data class ParsedDnsQuery(
    val transactionId: Int,
    val requestFlags: Int,
    val questionName: String,
    val questionType: Int,
    val questionClass: Int,
    val questionSection: ByteArray
)

internal object DnsPacketCodec {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val TYPE_SVCB = 64
    const val TYPE_HTTPS = 65
    const val TYPE_ANY = 255
    const val CLASS_IN = 1
    private const val CLASS_IN_CACHE_FLUSH = 0x8001

    fun parseQuery(packet: ByteArray): ParsedDnsQuery? {
        if (packet.size < 12) {
            return null
        }

        val transactionId = readU16(packet, 0)
        val flags = readU16(packet, 2)
        if (flags and 0x8000 != 0) {
            // Ignore responses.
            return null
        }
        val questionCount = readU16(packet, 4)
        if (questionCount < 1) {
            return null
        }

        val nameResult = parseName(packet, 12) ?: return null
        val typeOffset = nameResult.nextOffset
        if (typeOffset + 4 > packet.size) {
            return null
        }

        val questionType = readU16(packet, typeOffset)
        val questionClass = readU16(packet, typeOffset + 2)
        val questionSection = packet.copyOfRange(12, typeOffset + 4)

        return ParsedDnsQuery(
            transactionId = transactionId,
            requestFlags = flags,
            questionName = nameResult.name,
            questionType = questionType,
            questionClass = questionClass,
            questionSection = questionSection
        )
    }

    fun buildAResponse(query: ParsedDnsQuery, ipv4Address: ByteArray, ttlSeconds: Int = 120): ByteArray {
        if (ipv4Address.size != 4) {
            return buildServFail(query)
        }

        val out = ByteArrayOutputStream()
        writeHeader(out, query, answerCount = 1, rCode = 0)
        out.write(query.questionSection)
        writeU16(out, 0xC00C) // Name pointer to first question.
        writeU16(out, TYPE_A)
        writeU16(out, CLASS_IN)
        writeU32(out, ttlSeconds.toLong())
        writeU16(out, ipv4Address.size)
        out.write(ipv4Address)
        return out.toByteArray()
    }

    fun buildEmptyResponse(query: ParsedDnsQuery): ByteArray {
        val out = ByteArrayOutputStream()
        writeHeader(out, query, answerCount = 0, rCode = 0)
        out.write(query.questionSection)
        return out.toByteArray()
    }

    fun buildServFail(query: ParsedDnsQuery): ByteArray {
        val out = ByteArrayOutputStream()
        writeHeader(out, query, answerCount = 0, rCode = 2)
        out.write(query.questionSection)
        return out.toByteArray()
    }

    fun buildMdnsAResponse(query: ParsedDnsQuery, ipv4Address: ByteArray, ttlSeconds: Int = 120): ByteArray {
        if (ipv4Address.size != 4) {
            return buildMdnsEmptyResponse(query)
        }

        val out = ByteArrayOutputStream()
        writeMdnsHeader(out, query, answerCount = 1)
        out.write(query.questionSection)
        writeU16(out, 0xC00C) // Name pointer to first question.
        writeU16(out, TYPE_A)
        writeU16(out, CLASS_IN_CACHE_FLUSH)
        writeU32(out, ttlSeconds.toLong())
        writeU16(out, ipv4Address.size)
        out.write(ipv4Address)
        return out.toByteArray()
    }

    fun buildMdnsEmptyResponse(query: ParsedDnsQuery): ByteArray {
        val out = ByteArrayOutputStream()
        writeMdnsHeader(out, query, answerCount = 0)
        out.write(query.questionSection)
        return out.toByteArray()
    }

    fun buildMdnsAAnnouncement(
        domain: String,
        ipv4Address: ByteArray,
        ttlSeconds: Int = 120
    ): ByteArray? {
        if (ipv4Address.size != 4) {
            return null
        }

        val labels = domain.trim().trimEnd('.').split('.').filter { it.isNotBlank() }
        if (labels.isEmpty() || labels.any { it.length > 63 }) {
            return null
        }

        val out = ByteArrayOutputStream()
        writeU16(out, 0) // mDNS announcements use transaction id 0.
        writeU16(out, 0x8400) // QR + AA.
        writeU16(out, 0) // Questions.
        writeU16(out, 1) // Answers.
        writeU16(out, 0) // Authority.
        writeU16(out, 0) // Additional.
        if (!writeName(out, labels)) {
            return null
        }
        writeU16(out, TYPE_A)
        writeU16(out, CLASS_IN_CACHE_FLUSH)
        writeU32(out, ttlSeconds.toLong())
        writeU16(out, ipv4Address.size)
        out.write(ipv4Address)
        return out.toByteArray()
    }

    private fun writeHeader(
        out: ByteArrayOutputStream,
        query: ParsedDnsQuery,
        answerCount: Int,
        rCode: Int
    ) {
        writeU16(out, query.transactionId)

        val recursionDesired = query.requestFlags and 0x0100
        val responseFlags = 0x8000 or 0x0080 or recursionDesired or (rCode and 0xF)
        writeU16(out, responseFlags)

        writeU16(out, 1) // Questions.
        writeU16(out, answerCount)
        writeU16(out, 0) // Authority.
        writeU16(out, 0) // Additional.
    }

    private fun writeMdnsHeader(
        out: ByteArrayOutputStream,
        query: ParsedDnsQuery,
        answerCount: Int
    ) {
        writeU16(out, query.transactionId)
        writeU16(out, 0x8400) // QR + AA for mDNS response.
        writeU16(out, 1) // Questions.
        writeU16(out, answerCount)
        writeU16(out, 0) // Authority.
        writeU16(out, 0) // Additional.
    }

    private data class NameParseResult(
        val name: String,
        val nextOffset: Int
    )

    private fun parseName(message: ByteArray, startOffset: Int): NameParseResult? {
        var offset = startOffset
        var nextOffset = -1
        var pointerJumpCount = 0
        val labels = mutableListOf<String>()

        while (true) {
            if (offset >= message.size) {
                return null
            }

            val length = message[offset].toInt() and 0xFF
            if (length == 0) {
                if (nextOffset == -1) {
                    nextOffset = offset + 1
                }
                return NameParseResult(labels.joinToString("."), nextOffset)
            }

            if (length and 0xC0 == 0xC0) {
                if (offset + 1 >= message.size) {
                    return null
                }
                val pointer = ((length and 0x3F) shl 8) or (message[offset + 1].toInt() and 0xFF)
                if (pointer >= message.size) {
                    return null
                }
                if (nextOffset == -1) {
                    nextOffset = offset + 2
                }
                offset = pointer
                pointerJumpCount += 1
                if (pointerJumpCount > 16) {
                    return null
                }
                continue
            }

            if (length and 0xC0 != 0) {
                return null
            }

            val labelStart = offset + 1
            val labelEnd = labelStart + length
            if (labelEnd > message.size) {
                return null
            }
            labels.add(message.copyOfRange(labelStart, labelEnd).toString(Charsets.US_ASCII))
            offset = labelEnd
        }
    }

    private fun readU16(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }

    private fun writeName(out: ByteArrayOutputStream, labels: List<String>): Boolean {
        labels.forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            if (bytes.isEmpty() || bytes.size > 63) {
                return false
            }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return true
    }
}
