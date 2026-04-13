package com.example.etc.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

object HostRuleStore {
    private const val PREFS_NAME = "dns_host_mapper_prefs"
    private const val KEY_RULES_JSON = "rules_json"
    private const val KEY_VPN_RUNNING = "vpn_running"

    @Volatile
    private var cachedRulesJson: String? = null

    @Volatile
    private var cachedMap: Map<String, ByteArray> = emptyMap()

    fun loadRules(context: Context): MutableList<HostRule> {
        val json = prefs(context).getString(KEY_RULES_JSON, "[]") ?: "[]"
        return parseRules(json).toMutableList()
    }

    fun saveRules(context: Context, rules: List<HostRule>) {
        val normalized = rules.mapNotNull { rule ->
            val domain = normalizeDomain(rule.domain)
            val ipv4 = parseIpv4(rule.ip) ?: return@mapNotNull null
            HostRule(domain = domain, ip = ipv4.joinToString(".") { byte -> (byte.toInt() and 0xFF).toString() })
        }

        val array = JSONArray()
        normalized.forEach { rule ->
            val obj = JSONObject()
            obj.put("domain", rule.domain)
            obj.put("ip", rule.ip)
            array.put(obj)
        }

        prefs(context)
            .edit()
            .putString(KEY_RULES_JSON, array.toString())
            .apply()

        synchronized(this) {
            cachedRulesJson = null
            cachedMap = emptyMap()
        }
    }

    fun setVpnRunning(context: Context, running: Boolean) {
        prefs(context).edit().putBoolean(KEY_VPN_RUNNING, running).apply()
    }

    fun isVpnRunning(context: Context): Boolean {
        return prefs(context).getBoolean(KEY_VPN_RUNNING, false)
    }

    fun resolveIpv4(context: Context, domain: String): ByteArray? {
        val normalizedDomain = normalizeDomain(domain)
        val map = getRuleMap(context)
        val value = map[normalizedDomain] ?: return null
        return value.copyOf()
    }

    private fun getRuleMap(context: Context): Map<String, ByteArray> {
        val json = prefs(context).getString(KEY_RULES_JSON, "[]") ?: "[]"

        synchronized(this) {
            if (json == cachedRulesJson) {
                return cachedMap
            }

            val map = linkedMapOf<String, ByteArray>()
            parseRules(json).forEach { rule ->
                val bytes = parseIpv4(rule.ip) ?: return@forEach
                map[normalizeDomain(rule.domain)] = bytes
            }

            cachedRulesJson = json
            cachedMap = map
            return cachedMap
        }
    }

    private fun parseRules(json: String): List<HostRule> {
        val out = mutableListOf<HostRule>()
        val array = try {
            JSONArray(json)
        } catch (_: Exception) {
            JSONArray()
        }

        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val domain = normalizeDomain(item.optString("domain"))
            val ip = item.optString("ip").trim()
            if (domain.isEmpty() || parseIpv4(ip) == null) {
                continue
            }
            out.add(HostRule(domain = domain, ip = ip))
        }

        return out
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun normalizeDomain(rawDomain: String): String {
        return rawDomain.trim().lowercase(Locale.US).trimEnd('.')
    }

    fun parseIpv4(rawIp: String): ByteArray? {
        val parts = rawIp.trim().split(".")
        if (parts.size != 4) {
            return null
        }

        val out = ByteArray(4)
        for ((index, part) in parts.withIndex()) {
            val value = part.toIntOrNull() ?: return null
            if (value !in 0..255) {
                return null
            }
            out[index] = value.toByte()
        }
        return out
    }
}
