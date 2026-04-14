package com.example.etc

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.example.etc.data.HostRule
import com.example.etc.data.HostRuleStore
import com.example.etc.databinding.ActivityMainBinding
import com.example.etc.vpn.HostsVpnService
import java.util.Locale

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var ruleAdapter: BaseAdapter
    private val rules = mutableListOf<HostRule>()
    private var isReceiverRegistered = false

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != HostsVpnService.ACTION_VPN_STATE_CHANGED) {
                return
            }
            val running = intent.getBooleanExtra(
                HostsVpnService.EXTRA_VPN_RUNNING,
                HostRuleStore.isVpnRunning(this@MainActivity)
            )
            HostRuleStore.setVpnRunning(this@MainActivity, running)
            Log.i(LOG_TAG, "VPN state broadcast received running=$running")
            renderVpnState()
        }
    }

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpn()
            } else {
                toast(R.string.vpn_permission_denied)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupRuleList(binding.ruleListView)
        loadRulesFromStore()
        renderRules()
        renderVpnState()

        binding.addRuleButton.setOnClickListener {
            addOrUpdateRule()
        }

        binding.vpnToggleButton.setOnClickListener {
            if (HostRuleStore.isVpnRunning(this)) {
                stopVpn()
            } else {
                requestVpnPermissionAndStart()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        loadRulesFromStore()
        renderRules()
        renderVpnState()
        warnIfPrivateDnsEnabled()
        requestVpnStateSync()
    }

    override fun onStart() {
        super.onStart()
        registerVpnStateReceiver()
        requestVpnStateSync()
    }

    override fun onStop() {
        unregisterVpnStateReceiver()
        super.onStop()
    }

    private fun setupRuleList(listView: ListView) {
        ruleAdapter = object : BaseAdapter() {
            override fun getCount(): Int = rules.size

            override fun getItem(position: Int): HostRule = rules[position]

            override fun getItemId(position: Int): Long = getItem(position).domain.hashCode().toLong()

            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view: View
                val holder: RuleRowHolder
                if (convertView == null) {
                    view = LayoutInflater.from(parent.context)
                        .inflate(R.layout.item_rule, parent, false)
                    holder = RuleRowHolder(
                        domainView = view.findViewById(R.id.ruleDomainText),
                        ipView = view.findViewById(R.id.ruleIpText),
                        removeButton = view.findViewById(R.id.removeRuleButton)
                    )
                    view.tag = holder
                } else {
                    view = convertView
                    holder = convertView.tag as RuleRowHolder
                }

                val rule = getItem(position)
                holder.domainView.text = rule.domain
                holder.ipView.text = rule.ip
                holder.removeButton.setOnClickListener {
                    showDeleteRuleDialog(rule)
                }
                return view
            }
        }
        listView.adapter = ruleAdapter
        listView.emptyView = binding.emptyView
        listView.setOnItemLongClickListener { _, _, position, _ ->
            val rule = rules.getOrNull(position) ?: return@setOnItemLongClickListener true
            showDeleteRuleDialog(rule)
            true
        }
    }

    private fun showDeleteRuleDialog(rule: HostRule) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_rule_title)
            .setMessage(getString(R.string.delete_rule_message, rule.domain))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete) { _, _ ->
                deleteRule(rule)
            }
            .show()
    }

    private fun deleteRule(rule: HostRule) {
        rules.remove(rule)
        HostRuleStore.saveRules(this, rules)
        loadRulesFromStore()
        renderRules()
        toast(R.string.rule_deleted)
    }

    private fun addOrUpdateRule() {
        val domain = HostRuleStore.normalizeDomain(binding.domainInput.text?.toString().orEmpty())
        val ip = binding.ipInput.text?.toString().orEmpty().trim()

        if (!isValidDomain(domain)) {
            toast(R.string.invalid_domain)
            return
        }

        if (HostRuleStore.parseIpv4(ip) == null) {
            toast(R.string.invalid_ip)
            return
        }

        val existingIndex = rules.indexOfFirst { it.domain == domain }
        if (existingIndex >= 0) {
            rules[existingIndex] = HostRule(domain = domain, ip = ip)
            Log.i(LOG_TAG, "Rule updated domain=$domain ip=$ip")
            toast(R.string.rule_updated)
        } else {
            rules.add(HostRule(domain = domain, ip = ip))
            Log.i(LOG_TAG, "Rule added domain=$domain ip=$ip")
            toast(R.string.rule_saved)
        }

        rules.sortBy { it.domain }
        HostRuleStore.saveRules(this, rules)
        loadRulesFromStore()
        renderRules()

        binding.domainInput.text?.clear()
        binding.ipInput.text?.clear()
        binding.domainInput.requestFocus()
    }

    private fun requestVpnPermissionAndStart() {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            startVpn()
            return
        }
        vpnPermissionLauncher.launch(intent)
    }

    private fun startVpn() {
        val intent = Intent(this, HostsVpnService::class.java).apply {
            action = HostsVpnService.ACTION_START
        }
        warnIfPrivateDnsEnabled()
        HostRuleStore.setVpnRunning(this, true)
        Log.i(LOG_TAG, "Start VPN requested from UI")
        startService(intent)
        renderVpnState()
    }

    private fun stopVpn() {
        startService(
            Intent(this, HostsVpnService::class.java).apply {
                action = HostsVpnService.ACTION_STOP
            }
        )
        HostRuleStore.setVpnRunning(this, false)
        Log.i(LOG_TAG, "Stop VPN requested from UI")
        renderVpnState()
    }

    private fun requestVpnStateSync() {
        startService(
            Intent(this, HostsVpnService::class.java).apply {
                action = HostsVpnService.ACTION_QUERY_STATE
            }
        )
    }

    private fun renderRules() {
        ruleAdapter.notifyDataSetChanged()
    }

    private fun renderVpnState() {
        val running = HostRuleStore.isVpnRunning(this)
        val buttonText = if (running) R.string.stop_vpn else R.string.start_vpn
        val stateText = if (running) R.string.vpn_status_running else R.string.vpn_status_stopped
        binding.vpnToggleButton.setText(buttonText)
        binding.vpnStatusText.setText(stateText)
    }

    private fun loadRulesFromStore() {
        rules.clear()
        rules.addAll(HostRuleStore.loadRules(this))
        rules.sortBy { it.domain }
        val preview = rules.take(5).joinToString(",") { "${it.domain}->${it.ip}" }
        Log.i(
            LOG_TAG,
            "Rules loaded count=${rules.size} preview=${if (preview.isBlank()) "none" else preview}"
        )
    }

    private fun warnIfPrivateDnsEnabled() {
        val mode = try {
            Settings.Global.getString(contentResolver, PRIVATE_DNS_MODE_KEY)
        } catch (_: Exception) {
            null
        }?.trim()?.lowercase(Locale.US)

        if (mode.isNullOrEmpty()) {
            return
        }

        if (mode != PRIVATE_DNS_MODE_OFF) {
            Log.w(
                LOG_TAG,
                "Private DNS appears enabled (mode=$mode). This can bypass local DNS host mapping."
            )
            toast(R.string.private_dns_warning)
        }
    }

    private fun isValidDomain(domain: String): Boolean {
        if (domain.isBlank() || domain.length > 253) {
            return false
        }

        val labels = domain.split(".")
        if (labels.any { it.isBlank() || it.length > 63 }) {
            return false
        }

        return labels.all { label ->
            label.all { char ->
                char.isLetterOrDigit() || char == '-'
            } && !label.startsWith("-") && !label.endsWith("-")
        }
    }

    private fun toast(messageResId: Int) {
        Toast.makeText(this, messageResId, Toast.LENGTH_SHORT).show()
    }

    private fun registerVpnStateReceiver() {
        if (isReceiverRegistered) {
            return
        }
        val filter = IntentFilter(HostsVpnService.ACTION_VPN_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStateReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(vpnStateReceiver, filter)
        }
        isReceiverRegistered = true
        Log.i(LOG_TAG, "VPN state receiver registered")
    }

    private fun unregisterVpnStateReceiver() {
        if (!isReceiverRegistered) {
            return
        }
        try {
            unregisterReceiver(vpnStateReceiver)
        } catch (_: Exception) {
            // Ignore if receiver lifecycle raced with activity stop.
        }
        isReceiverRegistered = false
        Log.i(LOG_TAG, "VPN state receiver unregistered")
    }

    companion object {
        private const val LOG_TAG = "DNS_HOST_MAP_TRACE"
        private const val PRIVATE_DNS_MODE_KEY = "private_dns_mode"
        private const val PRIVATE_DNS_MODE_OFF = "off"
    }

    private data class RuleRowHolder(
        val domainView: TextView,
        val ipView: TextView,
        val removeButton: View
    )
}
