package com.foundationdevices.passport.quantumlink

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.ArrayDeque
import java.util.UUID
import uniffi.quantumlink_mobile.QlSession
import uniffi.quantumlink_mobile.buildHeartbeatResponse
import uniffi.quantumlink_mobile.buildPairingRequest
import uniffi.quantumlink_mobile.buildUnpairingRequest
import uniffi.quantumlink_mobile.buildUnpairingResponse
import uniffi.quantumlink_mobile.buildWdkMoneroKeyImageSyncRequest
import uniffi.quantumlink_mobile.buildWdkMoneroSignTransactionRequest
import uniffi.quantumlink_mobile.buildWdkMoneroVerifyAddressRequest
import uniffi.quantumlink_mobile.buildWdkMoneroWalletRemovalResponse
import uniffi.quantumlink_mobile.buildWdkMoneroWatchCredentialsRequest
import uniffi.quantumlink_mobile.buildWdkRequestCancelled
import uniffi.quantumlink_mobile.generateIdentity
import uniffi.quantumlink_mobile.identityXid

class PassportQuantumLinkPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
  companion object {
    private val NUS_SERVICE: UUID =
      UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
    private val NUS_RX: UUID =
      UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
    private val NUS_TX: UUID =
      UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E")
    private val CCCD: UUID =
      UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    private const val TRANSPORT_LE = 2
    private const val PREFS = "passport_quantumlink_public"
    private const val KEY_PRIME_XID = "prime_xid_b64"
    private const val KEY_PRIME_MAC = "prime_mac"
    private const val KEY_PRIME_NAME = "prime_name"
    private const val CONNECT_TIMEOUT_MS = 15_000L
    private const val SETUP_TIMEOUT_MS = 15_000L
    private const val SERVICE_DISCOVERY_DELAY_MS = 500L
    private const val PAIR_TIMEOUT_MS = 20_000L
    private const val UNPAIR_TIMEOUT_MS = 3_000L
    private const val MONERO_REQUEST_TIMEOUT_MS = 180_000L
    private const val MONERO_KEY_IMAGE_REQUEST_TIMEOUT_MS = 60_000L
    private const val LOG_TAG = "PassportQuantumLink"
    private val AUTO_RECONNECT_DELAYS_MS =
      longArrayOf(500L, 1_000L, 2_000L, 5_000L, 10_000L, 30_000L)
  }

  private enum class LinkState(val value: String) {
    UNAVAILABLE("unavailable"),
    DISCONNECTED("disconnected"),
    RECONNECTING("reconnecting"),
    SCANNING("scanning"),
    CONNECTING("connecting"),
    DISCOVERING("discovering"),
    CONNECTED("connected"),
    PAIRED("paired")
  }

  private lateinit var channel: MethodChannel
  private lateinit var context: Context
  private val mainHandler = Handler(Looper.getMainLooper())
  private val outbox = ArrayDeque<ByteArray>()
  private val diagnostics = ArrayDeque<String>()

  private var state = LinkState.DISCONNECTED
  private var gatt: BluetoothGatt? = null
  private var writeCharacteristic: BluetoothGattCharacteristic? = null
  private var session: QlSession? = null
  private var scanner: BluetoothLeScanner? = null
  private var scanning = false
  private var writeInProgress = false
  private var connectionGeneration = 0
  private var connectionStartedAt = 0L
  private var notificationsReady = false
  private var initialReconnectAttempts = 0
  private var targetAddress: String? = null
  private var connectResult: MethodChannel.Result? = null
  private val connectWaiters = mutableListOf<MethodChannel.Result>()
  private var pairResult: MethodChannel.Result? = null
  private var pairTimeout: Runnable? = null
  private val pairRetries = mutableListOf<Runnable>()
  private var unpairResult: MethodChannel.Result? = null
  private var unpairTimeout: Runnable? = null
  private var pendingPrimeXid: String? = null
  private var identityBytes: ByteArray? = null
  private val pendingMoneroRequests = mutableMapOf<String, PendingMoneroRequest>()
  private var autoReconnectEnabled = false
  private var autoReconnectAttempt = 0
  private var autoReconnectRunnable: Runnable? = null
  private var bluetoothStateReceiverRegistered = false

  private val bluetoothStateReceiver = object : BroadcastReceiver() {
    override fun onReceive(receiverContext: Context?, intent: Intent?) {
      if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
      when (
        intent.getIntExtra(
          BluetoothAdapter.EXTRA_STATE,
          BluetoothAdapter.ERROR
        )
      ) {
        BluetoothAdapter.STATE_TURNING_OFF,
        BluetoothAdapter.STATE_OFF -> {
          if (!isBluetoothEnabled()) handleBluetoothDisabled()
        }
        BluetoothAdapter.STATE_ON -> {
          if (isBluetoothEnabled()) handleBluetoothEnabled()
        }
      }
    }
  }

  private data class PendingMoneroRequest(
    val kind: String,
    val result: MethodChannel.Result,
    val timeout: Runnable
  )

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    context = binding.applicationContext
    channel = MethodChannel(binding.binaryMessenger, "foundation.devices/passport_quantumlink")
    channel.setMethodCallHandler(this)
    registerBluetoothStateReceiver()
    autoReconnectEnabled = isPaired()
    if (autoReconnectEnabled) {
      if (isBluetoothEnabled()) {
        scheduleAutoReconnect(immediate = true)
      } else {
        setState(LinkState.UNAVAILABLE)
      }
    }
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    autoReconnectEnabled = false
    cancelAutoReconnect()
    unregisterBluetoothStateReceiver()
    cleanupConnection("Plugin detached", true)
    channel.setMethodCallHandler(null)
  }

  override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
    when (call.method) {
      "isAvailable" -> result.success(isBluetoothEnabled())
      "getStatus" -> result.success(statusMap())
      "getIdentityXid" -> result.success(Base64.encodeToString(identityXid(identity()), Base64.NO_WRAP))
      "getDiagnostics" -> result.success(diagnostics.joinToString("\n"))
      "connect" -> connect(call.arguments as String, result)
      "reconnect" -> reconnect(result)
      "pair" -> {
        val args = call.arguments as? Map<*, *> ?: emptyMap<String, Any?>()
        val primeXid = args["primeXidBase64"] as? String
        val phoneName = args["phoneName"] as? String ?: "Cake Wallet"
        if (primeXid == null) {
          result.error("invalid_pairing", "Passport identity is missing", null)
        } else {
          pair(primeXid, phoneName, result)
        }
      }
      "disconnect" -> {
        autoReconnectEnabled = false
        cancelAutoReconnect()
        cleanupConnection("Disconnected", true)
        result.success(null)
      }
      "unpair" -> unpair(result)
      "forget" -> {
        autoReconnectEnabled = false
        cancelAutoReconnect()
        clearPairing()
        cleanupConnection("Forgotten on this phone", true)
        result.success(null)
      }
      "cancel" -> {
        cancelRequest(call.arguments as String)
        result.success(null)
      }
      "getMoneroWatchCredentials" -> getMoneroWatchCredentials(call.arguments as String, result)
      "syncMoneroKeyImages" -> {
        val args = call.arguments as? Map<*, *> ?: emptyMap<String, Any?>()
        val requestId = args["requestId"] as? String
        val outputsUr = args["outputsUr"] as? String
        if (requestId == null || outputsUr == null) {
          result.error("invalid_request", "Monero key-image sync request is incomplete", null)
        } else {
          syncMoneroKeyImages(requestId, outputsUr, result)
        }
      }
      "signMoneroTransaction" -> {
        val args = call.arguments as? Map<*, *> ?: emptyMap<String, Any?>()
        val requestId = args["requestId"] as? String
        val unsignedTxUr = args["unsignedTxUr"] as? String
        if (requestId == null || unsignedTxUr == null) {
          result.error("invalid_request", "Monero signing request is incomplete", null)
        } else {
          signMoneroTransaction(requestId, unsignedTxUr, result)
        }
      }
      "verifyMoneroAddress" -> {
        val args = call.arguments as? Map<*, *> ?: emptyMap<String, Any?>()
        val requestId = args["requestId"] as? String
        val walletAddress = args["walletAddress"] as? String
        val address = args["address"] as? String
        val accountIndex = (args["accountIndex"] as? Number)?.toLong()
        val addressIndex = (args["addressIndex"] as? Number)?.toLong()
        val validIndexes = accountIndex != null &&
          addressIndex != null &&
          accountIndex in 0..UInt.MAX_VALUE.toLong() &&
          addressIndex in 0..UInt.MAX_VALUE.toLong()
        if (requestId == null || walletAddress == null || address == null || !validIndexes) {
          result.error("invalid_request", "Monero address verification request is incomplete", null)
        } else {
          verifyMoneroAddress(
            requestId,
            walletAddress,
            accountIndex!!.toUInt(),
            addressIndex!!.toUInt(),
            address,
            result
          )
        }
      }
      "respondToMoneroWalletRemoval" -> {
        val args = call.arguments as? Map<*, *> ?: emptyMap<String, Any?>()
        val requestId = args["requestId"] as? String
        val walletAddress = args["walletAddress"] as? String
        val removed = args["removed"] as? Boolean
        if (requestId == null || walletAddress == null || removed == null) {
          result.error("invalid_request", "Monero wallet-removal response is incomplete", null)
        } else {
          respondToMoneroWalletRemoval(requestId, walletAddress, removed, result)
        }
      }
      else -> result.notImplemented()
    }
  }

  private fun publicPrefs() = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  private fun identity(): ByteArray {
    identityBytes?.let { return it }
    val store = SecureIdentityStore(context)
    val loaded = store.load()
    val identity = loaded ?: generateIdentity().also(store::save)
    identityBytes = identity
    return identity
  }

  @SuppressLint("MissingPermission")
  private fun bluetoothAdapter(): BluetoothAdapter? {
    val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    return manager?.adapter
  }

  @SuppressLint("MissingPermission")
  private fun isBluetoothEnabled(): Boolean = try {
    bluetoothAdapter()?.isEnabled == true
  } catch (_: SecurityException) {
    false
  }

  private fun registerBluetoothStateReceiver() {
    if (bluetoothStateReceiverRegistered) return
    val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      context.registerReceiver(
        bluetoothStateReceiver,
        filter,
        Context.RECEIVER_EXPORTED
      )
    } else {
      @Suppress("DEPRECATION")
      context.registerReceiver(bluetoothStateReceiver, filter)
    }
    bluetoothStateReceiverRegistered = true
  }

  private fun unregisterBluetoothStateReceiver() {
    if (!bluetoothStateReceiverRegistered) return
    try {
      context.unregisterReceiver(bluetoothStateReceiver)
    } catch (_: IllegalArgumentException) {
    }
    bluetoothStateReceiverRegistered = false
  }

  private fun handleBluetoothDisabled() {
    trace("adapter_off")
    cancelAutoReconnect()
    autoReconnectAttempt = 0
    val resumeWhenEnabled = autoReconnectEnabled && isPaired()
    setState(LinkState.UNAVAILABLE)
    cleanupConnection("Bluetooth is turned off", true)
    autoReconnectEnabled = resumeWhenEnabled
  }

  private fun handleBluetoothEnabled() {
    trace("adapter_on")
    if (!isPaired()) {
      setState(LinkState.DISCONNECTED)
      return
    }
    autoReconnectEnabled = true
    autoReconnectAttempt = 0
    cancelAutoReconnect()
    cleanupConnection("Bluetooth was restored", false)
    scheduleAutoReconnect(immediate = true)
  }

  private fun isPaired(): Boolean = publicPrefs().contains(KEY_PRIME_XID)

  private fun isConnected(): Boolean =
    gatt != null && writeCharacteristic != null &&
      (state == LinkState.CONNECTED || state == LinkState.PAIRED)

  private fun statusMap(): Map<String, Any?> {
    val available = isBluetoothEnabled()
    return mapOf(
      "available" to available,
      "paired" to isPaired(),
      "connected" to isConnected(),
      "state" to if (available) state.value else LinkState.UNAVAILABLE.value,
      "deviceName" to publicPrefs().getString(KEY_PRIME_NAME, null),
      "deviceAddress" to publicPrefs().getString(KEY_PRIME_MAC, targetAddress)
    )
  }

  private fun setState(next: LinkState) {
    if (state == next) return
    state = next
    trace("state", next.value)
    mainHandler.post {
      if (::channel.isInitialized) {
        channel.invokeMethod("connectionStateChanged", statusMap())
      }
    }
  }

  @Synchronized
  private fun trace(stage: String, detail: String = "") {
    val elapsed =
      if (connectionStartedAt == 0L) 0L else SystemClock.elapsedRealtime() - connectionStartedAt
    val entry = "${elapsed}ms $stage${if (detail.isEmpty()) "" else " $detail"}"
    if (diagnostics.size >= 64) diagnostics.removeFirst()
    diagnostics.addLast(entry)
    Log.i(LOG_TAG, entry)
  }

  @SuppressLint("MissingPermission")
  private fun reconnect(result: MethodChannel.Result) {
    val address = publicPrefs().getString(KEY_PRIME_MAC, null)
    if (address == null) {
      result.error("not_paired", "No paired Passport Prime is stored", null)
    } else {
      autoReconnectAttempt = 0
      connect(address, result)
    }
  }

  @SuppressLint("MissingPermission")
  private fun connect(
    deviceAddress: String,
    result: MethodChannel.Result,
    automatic: Boolean = false
  ) {
    try {
      autoReconnectEnabled = true
      cancelAutoReconnect()
      if (!automatic) autoReconnectAttempt = 0
      val normalizedAddress = deviceAddress.uppercase()
      if (isConnected() && targetAddress?.equals(normalizedAddress, ignoreCase = true) == true) {
        trace("connect_ready", normalizedAddress)
        result.success(null)
        return
      }
      if (connectResult != null) {
        if (targetAddress?.equals(normalizedAddress, ignoreCase = true) == true) {
          trace("connect_join", normalizedAddress)
          connectWaiters.add(result)
          return
        }
        failConnectResults(
          "connection_replaced",
          "Starting a new Passport Prime connection"
        )
      }

      val adapter = bluetoothAdapter()
      if (adapter == null) {
        result.error("ble_unavailable", "Bluetooth LE is unavailable", null)
        return
      }
      if (!adapter.isEnabled) {
        result.error("ble_disabled", "Bluetooth is turned off", null)
        return
      }

      cleanupConnection("Starting a new connection", true)
      connectionStartedAt = SystemClock.elapsedRealtime()
      trace("connect_start", normalizedAddress)
      session = QlSession(identity())
      storedPrimeXid()?.let { session?.setExpectedPeer(it) }
      targetAddress = normalizedAddress
      connectResult = result
      scanner = adapter.bluetoothLeScanner
      if (scanner == null) {
        failConnect("BLE scanner is unavailable")
        return
      }

      val filters = listOf(ScanFilter.Builder().setDeviceAddress(targetAddress).build())
      val settings = ScanSettings.Builder()
        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
        .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
        .build()
      scanning = true
      setState(LinkState.SCANNING)
      scanner?.startScan(filters, settings, scanCallback)
      val scanGeneration = connectionGeneration
      mainHandler.postDelayed({
        if (scanning && scanGeneration == connectionGeneration) {
          stopScan()
          failConnect("Passport Prime scan timed out")
        }
      }, CONNECT_TIMEOUT_MS)
    } catch (error: Exception) {
      result.error("ble_connect", error.message, null)
      connectResult = null
      cleanupConnection("Connection failed", false)
    }
  }

  @SuppressLint("MissingPermission")
  private fun stopScan() {
    scanning = false
    try {
      scanner?.stopScan(scanCallback)
    } catch (_: Exception) {
    }
  }

  private val scanCallback = object : ScanCallback() {
    @SuppressLint("MissingPermission")
    override fun onScanResult(callbackType: Int, result: ScanResult?) {
      val device = result?.device ?: return
      val addressMatches = device.address?.equals(targetAddress, ignoreCase = true) == true
      if (!scanning || !addressMatches) return

      stopScan()
      trace("scan_match", "${device.address} rssi=${result.rssi}")
      setState(LinkState.CONNECTING)
      gatt = device.connectGatt(context, true, gattCallback, TRANSPORT_LE)
      val currentResult = connectResult
      val generation = connectionGeneration
      mainHandler.postDelayed({
        if (
          generation == connectionGeneration &&
          connectResult === currentResult &&
          currentResult != null
        ) {
          trace("setup_timeout")
          failConnect("Passport Prime Bluetooth setup timed out")
        }
      }, SETUP_TIMEOUT_MS)
    }

    override fun onScanFailed(errorCode: Int) {
      failConnect("BLE scan failed ($errorCode)")
    }
  }

  @SuppressLint("MissingPermission")
  private fun pair(primeXidBase64: String, phoneName: String, result: MethodChannel.Result) {
    try {
      autoReconnectEnabled = true
      if (!isConnected()) {
        result.error("not_connected", "Connect to Passport Prime before pairing", null)
        return
      }
      check(pairResult == null) { "A Passport Prime pairing request is already pending" }
      val primeXid = Base64.decode(primeXidBase64, Base64.NO_WRAP)
      // Notifications received while connecting may belong to a peer that
      // Prime retained from an older pairing. Start the authenticated pairing
      // exchange with a clean decoder and the scanned Prime identity.
      session = QlSession(identity()).also { it.setExpectedPeer(primeXid) }
      pendingPrimeXid = primeXidBase64
      pairResult = result
      trace("pair_start", "xid_bytes=${primeXid.size}")
      sendPairingAttempt(primeXid, phoneName, result, 1)

      longArrayOf(1_500L, 4_000L, 8_000L).forEachIndexed { index, delay ->
        val retry = Runnable {
          if (pairResult !== result || !isConnected()) return@Runnable
          try {
            sendPairingAttempt(primeXid, phoneName, result, index + 2)
          } catch (error: Exception) {
            trace("pair_retry_error", error.message ?: error.javaClass.simpleName)
          }
        }
        pairRetries.add(retry)
        mainHandler.postDelayed(retry, delay)
      }

      val timeout = Runnable {
        if (pairResult === result) {
          trace("pair_timeout")
          cancelPairTimers()
          pairResult = null
          pendingPrimeXid = null
          result.error("pair_timeout", "Passport Prime pairing timed out", null)
        }
      }
      pairTimeout = timeout
      mainHandler.postDelayed(timeout, PAIR_TIMEOUT_MS)
    } catch (error: Exception) {
      trace("pair_error", error.message ?: error.javaClass.simpleName)
      cancelPairTimers()
      pairResult = null
      pendingPrimeXid = null
      result.error("pair_failed", error.message, null)
    }
  }

  private fun sendPairingAttempt(
    primeXid: ByteArray,
    phoneName: String,
    result: MethodChannel.Result,
    attempt: Int
  ) {
    if (pairResult !== result) return
    val frames = buildPairingRequest(identity(), primeXid, phoneName)
    trace("pair_tx", "attempt=$attempt frames=${frames.size}")
    enqueue(frames)
  }

  private fun cancelPairTimers() {
    pairTimeout?.let(mainHandler::removeCallbacks)
    pairTimeout = null
    pairRetries.forEach(mainHandler::removeCallbacks)
    pairRetries.clear()
  }

  @SuppressLint("MissingPermission")
  private fun unpair(result: MethodChannel.Result) {
    try {
      if (!isPaired()) {
        cleanupConnection("Unpaired", true)
        result.success(null)
        return
      }
      withPairedConnection(result, "unpair_failed") { primeXid ->
        check(unpairResult == null) { "An unpair request is already pending" }
        unpairResult = result
        enqueue(buildUnpairingRequest(identity(), primeXid))

        val timeout = Runnable {
          completeUnpair()
        }
        unpairTimeout = timeout
        mainHandler.postDelayed(timeout, UNPAIR_TIMEOUT_MS)
      }
    } catch (error: Exception) {
      unpairResult = null
      result.error("unpair_failed", error.message, null)
    }
  }

  @SuppressLint("MissingPermission")
  private fun cancelRequest(requestId: String) {
    val primeXid = storedPrimeXid()
    if (primeXid != null && isConnected()) {
      try {
        enqueue(buildWdkRequestCancelled(identity(), primeXid, requestIdBytes(requestId)))
      } catch (error: Exception) {
        trace("cancel_error", error.message ?: error.javaClass.simpleName)
      }
    }
    completeMoneroRequest(
      requestId,
      "request_cancelled",
      "The Passport Prime request was cancelled",
      null
    )
  }

  private fun getMoneroWatchCredentials(requestId: String, result: MethodChannel.Result) {
    submitMoneroRequest(requestId, "watch_credentials", "monero_watch_credentials", result) { primeXid, requestBytes ->
      buildWdkMoneroWatchCredentialsRequest(identity(), primeXid, requestBytes)
    }
  }

  private fun syncMoneroKeyImages(
    requestId: String,
    outputsUr: String,
    result: MethodChannel.Result
  ) {
    submitMoneroRequest(requestId, "key_image_sync", "monero_key_image_sync", result) { primeXid, requestBytes ->
      buildWdkMoneroKeyImageSyncRequest(identity(), primeXid, requestBytes, outputsUr)
    }
  }

  private fun signMoneroTransaction(
    requestId: String,
    unsignedTxUr: String,
    result: MethodChannel.Result
  ) {
    submitMoneroRequest(requestId, "transaction_signing", "monero_transaction_signing", result) { primeXid, requestBytes ->
      buildWdkMoneroSignTransactionRequest(identity(), primeXid, requestBytes, unsignedTxUr)
    }
  }

  private fun verifyMoneroAddress(
    requestId: String,
    walletAddress: String,
    accountIndex: UInt,
    addressIndex: UInt,
    address: String,
    result: MethodChannel.Result
  ) {
    submitMoneroRequest(requestId, "address_verification", "monero_address_verification", result) { primeXid, requestBytes ->
      buildWdkMoneroVerifyAddressRequest(
        identity(),
        primeXid,
        requestBytes,
        walletAddress,
        accountIndex,
        addressIndex,
        address
      )
    }
  }

  private fun respondToMoneroWalletRemoval(
    requestId: String,
    walletAddress: String,
    removed: Boolean,
    result: MethodChannel.Result
  ) {
    withPairedConnection(result, "monero_wallet_removal_response") { primeXid ->
      try {
        enqueue(
          buildWdkMoneroWalletRemovalResponse(
            identity(),
            primeXid,
            requestIdBytes(requestId),
            walletAddress,
            removed
          )
        )
        result.success(null)
      } catch (error: Exception) {
        result.error("monero_wallet_removal_response", error.message, null)
      }
    }
  }

  private fun submitMoneroRequest(
    requestId: String,
    kind: String,
    errorCode: String,
    result: MethodChannel.Result,
    buildFrames: (ByteArray, ByteArray) -> List<ByteArray>
  ) {
    withPairedConnection(result, errorCode) { primeXid ->
      try {
        val requestBytes = requestIdBytes(requestId)
        val frames = buildFrames(primeXid, requestBytes)
        val normalized = registerMoneroRequest(requestId, kind, result)
        try {
          enqueue(frames)
        } catch (error: Exception) {
          removePendingMoneroRequest(normalized)
          result.error(errorCode, error.message, null)
        }
      } catch (error: Exception) {
        result.error(errorCode, error.message, null)
      }
    }
  }

  private fun withPairedConnection(
    result: MethodChannel.Result,
    errorCode: String,
    action: (ByteArray) -> Unit
  ) {
    val address = publicPrefs().getString(KEY_PRIME_MAC, null)
    val pairedXid = storedPrimeXid()
    if (address == null || pairedXid == null) {
      result.error("not_paired", "Pair Passport Prime before continuing", null)
      return
    }
    if (isConnected()) {
      action(pairedXid)
      return
    }

    trace("auto_reconnect", errorCode)
    connect(address, object : MethodChannel.Result {
      override fun success(value: Any?) {
        val primeXid = storedPrimeXid()
        if (primeXid == null) {
          result.error("not_paired", "Pair Passport Prime before continuing", null)
          return
        }
        try {
          action(primeXid)
        } catch (error: Exception) {
          result.error(errorCode, error.message, null)
        }
      }

      override fun error(code: String, message: String?, details: Any?) {
        result.error(code, message, details)
      }

      override fun notImplemented() {
        result.notImplemented()
      }
    })
  }

  private fun registerMoneroRequest(
    requestId: String,
    kind: String,
    result: MethodChannel.Result
  ): String {
    val normalized = normalizeRequestId(requestId)
    pendingMoneroRequests.remove(normalized)?.let {
      mainHandler.removeCallbacks(it.timeout)
      it.result.error("request_replaced", "A newer Passport Prime request replaced this one", null)
    }
    val timeout = Runnable {
      val pending = pendingMoneroRequests.remove(normalized) ?: return@Runnable
      pending.result.error("request_timeout", "Passport Prime did not answer in time", null)
    }
    pendingMoneroRequests[normalized] = PendingMoneroRequest(kind, result, timeout)
    val timeoutMs =
      if (kind == "key_image_sync") MONERO_KEY_IMAGE_REQUEST_TIMEOUT_MS
      else MONERO_REQUEST_TIMEOUT_MS
    mainHandler.postDelayed(timeout, timeoutMs)
    trace("monero_tx", "kind=$kind request=$normalized")
    return normalized
  }

  private fun removePendingMoneroRequest(requestId: String) {
    pendingMoneroRequests.remove(normalizeRequestId(requestId))?.let {
      mainHandler.removeCallbacks(it.timeout)
    }
  }

  private fun completeMoneroRequest(
    requestId: String,
    errorCode: String?,
    errorMessage: String?,
    success: Any?
  ) {
    val normalized = normalizeRequestId(requestId)
    val pending = pendingMoneroRequests.remove(normalized) ?: return
    mainHandler.removeCallbacks(pending.timeout)
    trace("monero_complete", "kind=${pending.kind} request=$normalized")
    if (errorCode == null) {
      pending.result.success(success)
    } else {
      pending.result.error(errorCode, errorMessage, null)
    }
  }

  private fun completeConnectSuccess() {
    val primary = connectResult
    connectResult = null
    primary?.success(null)
    val waiters = connectWaiters.toList()
    connectWaiters.clear()
    waiters.forEach { it.success(null) }
  }

  private fun failConnectResults(code: String, message: String) {
    val primary = connectResult
    connectResult = null
    primary?.error(code, message, null)
    val waiters = connectWaiters.toList()
    connectWaiters.clear()
    waiters.forEach { it.error(code, message, null) }
  }

  private fun failPendingMoneroRequests(code: String, message: String) {
    val pending = pendingMoneroRequests.toList()
    pendingMoneroRequests.clear()
    for ((_, request) in pending) {
      mainHandler.removeCallbacks(request.timeout)
      request.result.error(code, message, null)
    }
  }

  private fun storedPrimeXid(): ByteArray? =
    publicPrefs().getString(KEY_PRIME_XID, null)?.let {
      Base64.decode(it, Base64.NO_WRAP)
    }

  @SuppressLint("MissingPermission")
  private fun enqueue(frames: List<ByteArray>) {
    check(isConnected()) { "Passport Prime is not connected" }
    outbox.addAll(frames)
    writeNext()
  }

  @SuppressLint("MissingPermission")
  private fun writeNext() {
    if (writeInProgress) return
    val gatt = gatt ?: return
    val characteristic = writeCharacteristic ?: return
    if (outbox.isEmpty()) return
    val frame = outbox.removeFirst()
    writeInProgress = true
    val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      gatt.writeCharacteristic(
        characteristic,
        frame,
        BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
      ) == android.bluetooth.BluetoothStatusCodes.SUCCESS
    } else {
      @Suppress("DEPRECATION")
      characteristic.value = frame
      @Suppress("DEPRECATION")
      characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
      @Suppress("DEPRECATION")
      gatt.writeCharacteristic(characteristic)
    }
    if (!started) {
      writeInProgress = false
      failAll("ble_write", "Could not write to Passport Prime")
    }
  }

  private val gattCallback = object : BluetoothGattCallback() {
    @SuppressLint("MissingPermission")
    override fun onConnectionStateChange(
      connection: BluetoothGatt,
      status: Int,
      newState: Int
    ) {
      if (gatt !== connection) return
      if (newState == BluetoothProfile.STATE_CONNECTED) {
        trace("gatt_connected", "status=$status bond=${connection.device.bondState}")
        setState(LinkState.DISCOVERING)
        connection.requestMtu(247)
        connection.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_BALANCED)
        connection.setPreferredPhy(
          BluetoothDevice.PHY_LE_2M,
          BluetoothDevice.PHY_LE_2M,
          BluetoothDevice.PHY_OPTION_NO_PREFERRED
        )
        val generation = connectionGeneration
        mainHandler.postDelayed({
          if (generation == connectionGeneration && gatt === connection) {
            trace("service_discovery_start")
            if (!connection.discoverServices()) {
              failConnect("Could not start Passport Prime service discovery")
            }
          }
        }, SERVICE_DISCOVERY_DELAY_MS)
      } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
        trace("gatt_disconnected", "status=$status")
        if (connectResult != null) {
          writeCharacteristic = null
          notificationsReady = false
          outbox.clear()
          writeInProgress = false
          setState(LinkState.CONNECTING)
          scheduleInitialReconnect(connection)
          return
        }
        failAll("ble_disconnected", "Passport Prime disconnected")
        cleanupConnection("Passport Prime disconnected", false)
        scheduleAutoReconnect()
      }
    }

    @SuppressLint("MissingPermission")
    override fun onMtuChanged(connection: BluetoothGatt, mtu: Int, status: Int) {
      trace("mtu", "value=$mtu status=$status")
    }

    @SuppressLint("MissingPermission")
    override fun onServicesDiscovered(connection: BluetoothGatt, status: Int) {
      if (status != BluetoothGatt.GATT_SUCCESS) {
        failConnect("Could not discover Passport Prime services")
        return
      }
      trace("services_discovered")
      val service = connection.getService(NUS_SERVICE)
      if (service == null) {
        failConnect("Passport Prime QuantumLink service was not found")
        return
      }
      writeCharacteristic = service.getCharacteristic(NUS_RX)
      val notify = service.getCharacteristic(NUS_TX)
      if (writeCharacteristic == null || notify == null) {
        failConnect("Passport Prime QuantumLink characteristics were not found")
        return
      }
      connection.setCharacteristicNotification(notify, true)
      val descriptor = notify.getDescriptor(CCCD)
      if (descriptor == null) {
        failConnect("Passport Prime notification descriptor was not found")
        return
      }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        val started = connection.writeDescriptor(
          descriptor,
          BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
        if (started != android.bluetooth.BluetoothStatusCodes.SUCCESS) {
          failConnect("Could not start Passport Prime notification setup")
        }
      } else {
        @Suppress("DEPRECATION")
        descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        @Suppress("DEPRECATION")
        connection.writeDescriptor(descriptor)
      }
    }

    override fun onDescriptorWrite(
      connection: BluetoothGatt,
      descriptor: BluetoothGattDescriptor,
      status: Int
    ) {
      if (status != BluetoothGatt.GATT_SUCCESS) {
        failConnect("Could not enable Passport Prime notifications")
        return
      }
      notificationsReady = true
      trace("notifications_enabled")
      finishConnectionSetup(connection, connectionGeneration)
    }

    override fun onCharacteristicWrite(
      connection: BluetoothGatt,
      characteristic: BluetoothGattCharacteristic,
      status: Int
    ) {
      writeInProgress = false
      if (status == BluetoothGatt.GATT_SUCCESS) {
        writeNext()
      } else {
        failAll("ble_write", "Passport Prime rejected a BLE frame")
      }
    }

    override fun onCharacteristicChanged(
      connection: BluetoothGatt,
      characteristic: BluetoothGattCharacteristic,
      value: ByteArray
    ) {
      handleNotification(value)
    }

    @Deprecated("Deprecated in API 33")
    override fun onCharacteristicChanged(
      connection: BluetoothGatt,
      characteristic: BluetoothGattCharacteristic
    ) {
      @Suppress("DEPRECATION")
      handleNotification(characteristic.value ?: ByteArray(0))
    }
  }

  @SuppressLint("MissingPermission")
  private fun scheduleInitialReconnect(connection: BluetoothGatt) {
    val delays = longArrayOf(250L, 750L, 1_500L)
    if (initialReconnectAttempts >= delays.size) {
      failConnect("Passport Prime disconnected during Bluetooth setup")
      return
    }
    val attempt = initialReconnectAttempts
    initialReconnectAttempts += 1
    val generation = connectionGeneration
    mainHandler.postDelayed({
      if (generation != connectionGeneration || gatt !== connection || connectResult == null) {
        return@postDelayed
      }
      trace("setup_reconnect", "attempt=${attempt + 1}")
      if (!connection.connect()) {
        scheduleInitialReconnect(connection)
      }
    }, delays[attempt])
  }

  private fun finishConnectionSetup(connection: BluetoothGatt, generation: Int) {
    if (generation != connectionGeneration || gatt !== connection || !notificationsReady) return
    trace("ready", "notifications=true")
    autoReconnectAttempt = 0
    cancelAutoReconnect()
    setState(if (isPaired()) LinkState.PAIRED else LinkState.CONNECTED)
    completeConnectSuccess()
  }

  private fun cancelAutoReconnect() {
    autoReconnectRunnable?.let(mainHandler::removeCallbacks)
    autoReconnectRunnable = null
  }

  private fun scheduleAutoReconnect(immediate: Boolean = false) {
    if (
      !autoReconnectEnabled ||
      !isPaired() ||
      isConnected() ||
      connectResult != null ||
      autoReconnectRunnable != null
    ) {
      return
    }
    if (!isBluetoothEnabled()) {
      setState(LinkState.UNAVAILABLE)
      return
    }
    val address = publicPrefs().getString(KEY_PRIME_MAC, null) ?: return
    val delayIndex = autoReconnectAttempt.coerceAtMost(AUTO_RECONNECT_DELAYS_MS.lastIndex)
    val delay = if (immediate) 0L else AUTO_RECONNECT_DELAYS_MS[delayIndex]
    autoReconnectAttempt += 1
    setState(LinkState.RECONNECTING)
    trace("reconnect_scheduled", "attempt=$autoReconnectAttempt delay=$delay")
    val retry = Runnable {
      autoReconnectRunnable = null
      if (!autoReconnectEnabled || !isPaired() || isConnected() || connectResult != null) {
        return@Runnable
      }
      trace("reconnect_start", "attempt=$autoReconnectAttempt")
      connect(address, backgroundReconnectResult(), automatic = true)
    }
    autoReconnectRunnable = retry
    mainHandler.postDelayed(retry, delay)
  }

  private fun backgroundReconnectResult() = object : MethodChannel.Result {
    override fun success(value: Any?) {
      trace("reconnect_complete")
    }

    override fun error(code: String, message: String?, details: Any?) {
      trace("reconnect_retry", "$code ${message ?: ""}".trim())
      scheduleAutoReconnect()
    }

    override fun notImplemented() {
      scheduleAutoReconnect()
    }
  }

  private fun handleNotification(frame: ByteArray) {
    try {
      trace("rx_frame", "bytes=${frame.size}")
      val message = session?.feed(frame) ?: return
      trace("rx_message", message.kind)
      when (message.kind) {
        "PairingResponse" -> {
          val primeXid = pendingPrimeXid ?: return
          val name = message.deviceName.ifEmpty { "Passport Prime" }
          publicPrefs().edit()
            .putString(KEY_PRIME_XID, primeXid)
            .putString(KEY_PRIME_MAC, targetAddress)
            .putString(KEY_PRIME_NAME, name)
            .apply()
          pendingPrimeXid = null
          cancelPairTimers()
          setState(LinkState.PAIRED)
          pairResult?.success(name)
          pairResult = null
        }

        "Heartbeat" -> {
          val primeXid = pendingPrimeXid?.let {
            Base64.decode(it, Base64.NO_WRAP)
          } ?: storedPrimeXid()
          if (primeXid == null) {
            trace("heartbeat_ignored", "missing_peer")
          } else {
            val frames = buildHeartbeatResponse(identity(), primeXid)
            trace("heartbeat_tx", "frames=${frames.size}")
            enqueue(frames)
          }
        }

        "UnpairingRequest" -> {
          val primeXid = storedPrimeXid()
          if (primeXid != null && isConnected()) {
            enqueue(buildUnpairingResponse(identity(), primeXid, true))
            mainHandler.postDelayed({ completeUnpair() }, 400L)
          } else {
            completeUnpair()
          }
        }

        "UnpairingResponse" -> {
          if (message.reasonCode == 1.toUByte()) {
            completeUnpair()
          } else {
            failUnpair("Passport Prime could not remove the pairing")
          }
        }

        "WdkMoneroWatchCredentialsResponse" -> {
          completeMoneroRequest(
            bytesToHex(message.requestId),
            null,
            null,
            mapOf(
              "watchKey" to message.watchKey,
              "address" to message.address,
              "walletName" to message.walletName,
              "restoreHeight" to message.restoreHeight?.toLong()
            )
          )
        }

        "WdkMoneroWalletMetadata" -> {
          mainHandler.post {
            channel.invokeMethod(
              "walletNameChanged",
              mapOf(
                "walletAddress" to message.address,
                "walletName" to message.walletName
              )
            )
          }
        }

        "WdkMoneroWalletRemovalRequest" -> {
          mainHandler.post {
            channel.invokeMethod(
              "walletRemovalRequested",
              mapOf(
                "requestId" to bytesToHex(message.requestId),
                "walletAddress" to message.address,
                "walletName" to message.walletName
              )
            )
          }
        }

        "WdkMoneroKeyImageSyncResponse" -> {
          completeMoneroRequest(
            bytesToHex(message.requestId),
            null,
            null,
            message.keyImagesUr
          )
        }

        "WdkMoneroSignTransactionResponse" -> {
          completeMoneroRequest(
            bytesToHex(message.requestId),
            null,
            null,
            message.signedTransactionUr
          )
        }

        "WdkMoneroVerifyAddressResponse" -> {
          completeMoneroRequest(
            bytesToHex(message.requestId),
            null,
            null,
            mapOf(
              "address" to message.address,
              "accountIndex" to message.accountIndex.toLong(),
              "addressIndex" to message.addressIndex.toLong()
            )
          )
        }

        "WdkRequestRejected" -> {
          completeMoneroRequest(
            bytesToHex(message.requestId),
            "request_rejected",
            message.message.ifEmpty { "Passport Prime rejected the request" },
            null
          )
        }

        "WdkRequestCancelled" -> {
          completeMoneroRequest(
            bytesToHex(message.requestId),
            "request_cancelled",
            "Passport Prime cancelled the request",
            null
          )
        }
      }
    } catch (error: Exception) {
      val detail = error.message ?: error.javaClass.simpleName
      trace("rx_error", detail)
      val pairingPeer = pendingPrimeXid
      if (pairingPeer != null && pairResult != null) {
        // BLE may deliver the tail of a message from Prime's previous peer
        // after the phone has scanned a fresh identity. Do not abort the new
        // pairing for that stale fragment: reset the decoder and let the
        // scheduled authenticated pairing retries continue.
        trace("rx_ignored_during_pair", detail)
        session = QlSession(identity()).also {
          it.setExpectedPeer(Base64.decode(pairingPeer, Base64.NO_WRAP))
        }
        return
      }
      if (
        pendingPrimeXid == null &&
        pairResult == null &&
        !isPaired() &&
        pendingMoneroRequests.isEmpty()
      ) {
        // A freshly reset phone can briefly receive a heartbeat encrypted for
        // Prime's previous peer. It is not part of this pairing attempt.
        trace("rx_ignored_pre_pair", detail)
        session = QlSession(identity())
        return
      }
      failAll("invalid_message", "Invalid QuantumLink response: $detail")
    }
  }

  private fun failConnect(reason: String) {
    failConnectResults("ble_connect", reason)
    cleanupConnection(reason, false)
    scheduleAutoReconnect()
  }

  private fun failAll(code: String, message: String) {
    cancelPairTimers()
    pairResult?.error(code, message, null)
    pairResult = null
    pendingPrimeXid = null
    val unpair = unpairResult
    unpairResult = null
    unpairTimeout?.let(mainHandler::removeCallbacks)
    unpairTimeout = null
    unpair?.error(code, message, null)
    failPendingMoneroRequests(code, message)
  }

  @SuppressLint("MissingPermission")
  private fun cleanupConnection(reason: String, clearRequests: Boolean) {
    connectionGeneration += 1
    stopScan()
    if (clearRequests) {
      failConnectResults("connection_closed", reason)
      failAll("connection_closed", reason)
    }
    try {
      gatt?.disconnect()
      gatt?.close()
    } catch (_: Exception) {
    }
    gatt = null
    writeCharacteristic = null
    notificationsReady = false
    initialReconnectAttempts = 0
    session = null
    outbox.clear()
    writeInProgress = false
    scanner = null
    if (state != LinkState.UNAVAILABLE) setState(LinkState.DISCONNECTED)
  }

  private fun clearPairing() {
    autoReconnectEnabled = false
    autoReconnectAttempt = 0
    cancelAutoReconnect()
    publicPrefs().edit()
      .remove(KEY_PRIME_XID)
      .remove(KEY_PRIME_MAC)
      .remove(KEY_PRIME_NAME)
      .apply()
    pendingPrimeXid = null
  }

  private fun completeUnpair() {
    val result = unpairResult
    unpairResult = null
    unpairTimeout?.let(mainHandler::removeCallbacks)
    unpairTimeout = null
    clearPairing()
    cleanupConnection("Unpaired", true)
    result?.success(null)
  }

  private fun failUnpair(message: String) {
    val result = unpairResult
    unpairResult = null
    unpairTimeout?.let(mainHandler::removeCallbacks)
    unpairTimeout = null
    result?.error("unpair_failed", message, null)
  }

  private fun requestIdBytes(value: String): ByteArray {
    val bytes = hexToBytes(normalizeRequestId(value))
    require(bytes.size == 16) { "Request ID must be 128 bits" }
    return bytes
  }

  private fun normalizeRequestId(value: String): String =
    value.removePrefix("0x").lowercase()

  private fun hexToBytes(value: String): ByteArray {
    val hex = value
    require(hex.length % 2 == 0 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
      "Invalid hex value"
    }
    return ByteArray(hex.length / 2) { index ->
      hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
  }

  private fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
