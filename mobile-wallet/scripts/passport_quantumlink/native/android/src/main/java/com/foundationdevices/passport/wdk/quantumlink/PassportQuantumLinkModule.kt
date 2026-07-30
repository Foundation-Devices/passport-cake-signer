package com.foundationdevices.passport.wdk.quantumlink

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
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.UUID
import uniffi.quantumlink_mobile.QlSession
import uniffi.quantumlink_mobile.buildHeartbeatResponse
import uniffi.quantumlink_mobile.buildPairingRequest
import uniffi.quantumlink_mobile.buildUnpairingRequest
import uniffi.quantumlink_mobile.buildUnpairingResponse
import uniffi.quantumlink_mobile.buildWdkEvmAccountRequest
import uniffi.quantumlink_mobile.buildWdkEvmSignTransactionRequest
import uniffi.quantumlink_mobile.buildWdkBtcAccountRequest
import uniffi.quantumlink_mobile.buildWdkBtcSignPsbtRequest
import uniffi.quantumlink_mobile.buildWdkRequestCancelled
import uniffi.quantumlink_mobile.generateIdentity
import uniffi.quantumlink_mobile.identityXid

class PassportQuantumLinkModule : Module() {
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
    private const val ACCOUNT_TIMEOUT_MS = 20_000L
    private const val REQUEST_TIMEOUT_MS = 120_000L
    private const val UNPAIR_TIMEOUT_MS = 3_000L
    private const val LOG_TAG = "PassportQuantumLink"
  }

  private enum class LinkState(val value: String) {
    UNAVAILABLE("unavailable"),
    DISCONNECTED("disconnected"),
    SCANNING("scanning"),
    CONNECTING("connecting"),
    DISCOVERING("discovering"),
    CONNECTED("connected"),
    PAIRED("paired")
  }

  private enum class RequestKind {
    EVM_ACCOUNT,
    EVM_SIGN,
    BTC_ACCOUNT,
    BTC_SIGN
  }

  private data class PendingRequest(
    val kind: RequestKind,
    val promise: Promise,
    val timeout: Runnable
  )

  private val mainHandler = Handler(Looper.getMainLooper())
  private val outbox = ArrayDeque<ByteArray>()
  private val pendingRequests = mutableMapOf<String, PendingRequest>()
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
  private var connectPromise: Promise? = null
  private var pairPromise: Promise? = null
  private var pairTimeout: Runnable? = null
  private val pairRetries = mutableListOf<Runnable>()
  private var unpairPromise: Promise? = null
  private var unpairTimeout: Runnable? = null
  private var pendingPrimeXid: String? = null
  private var identityBytes: ByteArray? = null
  private val diagnostics = ArrayDeque<String>()

  private val context: Context
    get() = requireNotNull(appContext.reactContext) { "React application context is unavailable" }

  override fun definition() = ModuleDefinition {
    Name("PassportQuantumLink")

    Events("onConnectionChanged", "onRequestProgress", "onUnpaired")

    Function("isAvailable") {
      bluetoothAdapter() != null
    }

    Function("getStatus") {
      statusMap()
    }

    Function("getIdentityXid") {
      Base64.encodeToString(identityXid(identity()), Base64.NO_WRAP)
    }

    Function("getDiagnostics") {
      diagnostics.joinToString("\n")
    }

    AsyncFunction("connect") { deviceAddress: String, promise: Promise ->
      connect(deviceAddress, promise)
    }

    AsyncFunction("reconnect") { promise: Promise ->
      val address = publicPrefs().getString(KEY_PRIME_MAC, null)
      if (address == null) {
        promise.reject("not_paired", "No paired Passport Prime is stored", null)
      } else {
        connect(address, promise)
      }
    }

    AsyncFunction("pair") { primeXidBase64: String, phoneName: String, promise: Promise ->
      pair(primeXidBase64, phoneName, promise)
    }

    AsyncFunction("disconnect") {
      cleanupConnection("Disconnected", true)
    }

    AsyncFunction("unpair") { promise: Promise ->
      unpair(promise)
    }

    AsyncFunction("forget") {
      // Local escape hatch for replacing a lost or unavailable Prime. When a
      // link is live the UI uses unpair() so both peers acknowledge removal;
      // this deliberately clears only Android's stale relationship.
      clearPairing()
      cleanupConnection("Forgotten on this phone", true)
      sendEvent("onUnpaired")
    }

    AsyncFunction("getEvmAccount") { path: String, requestId: String, promise: Promise ->
      getEvmAccount(path, requestId, promise)
    }

    AsyncFunction("signEvmTransaction") {
        request: Map<String, Any?>,
        promise: Promise
      ->
      signEvmTransaction(request, promise)
    }

    AsyncFunction("getBtcAccount") { path: String, requestId: String, promise: Promise ->
      getBtcAccount(path, requestId, promise)
    }

    AsyncFunction("signBtcPsbt") {
        request: Map<String, Any?>,
        promise: Promise
      ->
      signBtcPsbt(request, promise)
    }

    AsyncFunction("cancel") { requestId: String ->
      cancelRequest(requestId)
    }

    OnDestroy {
      cleanupConnection("Module destroyed", true)
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

  private fun isPaired(): Boolean = publicPrefs().contains(KEY_PRIME_XID)

  private fun isConnected(): Boolean =
    gatt != null && writeCharacteristic != null &&
      (state == LinkState.CONNECTED || state == LinkState.PAIRED)

  private fun statusMap(): Map<String, Any?> {
    val available = bluetoothAdapter() != null
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
    state = next
    trace("state", next.value)
    sendEvent(
      "onConnectionChanged",
      mapOf(
        "state" to next.value,
        "connected" to isConnected(),
        "paired" to isPaired(),
        "deviceName" to publicPrefs().getString(KEY_PRIME_NAME, null),
        "deviceAddress" to publicPrefs().getString(KEY_PRIME_MAC, targetAddress)
      )
    )
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

  private fun emitProgress(requestId: String, stage: String) {
    sendEvent(
      "onRequestProgress",
      mapOf("requestId" to requestId, "stage" to stage)
    )
  }

  @SuppressLint("MissingPermission")
  private fun connect(deviceAddress: String, promise: Promise) {
    try {
      val adapter = bluetoothAdapter()
      if (adapter == null) {
        promise.reject("ble_unavailable", "Bluetooth LE is unavailable", null)
        return
      }
      if (!adapter.isEnabled) {
        promise.reject("ble_disabled", "Bluetooth is turned off", null)
        return
      }

      connectPromise?.reject("connection_replaced", "Starting a new Passport connection", null)
      connectPromise = null
      cleanupConnection("Starting a new connection", true)
      connectionStartedAt = SystemClock.elapsedRealtime()
      trace("connect_start", deviceAddress.uppercase())
      session = QlSession(identity())
      storedPrimeXid()?.let { session?.setExpectedPeer(it) }
      targetAddress = deviceAddress.uppercase()
      connectPromise = promise
      scanner = adapter.bluetoothLeScanner
      if (scanner == null) {
        failConnect("BLE scanner is unavailable")
        return
      }

      val filters = listOf(
        ScanFilter.Builder()
          .setDeviceAddress(targetAddress)
          .build()
      )
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
      promise.reject("ble_connect", error.message, error)
      connectPromise = null
      cleanupConnection("Connection failed", false)
    }
  }

  @SuppressLint("MissingPermission")
  private fun stopScan() {
    scanning = false
    try {
      scanner?.stopScan(scanCallback)
    } catch (_: Exception) {
      // The adapter may have turned off during a scan.
    }
  }

  private val scanCallback = object : ScanCallback() {
    @SuppressLint("MissingPermission")
    override fun onScanResult(callbackType: Int, result: ScanResult?) {
      val device = result?.device ?: return
      val addressMatches =
        device.address?.equals(targetAddress, ignoreCase = true) == true
      if (!scanning || !addressMatches) return

      stopScan()
      trace("scan_match", "${device.address} rssi=${result.rssi}")
      setState(LinkState.CONNECTING)
      gatt = device.connectGatt(context, true, gattCallback, TRANSPORT_LE)
      val connectionPromise = connectPromise
      val generation = connectionGeneration
      mainHandler.postDelayed({
        if (
          generation == connectionGeneration &&
          connectPromise === connectionPromise &&
          connectionPromise != null
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
  private fun pair(primeXidBase64: String, phoneName: String, promise: Promise) {
    try {
      if (!isConnected()) {
        promise.reject("not_connected", "Connect to Passport Prime before pairing", null)
        return
      }
      check(pairPromise == null) { "A Passport Prime pairing request is already pending" }
      val primeXid = Base64.decode(primeXidBase64, Base64.NO_WRAP)
      requireNotNull(session) { "QuantumLink session is unavailable" }
        .setExpectedPeer(primeXid)
      pendingPrimeXid = primeXidBase64
      pairPromise = promise
      trace("pair_start", "xid_bytes=${primeXid.size}")
      sendPairingAttempt(primeXid, phoneName, promise, 1)

      longArrayOf(1_500L, 4_000L, 8_000L).forEachIndexed { index, delay ->
        val retry = Runnable {
          if (pairPromise !== promise || !isConnected()) return@Runnable
          try {
            sendPairingAttempt(primeXid, phoneName, promise, index + 2)
          } catch (error: Exception) {
            trace("pair_retry_error", error.message ?: error.javaClass.simpleName)
          }
        }
        pairRetries.add(retry)
        mainHandler.postDelayed(retry, delay)
      }

      val timeout = Runnable {
        if (pairPromise === promise) {
          trace("pair_timeout")
          cancelPairTimers()
          pairPromise = null
          pendingPrimeXid = null
          promise.reject("pair_timeout", "Passport Prime pairing timed out", null)
        }
      }
      pairTimeout = timeout
      mainHandler.postDelayed(timeout, PAIR_TIMEOUT_MS)
    } catch (error: Exception) {
      trace("pair_error", error.message ?: error.javaClass.simpleName)
      cancelPairTimers()
      pairPromise = null
      pendingPrimeXid = null
      promise.reject("pair_failed", error.message, error)
    }
  }

  private fun sendPairingAttempt(
    primeXid: ByteArray,
    phoneName: String,
    promise: Promise,
    attempt: Int
  ) {
    if (pairPromise !== promise) return
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
  private fun unpair(promise: Promise) {
    try {
      if (!isPaired()) {
        cleanupConnection("Unpaired", true)
        promise.resolve()
        return
      }
      val primeXid = requireReady()
      check(unpairPromise == null) { "An unpair request is already pending" }
      unpairPromise = promise
      enqueue(buildUnpairingRequest(identity(), primeXid))

      val timeout = Runnable {
        // Prime removes its pairing immediately after queueing the response.
        // A lost acknowledgement must not strand the phone in a stale pair.
        completeUnpair()
      }
      unpairTimeout = timeout
      mainHandler.postDelayed(timeout, UNPAIR_TIMEOUT_MS)
    } catch (error: Exception) {
      unpairPromise = null
      promise.reject("unpair_failed", error.message, error)
    }
  }

  @SuppressLint("MissingPermission")
  private fun getEvmAccount(path: String, requestId: String, promise: Promise) {
    try {
      val primeXid = requireReady()
      val requestIdBytes = requestIdBytes(requestId)
      registerPending(requestId, RequestKind.EVM_ACCOUNT, promise, ACCOUNT_TIMEOUT_MS)
      emitProgress(requestId, "sending")
      val frames = buildWdkEvmAccountRequest(
        identity(),
        primeXid,
        requestIdBytes,
        path,
        11_155_111u
      )
      trace("account_tx", "request=$requestId frames=${frames.size}")
      enqueue(frames)
    } catch (error: Exception) {
      removePending(requestId)
      promise.reject("account_request", error.message, error)
    }
  }

  @SuppressLint("MissingPermission")
  private fun signEvmTransaction(request: Map<String, Any?>, promise: Promise) {
    val requestId = request.requiredString("requestId")
    try {
      val primeXid = requireReady()
      registerPending(requestId, RequestKind.EVM_SIGN, promise)
      emitProgress(requestId, "sending")
      enqueue(
        buildWdkEvmSignTransactionRequest(
          identity(),
          primeXid,
          requestIdBytes(requestId),
          request.requiredString("path"),
          request.requiredNumber("chainId").toInt().toUInt(),
          request.requiredNumber("nonce").toLong().toULong(),
          request.requiredString("from"),
          request.requiredString("to"),
          hexToBytes(request.requiredString("data")),
          request.requiredString("value"),
          request.requiredString("gasLimit"),
          request.requiredString("maxFeePerGas"),
          request.requiredString("maxPriorityFeePerGas")
        )
      )
      emitProgress(requestId, "reviewing")
    } catch (error: Exception) {
      removePending(requestId)
      promise.reject("sign_request", error.message, error)
    }
  }

  @SuppressLint("MissingPermission")
  private fun getBtcAccount(path: String, requestId: String, promise: Promise) {
    try {
      val primeXid = requireReady()
      registerPending(requestId, RequestKind.BTC_ACCOUNT, promise, ACCOUNT_TIMEOUT_MS)
      emitProgress(requestId, "sending")
      enqueue(
        buildWdkBtcAccountRequest(
          identity(),
          primeXid,
          requestIdBytes(requestId),
          path,
          1u.toUByte()
        )
      )
    } catch (error: Exception) {
      removePending(requestId)
      promise.reject("btc_account_request", error.message, error)
    }
  }

  @SuppressLint("MissingPermission")
  private fun signBtcPsbt(request: Map<String, Any?>, promise: Promise) {
    val requestId = request.requiredString("requestId")
    try {
      val primeXid = requireReady()
      registerPending(requestId, RequestKind.BTC_SIGN, promise)
      emitProgress(requestId, "sending")
      enqueue(
        buildWdkBtcSignPsbtRequest(
          identity(),
          primeXid,
          requestIdBytes(requestId),
          request.requiredString("path"),
          1u.toUByte(),
          hexToBytes(request.requiredString("psbt"))
        )
      )
      emitProgress(requestId, "reviewing")
    } catch (error: Exception) {
      removePending(requestId)
      promise.reject("btc_sign_request", error.message, error)
    }
  }

  @SuppressLint("MissingPermission")
  private fun cancelRequest(requestId: String) {
    val pending = removePending(requestId)
    pending?.promise?.reject("cancelled", "Signing request cancelled", null)
    emitProgress(requestId, "cancelled")
    val primeXid = storedPrimeXid() ?: return
    if (!isConnected()) return
    enqueue(buildWdkRequestCancelled(identity(), primeXid, requestIdBytes(requestId)))
  }

  private fun registerPending(
    requestId: String,
    kind: RequestKind,
    promise: Promise,
    timeoutMs: Long = REQUEST_TIMEOUT_MS
  ) {
    require(!pendingRequests.containsKey(requestId)) { "Duplicate request ID" }
    val timeout = Runnable {
      val pending = removePending(requestId) ?: return@Runnable
      trace("request_timeout", "kind=${pending.kind} request=$requestId")
      pending.promise.reject("request_timeout", "Passport request timed out", null)
    }
    pendingRequests[requestId] = PendingRequest(kind, promise, timeout)
    trace("request_pending", "kind=$kind request=$requestId")
    mainHandler.postDelayed(timeout, timeoutMs)
  }

  private fun removePending(requestId: String): PendingRequest? {
    val pending = pendingRequests.remove(requestId)
    if (pending != null) mainHandler.removeCallbacks(pending.timeout)
    return pending
  }

  private fun requireReady(): ByteArray {
    check(isConnected()) { "Passport Prime is not connected" }
    return storedPrimeXid() ?: error("Passport Prime is not paired")
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
    val frame = outbox.removeFirstOrNull() ?: return
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
        if (connectPromise != null) {
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
      if (
        generation != connectionGeneration ||
        gatt !== connection ||
        connectPromise == null
      ) {
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
    setState(if (isPaired()) LinkState.PAIRED else LinkState.CONNECTED)
    connectPromise?.resolve()
    connectPromise = null
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
          pairPromise?.resolve(name)
          pairPromise = null
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

        "WdkEvmAccountResponse" -> {
          val requestId = bytesToHex(message.requestId)
          val pending = removePending(requestId) ?: return
          if (pending.kind != RequestKind.EVM_ACCOUNT) {
            pending.promise.reject("response_mismatch", "Unexpected account response", null)
            return
          }
          pending.promise.resolve(
            mapOf(
              "protocolVersion" to 1,
              "requestId" to requestId,
              "path" to message.derivationPath,
              "address" to message.address,
              "publicKey" to bytesToHex(message.publicKey, true)
            )
          )
        }

        "WdkEvmSignTransactionResponse" -> {
          val requestId = bytesToHex(message.requestId)
          val pending = removePending(requestId) ?: return
          if (pending.kind != RequestKind.EVM_SIGN) {
            pending.promise.reject("response_mismatch", "Unexpected signing response", null)
            return
          }
          emitProgress(requestId, "signed")
          pending.promise.resolve(
            mapOf(
              "protocolVersion" to 1,
              "requestId" to requestId,
              "address" to message.address,
              "signedTransaction" to bytesToHex(message.signedTransaction, true)
            )
          )
        }

        "WdkBtcAccountResponse" -> {
          val requestId = bytesToHex(message.requestId)
          val pending = removePending(requestId) ?: return
          if (pending.kind != RequestKind.BTC_ACCOUNT) {
            pending.promise.reject("response_mismatch", "Unexpected Bitcoin account response", null)
            return
          }
          pending.promise.resolve(
            mapOf(
              "protocolVersion" to 1,
              "requestId" to requestId,
              "path" to message.derivationPath,
              "address" to message.address,
              "publicKey" to bytesToHex(message.publicKey, true)
            )
          )
        }

        "WdkBtcSignPsbtResponse" -> {
          val requestId = bytesToHex(message.requestId)
          val pending = removePending(requestId) ?: return
          if (pending.kind != RequestKind.BTC_SIGN) {
            pending.promise.reject("response_mismatch", "Unexpected Bitcoin signing response", null)
            return
          }
          emitProgress(requestId, "signed")
          pending.promise.resolve(
            mapOf(
              "protocolVersion" to 1,
              "requestId" to requestId,
              "address" to message.address,
              "signedTransaction" to bytesToHex(message.signedTransaction, true)
            )
          )
        }

        "WdkRequestRejected" -> {
          val requestId = bytesToHex(message.requestId)
          emitProgress(requestId, "rejected")
          removePending(requestId)?.promise?.reject(
            "passport_rejected",
            message.message.ifEmpty { "Rejected on Passport Prime" },
            null
          )
        }

        "WdkRequestCancelled" -> {
          val requestId = bytesToHex(message.requestId)
          emitProgress(requestId, "cancelled")
          removePending(requestId)?.promise?.reject(
            "passport_cancelled",
            "Request cancelled by Passport Prime",
            null
          )
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
      }
    } catch (error: Exception) {
      val detail = error.message ?: error.javaClass.simpleName
      trace("rx_error", detail)
      val pairingPeer = pendingPrimeXid
      if (pairingPeer != null && pairPromise != null) {
        trace("rx_ignored_during_pair", detail)
        session = QlSession(identity()).also {
          it.setExpectedPeer(Base64.decode(pairingPeer, Base64.NO_WRAP))
        }
        return
      }
      failAll("invalid_message", "Invalid QuantumLink response")
    }
  }

  private fun failConnect(reason: String) {
    connectPromise?.reject("ble_connect", reason, null)
    connectPromise = null
    cleanupConnection(reason, false)
  }

  private fun failAll(code: String, message: String) {
    cancelPairTimers()
    pairPromise?.reject(code, message, null)
    pairPromise = null
    pendingPrimeXid = null
    val unpair = unpairPromise
    unpairPromise = null
    unpairTimeout?.let(mainHandler::removeCallbacks)
    unpairTimeout = null
    unpair?.reject(code, message, null)
    val requests = pendingRequests.values.toList()
    pendingRequests.clear()
    requests.forEach {
      mainHandler.removeCallbacks(it.timeout)
      it.promise.reject(code, message, null)
    }
  }

  @SuppressLint("MissingPermission")
  private fun cleanupConnection(reason: String, clearRequests: Boolean) {
    connectionGeneration += 1
    stopScan()
    if (clearRequests) failAll("connection_closed", reason)
    try {
      gatt?.disconnect()
      gatt?.close()
    } catch (_: Exception) {
      // The GATT instance may already be closed.
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
    publicPrefs().edit()
      .remove(KEY_PRIME_XID)
      .remove(KEY_PRIME_MAC)
      .remove(KEY_PRIME_NAME)
      .apply()
    pendingPrimeXid = null
  }

  private fun completeUnpair() {
    val promise = unpairPromise
    unpairPromise = null
    unpairTimeout?.let(mainHandler::removeCallbacks)
    unpairTimeout = null
    clearPairing()
    cleanupConnection("Unpaired", true)
    promise?.resolve()
    sendEvent("onUnpaired")
  }

  private fun failUnpair(message: String) {
    val promise = unpairPromise
    unpairPromise = null
    unpairTimeout?.let(mainHandler::removeCallbacks)
    unpairTimeout = null
    promise?.reject("unpair_failed", message, null)
  }

  private fun requestIdBytes(value: String): ByteArray {
    val bytes = hexToBytes(value)
    require(bytes.size == 16) { "Request ID must be 128 bits" }
    return bytes
  }

  private fun hexToBytes(value: String): ByteArray {
    val hex = value.removePrefix("0x")
    require(hex.length % 2 == 0 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
      "Invalid hex value"
    }
    return ByteArray(hex.length / 2) { index ->
      hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
  }

  private fun bytesToHex(value: ByteArray, prefix: Boolean = false): String {
    val hex = value.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    return if (prefix) "0x$hex" else hex
  }

  private fun Map<String, Any?>.requiredString(key: String): String =
    this[key] as? String ?: error("$key is required")

  private fun Map<String, Any?>.requiredNumber(key: String): Number =
    this[key] as? Number ?: error("$key is required")
}
