import "dart:async";
import "dart:convert";
import "dart:io";
import "dart:math";

import "package:cake_wallet/entities/hardware_wallet/hardware_wallet_device.dart";
import "package:cake_wallet/entities/qr_scanner.dart";
import "package:cake_wallet/monero/monero.dart";
import "package:cake_wallet/view_model/hardware_wallet/hardware_wallet_view_model.dart";
import "package:cake_wallet/wallet_type_utils.dart";
import "package:cw_core/hardware/device_connection_type.dart";
import "package:cw_core/hardware/hardware_wallet_service.dart";
import "package:cw_core/utils/print_verbose.dart";
import "package:cw_core/wallet_base.dart";
import "package:cw_core/wallet_info.dart";
import "package:cw_core/wallet_type.dart";
import "package:device_info_plus/device_info_plus.dart";
import "package:flutter/widgets.dart";
import "package:passport_quantumlink/passport_quantumlink.dart";
import "package:permission_handler/permission_handler.dart";
import "package:ur/ur.dart";
import "package:ur/ur_decoder.dart";

class PassportPrimeViewModel extends HardwareWalletViewModel {
  PassportPrimeViewModel() {
    if (_doesSupportHardwareWallets) {
      _statusSubscription = PassportQuantumLink.statusUpdates.listen(_applyStatus);
      unawaited(updateBleState());
    }
  }

  StreamSubscription<PassportQuantumLinkStatus>? _statusSubscription;

  @override
  HardwareWalletType get hardwareWalletType => HardwareWalletType.passportPrime;

  @override
  bool isBleEnabled = false;

  @override
  bool isConnecting = false;

  bool _connected = false;

  @override
  bool get hasBluetooth => Platform.isAndroid;

  bool get _doesSupportHardwareWallets {
    if (!Platform.isAndroid) {
      return false;
    }

    if (isMoneroOnly) {
      return DeviceConnectionType.supportedConnectionTypes(
        WalletType.monero,
        HardwareWalletType.passportPrime,
        false,
      ).isNotEmpty;
    }

    return true;
  }

  @override
  Future<void> updateBleState() async {
    if (Platform.isAndroid) {
      _applyStatus(await PassportQuantumLink.getStatus());
    }
  }

  void _applyStatus(PassportQuantumLinkStatus status) {
    isBleEnabled = status.available;
    _connected = status.connected;
  }

  @override
  Stream<HardwareWalletDevice> scanForBleDevices() async* {
    if (!Platform.isAndroid) {
      return;
    }

    final status = await PassportQuantumLink.getStatus();
    final address = status.deviceAddress;
    if (status.paired && address != null) {
      yield PassportPrimeHardwareWalletDevice(
        name: status.deviceName ?? "Passport Prime",
        address: address,
      );
    }
  }

  @override
  Future<List<HardwareWalletDevice>> getAllUsbDevices() async => [];

  @override
  Future<void> stopScanning() async {}

  @override
  Future<bool> connectDevice(HardwareWalletDevice device, WalletType type) async {
    if (device is! PassportPrimeHardwareWalletDevice || type != WalletType.monero) {
      return false;
    }

    try {
      return await _connect(device.address);
    } catch (_) {
      return false;
    }
  }

  Future<bool> pairFromQr(
    BuildContext context,
    WalletType type, {
    bool replaceExisting = false,
  }) async {
    if (type != WalletType.monero || isConnecting) {
      return false;
    }

    final savedStatus = await PassportQuantumLink.getStatus();
    if (savedStatus.paired && !replaceExisting) {
      throw StateError(
        "A Passport Prime is already paired. Use Add wallet from Passport, or explicitly choose Pair a different Passport.",
      );
    }
    if (!context.mounted) {
      return false;
    }
    final staticQr = await presentQRScanner(context, showManualInput: false);
    if (staticQr == null || staticQr.isEmpty) {
      return false;
    }

    final address = _parsePairingAddress(staticQr);
    if (savedStatus.paired) {
      await _forgetBeforeFreshPairing();
      if (!context.mounted) {
        return false;
      }
    }
    final connected = await _connect(address);
    if (!connected) {
      return false;
    }
    if (!context.mounted) {
      return false;
    }

    // Give Prime time to leave the Bluetooth QR screen before opening the second scanner.
    await Future<void>.delayed(const Duration(milliseconds: 750));
    if (!context.mounted) {
      return false;
    }

    final identityQr = await presentQRScanner(
      context,
      showManualInput: false,
      resultValidator: _isPassportIdentityQr,
    );
    if (identityQr == null || identityQr.isEmpty) {
      return false;
    }

    final primeXidBase64 = _decodeEnvelopeXid(identityQr);

    isConnecting = true;
    try {
      final name = await PassportQuantumLink.pair(
        primeXidBase64: primeXidBase64,
        phoneName: "Cake Wallet",
      );
      printV("Paired with $name over Passport QuantumLink");
      return true;
    } catch (error) {
      printV(error);
      rethrow;
    } finally {
      isConnecting = false;
    }
  }

  Future<void> _forgetBeforeFreshPairing() async {
    if (!Platform.isAndroid) {
      _connected = false;
      return;
    }

    try {
      await forgetPairing();
    } catch (error) {
      printV(error);
      try {
        await PassportQuantumLink.disconnect();
      } catch (disconnectError) {
        printV(disconnectError);
      }
    } finally {
      _connected = false;
    }
  }

  Future<bool> _connect(String address) async {
    if (isConnecting) {
      return false;
    }

    isConnecting = true;
    try {
      await _requestBluetoothPermissions();
      final status = await PassportQuantumLink.getStatus();
      if (status.connected && status.deviceAddress?.toUpperCase() == address.toUpperCase()) {
        _connected = true;
        return true;
      }
      await PassportQuantumLink.connect(address);
      _connected = true;
      return true;
    } catch (error) {
      printV(error);
      _connected = false;
      rethrow;
    } finally {
      isConnecting = false;
    }
  }

  Future<void> reconnect() async {
    await _requestBluetoothPermissions();
    final status = await PassportQuantumLink.getStatus();
    if (!status.connected) {
      await PassportQuantumLink.reconnect();
    }
    _connected = true;
  }

  Future<PassportMoneroWatchCredentials> prefetchMoneroWalletDetails() async {
    final status = await PassportQuantumLink.getStatus();
    if (!status.connected) {
      await reconnect();
    }
    final random = Random.secure();
    final requestId = List<int>.generate(16, (_) => random.nextInt(256))
        .map((byte) => byte.toRadixString(16).padLeft(2, "0"))
        .join();
    return PassportQuantumLink.prefetchMoneroWatchCredentials(requestId: requestId);
  }

  Future<void> disconnect() async {
    if (!Platform.isAndroid) {
      _connected = false;
      return;
    }

    await PassportQuantumLink.disconnect();
    _connected = false;
  }

  Future<void> forget() async {
    if (!Platform.isAndroid) {
      _connected = false;
      return;
    }

    await PassportQuantumLink.forget();
    _connected = false;
  }

  Future<void> unpair() async {
    if (!Platform.isAndroid) {
      _connected = false;
      return;
    }

    await _requestBluetoothPermissions();
    await PassportQuantumLink.unpair();
    _connected = false;
  }

  Future<void> forgetPairing() async {
    try {
      await unpair();
    } catch (error) {
      printV(error);
      await forget();
    }
  }

  @override
  bool isConnected(WalletType type) => type == WalletType.monero && _connected;

  @override
  HardwareWalletService getHardwareWalletService(WalletType type) {
    if (type != WalletType.monero) {
      throw UnimplementedError();
    }

    return monero!.getPassportHardwareWalletService();
  }

  @override
  Future<void> initWallet(WalletBase wallet) async {
    if (wallet.type != WalletType.monero) {
      throw Exception("Unexpected wallet type: ${wallet.type} for Passport Prime");
    }

    return monero!.setHardwareWalletService(wallet, getHardwareWalletService(wallet.type));
  }

  Future<void> _requestBluetoothPermissions() async {
    if (!Platform.isAndroid) {
      return;
    }

    final androidInfo = await DeviceInfoPlugin().androidInfo;
    final permissions = androidInfo.version.sdkInt >= 31
        ? [
            Permission.bluetoothScan,
            Permission.bluetoothConnect,
          ]
        : [Permission.locationWhenInUse];
    final statuses = await permissions.request();

    final denied = statuses.values.any((status) => status.isDenied || status.isPermanentlyDenied);
    if (denied) {
      throw Exception("Bluetooth permission is required to connect to Passport Prime");
    }
  }

  String _parsePairingAddress(String value) {
    final trimmed = value.trim();
    if (_looksLikeCupcakeWatchOnlyQr(trimmed)) {
      throw const FormatException(
        "This is the watch-only Cake restore QR. On Passport Prime, open Connect with Cake to show the QuantumLink pairing QR.",
      );
    }

    final parsed = Uri.tryParse(trimmed);
    final fromQuery = parsed?.queryParameters["p"];
    final rawAddress = fromQuery ??
        RegExp(r"(?:^|[?&])p=([0-9a-fA-F:]{12,17})(?:&|$)").firstMatch(value)?.group(1);

    if (rawAddress == null) {
      throw const FormatException("Passport Prime pairing QR did not contain a Bluetooth address");
    }

    final compact = rawAddress.replaceAll(":", "").toUpperCase();
    if (!RegExp(r"^[0-9A-F]{12}$").hasMatch(compact)) {
      throw const FormatException(
        "Passport Prime pairing QR contained an invalid Bluetooth address",
      );
    }

    return [
      for (int offset = 0; offset < compact.length; offset += 2)
        compact.substring(offset, offset + 2),
    ].join(":");
  }

  bool _looksLikeCupcakeWatchOnlyQr(String value) {
    try {
      final decoded = jsonDecode(value);
      return decoded is Map &&
          decoded.containsKey("primaryAddress") &&
          decoded.containsKey("privateViewKey");
    } catch (_) {
      return false;
    }
  }

  bool _isPassportIdentityQr(String value) => _tryDecodeEnvelopeXid(value) != null;

  String? _tryDecodeEnvelopeXid(String value) {
    try {
      return _decodeEnvelopeXid(value);
    } catch (_) {
      return null;
    }
  }

  String _decodeEnvelopeXid(String value) {
    final decoder = URDecoder();
    final parts =
        value.split(RegExp(r"\s+")).map((part) => part.trim()).where((part) => part.isNotEmpty);

    for (final part in parts) {
      decoder.receivePart(part.toLowerCase());
    }

    final result = decoder.result;
    if (!decoder.isSuccess() || result is! UR) {
      throw const FormatException("Passport Prime identity QR was not complete");
    }

    if (result.type != "envelope") {
      throw FormatException("Passport Prime identity QR had unexpected type ${result.type}");
    }

    return base64Encode(result.cbor);
  }

  @override
  String? interpretErrorCode(String error) {
    if (error.contains("monero_protocol_missing")) {
      return "This build can pair with Passport Prime, but the shared QuantumLink Monero messages are not available yet.";
    }
    if (error.contains("ble_disabled")) {
      return "Turn on Bluetooth to connect to Passport Prime.";
    }
    if (error.contains("not_paired")) {
      return "Pair Passport Prime before restoring or signing with this wallet.";
    }
    if (error.contains("not_connected")) {
      return "Reconnect Passport Prime before continuing.";
    }

    return null;
  }

  @override
  Future<void> close() async {
    await _statusSubscription?.cancel();
    _statusSubscription = null;
    _connected = false;
    if (!Platform.isAndroid) {
      return;
    }

    try {
      await PassportQuantumLink.disconnect();
    } catch (error) {
      printV(error);
    }
  }
}
