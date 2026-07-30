import "dart:async";

import "package:flutter/services.dart";

class PassportQuantumLinkStatus {
  const PassportQuantumLinkStatus({
    required this.available,
    required this.paired,
    required this.connected,
    required this.state,
    this.deviceName,
    this.deviceAddress,
  });

  factory PassportQuantumLinkStatus.fromMap(Map<dynamic, dynamic> map) => PassportQuantumLinkStatus(
    available: map["available"] == true,
    paired: map["paired"] == true,
    connected: map["connected"] == true,
    state: map["state"] as String? ?? "unavailable",
    deviceName: map["deviceName"] as String?,
    deviceAddress: map["deviceAddress"] as String?,
  );

  final bool available;
  final bool paired;
  final bool connected;
  final String state;
  final String? deviceName;
  final String? deviceAddress;
}

class PassportMoneroWatchCredentials {
  const PassportMoneroWatchCredentials({
    required this.watchKey,
    required this.address,
    required this.walletName,
    this.restoreHeight,
  });

  factory PassportMoneroWatchCredentials.fromMap(Map<dynamic, dynamic> map) =>
      PassportMoneroWatchCredentials(
        watchKey: map["watchKey"] as String,
        address: map["address"] as String,
        walletName: map["walletName"] as String? ?? "",
        restoreHeight: (map["restoreHeight"] as num?)?.toInt(),
      );

  final String watchKey;
  final String address;
  final String walletName;
  final int? restoreHeight;
}

class PassportMoneroWalletMetadata {
  const PassportMoneroWalletMetadata({required this.walletAddress, required this.walletName});

  factory PassportMoneroWalletMetadata.fromMap(Map<dynamic, dynamic> map) =>
      PassportMoneroWalletMetadata(
        walletAddress: map["walletAddress"] as String,
        walletName: map["walletName"] as String,
      );

  final String walletAddress;
  final String walletName;
}

class PassportMoneroWalletRemovalRequest {
  const PassportMoneroWalletRemovalRequest({
    required this.requestId,
    required this.walletAddress,
    required this.walletName,
  });

  factory PassportMoneroWalletRemovalRequest.fromMap(Map<dynamic, dynamic> map) =>
      PassportMoneroWalletRemovalRequest(
        requestId: map["requestId"] as String,
        walletAddress: map["walletAddress"] as String,
        walletName: map["walletName"] as String,
      );

  final String requestId;
  final String walletAddress;
  final String walletName;
}

class PassportMoneroVerifiedAddress {
  const PassportMoneroVerifiedAddress({
    required this.address,
    required this.accountIndex,
    required this.addressIndex,
  });

  factory PassportMoneroVerifiedAddress.fromMap(Map<dynamic, dynamic> map) =>
      PassportMoneroVerifiedAddress(
        address: map["address"] as String,
        accountIndex: (map["accountIndex"] as num).toInt(),
        addressIndex: (map["addressIndex"] as num).toInt(),
      );

  final String address;
  final int accountIndex;
  final int addressIndex;
}

class PassportQuantumLink {
  PassportQuantumLink._();

  static const MethodChannel _channel = MethodChannel("foundation.devices/passport_quantumlink");
  static final StreamController<PassportMoneroWalletMetadata> _walletMetadataController =
      StreamController<PassportMoneroWalletMetadata>.broadcast();
  static final StreamController<PassportMoneroWalletRemovalRequest>
  _walletRemovalRequestController =
      StreamController<PassportMoneroWalletRemovalRequest>.broadcast();
  static final StreamController<PassportQuantumLinkStatus> _statusController =
      StreamController<PassportQuantumLinkStatus>.broadcast();
  static PassportMoneroWatchCredentials? _prefetchedWatchCredentials;
  static bool _methodHandlerInstalled = false;

  static Stream<PassportMoneroWalletMetadata> get walletMetadataUpdates {
    _installMethodHandler();
    return _walletMetadataController.stream;
  }

  static Stream<PassportQuantumLinkStatus> get statusUpdates {
    _installMethodHandler();
    return _statusController.stream;
  }

  static Stream<PassportMoneroWalletRemovalRequest> get walletRemovalRequests {
    _installMethodHandler();
    return _walletRemovalRequestController.stream;
  }

  static Future<bool> isAvailable() async =>
      await _channel.invokeMethod<bool>("isAvailable") ?? false;

  static Future<PassportQuantumLinkStatus> getStatus() async {
    final status = await _channel.invokeMapMethod<dynamic, dynamic>("getStatus");
    return PassportQuantumLinkStatus.fromMap(status ?? <String, dynamic>{});
  }

  static Future<String> getIdentityXid() async =>
      await _channel.invokeMethod<String>("getIdentityXid") ?? "";

  static Future<String> getDiagnostics() async =>
      await _channel.invokeMethod<String>("getDiagnostics") ?? "";

  static Future<void> connect(String deviceAddress) =>
      _channel.invokeMethod<void>("connect", deviceAddress);

  static Future<void> reconnect() => _channel.invokeMethod<void>("reconnect");

  static Future<String> pair({required String primeXidBase64, required String phoneName}) async =>
      await _channel.invokeMethod<String>("pair", <String, Object?>{
        "primeXidBase64": primeXidBase64,
        "phoneName": phoneName,
      }) ??
      "Passport Prime";

  static Future<void> disconnect() => _channel.invokeMethod<void>("disconnect");

  static Future<void> unpair() async {
    _prefetchedWatchCredentials = null;
    await _channel.invokeMethod<void>("unpair");
  }

  static Future<void> forget() async {
    _prefetchedWatchCredentials = null;
    await _channel.invokeMethod<void>("forget");
  }

  static Future<PassportMoneroWatchCredentials> getMoneroWatchCredentials({
    required String requestId,
  }) async {
    final prefetched = _prefetchedWatchCredentials;
    if (prefetched != null) {
      _prefetchedWatchCredentials = null;
      return prefetched;
    }
    return _requestMoneroWatchCredentials(requestId);
  }

  static Future<PassportMoneroWatchCredentials> prefetchMoneroWatchCredentials({
    required String requestId,
  }) async {
    _prefetchedWatchCredentials = null;
    final credentials = await _requestMoneroWatchCredentials(requestId);
    _prefetchedWatchCredentials = credentials;
    return credentials;
  }

  static Future<PassportMoneroWatchCredentials> _requestMoneroWatchCredentials(
    String requestId,
  ) async {
    final response = await _channel.invokeMapMethod<dynamic, dynamic>(
      "getMoneroWatchCredentials",
      requestId,
    );
    return PassportMoneroWatchCredentials.fromMap(response ?? <String, dynamic>{});
  }

  static Future<String> syncMoneroKeyImages({
    required String requestId,
    required String outputsUr,
  }) async =>
      await _channel.invokeMethod<String>("syncMoneroKeyImages", <String, Object?>{
        "requestId": requestId,
        "outputsUr": outputsUr,
      }) ??
      "";

  static Future<String> signMoneroTransaction({
    required String requestId,
    required String unsignedTxUr,
  }) async =>
      await _channel.invokeMethod<String>("signMoneroTransaction", <String, Object?>{
        "requestId": requestId,
        "unsignedTxUr": unsignedTxUr,
      }) ??
      "";

  static Future<PassportMoneroVerifiedAddress> verifyMoneroAddress({
    required String requestId,
    required String walletAddress,
    required int accountIndex,
    required int addressIndex,
    required String address,
  }) async {
    final response = await _channel
        .invokeMapMethod<dynamic, dynamic>("verifyMoneroAddress", <String, Object?>{
          "requestId": requestId,
          "walletAddress": walletAddress,
          "accountIndex": accountIndex,
          "addressIndex": addressIndex,
          "address": address,
        });
    return PassportMoneroVerifiedAddress.fromMap(response ?? <String, dynamic>{});
  }

  static Future<void> cancel(String requestId) => _channel.invokeMethod<void>("cancel", requestId);

  static Future<void> respondToMoneroWalletRemoval({
    required String requestId,
    required String walletAddress,
    required bool removed,
  }) => _channel.invokeMethod<void>("respondToMoneroWalletRemoval", <String, Object?>{
    "requestId": requestId,
    "walletAddress": walletAddress,
    "removed": removed,
  });

  static void _installMethodHandler() {
    if (_methodHandlerInstalled) {
      return;
    }
    _methodHandlerInstalled = true;
    _channel.setMethodCallHandler((call) async {
      final arguments = call.arguments;
      if (arguments is! Map) {
        return;
      }
      switch (call.method) {
        case "walletNameChanged":
          _walletMetadataController.add(PassportMoneroWalletMetadata.fromMap(arguments));
        case "walletRemovalRequested":
          _walletRemovalRequestController.add(
            PassportMoneroWalletRemovalRequest.fromMap(arguments),
          );
        case "connectionStateChanged":
          _statusController.add(PassportQuantumLinkStatus.fromMap(arguments));
      }
    });
  }
}
