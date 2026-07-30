import "dart:math";

import "package:cw_core/hardware/hardware_wallet_service.dart";
import "package:cw_monero/passport_prime_output_sync.dart";
import "package:cw_monero/trezor.dart";
import "package:passport_quantumlink/passport_quantumlink.dart";

class MoneroPassportPrimeService extends HardwareWalletService {}

class MoneroPassportVerifiedAddress {
  const MoneroPassportVerifiedAddress({
    required this.address,
    required this.accountIndex,
    required this.addressIndex,
  });

  final String address;
  final int accountIndex;
  final int addressIndex;
}

class PassportPrime {
  PassportPrime(this.service);

  final MoneroPassportPrimeService service;

  Future<MoneroTrezorWatchCredentials> getWatchCredentials() async {
    final credentials = await _withLiveConnection(
      () => PassportQuantumLink.getMoneroWatchCredentials(
        requestId: _requestId(),
      ),
    );

    return MoneroTrezorWatchCredentials(credentials.watchKey, credentials.address);
  }

  Future<String> keyImageSync(String outputsUr) {
    final requestId = _requestId();
    return retryPassportPrimeSyncRequest(
      request: () => _withLiveConnection(
        () => PassportQuantumLink.syncMoneroKeyImages(
          requestId: requestId,
          outputsUr: outputsUr,
        ),
      ),
    );
  }

  Future<String> signTransaction(String unsignedTxUr) => _withLiveConnection(
        () => PassportQuantumLink.signMoneroTransaction(
          requestId: _requestId(),
          unsignedTxUr: unsignedTxUr,
        ),
      );

  Future<MoneroPassportVerifiedAddress> verifyAddress({
    required String walletAddress,
    required int accountIndex,
    required int addressIndex,
    required String address,
  }) async {
    final response = await _withLiveConnection(
      () => PassportQuantumLink.verifyMoneroAddress(
        requestId: _requestId(),
        walletAddress: walletAddress,
        accountIndex: accountIndex,
        addressIndex: addressIndex,
        address: address,
      ),
    );
    return MoneroPassportVerifiedAddress(
      address: response.address,
      accountIndex: response.accountIndex,
      addressIndex: response.addressIndex,
    );
  }

  Future<T> _withLiveConnection<T>(Future<T> Function() request) async {
    final status = await PassportQuantumLink.getStatus();
    if (!status.connected) {
      await PassportQuantumLink.reconnect();
    }
    return request();
  }

  String _requestId() {
    final random = Random.secure();
    return List<int>.generate(16, (_) => random.nextInt(256))
        .map((byte) => byte.toRadixString(16).padLeft(2, "0"))
        .join();
  }
}
