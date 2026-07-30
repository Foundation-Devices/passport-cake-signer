import "dart:async";
import "dart:io";

import "package:cake_wallet/core/wallet_loading_service.dart";
import "package:cake_wallet/entities/preferences_key.dart";
import "package:cake_wallet/entities/wallet_description.dart";
import "package:cake_wallet/store/app_store.dart";
import "package:cw_core/utils/print_verbose.dart";
import "package:cw_core/wallet_info.dart";
import "package:cw_core/wallet_type.dart";
import "package:passport_quantumlink/passport_quantumlink.dart";
import "package:shared_preferences/shared_preferences.dart";

class PassportWalletNameSyncService {
  PassportWalletNameSyncService({
    required this.walletLoadingService,
    required this.appStore,
    required this.sharedPreferences,
  });

  final WalletLoadingService walletLoadingService;
  final AppStore appStore;
  final SharedPreferences sharedPreferences;

  StreamSubscription<PassportMoneroWalletMetadata>? _subscription;
  Future<void> _pending = Future<void>.value();

  void start() {
    if (!Platform.isAndroid || _subscription != null) {
      return;
    }
    _subscription = PassportQuantumLink.walletMetadataUpdates.listen((metadata) {
      _pending =
          _pending.then((_) => _apply(metadata)).catchError((Object error, StackTrace stackTrace) {
        printV("Could not sync Passport Prime wallet name: $error\n$stackTrace");
      });
    });
  }

  Future<void> dispose() async {
    await _subscription?.cancel();
    _subscription = null;
  }

  Future<void> _apply(PassportMoneroWalletMetadata metadata) async {
    final name = metadata.walletName.trim();
    if (!_isValidCakeWalletName(name)) {
      throw const FormatException("Passport Prime supplied an invalid wallet name");
    }

    final wallets = await WalletInfo.getAll();
    final matching = wallets
        .where(
          (wallet) =>
              wallet.type == WalletType.monero &&
              wallet.hardwareWalletType == HardwareWalletType.passportPrime &&
              wallet.address == metadata.walletAddress,
        )
        .toList();
    if (matching.length != 1) {
      if (matching.isNotEmpty) {
        throw StateError("Multiple Cake wallets match the same Passport Prime address");
      }
      return;
    }

    final wallet = matching.single;
    if (wallet.name == name) {
      return;
    }
    final collision = wallets.any(
      (candidate) =>
          candidate.type == wallet.type &&
          candidate.name == name &&
          candidate.address != metadata.walletAddress,
    );
    if (collision) {
      throw StateError('A different Cake wallet is already named "$name"');
    }

    await walletLoadingService.renameWallet(wallet.type, wallet.name, name);
    final renamed = await WalletInfo.get(name, wallet.type);
    if (renamed == null || renamed.address != metadata.walletAddress) {
      throw StateError("Cake did not complete the Passport Prime wallet rename");
    }

    final currentWallet = appStore.wallet;
    if (currentWallet?.walletInfo.address == metadata.walletAddress &&
        currentWallet?.hardwareWalletType == HardwareWalletType.passportPrime) {
      currentWallet!.walletInfo = renamed;
      await sharedPreferences.setString(PreferencesKey.currentWalletName, name);
    }

    final listIndex = appStore.walletList.wallets.indexWhere(
      (description) => description.type == wallet.type && description.name == wallet.name,
    );
    if (listIndex >= 0) {
      appStore.walletList.wallets[listIndex] = WalletDescription(name: name, type: wallet.type);
    }
  }

  bool _isValidCakeWalletName(String name) =>
      name.isNotEmpty && name.length <= 33 && RegExp(r"^[a-zA-Z0-9\-_ ]+$").hasMatch(name);
}
