import "dart:async";
import "dart:io";

import "package:cake_wallet/core/auth_service.dart";
import "package:cake_wallet/entities/preferences_key.dart";
import "package:cake_wallet/entities/wallet_manager.dart";
import "package:cake_wallet/generated/i18n.dart";
import "package:cake_wallet/routes.dart";
import "package:cake_wallet/src/widgets/alert_with_two_actions.dart";
import "package:cake_wallet/store/app_store.dart";
import "package:cake_wallet/utils/show_pop_up.dart";
import "package:cw_core/utils/print_verbose.dart";
import "package:cw_core/wallet_info.dart";
import "package:cw_core/wallet_type.dart";
import "package:flutter/material.dart";
import "package:passport_quantumlink/passport_quantumlink.dart";
import "package:shared_preferences/shared_preferences.dart";

typedef RemovePassportWallet = Future<void> Function(WalletInfo wallet);
typedef RefreshWalletList = Future<void> Function();

/// Handles authenticated, wallet-scoped removal requests initiated on Passport.
///
/// The immutable primary Monero address identifies the Cake watch-only wallet.
/// Prime remains linked until this service confirms that Cake completed the
/// deletion (or that the matching wallet was already absent).
class PassportWalletRemovalService {
  PassportWalletRemovalService({
    required this.authService,
    required this.appStore,
    required this.walletManager,
    required this.sharedPreferences,
    required this.navigatorKey,
    required this.removeWallet,
    required this.refreshWalletList,
  });

  final AuthService authService;
  final AppStore appStore;
  final WalletManager walletManager;
  final SharedPreferences sharedPreferences;
  final GlobalKey<NavigatorState> navigatorKey;
  final RemovePassportWallet removeWallet;
  final RefreshWalletList refreshWalletList;

  StreamSubscription<PassportMoneroWalletRemovalRequest>? _subscription;
  Future<void> _pending = Future<void>.value();

  void start() {
    if (!Platform.isAndroid || _subscription != null) {
      return;
    }
    _subscription = PassportQuantumLink.walletRemovalRequests.listen((request) {
      _pending =
          _pending.then((_) => _handle(request)).catchError((Object error, StackTrace stackTrace) {
        printV("Could not handle Passport Prime wallet removal: $error\n$stackTrace");
      });
    });
  }

  Future<void> dispose() async {
    await _subscription?.cancel();
    _subscription = null;
  }

  Future<void> _handle(PassportMoneroWalletRemovalRequest request) async {
    final matches = await _matchingWallets(request.walletAddress);
    if (matches.isEmpty) {
      await _respond(request, removed: true);
      return;
    }
    if (matches.length != 1) {
      printV("Multiple Cake wallets match Passport address ${request.walletAddress}");
      await _respond(request, removed: false);
      return;
    }

    final context = navigatorKey.currentContext;
    if (context == null || !context.mounted) {
      await _respond(request, removed: false);
      return;
    }
    if (!await _authenticate(context)) {
      await _respond(request, removed: false);
      return;
    }
    if (!context.mounted) {
      await _respond(request, removed: false);
      return;
    }
    final confirmed = await _confirmRemoval(context, matches.single.name);
    if (!confirmed) {
      await _respond(request, removed: false);
      return;
    }

    try {
      final currentMatches = await _matchingWallets(request.walletAddress);
      if (currentMatches.isEmpty) {
        await _respond(request, removed: true);
        return;
      }
      if (currentMatches.length != 1) {
        throw StateError("Multiple Cake wallets match the requested Passport wallet");
      }
      final wallet = currentMatches.single;
      final wasCurrent = appStore.wallet?.walletInfo.address == request.walletAddress &&
          appStore.wallet?.hardwareWalletType == HardwareWalletType.passportPrime;
      await removeWallet(wallet);
      walletManager.removeWallet(wallet);
      appStore.walletList.wallets.removeWhere(
        (description) => description.type == wallet.type && description.name == wallet.name,
      );
      if (wasCurrent) {
        appStore.wallet = null;
        await sharedPreferences.remove(PreferencesKey.currentWalletName);
        await sharedPreferences.remove(PreferencesKey.currentWalletType);
      }
      await refreshWalletList();
      if (wasCurrent) {
        unawaited(
          navigatorKey.currentState?.pushNamedAndRemoveUntil(Routes.walletList, (_) => false),
        );
      }
      await _respond(request, removed: true);
    } catch (error, stackTrace) {
      printV("Could not remove Passport Prime wallet from Cake: $error\n$stackTrace");
      await _respond(request, removed: false);
    }
  }

  Future<List<WalletInfo>> _matchingWallets(String address) async => (await WalletInfo.getAll())
      .where(
        (wallet) =>
            wallet.type == WalletType.monero &&
            wallet.hardwareWalletType == HardwareWalletType.passportPrime &&
            wallet.address == address,
      )
      .toList();

  Future<bool> _authenticate(BuildContext context) {
    final result = Completer<bool>();
    authService.authenticateAction(
      context,
      onAuthSuccess: (success) {
        if (!result.isCompleted) {
          result.complete(success);
        }
      },
      conditionToDetermineIfToUse2FA: false,
    );
    return result.future;
  }

  Future<bool> _confirmRemoval(BuildContext context, String walletName) async {
    var confirmed = false;
    await showPopUp<void>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => AlertWithTwoActions(
        alertTitle: S.current.delete_wallet,
        alertContent:
            'Passport Prime is asking to remove "$walletName" from this phone. Funds and private keys remain on Passport Prime.',
        leftButtonText: S.current.cancel,
        rightButtonText: S.current.delete,
        alertBarrierDismissible: false,
        actionLeftButton: () => Navigator.of(dialogContext).pop(),
        actionRightButton: () {
          confirmed = true;
          Navigator.of(dialogContext).pop();
        },
      ),
    );
    return confirmed;
  }

  Future<void> _respond(
    PassportMoneroWalletRemovalRequest request, {
    required bool removed,
  }) async {
    try {
      await PassportQuantumLink.respondToMoneroWalletRemoval(
        requestId: request.requestId,
        walletAddress: request.walletAddress,
        removed: removed,
      );
    } catch (error, stackTrace) {
      printV("Could not acknowledge Passport Prime wallet removal: $error\n$stackTrace");
    }
  }
}
