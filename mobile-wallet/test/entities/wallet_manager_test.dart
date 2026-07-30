import 'package:cake_wallet/entities/wallet_manager.dart';
import 'package:cw_core/wallet_info.dart';
import 'package:cw_core/wallet_type.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  late WalletManager walletManager;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    walletManager = WalletManager(await SharedPreferences.getInstance());
  });

  test('keeps Passport wallets with different primary addresses separate', () {
    walletManager
      ..addWallet(_walletInfo(
        name: 'Prime wallet',
        address: 'address-one',
        hashedWalletIdentifier: 'same-empty-seed-hash',
        hardwareWalletType: HardwareWalletType.passportPrime,
      ))
      ..addWallet(_walletInfo(
        name: 'Imported wallet',
        address: 'address-two',
        hashedWalletIdentifier: 'same-empty-seed-hash',
        hardwareWalletType: HardwareWalletType.passportPrime,
      ));

    expect(walletManager.walletGroups, hasLength(2));
    expect(
      walletManager.walletGroups.map((group) => group.wallets.single.name),
      containsAll(<String>['Prime wallet', 'Imported wallet']),
    );
  });

  test('still groups Passport wallet records with the same primary address', () {
    walletManager
      ..addWallet(_walletInfo(
        name: 'Prime wallet',
        address: 'same-address',
        hashedWalletIdentifier: 'first-hash',
        hardwareWalletType: HardwareWalletType.passportPrime,
      ))
      ..addWallet(_walletInfo(
        name: 'Prime wallet copy',
        address: 'same-address',
        hashedWalletIdentifier: 'second-hash',
        hardwareWalletType: HardwareWalletType.passportPrime,
      ));

    expect(walletManager.walletGroups, hasLength(1));
    expect(walletManager.walletGroups.single.wallets, hasLength(2));
  });

  test('preserves shared-seed grouping for other wallets', () {
    walletManager
      ..addWallet(_walletInfo(
        name: 'Wallet one',
        address: 'address-one',
        hashedWalletIdentifier: 'shared-seed-hash',
      ))
      ..addWallet(_walletInfo(
        name: 'Wallet two',
        address: 'address-two',
        hashedWalletIdentifier: 'shared-seed-hash',
      ));

    expect(walletManager.walletGroups, hasLength(1));
    expect(walletManager.walletGroups.single.wallets, hasLength(2));
  });
}

WalletInfo _walletInfo({
  required String name,
  required String address,
  required String hashedWalletIdentifier,
  HardwareWalletType? hardwareWalletType,
}) =>
    WalletInfo.external(
      id: name,
      name: name,
      type: WalletType.monero,
      isRecovery: true,
      restoreHeight: 0,
      date: DateTime(2026),
      dirPath: '/tmp/$name',
      path: '/tmp/$name/$name',
      address: address,
      hardwareWalletType: hardwareWalletType,
      hashedWalletIdentifier: hashedWalletIdentifier,
    );
