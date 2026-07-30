import 'dart:convert';

import 'package:cake_wallet/.secrets.g.dart' as secrets;
import 'package:cw_core/wallet_base.dart';
import 'package:flutter/foundation.dart';
import 'package:hashlib/hashlib.dart';

String createHashedWalletIdentifier(WalletBase wallet) {
  final hashContent = walletIdentifierHashContent(
    seed: wallet.seed,
    primaryAddress: wallet.walletAddresses.primaryAddress,
  );

  final salt = secrets.walletGroupSalt;
  final combined = '$salt.$hashContent';
  final bytes = utf8.encode(combined);
  final digest = sha256.convert(bytes);
  if (kDebugMode) {
    return "$combined;$digest";
  }
  return digest.toString();
}

String walletIdentifierHashContent({
  required String? seed,
  required String primaryAddress,
}) =>
    seed?.isNotEmpty == true ? seed! : primaryAddress;
