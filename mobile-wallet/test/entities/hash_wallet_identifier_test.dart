import 'package:cake_wallet/entities/hash_wallet_identifier.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('walletIdentifierHashContent', () {
    test('uses the seed when it is available', () {
      expect(
        walletIdentifierHashContent(
          seed: 'alpha beta gamma',
          primaryAddress: 'address-one',
        ),
        'alpha beta gamma',
      );
    });

    test('uses the primary address when the seed is empty', () {
      expect(
        walletIdentifierHashContent(
          seed: '',
          primaryAddress: 'address-one',
        ),
        'address-one',
      );
    });

    test('uses the primary address when the seed is unavailable', () {
      expect(
        walletIdentifierHashContent(
          seed: null,
          primaryAddress: 'address-one',
        ),
        'address-one',
      );
    });
  });
}
