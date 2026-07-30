import "package:cw_monero/passport_prime_output_sync.dart";
import "package:flutter_test/flutter_test.dart";

void main() {
  test("stops after the first snapshot when all key images are known", () async {
    var snapshots = 0;
    var hasUnknown = true;

    final ready = await syncPassportPrimeOutputSnapshots(
      isReadyToSpend: () => !hasUnknown,
      syncSnapshot: () async {
        snapshots++;
        hasUnknown = false;
      },
    );

    expect(ready, isTrue);
    expect(snapshots, 1);
  });

  test("takes a fresh snapshot when a new output arrives during sync", () async {
    var snapshots = 0;
    var hasUnknown = true;

    final ready = await syncPassportPrimeOutputSnapshots(
      isReadyToSpend: () => !hasUnknown,
      syncSnapshot: () async {
        snapshots++;
        hasUnknown = snapshots == 1;
      },
    );

    expect(ready, isTrue);
    expect(snapshots, 2);
  });

  test("stops at the snapshot limit when the output set keeps changing", () async {
    var snapshots = 0;

    final ready = await syncPassportPrimeOutputSnapshots(
      isReadyToSpend: () => false,
      syncSnapshot: () async => snapshots++,
      maxSnapshots: 3,
    );

    expect(ready, isFalse);
    expect(snapshots, 3);
  });

  test("rejects a zero snapshot limit", () {
    expect(
      () => syncPassportPrimeOutputSnapshots(
        isReadyToSpend: () => false,
        syncSnapshot: () async {},
        maxSnapshots: 0,
      ),
      throwsArgumentError,
    );
  });

  test("retries a timed-out QuantumLink sync request", () async {
    var attempts = 0;

    final result = await retryPassportPrimeSyncRequest(
      request: () async {
        attempts++;
        if (attempts == 1) {
          throw Exception("PlatformException(request_timeout)");
        }
        return "key-images";
      },
      retryDelay: Duration.zero,
    );

    expect(result, "key-images");
    expect(attempts, 2);
  });

  test("does not retry a Monero import error", () async {
    var attempts = 0;

    await expectLater(
      retryPassportPrimeSyncRequest<void>(
        request: () async {
          attempts++;
          throw Exception("unable to import key images");
        },
        retryDelay: Duration.zero,
      ),
      throwsException,
    );

    expect(attempts, 1);
  });

  test("rejects a zero request-attempt limit", () {
    expect(
      () => retryPassportPrimeSyncRequest<void>(
        request: () async {},
        maxAttempts: 0,
      ),
      throwsArgumentError,
    );
  });

  test("reports the phase that failed", () async {
    await expectLater(
      runPassportPrimeOutputSyncPhase<void>(
        phase: PassportPrimeOutputSyncPhase.importKeyImages,
        action: () async => throw Exception("signature check failed"),
      ),
      throwsA(
        isA<PassportPrimeOutputSyncException>()
            .having(
              (error) => error.phase,
              "phase",
              PassportPrimeOutputSyncPhase.importKeyImages,
            )
            .having(
              (error) => error.toString(),
              "message",
              contains("signature check failed"),
            ),
      ),
    );
  });

  test("does not wrap an already classified sync error", () async {
    final original = PassportPrimeOutputSyncException(
      phase: PassportPrimeOutputSyncPhase.requestKeyImages,
      cause: Exception("request_timeout"),
    );

    await expectLater(
      runPassportPrimeOutputSyncPhase<void>(
        phase: PassportPrimeOutputSyncPhase.importKeyImages,
        action: () async => throw original,
      ),
      throwsA(same(original)),
    );
  });

  test("temporarily trusts the daemon while importing key images", () async {
    var trusted = false;
    final trustChanges = <bool>[];

    final result = await runPassportPrimeKeyImageImport(
      isTrustedDaemon: () async => trusted,
      setTrustedDaemon: (value) async {
        trusted = value;
        trustChanges.add(value);
      },
      importKeyImages: () async {
        expect(trusted, isTrue);
        return "imported";
      },
    );

    expect(result, "imported");
    expect(trusted, isFalse);
    expect(trustChanges, [true, false]);
  });

  test("leaves an already trusted daemon unchanged", () async {
    var trusted = true;
    final trustChanges = <bool>[];

    await runPassportPrimeKeyImageImport(
      isTrustedDaemon: () async => trusted,
      setTrustedDaemon: (value) async {
        trusted = value;
        trustChanges.add(value);
      },
      importKeyImages: () async {
        expect(trusted, isTrue);
      },
    );

    expect(trusted, isTrue);
    expect(trustChanges, isEmpty);
  });

  test("restores daemon trust when key-image import fails", () async {
    var trusted = false;

    await expectLater(
      runPassportPrimeKeyImageImport<void>(
        isTrustedDaemon: () async => trusted,
        setTrustedDaemon: (value) async => trusted = value,
        importKeyImages: () async => throw Exception("signature check failed"),
      ),
      throwsException,
    );

    expect(trusted, isFalse);
  });
}
