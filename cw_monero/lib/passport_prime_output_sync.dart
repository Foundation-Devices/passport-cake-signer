enum PassportPrimeOutputSyncPhase {
  exportOutputs,
  requestKeyImages,
  importKeyImages,
}

class PassportPrimeOutputSyncException implements Exception {
  PassportPrimeOutputSyncException({
    required this.phase,
    required this.cause,
  });

  final PassportPrimeOutputSyncPhase phase;
  final Object cause;

  String get phaseDescription {
    switch (phase) {
      case PassportPrimeOutputSyncPhase.exportOutputs:
        return "Cake Wallet could not prepare the wallet outputs";
      case PassportPrimeOutputSyncPhase.requestKeyImages:
        return "Passport Prime did not return the spent-output data";
      case PassportPrimeOutputSyncPhase.importKeyImages:
        return "Cake Wallet could not import the spent-output data";
    }
  }

  String get causeDescription {
    final message = cause.toString();
    const exceptionPrefix = "Exception: ";
    return message.startsWith(exceptionPrefix)
        ? message.substring(exceptionPrefix.length)
        : message;
  }

  @override
  String toString() => "$phaseDescription: $causeDescription";
}

Future<T> runPassportPrimeOutputSyncPhase<T>({
  required PassportPrimeOutputSyncPhase phase,
  required Future<T> Function() action,
}) async {
  try {
    return await action();
  } catch (error) {
    if (error is PassportPrimeOutputSyncException) {
      rethrow;
    }
    throw PassportPrimeOutputSyncException(phase: phase, cause: error);
  }
}

Future<T> runPassportPrimeKeyImageImport<T>({
  required Future<bool> Function() isTrustedDaemon,
  required Future<void> Function(bool trusted) setTrustedDaemon,
  required Future<T> Function() importKeyImages,
}) async {
  final wasTrusted = await isTrustedDaemon();
  if (!wasTrusted) {
    await setTrustedDaemon(true);
  }

  try {
    return await importKeyImages();
  } finally {
    if (!wasTrusted) {
      await setTrustedDaemon(false);
    }
  }
}

Future<bool> syncPassportPrimeOutputSnapshots({
  required bool Function() isReadyToSpend,
  required Future<void> Function() syncSnapshot,
  int maxSnapshots = 3,
}) async {
  if (maxSnapshots < 1) {
    throw ArgumentError.value(maxSnapshots, "maxSnapshots", "Must be at least 1");
  }

  for (var snapshot = 0; snapshot < maxSnapshots; snapshot++) {
    await syncSnapshot();
    if (isReadyToSpend()) {
      return true;
    }
  }

  return isReadyToSpend();
}

Future<T> retryPassportPrimeSyncRequest<T>({
  required Future<T> Function() request,
  int maxAttempts = 2,
  Duration retryDelay = const Duration(milliseconds: 750),
}) async {
  if (maxAttempts < 1) {
    throw ArgumentError.value(maxAttempts, "maxAttempts", "Must be at least 1");
  }

  Object? lastError;
  StackTrace? lastStackTrace;
  for (var attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await request();
    } catch (error, stackTrace) {
      lastError = error;
      lastStackTrace = stackTrace;
      if (attempt == maxAttempts || !isRetryablePassportPrimeSyncError(error)) {
        rethrow;
      }
      await Future<void>.delayed(retryDelay);
    }
  }

  Error.throwWithStackTrace(lastError!, lastStackTrace!);
}

bool isRetryablePassportPrimeSyncError(Object error) {
  final message = error.toString().toLowerCase();
  return message.contains("request_timeout") ||
      message.contains("did not answer in time") ||
      message.contains("connection_lost") ||
      message.contains("disconnected") ||
      message.contains("gatt") ||
      message.contains("bluetooth") ||
      message.contains("ble_");
}
