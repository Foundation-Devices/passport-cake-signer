import "dart:async";

import "package:cake_wallet/generated/i18n.dart";
import "package:cake_wallet/src/widgets/alert_with_one_action.dart";
import "package:cake_wallet/src/widgets/alert_with_no_action.dart.dart";
import "package:cake_wallet/utils/show_pop_up.dart";
import "package:flutter/material.dart";

Future<T?> runWithPassportPrimeSyncProgress<T>(
  BuildContext context,
  Future<T> Function() action,
) async {
  final dialogContext = Completer<BuildContext>();

  unawaited(
    showPopUp<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        if (!dialogContext.isCompleted) {
          dialogContext.complete(context);
        }
        return AlertWithNoAction(
          alertTitle: "Preparing transaction",
          alertContent: "Syncing spent outputs with Passport Prime over QuantumLink. "
              "Keep both devices nearby. This can take up to a minute.",
          alertBarrierDismissible: false,
        );
      },
    ),
  );

  final popupContext = await dialogContext.future;
  var progressClosed = false;
  try {
    return await action();
  } catch (error) {
    if (popupContext.mounted) {
      Navigator.of(popupContext, rootNavigator: true).pop();
      progressClosed = true;
      await Future<void>.delayed(Duration.zero);
    }
    if (context.mounted) {
      await showPopUp<void>(
        context: context,
        barrierDismissible: false,
        builder: (alertContext) => AlertWithOneAction(
          alertTitle: "Spent-output sync failed",
          alertContent: error.toString(),
          buttonText: S.of(alertContext).ok,
          buttonAction: () => Navigator.of(alertContext).pop(),
        ),
      );
    }
    return null;
  } finally {
    if (!progressClosed && popupContext.mounted) {
      Navigator.of(popupContext, rootNavigator: true).pop();
    }
  }
}
