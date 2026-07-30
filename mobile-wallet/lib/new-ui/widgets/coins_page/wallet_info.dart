import 'dart:async';

import 'package:cake_wallet/new-ui/widgets/modern_button.dart';
import 'package:cake_wallet/src/widgets/cake_image_widget.dart';
import 'package:cw_core/wallet_info.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:passport_quantumlink/passport_quantumlink.dart';

class WalletInfoBar extends StatelessWidget {
  const WalletInfoBar(
      {super.key,
      required this.lightningMode,
      required this.name,
      required this.hardwareWalletType,
      required this.onCustomizeButtonTap,
      required this.hasCustomize});

  final bool lightningMode;
  final String name;
  final HardwareWalletType? hardwareWalletType;
  final bool hasCustomize;
  final VoidCallback onCustomizeButtonTap;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        if (hasCustomize) {
          onCustomizeButtonTap();
          HapticFeedback.mediumImpact();
        }
      },
      child: Row(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          AnimatedSwitcher(
            duration: Duration(milliseconds: 150),
            transitionBuilder: (child, animation) {
              return SizeTransition(
                axis: Axis.horizontal,
                sizeFactor: animation,
                child: FadeTransition(opacity: animation, child: child),
              );
            },
            child: hardwareWalletIcon == null
                ? const SizedBox.shrink(key: ValueKey("empty"))
                : Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: Stack(
                      clipBehavior: Clip.none,
                      children: [
                        CakeImageWidget(
                          imageUrl: hardwareWalletIcon!,
                          key: const ValueKey("hardware_wallet_icon"),
                          width: 24,
                          height: 24,
                          colorFilter: hardwareWalletType == HardwareWalletType.passportPrime
                              ? null
                              : ColorFilter.mode(
                                  Theme.of(context).colorScheme.onSurfaceVariant,
                                  BlendMode.srcIn,
                                ),
                        ),
                        if (hardwareWalletType == HardwareWalletType.passportPrime)
                          const Positioned(
                            right: -2,
                            bottom: -2,
                            child: _PassportConnectionIndicator(),
                          ),
                      ],
                    ),
                  ),
          ),
          Text(
            name,
            style: Theme.of(context)
                .textTheme
                .titleLarge
                ?.copyWith(color: Theme.of(context).colorScheme.onSurface),
          ),
          if (hasCustomize) ...[
            SizedBox(width: 8),
            ModernButton.svg(
              size: 24,
              onPressed: () {
                if (hasCustomize) {
                  onCustomizeButtonTap();
                  HapticFeedback.mediumImpact();
                }
              },
              svgPath: "assets/new-ui/icon-accounts.svg",
            )
          ]
        ],
      ),
    );
  }

  String? get hardwareWalletIcon {
    switch (hardwareWalletType) {
      case null:
        return null;
      case HardwareWalletType.bitbox:
        return "assets/new-ui/hardware_wallets/device_bitbox.svg";
      case HardwareWalletType.ledger:
        return "assets/new-ui/hardware_wallets/device_ledger_nano_x.svg";
      case HardwareWalletType.trezor:
        return "assets/new-ui/hardware_wallets/device_trezor_safe_5.svg";
      case HardwareWalletType.passportPrime:
        return "assets/images/hardware_wallet/foundation.svg";
      case HardwareWalletType.cupcake:
        return "assets/images/cupcake.svg";
      case HardwareWalletType.coldcard:
      case HardwareWalletType.seedsigner:
      case HardwareWalletType.keystone:
        return "assets/images/hardware_wallet/device_qr.svg";
    }
  }
}

class _PassportConnectionIndicator extends StatefulWidget {
  const _PassportConnectionIndicator();

  @override
  State<_PassportConnectionIndicator> createState() => _PassportConnectionIndicatorState();
}

class _PassportConnectionIndicatorState extends State<_PassportConnectionIndicator> {
  StreamSubscription<PassportQuantumLinkStatus>? _statusSubscription;
  bool _connected = false;

  @override
  void initState() {
    super.initState();
    _statusSubscription = PassportQuantumLink.statusUpdates.listen(_applyStatus);
    unawaited(_loadInitialStatus());
  }

  @override
  void dispose() {
    unawaited(_statusSubscription?.cancel());
    super.dispose();
  }

  Future<void> _loadInitialStatus() async {
    try {
      _applyStatus(await PassportQuantumLink.getStatus());
    } catch (_) {
      _setConnected(false);
    }
  }

  void _applyStatus(PassportQuantumLinkStatus status) {
    _setConnected(status.connected);
  }

  void _setConnected(bool connected) {
    if (!mounted || connected == _connected) {
      return;
    }
    setState(() => _connected = connected);
  }

  @override
  Widget build(BuildContext context) => Semantics(
        label: _connected ? "Passport Prime connected" : "Passport Prime disconnected",
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          width: 9,
          height: 9,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: _connected ? const Color(0xFF35A854) : Theme.of(context).colorScheme.error,
            border: Border.all(
              color: Theme.of(context).colorScheme.surface,
              width: 1.5,
            ),
          ),
        ),
      );
}
