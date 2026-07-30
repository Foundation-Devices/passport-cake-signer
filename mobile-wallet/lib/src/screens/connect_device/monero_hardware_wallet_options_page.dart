import "dart:async";

import "package:cake_wallet/core/execution_state.dart";
import "package:cake_wallet/core/wallet_name_validator.dart";
import "package:cake_wallet/generated/i18n.dart";
import "package:cake_wallet/routes.dart";
import "package:cake_wallet/src/screens/base_page.dart";
import "package:cake_wallet/src/screens/connect_device/monero_hardware_wallet_passphrase_input.dart";
import "package:cake_wallet/src/widgets/alert_with_one_action.dart";
import "package:cake_wallet/src/widgets/base_text_form_field.dart";
import "package:cake_wallet/src/widgets/blockchain_height_widget.dart";
import "package:cake_wallet/src/widgets/primary_button.dart";
import "package:cake_wallet/src/widgets/scrollable_with_bottom_section.dart";
import "package:cake_wallet/utils/responsive_layout_util.dart";
import "package:cake_wallet/utils/show_pop_up.dart";
import "package:cake_wallet/view_model/hardware_wallet/passport_prime_view_model.dart";
import "package:cake_wallet/view_model/wallet_hardware_restore_view_model.dart";
import "package:cw_core/generate_name.dart";
import "package:cw_core/wallet_info.dart";
import "package:cw_core/wallet_type.dart";
import "package:flutter/material.dart";
import "package:flutter_mobx/flutter_mobx.dart";
import "package:mobx/mobx.dart";

class MoneroHardwareWalletOptionsPage extends BasePage {
  MoneroHardwareWalletOptionsPage(this._walletHardwareRestoreVM);

  final WalletHardwareRestoreViewModel _walletHardwareRestoreVM;

  @override
  String get title => S.current.restore_title_from_hardware_wallet;

  @override
  Widget body(BuildContext context) => _MoneroHardwareWalletOptionsForm(_walletHardwareRestoreVM);
}

class _MoneroHardwareWalletOptionsForm extends StatefulWidget {
  const _MoneroHardwareWalletOptionsForm(this._walletHardwareRestoreVM);

  final WalletHardwareRestoreViewModel _walletHardwareRestoreVM;

  @override
  _MoneroHardwareWalletOptionsFormState createState() =>
      _MoneroHardwareWalletOptionsFormState(_walletHardwareRestoreVM);
}

class _MoneroHardwareWalletOptionsFormState extends State<_MoneroHardwareWalletOptionsForm> {
  _MoneroHardwareWalletOptionsFormState(this._walletHardwareRestoreVM)
      : _formKey = GlobalKey<FormState>(),
        _blockchainHeightKey = GlobalKey<BlockchainHeightState>(),
        _blockHeightFocusNode = FocusNode(),
        _walletNameController = TextEditingController(),
        _passphraseController = TextEditingController();

  final GlobalKey<FormState> _formKey;
  final GlobalKey<BlockchainHeightState> _blockchainHeightKey;
  final FocusNode _blockHeightFocusNode;
  final WalletHardwareRestoreViewModel _walletHardwareRestoreVM;
  final TextEditingController _walletNameController;
  final TextEditingController _passphraseController;
  bool _isRestoring = false;
  bool _isLoadingPassportDetails = false;

  bool get _isPassportPrime =>
      _walletHardwareRestoreVM.hardwareWalletVM.hardwareWalletType ==
      HardwareWalletType.passportPrime;

  @override
  void initState() {
    super.initState();
    _setEffects(context);
    if (_isPassportPrime) {
      unawaited(_loadPassportWalletDetails());
    }
  }

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(top: 24),
        child: ScrollableWithBottomSection(
          contentPadding: const EdgeInsets.only(left: 24, right: 24, bottom: 24),
          content: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(
                maxWidth: ResponsiveLayoutUtilBase.kDesktopMaxWidthConstraint,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Padding(
                    padding: EdgeInsets.zero,
                    child: Form(
                      key: _formKey,
                      child: Stack(
                        alignment: Alignment.centerRight,
                        children: [
                          BaseTextFormField(
                            onChanged: (value) => _walletHardwareRestoreVM.name = value,
                            controller: _walletNameController,
                            readOnly: _isPassportPrime,
                            textStyle: Theme.of(context).textTheme.bodyMedium!.copyWith(
                                  fontSize: 20,
                                  fontWeight: FontWeight.w600,
                                ),
                            placeholderTextStyle: Theme.of(context).textTheme.bodyMedium!.copyWith(
                                  fontSize: 18,
                                  fontWeight: FontWeight.w500,
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                            hintText: S.of(context).wallet_name,
                            suffixIcon: _isPassportPrime
                                ? (_isLoadingPassportDetails
                                    ? const Padding(
                                        padding: EdgeInsets.all(12),
                                        child: SizedBox.square(
                                          dimension: 20,
                                          child: CircularProgressIndicator(strokeWidth: 2),
                                        ),
                                      )
                                    : null)
                                : Semantics(
                                    label: S.of(context).generate_name,
                                    child: IconButton(
                                      onPressed: _onGenerateName,
                                      icon: Container(
                                        padding: const EdgeInsets.all(8),
                                        decoration: BoxDecoration(
                                          borderRadius: BorderRadius.circular(6),
                                          color:
                                              Theme.of(context).colorScheme.surfaceContainerHighest,
                                        ),
                                        width: 34,
                                        height: 34,
                                        child: Image.asset(
                                          "assets/images/refresh_icon.png",
                                          color: Theme.of(context).colorScheme.primary,
                                        ),
                                      ),
                                    ),
                                  ),
                            validator: WalletNameValidator(),
                          ),
                        ],
                      ),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(top: 20),
                    child: BlockchainHeightWidget(
                      focusNode: _blockHeightFocusNode,
                      key: _blockchainHeightKey,
                      hasDatePicker: true,
                      walletType: WalletType.monero,
                    ),
                  ),
                ],
              ),
            ),
          ),
          bottomSectionPadding: const EdgeInsets.all(24),
          bottomSection: Observer(
            builder: (_) => Column(
              children: [
                if (_walletHardwareRestoreVM.passphraseAvailable) ...[
                  TextButton(
                    onPressed: () {
                      showModalBottomSheet(
                        context: context,
                        isScrollControlled: true,
                        backgroundColor: Colors.transparent,
                        builder: (context) => MoneroHardwareWalletPassphraseInputModal(
                          controller: _passphraseController,
                        ),
                      );
                    },
                    child: Text(S.of(context).add_a_passphrase),
                  ),
                ],
                LoadingPrimaryButton(
                  onPressed: _confirmForm,
                  text: S.of(context).seed_language_next,
                  color: Theme.of(context).colorScheme.primary,
                  textColor: Theme.of(context).colorScheme.onPrimary,
                  isDisabled: _walletHardwareRestoreVM.name.isEmpty,
                ),
              ],
            ),
          ),
        ),
      );

  Future<void> _onGenerateName() async {
    final rName = await generateName();
    FocusManager.instance.primaryFocus?.unfocus();

    setState(() {
      _walletNameController.text = rName;
      _walletHardwareRestoreVM.name = rName;
      _walletNameController.selection =
          TextSelection.fromPosition(TextPosition(offset: _walletNameController.text.length));
    });
  }

  Future<void> _loadPassportWalletDetails() async {
    final hardwareWalletVM = _walletHardwareRestoreVM.hardwareWalletVM;
    if (hardwareWalletVM is! PassportPrimeViewModel) {
      return;
    }
    setState(() => _isLoadingPassportDetails = true);
    try {
      final details = await hardwareWalletVM.prefetchMoneroWalletDetails();
      if (!mounted) {
        return;
      }
      final name = details.walletName.trim();
      if (name.isEmpty) {
        throw StateError("Passport Prime did not provide a wallet name.");
      }
      setState(() {
        _walletNameController.text = name;
        _walletHardwareRestoreVM.name = name;
        _walletNameController.selection =
            TextSelection.collapsed(offset: _walletNameController.text.length);
      });
    } catch (error) {
      _walletHardwareRestoreVM.error = error.toString();
    } finally {
      if (mounted) {
        setState(() => _isLoadingPassportDetails = false);
      }
    }
  }

  Future<void> _confirmForm() async {
    if (_isRestoring) {
      return;
    }

    final isPassportPrime = _isPassportPrime;

    _isRestoring = true;
    var waitDialogOpen = true;
    final waitDialog = showPopUp<void>(
      context: context,
      builder: (context) => AlertWithOneAction(
        alertTitle:
            isPassportPrime ? "Connecting to Passport Prime" : S.of(context).proceed_on_device,
        alertContent: isPassportPrime
            ? "Cake Wallet is requesting the watch-only wallet details over QuantumLink. Keep Passport Prime awake and nearby."
            : S.of(context).proceed_on_device_description,
        buttonText: S.of(context).cancel,
        alertBarrierDismissible: false,
        buttonAction: () => Navigator.of(context).pop(),
      ),
    ).whenComplete(() => waitDialogOpen = false);
    unawaited(waitDialog);

    final options = <String, dynamic>{"height": _blockchainHeightKey.currentState?.height ?? -1};

    if (_walletHardwareRestoreVM.passphraseAvailable && _passphraseController.text.isNotEmpty) {
      options["passphrase"] = _passphraseController.text;
    }

    try {
      await _walletHardwareRestoreVM.create(options: options);
    } finally {
      _isRestoring = false;
      if (mounted && waitDialogOpen) {
        Navigator.of(context, rootNavigator: true).pop();
      }
    }

    if (!mounted) {
      return;
    }

    final state = _walletHardwareRestoreVM.state;
    if (state is ExecutedSuccessfullyState) {
      Navigator.of(context).pushNamedAndRemoveUntil(Routes.dashboard, (route) => false);
    } else if (state is FailureState) {
      await _showRestoreError(context, state.error);
    }
  }

  bool _effectsInstalled = false;

  void _setEffects(BuildContext context) {
    if (_effectsInstalled) {
      return;
    }

    reaction((_) => _walletHardwareRestoreVM.error, (error) {
      if (error != null) {
        if (error == S.current.ledger_connection_error) {
          Navigator.of(context).pop();
        }

        WidgetsBinding.instance.addPostFrameCallback((_) {
          showPopUp<void>(
            context: context,
            builder: (context) => AlertWithOneAction(
              alertTitle: S.of(context).error,
              alertContent: error,
              buttonText: S.of(context).ok,
              buttonAction: () {
                _walletHardwareRestoreVM.error = null;
                Navigator.of(context).pop();
              },
            ),
          );
        });
      }
    });

    _effectsInstalled = true;
  }

  Future<void> _showRestoreError(BuildContext context, String error) {
    return showPopUp<void>(
      context: context,
      builder: (context) => AlertWithOneAction(
        alertTitle: S.of(context).error,
        alertContent: error,
        buttonText: S.of(context).ok,
        buttonAction: () => Navigator.of(context).pop(),
      ),
    );
  }
}
