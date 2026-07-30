import { requireNativeModule, type EventSubscription } from 'expo-modules-core';

export type QuantumLinkConnectionState =
  | 'unavailable'
  | 'disconnected'
  | 'scanning'
  | 'connecting'
  | 'discovering'
  | 'connected'
  | 'paired';

export type QuantumLinkStatus = {
  available: boolean;
  paired: boolean;
  connected: boolean;
  state: QuantumLinkConnectionState;
  deviceName: string | null;
  deviceAddress: string | null;
};

export type NativeEvmAccount = {
  protocolVersion: 1;
  requestId: string;
  path: string;
  address: string;
  publicKey: string;
};

export type NativeSignEvmTransactionRequest = {
  requestId: string;
  path: string;
  chainId: number;
  nonce: number;
  from: string;
  to: string;
  data: string;
  value: string;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
};

export type NativeSignEvmTransactionResponse = {
  protocolVersion: 1;
  requestId: string;
  address: string;
  signedTransaction: string;
};

export type NativeBtcAccount = {
  protocolVersion: 1;
  requestId: string;
  path: string;
  address: string;
  publicKey: string;
};

export type NativeSignBtcPsbtRequest = {
  requestId: string;
  path: string;
  psbt: string;
};

export type NativeSignBtcPsbtResponse = {
  protocolVersion: 1;
  requestId: string;
  address: string;
  signedTransaction: string;
};

type ConnectionEvent = {
  state: QuantumLinkConnectionState;
  connected: boolean;
  paired: boolean;
  deviceName: string | null;
  deviceAddress: string | null;
};

type RequestProgressEvent = {
  requestId: string;
  stage: 'sending' | 'reviewing' | 'signed' | 'rejected' | 'cancelled';
};

type PassportQuantumLinkNativeModule = {
  isAvailable(): boolean;
  getStatus(): QuantumLinkStatus;
  getIdentityXid(): string;
  getDiagnostics(): string;
  connect(deviceAddress: string): Promise<void>;
  reconnect(): Promise<void>;
  pair(primeXidBase64: string, phoneName: string): Promise<string>;
  disconnect(): Promise<void>;
  unpair(): Promise<void>;
  forget(): Promise<void>;
  getEvmAccount(path: string, requestId: string): Promise<NativeEvmAccount>;
  signEvmTransaction(
    request: NativeSignEvmTransactionRequest
  ): Promise<NativeSignEvmTransactionResponse>;
  getBtcAccount(path: string, requestId: string): Promise<NativeBtcAccount>;
  signBtcPsbt(request: NativeSignBtcPsbtRequest): Promise<NativeSignBtcPsbtResponse>;
  cancel(requestId: string): Promise<void>;
  addListener(
    event: 'onConnectionChanged',
    listener: (event: ConnectionEvent) => void
  ): EventSubscription;
  addListener(
    event: 'onRequestProgress',
    listener: (event: RequestProgressEvent) => void
  ): EventSubscription;
  addListener(event: 'onUnpaired', listener: () => void): EventSubscription;
};

const PassportQuantumLink =
  requireNativeModule<PassportQuantumLinkNativeModule>('PassportQuantumLink');

export default PassportQuantumLink;
