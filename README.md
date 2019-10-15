# Fabric Client Flutter: Hyperledger Fabric Client for Mobile Devices

This is the repo for the implementation of the full lifecycle of Hyperledger Fabric offline signing and also a sibling project's frontend app serves for [fabric-server-node](https://github.com/5sWind/fabric-server-node).

*Note*: This is an experimental software. Uses at your own risk.

## Quick Start

Since the environment only supports localhost currently, we'd like to nevigate to `client` folder, and run.

### Run with Flutter

```bash
flutter run
```

You need to open iOS simulator first if you are using mac, or install Android emulator and open it if you would like to run the app on Android device.

What's more such as Flutter installation, please refer to the [docs](https://flutter.dev/docs/get-started/install).

## Crypto Scheme

We use pointycastle for generating RSA asymmetric keys. The keys which follows PKCS#8 standard. And basic_utils for generating Certificate Signing Request (CSR), which encrypted by sha-256 with RSA encryption algorithm, by using the above generated asymmetric keys.
