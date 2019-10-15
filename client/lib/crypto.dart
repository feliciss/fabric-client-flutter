import 'package:flutter/foundation.dart';
import 'package:asn1lib/asn1lib.dart';

import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/rsa_signer.dart';
import 'package:basic_utils/basic_utils.dart';

SecureRandom getSecureRandom() {
  var secureRandom = FortunaRandom();
  var random = Random.secure();
  List<int> seeds = [];
  for (int i = 0; i < 32; i++) {
    seeds.add(random.nextInt(255));
  }
  secureRandom.seed(new KeyParameter(new Uint8List.fromList(seeds)));
  return secureRandom;
}

AsymmetricKeyPair<PublicKey, PrivateKey> getRSAKeyPair(
    SecureRandom secureRandom) {
  var keyParams =
      new RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12);
  var rngParams = new ParametersWithRandom(keyParams, secureRandom);
  var keyGenerator = new RSAKeyGenerator();
  keyGenerator.init(rngParams);
  return keyGenerator.generateKeyPair();
}

Future<AsymmetricKeyPair<PublicKey, PrivateKey>> computeRSAKeyPair(
    SecureRandom secureRandom) async {
  return await compute(getRSAKeyPair, secureRandom);
}

String encodePublicKeyToPem(RSAPublicKey publicKey) {
  var algorithmSeq = new ASN1Sequence();
  var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  var paramsAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  var publicKeySeq = new ASN1Sequence();
  publicKeySeq.add(ASN1Integer(publicKey.modulus));
  publicKeySeq.add(ASN1Integer(publicKey.exponent));
  var publicKeySeqBitString =
      new ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

  var topLevelSeq = new ASN1Sequence();
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqBitString);
  var dataBase64 = base64.encode(topLevelSeq.encodedBytes);

  return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
}

String encodePrivateKeyToPem(RSAPrivateKey privateKey) {
  var version = ASN1Integer(BigInt.from(0));

  var algorithmSeq = new ASN1Sequence();
  var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  var paramsAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  var privateKeySeq = new ASN1Sequence();
  var modulus = ASN1Integer(privateKey.n);
  var publicExponent = ASN1Integer(BigInt.parse('65537'));
  var privateExponent = ASN1Integer(privateKey.d);
  var p = ASN1Integer(privateKey.p);
  var q = ASN1Integer(privateKey.q);
  var dP = privateKey.d % (privateKey.p - BigInt.from(1));
  var exp1 = ASN1Integer(dP);
  var dQ = privateKey.d % (privateKey.q - BigInt.from(1));
  var exp2 = ASN1Integer(dQ);
  var iQ = privateKey.q.modInverse(privateKey.p);
  var co = ASN1Integer(iQ);

  privateKeySeq.add(version);
  privateKeySeq.add(modulus);
  privateKeySeq.add(publicExponent);
  privateKeySeq.add(privateExponent);
  privateKeySeq.add(p);
  privateKeySeq.add(q);
  privateKeySeq.add(exp1);
  privateKeySeq.add(exp2);
  privateKeySeq.add(co);

  var publicKeySeqOctetString =
      new ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));
  var topLevelSeq = new ASN1Sequence();
  topLevelSeq.add(version);
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqOctetString);
  var dataBase64 = base64.encode(topLevelSeq.encodedBytes);

  return """-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----""";
}

Future<AsymmetricKeyPair<PublicKey, PrivateKey>> makeGenerationRequest() async {
  var secureRandom = getSecureRandom();
  var keypair = getRSAKeyPair(secureRandom);
  await computeRSAKeyPair(secureRandom);
  return keypair;
}

String sign(Uint8List unsignedProposal, RSAPrivateKey privateKey) {
  var signer = RSASigner(SHA256Digest(), "0609608648016503040201");
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
  return base64Encode(signer.generateSignature(unsignedProposal).bytes);
}

ASN1Sequence makePublicKeyBlock(RSAPublicKey publicKey) {
  ASN1Sequence blockEncryptionType = ASN1Sequence();
  blockEncryptionType.add(ASN1ObjectIdentifier.fromName("rsaEncryption"));
  blockEncryptionType.add(ASN1Null());

  ASN1Sequence publicKeySequence = ASN1Sequence();
  publicKeySequence.add(ASN1Integer(publicKey.modulus));
  publicKeySequence.add(ASN1Integer(publicKey.exponent));

  ASN1BitString blockPublicKey = ASN1BitString(publicKeySequence.encodedBytes);

  ASN1Sequence outer = ASN1Sequence();
  outer.add(blockEncryptionType);
  outer.add(blockPublicKey);

  return outer;
}

String generateRsaCsrPem(Map<String, String> attributes,
    RSAPrivateKey privateKey, RSAPublicKey publicKey) {
  ASN1Object encodedDN = X509Utils.encodeDN(attributes);

  ASN1Sequence blockDN = ASN1Sequence();
  blockDN.add(ASN1Integer(BigInt.from(0)));
  blockDN.add(encodedDN);
  blockDN.add(makePublicKeyBlock(publicKey));
  blockDN.add(ASN1Null(tag: 0xA0)); // let's call this WTF

  ASN1Sequence blockProtocol = ASN1Sequence();
  blockProtocol.add(ASN1ObjectIdentifier.fromName("sha256WithRSAEncryption")); // let's use this secure algorithm
  blockProtocol.add(ASN1Null());

  ASN1Sequence outer = ASN1Sequence();
  outer.add(blockDN);
  outer.add(blockProtocol);
  outer.add(ASN1BitString(X509Utils.rsaPrivateKeyModulusToBytes(privateKey)));
  List<String> chunks =
      StringUtils.chunk(base64.encode(outer.encodedBytes), 64);

  return "${X509Utils.BEGIN_CSR}\n${chunks.join("\r\n")}\n${X509Utils.END_CSR}";
}

String generateCSR(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
  ASN1ObjectIdentifier.registerFrequentNames();
  Map<String, String> attributes = {
    "CN": "admin",
    "L": "",
    "O": "Hyperledger",
    "OU": "Fabric",
    "ST": "North Carolina",
    "C": "US",
  };

  return generateRsaCsrPem(attributes, privateKey, publicKey);
}
