import 'dart:async';
import 'dart:typed_data';

import 'package:aes_crypt_null_safe/aes_crypt_null_safe.dart';
import 'package:fast_rsa/fast_rsa.dart';

/// Encryption Service builder
///
/// {@category Services}.
class EncryptionServiceBuilder {
  late String key;
  late EncryptType encryptType;
  // Init vector. This code was got from molusca.
  // Backslashes are a part of key.
  // ignore: unnecessary_string_escapes
  String initializationVector = 'zxcvbnmlkjhg\0\0\0\0';
  // Password. This code was got from molusca.
  String password = 'password';

  /// Default builder with manual set field.
  EncryptionService build() {
    assert(password.isNotEmpty);

    assert(initializationVector.isNotEmpty);

    // Can be null due to [late] modifier.
    // ignore: unnecessary_non_null_assertion, unnecessary_null_comparison
    assert(key != null && key!.isNotEmpty);

    // Can be null due to [late] modifier.
    // ignore: unnecessary_null_comparison
    assert(encryptType != null);

    return EncryptionService.build(this);
  }

  /// Builder with preset for most of cases.
  EncryptionService buildWithDefaultParams() {
    encryptType = EncryptType.unencrypted;
    // TODO(Any): Use UAK instead this hardcoded key, when it will be ready.
    key = '1234567890qwertyuiopasdfghjklzxc';
    // Init vector. This code was got from molusca.
    // Backslashes are a part of key.
    // ignore: unnecessary_string_escapes
    initializationVector = 'zxcvbnmlkjhg\0\0\0\0';
    // Password. This code was got from molusca.
    password = 'password';

    return EncryptionService.build(this);
  }
}

/// Encryption Service.
///
/// Use [EncryptionServiceBuilder] to create instance of this class.
/// This class can be used in file's upload or download chain.
///
/// {@category Services}.
class EncryptionService extends StreamTransformerBase<Uint8List, Uint8List> {
  /// Forbidden to use this constructor directly.
  const EncryptionService._({
    required this.key,
    required this.encryptType,
    required this.crypt,
  });

  factory EncryptionService.build(EncryptionServiceBuilder builder) {
    const AesMode mode = AesMode.cbc;
    final crypt = AesCrypt()
      ..aesSetKeys(
        Uint8List.fromList(builder.key.codeUnits),
        Uint8List.fromList(builder.initializationVector.codeUnits),
      )
      ..aesSetMode(mode)
      ..setPassword(builder.password);

    return EncryptionService._(
      key: builder.key,
      encryptType: builder.encryptType,
      crypt: crypt,
    );
  }

  final String key;
  final EncryptType encryptType;

  final AesCrypt crypt;

  static Future<Uint8List> encryptRSA({
    required Uint8List cipherBytes,
    required String publicKey,
  }) =>
      RSA.encryptPKCS1v15Bytes(cipherBytes, publicKey);

  @override
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    switch (encryptType) {
      // Pass data without any changes.
      case EncryptType.unencrypted:
        yield* stream;
        break;
      // Legacy option, AES-256 with chunk size 1 Mb.
      // ignore: deprecated_member_use_from_same_package
      case EncryptType.aes256:
      // Encrypt chunk and pass.
      case EncryptType.aes256chunk64Kb:
        await for (final chunk in stream) {
          final encryptedData = crypt.aesEncrypt(chunk);
          yield encryptedData;
        }

        break;
    }
  }
}
