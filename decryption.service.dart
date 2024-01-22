import 'dart:async';
import 'dart:typed_data';

import 'package:aes_crypt_null_safe/aes_crypt_null_safe.dart';
import 'package:fast_rsa/fast_rsa.dart';

/// Decryption Service builder
///
/// {@category Services}.
class DecryptionServiceBuilder {
  late String key;
  // Init vector. This code was got from molusca.
  // Backslashes are a part of key.
  // ignore: unnecessary_string_escapes
  String initializationVector = 'zxcvbnmlkjhg\0\0\0\0';
  // Password. This code was got from molusca.
  String password = 'password';
  EncryptType encryptType = EncryptType.unencrypted;

  /// Default builder with manual set field.
  DecryptionService build() {
    assert(password.isNotEmpty);

    assert(initializationVector.isNotEmpty);

    assert(
      encryptType == EncryptType.unencrypted ||

          // Can be null due to [late] modifier.
          // ignore: unnecessary_non_null_assertion, unnecessary_null_comparison
          (key != null && key!.isNotEmpty),
    );

    return DecryptionService.build(this);
  }

  /// Builder with preset for most of cases.
  DecryptionService buildWithDefaultParams() {
    encryptType = EncryptType.unencrypted;
    // TODO(Any): Use UAK instead this hardcoded key, when it will be ready.
    key = '1234567890qwertyuiopasdfghjklzxc';

    return DecryptionService.build(this);
  }
}

/// Decryption Service.
///
/// Use [DecryptionServiceBuilder] to create instance of this class.
/// This class can be used in file's upload or download chain.
///
/// {@category Services}.
class DecryptionService extends StreamTransformerBase<Uint8List, Uint8List> {
  /// Forbidden to use this constructor directly.
  const DecryptionService._({
    required this.key,
    required this.encryptType,
    required this.crypt,
  });

  factory DecryptionService.build(DecryptionServiceBuilder builder) {
    const AesMode mode = AesMode.cbc;
    final crypt = AesCrypt();
    if (builder.encryptType != EncryptType.unencrypted) {
      crypt
        ..aesSetKeys(
          Uint8List.fromList(builder.key.codeUnits),
          Uint8List.fromList(builder.initializationVector.codeUnits),
        )
        ..aesSetMode(mode)
        ..setPassword(builder.password);
    }

    return DecryptionService._(
      key: builder.key,
      encryptType: builder.encryptType,
      crypt: crypt,
    );
  }

  final String key;
  final EncryptType encryptType;
  final AesCrypt crypt;

  static Future<Uint8List> decodeRSA({
    required Uint8List cipherBytes,
    required String privateKey,
  }) =>
      RSA.decryptPKCS1v15Bytes(cipherBytes, privateKey);

  @override
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    Uint8List? encryptedData;
    switch (encryptType) {
      // Pass data without any changes.
      case EncryptType.unencrypted:
        yield* stream;
        break;
      // Legacy option, AES-256 with chunk size 1 Mb.
      // ignore: deprecated_member_use_from_same_package
      case EncryptType.aes256:
      // Decrypt chunk and pass.
      case EncryptType.aes256chunk64Kb:
        await for (final chunk in stream) {
          if (encryptedData != null) {
            yield encryptedData;
          }
          encryptedData = crypt.aesDecrypt(chunk);
        }

        if (encryptedData!.last <= encryptedData.length &&
            encryptedData
                    .getRange(
                      encryptedData.length - encryptedData.last,
                      encryptedData.length,
                    )
                    .where((element) => element == 0)
                    .length ==
                encryptedData.last - 1) {
          yield Uint8List.fromList(
            encryptedData
                .getRange(0, encryptedData.length - encryptedData.last)
                .toList(),
          );
        } else {
          yield encryptedData;
        }

        break;
    }
  }
}
