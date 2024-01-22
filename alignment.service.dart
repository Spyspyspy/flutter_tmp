import 'dart:async';
import 'dart:typed_data';

/// Alignment Service builder.
///
/// Network chunk != file chunk. This service transform (align) one chunk to another.
/// FileBuffer (when read file for upload) size != chunk for encryption too.
/// Have store, where accumulate data.
///
/// The pkcs7padding algorithm was used to align the last chunk
///
/// {@category Services}.
class AlignmentServiceBuilder {
  int outcomeChunkSize = defaultChunkSizeForAES;
  late final EncryptType encryptType;

  /// Default chunk size regulated by AES requirement
  ///
  /// AES ALWAYS HAVE BLOCK SIZE = 16 BYTES (128 bits)!
  /// This count is divisible without remainder by 16.
  /// 16777216 bytes = 16 Mb.
  /// 4194304 bytes = 4 Mb.
  /// 1048576 bytes = 1 Mb.
  /// 65536 bytes = 64 Kb.
  static const int defaultChunkSizeForAES = 64 * 1024; // 64 Kb

  AlignmentService buildWithDefaultParams() {
    outcomeChunkSize = defaultChunkSizeForAES;
    encryptType = EncryptType.unencrypted;

    return AlignmentService.build(this);
  }

  AlignmentService build() {
    // Can be null due to [late] modifier.
    // ignore: unnecessary_null_comparison
    assert(encryptType != null);

    return AlignmentService.build(this);
  }
}

/// Alignment Service.
///
/// Use [AlignmentServiceBuilder] to create instance of this class.
/// This class can be used in file's upload or download chain.
///
/// {@category Services}.
class AlignmentService extends StreamTransformerBase<Uint8List, Uint8List> {
  /// Forbidden to use directly.
  AlignmentService._internal({
    required this.outcomeChunkSize,
    required this.encryptType,
  }) : _store = <int>[];

  factory AlignmentService.build(AlignmentServiceBuilder builder) =>
      AlignmentService._internal(
        outcomeChunkSize: builder.outcomeChunkSize,
        encryptType: builder.encryptType,
      );

  /// Target value.
  final int outcomeChunkSize;
  final EncryptType encryptType;

  /// Temp accumulator for target count of bytes.
  ///
  /// Can't be [Uint8List], because it's fixed length.
  /// So, [bind] method need some transformation.
  List<int> _store;

  @override
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    switch (encryptType) {
      case EncryptType.unencrypted:
        yield* stream;
        break;
      // Legacy option, AES-256 with chunk size 1 Mb.
      // ignore: deprecated_member_use_from_same_package
      case EncryptType.aes256:
      case EncryptType.aes256chunk64Kb:
        await for (final chunk in stream) {
          _store.addAll(chunk);
          while (_store.length >= outcomeChunkSize) {
            yield Uint8List.fromList(_store.sublist(0, outcomeChunkSize));
            _store = _store.sublist(outcomeChunkSize);
          }
        }
        // Next block of code will be executed after stream ended.
        // Fill last chunk by zero.
        if (_store.isNotEmpty) {
          final requestedLength = -_store.length & 0xf;
          final requestedList = List.generate(
            requestedLength,
            (index) => index == requestedLength - 1 ? requestedLength : 0,
          );
          _store.addAll(requestedList);
          yield Uint8List.fromList(_store);
        }

        break;
    }
  }
}
