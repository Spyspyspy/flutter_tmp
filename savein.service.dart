import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

/// Allow to save in file as part of stream's chain.
///
/// {@category Services}.
class SaveInFileServiceBuilder {
  late String name;
  late String pathToDirectory;
  late File file;
  late StreamController<ProgressMessage> receivedProgress;
  late int size;
  final savedSize = Completer<int>();

  /// Builder, which is useful in download task.
  ///
  /// Manual name and destination.
  SaveInFileService buildByPathAndName({
    required String name,
    required String pathToDirectory,
  }) {
    // Check field.
    // ignore:  unnecessary_null_comparison
    assert(size != null, "Size can't be empty");
    this.name = name;
    this.pathToDirectory = pathToDirectory;
    file = File(
      PlatformDependentMethod.convertToPlatformPath('$pathToDirectory/$name'),
    );
    receivedProgress = StreamController();

    return SaveInFileService.build(this);
  }

  /// Builder, which is useful in upload task.
  ///
  /// Guaranteed  that file under encryption or other temp file
  /// will lay in special system temporary folder.
  ///
  /// Also, allow to use async constructor).
  Future<SaveInFileService> buildByTempName({required String name}) {
    // Check field.
    // ignore:  unnecessary_null_comparison
    assert(size != null, "Size can't be empty");
    this.name = name;

    return getTemporaryDirectory().then((value) {
      pathToDirectory = value.path;
      file = File(
        PlatformDependentMethod.convertToPlatformPath('$pathToDirectory/$name'),
      );
      receivedProgress = StreamController<ProgressMessage>();

      return SaveInFileService.build(this);
    });
  }
}

/// SaveInFile Service.
///
/// Use [SaveInFileServiceBuilder] to create instance of this class.
/// This class can be used in file's upload or download chain.
/// Be careful, this class do not emit stream's event,
/// so can't pass data through itself. Place this class at the last in the chain.
///
/// {@category Services}.
class SaveInFileService extends StreamTransformerBase<Uint8List, Uint8List> {
  /// Forbidden to use directly.
  const SaveInFileService._internal({
    required File file,
    required StreamController<ProgressMessage> receivedProgress,
    required int originalSize,
    required Completer<int> savedSize,
  })  : _file = file,
        _originalSize = originalSize,
        _savedSize = savedSize,
        _receivedProgressController = receivedProgress;

  factory SaveInFileService.build(SaveInFileServiceBuilder builder) =>
      SaveInFileService._internal(
        file: builder.file,
        receivedProgress: builder.receivedProgress,
        originalSize: builder.size,
        savedSize: builder.savedSize,
      );

  final File _file;

  final StreamController<ProgressMessage> _receivedProgressController;

  Stream<ProgressMessage> get receivedProgress =>
      _receivedProgressController.stream;

  final int _originalSize;

  final Completer<int> _savedSize;

  Future<int> get savedSize => _savedSize.future;

  static const int _fullProgress = 100;

  static const double _noiseLevel = 1.0;

  static const Duration _minMessageDelay = Duration(seconds: 3);

  @override
  //
  // ignore: long-method
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    int receivedSize = 0;
    double lastValue = 0.0;
    final buffer = <List<int>>[];
    DateTime lastTimestamp = DateTime.now();
    final writeIO = _file.openWrite(mode: FileMode.writeOnly);

    await for (final chunk in stream) {
      buffer.add(chunk);
      final size = chunk.lengthInBytes;
      receivedSize += size;
      num progress = (receivedSize / _originalSize) * _fullProgress;

      /// Check full.
      /// Encrypted file's size can be more than original file's size.
      if (progress > _fullProgress) {
        progress = _fullProgress;
      }

      final timeStamp = DateTime.now();

      /// Prevent stream flood.
      ///
      /// More than [_noiseLevel] percent of progress
      /// and more than [_minMessageDelay] second from previous message.
      if ((lastValue - progress).abs() > _noiseLevel &&
          timeStamp.isAfter(lastTimestamp) &&
          timeStamp.difference(lastTimestamp).compareTo(_minMessageDelay) > 0) {
        lastValue = progress.toDouble();
        lastTimestamp = timeStamp;
        final lastIndex = buffer.length;
        try {
          writeIO.add(
            buffer
                .sublist(0, lastIndex)
                .reduce((value, element) => value + element),
          );
        } catch (e) {
          LoggerService().e(e, stackTrace: StackTrace.current);
        }
        buffer.removeRange(0, lastIndex);
        _receivedProgressController
            .add(ProgressMessage(progress: lastValue, bytes: receivedSize));
      }
    }

    try {
      /// Erase buffer.
      if (buffer.isNotEmpty) {
        for (final bytes in buffer) {
          writeIO.add(bytes);
        }
        buffer.clear();
      }

      /// Forcing waiting. Flush and close IOSink after end of data.
      ///
      /// addStream.then in this case mean 'in the end of original stream, onDone'.
      await writeIO.flush();
      _savedSize.complete(receivedSize);
      await writeIO.close();
    } on Object catch (error, stackTrace) {
      LoggerService().e(
        'Error while saving file: $error',
        stackTrace: stackTrace,
      );
      rethrow;
    }

    /// Emit single event of the end.
    yield Uint8List(0);
  }
}

/// Signature message for [SaveInFileService._receivedProgressController].
///
/// Do not move counter progress to upper level, in Manager for example,
/// because it is good to avoid the occurrence of events as earlier as possible.
class ProgressMessage {
  const ProgressMessage({required this.progress, required this.bytes});

  /// Actual progress in percent.
  final num progress;

  /// Actual progress in bytes.
  final int bytes;
}
