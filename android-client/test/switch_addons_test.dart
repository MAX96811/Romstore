import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:romstore_client/switch_addons.dart';

Uint8List _hex(String h) =>
    Uint8List.fromList(List.generate(h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16)));

void main() {
  test('sha256 matches known vectors', () {
    expect(hexUpper(sha256(Uint8List(0))),
        'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855');
    expect(hexUpper(sha256(Uint8List.fromList('abc'.codeUnits))),
        'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD');
    // 56 bytes: exercises the two-block padding path.
    expect(hexUpper(sha256(Uint8List.fromList('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'.codeUnits))),
        '248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1');
  });

  test('registeredDirFor reproduces the folders Eden used for Mario Kart content', () {
    // Verified on-device: these NCA IDs landed in these folders.
    expect(registeredDirFor('51ace2d9803f4b5b9c8240064aa46116'), '000000AD');
    expect(registeredDirFor('f17a2008367178b53c6872faba41995d'), '000000E7');
    expect(registeredDirFor('1fa7f2036e3aabdede91fa1cd78705ca'), '00000020');
    expect(registeredDirFor('a3e030a30e112d39de059a24f7c80b63'), '0000005B');
  });

  test('readPfs0, planInstall and readTicket parse a synthetic NSP', () {
    final names = [
      'a3e030a30e112d39de059a24f7c80b63.nca',
      '1fa7f2036e3aabdede91fa1cd78705ca.cnmt.nca',
      '0100152000023001000000000000000d.tik',
      '0100152000023001000000000000000d.cert',
    ];
    final strings = BytesBuilder();
    final nameOffsets = <int>[];
    for (final n in names) {
      nameOffsets.add(strings.length);
      strings.add(n.codeUnits);
      strings.addByte(0);
    }
    final payloads = <Uint8List>[
      Uint8List.fromList(List.filled(100, 1)),
      Uint8List.fromList(List.filled(50, 2)),
      _ticket(),
      Uint8List.fromList(List.filled(10, 4)),
    ];
    final header = ByteData(16)
      ..setUint8(0, 'P'.codeUnitAt(0))
      ..setUint8(1, 'F'.codeUnitAt(0))
      ..setUint8(2, 'S'.codeUnitAt(0))
      ..setUint8(3, '0'.codeUnitAt(0))
      ..setUint32(4, names.length, Endian.little)
      ..setUint32(8, strings.length, Endian.little);
    final entries = ByteData(names.length * 24);
    var offset = 0;
    for (var i = 0; i < names.length; i++) {
      entries.setUint64(i * 24, offset, Endian.little);
      entries.setUint64(i * 24 + 8, payloads[i].length, Endian.little);
      entries.setUint32(i * 24 + 16, nameOffsets[i], Endian.little);
      offset += payloads[i].length;
    }
    final file = File('${Directory.systemTemp.createTempSync('nsp').path}/t.nsp');
    file.writeAsBytesSync([
      ...header.buffer.asUint8List(),
      ...entries.buffer.asUint8List(),
      ...strings.toBytes(),
      for (final p in payloads) ...p,
    ]);

    final parsed = readPfs0(file.path);
    expect(parsed.map((e) => e.name), names);
    final headerSize = 16 + names.length * 24 + strings.length;
    expect(parsed[1].offset, headerSize + 100);
    expect(parsed[1].size, 50);

    final plan = planInstall(parsed);
    expect(plan.ncas.map((n) => n.relTarget), [
      '0000005B/a3e030a30e112d39de059a24f7c80b63.nca',
      '00000020/1fa7f2036e3aabdede91fa1cd78705ca.nca',
    ]);
    expect(plan.tickets.length, 1);

    final key = readTicket(file.path, plan.tickets.first)!;
    expect(key.rightsId, '0100152000023001000000000000000D');
    expect(key.titleKey, '43F99B785E9E203EE4D253897F3F32D1');

    // The bytes the installer would slice with tail/head are the payload.
    final raf = file.openSync();
    raf.setPositionSync(parsed[1].offset);
    expect(raf.readSync(50), payloads[1]);
    raf.closeSync();
  });
}

Uint8List _ticket() {
  final t = Uint8List(0x2C0);
  t[0x141] = 0; // common ticket
  t.setRange(0x180, 0x190, _hex('43F99B785E9E203EE4D253897F3F32D1'));
  t.setRange(0x2A0, 0x2B0, _hex('0100152000023001000000000000000D'));
  return t;
}
