import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:romstore_client/esde_export.dart';
import 'package:romstore_client/main.dart';

// The gamelist is the contract with Cocoon: it reads this file on every start
// and shows whatever it finds. A malformed or clobbered file is a library full
// of wrong names, so the merge is pinned down here rather than on the device.

Game _game(String relPath, String name,
        {String system = 'nds', String description = '', int? releaseDate}) =>
    Game(name, relPath.split('/').last, system, system, relPath, '16 MB', null, false,
        description: description, releaseDate: releaseDate);

void main() {
  late Directory tmp;
  late EsdeExport esde;

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('esde_test');
    esde = EsdeExport(Api(AppConfig()), root: tmp.path);
  });

  tearDown(() => tmp.deleteSync(recursive: true));

  String gamelist(String platform) => esde.gamelistFile(platform).readAsStringSync();

  test('publishes a game as an ES-DE entry Cocoon can match by file name', () async {
    await esde.publish(_game('nds/Tetris DS (USA).nds', 'Tetris DS',
        description: 'Falling blocks.', releaseDate: 1142812800)); // 2006-03-20

    final xml = gamelist('nds');
    expect(xml, contains('<path>./Tetris DS (USA).nds</path>'));
    expect(xml, contains('<name>Tetris DS</name>'));
    expect(xml, contains('<desc>Falling blocks.</desc>'));
    // ES-DE's date format, which is what Cocoon parses.
    expect(xml, contains('<releasedate>20060320T000000</releasedate>'));
  });

  test('a second game is added without disturbing the first', () async {
    await esde.publish(_game('nds/Tetris DS (USA).nds', 'Tetris DS'));
    await esde.publish(_game('nds/Mario Kart DS (USA).nds', 'Mario Kart DS'));

    final xml = gamelist('nds');
    expect(xml, contains('<name>Tetris DS</name>'));
    expect(xml, contains('<name>Mario Kart DS</name>'));
    expect('<game>'.allMatches(xml).length, 2);
  });

  test('republishing replaces the entry instead of duplicating it', () async {
    await esde.publish(_game('nds/Tetris DS (USA).nds', 'Old Title'));
    await esde.publish(_game('nds/Tetris DS (USA).nds', 'Tetris DS'));

    final xml = gamelist('nds');
    expect('<game>'.allMatches(xml).length, 1);
    expect(xml, contains('<name>Tetris DS</name>'));
    expect(xml, isNot(contains('Old Title')));
  });

  test('entries written by anything else are carried through untouched', () async {
    final file = esde.gamelistFile('nds');
    file.parent.createSync(recursive: true);
    file.writeAsStringSync('<?xml version="1.0"?>\n<gameList>\n'
        '\t<game>\n\t\t<path>./Scraped Elsewhere.nds</path>\n'
        '\t\t<name>Scraped Elsewhere</name>\n\t\t<rating>0.9</rating>\n\t</game>\n'
        '</gameList>\n');

    await esde.publish(_game('nds/Tetris DS (USA).nds', 'Tetris DS'));

    final xml = gamelist('nds');
    expect(xml, contains('<path>./Scraped Elsewhere.nds</path>'));
    expect(xml, contains('<rating>0.9</rating>'), reason: 'foreign fields must survive');
    expect(xml, contains('<name>Tetris DS</name>'));
  });

  test('markup in a title or summary cannot break the file', () async {
    await esde.publish(_game('nds/Odd & Ends <1>.nds', 'Odd & Ends <1>',
        description: 'Uses <b>tags</b> & ampersands.'));

    final xml = gamelist('nds');
    expect(xml, contains('<name>Odd &amp; Ends &lt;1&gt;</name>'));
    expect(xml, contains('<desc>Uses &lt;b&gt;tags&lt;/b&gt; &amp; ampersands.</desc>'));
    // One entry, and no stray unescaped element from the title.
    expect('<game>'.allMatches(xml).length, 1);
  });

  test('withdraw drops only the game that was removed', () async {
    await esde.publish(_game('nds/Tetris DS (USA).nds', 'Tetris DS'));
    await esde.publish(_game('nds/Mario Kart DS (USA).nds', 'Mario Kart DS'));

    esde.withdraw(_game('nds/Tetris DS (USA).nds', 'Tetris DS'));

    final xml = gamelist('nds');
    expect(xml, isNot(contains('Tetris DS')));
    expect(xml, contains('<name>Mario Kart DS</name>'));
  });

  test('withdraw also deletes the cover it wrote', () async {
    final cover = File('${esde.coversDir('nds').path}/Tetris DS (USA).png');
    cover.parent.createSync(recursive: true);
    cover.writeAsBytesSync([1, 2, 3]);

    esde.withdraw(_game('nds/Tetris DS (USA).nds', 'Tetris DS'));

    expect(cover.existsSync(), isFalse);
  });

  test('games land in the folder Cocoon names the platform', () async {
    // Cocoon's compatibility list calls these gc and genesis; the server tree
    // uses the longer names, so the two have to be translated on the way out.
    expect(esdePlatformFor('gamecube'), 'gc');
    expect(esdePlatformFor('megadrive'), 'genesis');
    expect(esdePlatformFor('nds'), 'nds');

    await esde.publish(_game('gamecube/Pikmin.iso', 'Pikmin', system: 'gamecube'));
    expect(esde.gamelistFile('gc').existsSync(), isTrue);
    expect(esde.gamelistFile('gamecube').existsSync(), isFalse);
  });

  test('a shop link carrying Cocoon ids maps back to the server folder', () {
    expect(systemForEsdePlatform('gc'), 'gamecube');
    expect(systemForEsdePlatform('genesis'), 'megadrive');
    expect(systemForEsdePlatform('nds'), 'nds');
    expect(platformFromLink('romstore://shop?platform=nds'), 'nds');
    expect(platformFromLink('romstore://shop?platform=GC'), 'gc');
    expect(platformFromLink('romstore://shop'), isNull);
    expect(platformFromLink('https://example.com?platform=nds'), isNull);
    expect(platformFromLink(null), isNull);
  });
}
