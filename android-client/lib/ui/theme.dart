import 'package:flutter/cupertino.dart' show CupertinoPageTransitionsBuilder;
import 'package:flutter/material.dart';

// RomStore's look: warm charcoal and the orange from the launcher icon, with
// generous corners. It is meant to sit next to Cocoon on the same handheld
// without feeling like a different device, and to stay readable at arm's
// length on a screen you hold in two hands.

const kBrandOrange = Color(0xFFE8590C);
const kBrandOrangeLight = Color(0xFFFF8A3D);
const kInk = Color(0xFF14110F);
const kSurface = Color(0xFF1E1A17);
const kSurfaceHigh = Color(0xFF2A2521);

ThemeData buildRomStoreTheme() {
  final scheme = ColorScheme.fromSeed(
    seedColor: kBrandOrange,
    brightness: Brightness.dark,
  ).copyWith(
    surface: kSurface,
    surfaceContainerHighest: kSurfaceHigh,
    primary: kBrandOrangeLight,
  );

  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: kInk,
    splashFactory: InkSparkle.splashFactory,
    cardTheme: CardThemeData(
      color: kSurface,
      elevation: 0,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      centerTitle: false,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: kSurfaceHigh,
      isDense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(30),
        borderSide: BorderSide.none,
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 14),
      ),
    ),
    bottomSheetTheme: const BottomSheetThemeData(
      backgroundColor: kSurface,
      showDragHandle: true,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
      ),
    ),
    // Screens slide in rather than cross-fading: on a handheld it reads as
    // depth, and makes back navigation obvious without a visible bar.
    pageTransitionsTheme: const PageTransitionsTheme(builders: {
      TargetPlatform.android: CupertinoPageTransitionsBuilder(),
    }),
  );
}

// A soft warm wash behind the grid, so a library of dark box art does not sit
// on a flat black rectangle.
class StoreBackdrop extends StatelessWidget {
  final Widget child;
  const StoreBackdrop({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: const BoxDecoration(
        gradient: RadialGradient(
          center: Alignment(-0.7, -1.0),
          radius: 1.5,
          colors: [Color(0xFF2C1D14), kInk],
        ),
      ),
      child: child,
    );
  }
}

// Fade-and-rise used for grid items as they appear. Index staggers the start
// so a screen of games assembles instead of popping.
class EntranceFade extends StatelessWidget {
  final int index;
  final Widget child;
  const EntranceFade({super.key, required this.index, required this.child});

  @override
  Widget build(BuildContext context) {
    final delay = (index % 12) * 28;
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: 1),
      duration: Duration(milliseconds: 320 + delay),
      curve: Curves.easeOutCubic,
      builder: (context, t, child) => Opacity(
        opacity: t,
        child: Transform.translate(offset: Offset(0, 18 * (1 - t)), child: child),
      ),
      child: child,
    );
  }
}
