#!/usr/bin/env python3
"""Draws RomStore's launcher icon.

Kept in the repo so the mark can be regenerated rather than being a set of
binaries nobody can edit. Run from the android-client folder:

    python3 tool/make_icons.py

The mark is a game cartridge with a download arrow through it: what the app
does, in one shape that still reads at 48px. Android's adaptive icon wants the
foreground to sit inside the middle 66% of the canvas, since launchers crop the
rest to whatever mask they use -- Cocoon's tiles crop hard, so the cartridge is
kept well inside that circle.
"""

import os
from PIL import Image, ImageDraw

# Brand colours: the app's seed orange, on the warm charcoal its dark theme uses.
ORANGE = (232, 89, 12)
ORANGE_LIGHT = (255, 138, 61)
CREAM = (255, 241, 230)
CHARCOAL = (26, 22, 20)

RES = os.path.join("android", "app", "src", "main", "res")
SUPERSAMPLE = 4  # draw big, shrink down: cheap anti-aliasing

LEGACY_SIZES = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
ADAPTIVE_SIZES = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}


def rounded(draw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def draw_cartridge(img, scale, cx, cy, width):
    """A cartridge, centred on (cx, cy), `width` wide, with a download arrow."""
    d = ImageDraw.Draw(img)
    height = width * 1.12
    left, top = cx - width / 2, cy - height / 2
    right, bottom = cx + width / 2, cy + height / 2
    r = width * 0.14

    # Body.
    rounded(d, (left, top, right, bottom), r, CREAM)

    # Clipped top-right corner, the detail that makes it read as a cartridge
    # rather than a plain card.
    notch = width * 0.30
    d.polygon(
        [(right - notch, top), (right, top), (right, top + notch)],
        fill=(0, 0, 0, 0),
    )
    rounded(d, (left, top, right - notch * 0.55, bottom), r, CREAM)
    d.polygon(
        [
            (right - notch, top),
            (right, top + notch),
            (right, bottom - r),
            (right - notch, bottom),
        ],
        fill=CREAM,
    )

    # Contact pins along the bottom edge.
    pin_w = width * 0.10
    pin_h = height * 0.09
    pin_y = bottom - pin_h - height * 0.05
    for i in range(3):
        x = cx - width * 0.26 + i * (pin_w + width * 0.13)
        rounded(d, (x, pin_y, x + pin_w, pin_y + pin_h), pin_w * 0.3, CHARCOAL)

    # Download arrow: stem plus head, knocked through the label area.
    stem_w = width * 0.13
    stem_top = top + height * 0.20
    stem_bottom = cy + height * 0.02
    rounded(
        d,
        (cx - stem_w / 2, stem_top, cx + stem_w / 2, stem_bottom),
        stem_w * 0.4,
        ORANGE,
    )
    head = width * 0.30
    d.polygon(
        [
            (cx - head, stem_bottom - head * 0.15),
            (cx + head, stem_bottom - head * 0.15),
            (cx, stem_bottom + head * 0.85),
        ],
        fill=ORANGE,
    )


def background(size):
    """Charcoal with a warm glow behind the mark, so the tile is not flat."""
    img = Image.new("RGBA", (size, size), CHARCOAL + (255,))
    d = ImageDraw.Draw(img)
    steps = 26
    for i in range(steps, 0, -1):
        t = i / steps
        radius = size * 0.62 * t
        blend = (1 - t) * 0.5
        colour = tuple(
            int(CHARCOAL[c] + (ORANGE[c] - CHARCOAL[c]) * blend) for c in range(3)
        )
        d.ellipse(
            (
                size / 2 - radius,
                size / 2 - radius,
                size / 2 + radius,
                size / 2 + radius,
            ),
            fill=colour + (255,),
        )
    return img


def make_legacy(size):
    s = size * SUPERSAMPLE
    img = background(s)
    # Legacy icons are their own shape, so the mark can use more of the canvas.
    draw_cartridge(img, s, s / 2, s / 2, s * 0.52)
    return img.resize((size, size), Image.LANCZOS)


def make_foreground(size):
    s = size * SUPERSAMPLE
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    # 0.40 keeps the cartridge inside the 66% safe zone even under a circular
    # mask, which is what Cocoon and most launchers apply.
    draw_cartridge(img, s, s / 2, s / 2, s * 0.40)
    return img.resize((size, size), Image.LANCZOS)


def make_background(size):
    return background(size * SUPERSAMPLE).resize((size, size), Image.LANCZOS)


def write(img, folder, name):
    path = os.path.join(RES, folder, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    print("wrote", path)


def main():
    for density, size in LEGACY_SIZES.items():
        write(make_legacy(size), f"mipmap-{density}", "ic_launcher.png")
    for density, size in ADAPTIVE_SIZES.items():
        write(make_foreground(size), f"mipmap-{density}", "ic_launcher_foreground.png")
        write(make_background(size), f"mipmap-{density}", "ic_launcher_background.png")

    # A big one for the store screen's own header.
    os.makedirs("assets", exist_ok=True)
    make_legacy(512).save(os.path.join("assets", "icon.png"))
    print("wrote assets/icon.png")


if __name__ == "__main__":
    main()
