"""Draw the MailTrace application icon: a classic-style envelope tile with a large magnifying glass.

The artwork is original. It evokes the look of an older mail-client icon (blue tile,
white envelope with a letter badge) rather than copying any vendor's trademarked
icon. Run: ``python assets/make_icon.py`` -> assets/mailtrace.ico + mailtrace.png
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
SIZES = (16, 24, 32, 48, 64, 128, 256)


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def draw_icon(size: int = 256) -> Image.Image:
    s = 4  # supersample for smooth edges
    W = size * s
    img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    u = W / 256.0  # unit: design on a 256 grid

    # --- blue tile with a subtle vertical gradient (classic mail-client look)
    tile = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    td = ImageDraw.Draw(tile)
    top, bottom = (28, 96, 176), (12, 58, 122)
    for y in range(W):
        t = y / W
        c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,)
        td.line([(0, y), (W, y)], fill=c)
    mask = Image.new("L", (W, W), 0)
    ImageDraw.Draw(mask).rounded_rectangle([12 * u, 12 * u, 244 * u, 244 * u], radius=44 * u, fill=255)
    img.paste(tile, (0, 0), mask)

    # --- white envelope
    ex0, ey0, ex1, ey1 = 44 * u, 76 * u, 212 * u, 186 * u
    d.rounded_rectangle(
        [ex0, ey0, ex1, ey1],
        radius=10 * u,
        fill=(250, 251, 253, 255),
        outline=(200, 210, 224, 255),
        width=int(2 * u),
    )
    # flap (V) and back fold lines
    mx, my = (ex0 + ex1) / 2, ey0 + (ey1 - ey0) * 0.58
    d.line(
        [(ex0 + 3 * u, ey0 + 4 * u), (mx, my), (ex1 - 3 * u, ey0 + 4 * u)],
        fill=(176, 190, 210, 255),
        width=int(7 * u),
        joint="curve",
    )
    d.line(
        [(ex0 + 3 * u, ey1 - 4 * u), (ex0 + 62 * u, my - 4 * u)], fill=(214, 222, 234, 255), width=int(5 * u)
    )
    d.line(
        [(ex1 - 3 * u, ey1 - 4 * u), (ex1 - 62 * u, my - 4 * u)], fill=(214, 222, 234, 255), width=int(5 * u)
    )
    # yellow letter badge peeking out (old-style "O" stamp)
    d.rounded_rectangle(
        [ex0 + 12 * u, ey0 - 14 * u, ex0 + 74 * u, ey0 + 34 * u],
        radius=8 * u,
        fill=(255, 196, 37, 255),
        outline=(214, 150, 0, 255),
        width=int(2 * u),
    )
    f = _font(int(40 * u))
    d.text((ex0 + 43 * u, ey0 + 10 * u), "O", font=f, fill=(20, 60, 120, 255), anchor="mm")

    # --- large magnifying glass over the lower-right, covering much of the tile
    cx, cy, r = 150 * u, 150 * u, 66 * u
    # handle
    hx0, hy0 = cx + r * 0.62, cy + r * 0.62
    hx1, hy1 = 236 * u, 236 * u
    d.line([(hx0, hy0), (hx1, hy1)], fill=(52, 58, 70, 255), width=int(30 * u))
    d.ellipse([hx1 - 15 * u, hy1 - 15 * u, hx1 + 15 * u, hy1 + 15 * u], fill=(52, 58, 70, 255))
    # rim + lens (translucent so the envelope shows through)
    d.ellipse(
        [cx - r, cy - r, cx + r, cy + r],
        fill=(160, 210, 255, 90),
        outline=(52, 58, 70, 255),
        width=int(16 * u),
    )
    d.ellipse(
        [cx - r + 12 * u, cy - r + 12 * u, cx + r - 12 * u, cy + r - 12 * u],
        outline=(255, 255, 255, 120),
        width=int(4 * u),
    )
    # glint
    d.arc(
        [cx - r + 22 * u, cy - r + 22 * u, cx + r - 22 * u, cy + r - 22 * u],
        start=200,
        end=250,
        fill=(255, 255, 255, 220),
        width=int(8 * u),
    )

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    base = draw_icon(256)
    base.save(HERE / "mailtrace.png")
    frames = [draw_icon(sz) for sz in SIZES]
    frames[-1].save(
        HERE / "mailtrace.ico", format="ICO", sizes=[(sz, sz) for sz in SIZES], append_images=frames[:-1]
    )
    print("wrote", HERE / "mailtrace.ico", "and mailtrace.png")


if __name__ == "__main__":
    main()
