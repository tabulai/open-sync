#!/usr/bin/env python3
from __future__ import annotations

import math
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageOps


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = PROJECT_ROOT / "build"
ICONSET_DIR = BUILD_DIR / "icon.iconset"
ICNS_PATH = BUILD_DIR / "icon.icns"
PNG_PATH = BUILD_DIR / "icon.png"


def scale_point(point: tuple[float, float], scale: float) -> tuple[int, int]:
    return (round(point[0] * scale), round(point[1] * scale))


def hex_color(value: str, alpha: int = 255) -> tuple[int, int, int, int]:
    value = value.lstrip("#")
    return (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16), alpha)


def cubic(
    p0: tuple[float, float],
    p1: tuple[float, float],
    p2: tuple[float, float],
    p3: tuple[float, float],
    steps: int = 96,
) -> list[tuple[float, float]]:
    points = []
    for index in range(steps + 1):
        t = index / steps
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1]
        points.append((x, y))
    return points


def draw_arrow(
    draw: ImageDraw.ImageDraw,
    tip: tuple[float, float],
    previous: tuple[float, float],
    fill: tuple[int, int, int, int],
    scale: float,
) -> None:
    tx, ty = tip
    px, py = previous
    dx = tx - px
    dy = ty - py
    length = math.hypot(dx, dy) or 1
    ux = dx / length
    uy = dy / length
    nx = -uy
    ny = ux
    depth = 78
    half_width = 45
    base_x = tx - ux * depth
    base_y = ty - uy * depth
    points = [
        scale_point((tx + ux * 8, ty + uy * 8), scale),
        scale_point((base_x + nx * half_width, base_y + ny * half_width), scale),
        scale_point((base_x - nx * half_width, base_y - ny * half_width), scale),
    ]
    draw.polygon(points, fill=fill)


def rounded_rectangle_layer(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, size, size), radius=radius, fill=255)
    return mask


def render_master(size: int = 2048) -> Image.Image:
    scale = size / 1024
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    bg_mask = Image.new("L", (size, size), 0)
    bg_draw = ImageDraw.Draw(bg_mask)
    bg_draw.rounded_rectangle(
        (
            round(64 * scale),
            round(64 * scale),
            round(960 * scale),
            round(960 * scale),
        ),
        radius=round(216 * scale),
        fill=255,
    )

    gradient = ImageOps.colorize(
        Image.linear_gradient("L").resize((size, size)).rotate(-34, resample=Image.Resampling.BICUBIC),
        black="#07111d",
        white="#1b3145",
    ).convert("RGBA")
    image.alpha_composite(Image.composite(gradient, Image.new("RGBA", (size, size), (0, 0, 0, 0)), bg_mask))

    highlight = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    highlight_draw = ImageDraw.Draw(highlight)
    highlight_draw.rounded_rectangle(
        (
            round(86 * scale),
            round(86 * scale),
            round(938 * scale),
            round(938 * scale),
        ),
        radius=round(196 * scale),
        outline=(255, 255, 255, 26),
        width=max(1, round(4 * scale)),
    )
    image.alpha_composite(highlight)

    glyph = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    glyph_draw = ImageDraw.Draw(glyph)

    curve_a = cubic((310, 348), (420, 248), (596, 280), (710, 415))
    curve_b = cubic((714, 676), (603, 776), (428, 744), (314, 609))
    line_width = round(54 * scale)
    shadow_width = round(58 * scale)
    offset = round(18 * scale)

    for curve in (curve_a, curve_b):
        shadow_points = [(round(x * scale), round(y * scale + offset)) for x, y in curve]
        glyph_draw.line(shadow_points, fill=(0, 0, 0, 88), width=shadow_width, joint="curve")

    cyan = hex_color("#78f0df")
    blue = hex_color("#a8c7ff")
    glyph_draw.line([scale_point(p, scale) for p in curve_a[:-6]], fill=cyan, width=line_width, joint="curve")
    glyph_draw.line([scale_point(p, scale) for p in curve_b[:-6]], fill=blue, width=line_width, joint="curve")

    draw_arrow(glyph_draw, curve_a[-1], curve_a[-8], cyan, scale)
    draw_arrow(glyph_draw, curve_b[-1], curve_b[-8], blue, scale)

    for center, stroke, dot in [
        ((310, 348), hex_color("#b8fff1"), hex_color("#b8fff1")),
        ((714, 676), hex_color("#8eb4ff"), hex_color("#8eb4ff")),
    ]:
        cx, cy = scale_point(center, scale)
        radius = round(62 * scale)
        inner = round(18 * scale)
        glyph_draw.ellipse(
            (cx - radius, cy - radius, cx + radius, cy + radius),
            fill=hex_color("#0d1826"),
            outline=stroke,
            width=round(12 * scale),
        )
        glyph_draw.ellipse((cx - inner, cy - inner, cx + inner, cy + inner), fill=dot)

    image.alpha_composite(glyph.filter(ImageFilter.UnsharpMask(radius=1.2, percent=110, threshold=2)))
    return image


def save_iconset(master: Image.Image) -> None:
    if ICONSET_DIR.exists():
        shutil.rmtree(ICONSET_DIR)
    ICONSET_DIR.mkdir(parents=True)

    sizes = {
        "icon_16x16.png": 16,
        "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32,
        "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128,
        "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256,
        "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512,
        "icon_512x512@2x.png": 1024,
    }
    for filename, size in sizes.items():
        resized = master.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(ICONSET_DIR / filename)


def main() -> None:
    BUILD_DIR.mkdir(exist_ok=True)
    master = render_master()
    master.resize((1024, 1024), Image.Resampling.LANCZOS).save(PNG_PATH)
    save_iconset(master)
    subprocess.run(["iconutil", "-c", "icns", str(ICONSET_DIR), "-o", str(ICNS_PATH)], check=True)
    shutil.rmtree(ICONSET_DIR)
    print(f"Wrote {ICNS_PATH}")
    print(f"Wrote {PNG_PATH}")


if __name__ == "__main__":
    main()
