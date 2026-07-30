#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Physical Passport Prime visual regression checks for the Cake signer."""

from __future__ import annotations

import argparse
import math
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageChops

PRIME_SIZE = (480, 800)
STATUS_BAR_HEIGHT = 48
CAKE_LIST_CARD = (0x23, 0x31, 0x56)
CAKE_DIVIDER = (0x2A, 0x3E, 0x73)
CAKE_BLUE = (0x91, 0xB0, 0xFF)
CAKE_SURFACE_CARD_SOLID = (0x2B, 0x3A, 0x67)
CAKE_MONERO_CARD_SOLID = (0xF4, 0x51, 0x0C)
CAKE_BLUE_SOFT = (0xA1, 0xB9, 0xFF)
CAKE_ON_SURFACE_SOFT = (0xBA, 0xCB, 0xFF)
CAKE_SUCCESS = (0x12, 0xA4, 0x39)
PRIME_ICON_LIGHT = (0xD7, 0xE2, 0xF7)
PRIME_ICON_MUTED = (0xB3, 0xBE, 0xD5)


class VisualFailure(AssertionError):
    pass


@dataclass(frozen=True)
class Bounds:
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return self.right - self.left + 1

    @property
    def height(self) -> int:
        return self.bottom - self.top + 1

    @property
    def center_y(self) -> float:
        return (self.top + self.bottom) / 2


def near(pixel: tuple[int, ...], target: tuple[int, int, int], tolerance: int = 10) -> bool:
    return sum((int(pixel[i]) - target[i]) ** 2 for i in range(3)) <= tolerance**2


def is_orange(pixel: tuple[int, ...]) -> bool:
    red, green, blue = pixel[:3]
    return red >= 175 and 45 <= green <= 125 and blue <= 75


def contiguous_ranges(
    values: list[int],
    *,
    max_gap: int = 0,
) -> list[tuple[int, int]]:
    if not values:
        return []
    ranges: list[tuple[int, int]] = []
    start = previous = values[0]
    for value in values[1:]:
        if value - previous - 1 > max_gap:
            ranges.append((start, previous))
            start = value
        previous = value
    ranges.append((start, previous))
    return ranges


def locate_surfaces(
    image: Image.Image,
    predicate,
    *,
    min_width: int = 280,
    min_height: int = 45,
    y_min: int = 90,
    y_max: int | None = None,
    max_row_gap: int = 6,
) -> list[Bounds]:
    rgb = image.convert("RGB")
    active_rows: list[int] = []
    row_extents: dict[int, tuple[int, int]] = {}
    for y in range(y_min, min(rgb.height, y_max or rgb.height)):
        xs = [x for x in range(rgb.width) if predicate(rgb.getpixel((x, y)))]
        if len(xs) >= min_width:
            active_rows.append(y)
            row_extents[y] = (min(xs), max(xs))

    candidates = [
        (top, bottom)
        for top, bottom in contiguous_ranges(active_rows, max_gap=max_row_gap)
        if bottom - top + 1 >= min_height
    ]
    if not candidates:
        return []

    surfaces = []
    for top, bottom in candidates:
        middle_rows = range(
            top + (bottom - top) // 3,
            top + 2 * (bottom - top) // 3 + 1,
        )
        extents = [row_extents[y] for y in middle_rows if y in row_extents]
        if not extents:
            continue
        surfaces.append(
            Bounds(
                min(item[0] for item in extents),
                top,
                max(item[1] for item in extents),
                bottom,
            )
        )
    return surfaces


def locate_surface(
    image: Image.Image,
    predicate,
    *,
    min_width: int = 280,
    min_height: int = 45,
    y_min: int = 90,
    y_max: int | None = None,
    max_row_gap: int = 6,
) -> Bounds:
    surfaces = locate_surfaces(
        image,
        predicate,
        min_width=min_width,
        min_height=min_height,
        y_min=y_min,
        y_max=y_max,
        max_row_gap=max_row_gap,
    )
    if not surfaces:
        raise VisualFailure("No expected wide card surface was found")
    return max(surfaces, key=lambda bounds: bounds.height)


def assert_rounded(image: Image.Image, bounds: Bounds, predicate, label: str) -> None:
    rgb = image.convert("RGB")
    radius = min(18, max(8, bounds.height // 5))
    points_that_must_be_clear = [
        (bounds.left, bounds.top),
        (bounds.right, bounds.top),
        (bounds.left, bounds.bottom),
        (bounds.right, bounds.bottom),
    ]
    points_that_must_be_filled = [
        ((bounds.left + bounds.right) // 2, bounds.top + 1),
        (bounds.left + radius, bounds.top + 2),
        (bounds.right - radius, bounds.top + 2),
        (bounds.left + 2, bounds.top + radius),
        (bounds.right - 2, bounds.top + radius),
    ]
    if any(predicate(rgb.getpixel(point)) for point in points_that_must_be_clear):
        raise VisualFailure(f"{label} has square or protruding outer corners")
    if not all(predicate(rgb.getpixel(point)) for point in points_that_must_be_filled):
        raise VisualFailure(f"{label} rounding clips too much of the card surface")

    middle_y = (bounds.top + bounds.bottom) // 2
    for x in (bounds.left - 2, bounds.right + 2):
        if 0 <= x < rgb.width and predicate(rgb.getpixel((x, middle_y))):
            raise VisualFailure(f"{label} has pixels protruding outside its side edge")


def locate_colored_glyph(
    image: Image.Image,
    region: Bounds,
    targets: list[tuple[int, int, int]],
    *,
    tolerance: int = 24,
    min_pixels: int = 6,
) -> Bounds:
    rgb = image.convert("RGB")
    points = [
        (x, y)
        for y in range(region.top, region.bottom + 1)
        for x in range(region.left, region.right + 1)
        if any(near(rgb.getpixel((x, y)), target, tolerance) for target in targets)
    ]
    if len(points) < min_pixels:
        raise VisualFailure("Expected icon pixels were not found")
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    return Bounds(min(xs), min(ys), max(xs), max(ys))


def locate_predicate_glyph(
    image: Image.Image,
    region: Bounds,
    predicate,
    *,
    min_pixels: int = 6,
) -> Bounds:
    rgb = image.convert("RGB")
    points = [
        (x, y)
        for y in range(region.top, region.bottom + 1)
        for x in range(region.left, region.right + 1)
        if predicate(rgb.getpixel((x, y)))
    ]
    if len(points) < min_pixels:
        raise VisualFailure("Expected image pixels were not found")
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    return Bounds(min(xs), min(ys), max(xs), max(ys))


def assert_glyph_centered(
    image: Image.Image,
    region: Bounds,
    targets: list[tuple[int, int, int]],
    expected_y: float,
    label: str,
    *,
    tolerance: float = 3.0,
) -> Bounds:
    try:
        glyph = locate_colored_glyph(image, region, targets)
    except VisualFailure as error:
        raise VisualFailure(f"{label}: {error}") from error
    offset = glyph.center_y - expected_y
    if abs(offset) > tolerance:
        raise VisualFailure(
            f"{label} is vertically misaligned by {offset:+.1f}px"
        )
    return glyph


def row_bounds(bounds: Bounds, divider_rows: list[int]) -> list[Bounds]:
    dividers = [
        round((top + bottom) / 2)
        for top, bottom in contiguous_ranges(divider_rows, max_gap=1)
    ]
    rows: list[Bounds] = []
    top = bounds.top
    for divider in dividers:
        rows.append(Bounds(bounds.left, top, bounds.right, divider - 1))
        top = divider + 1
    rows.append(Bounds(bounds.left, top, bounds.right, bounds.bottom))
    return rows


def assert_wallet_list_layout(
    cards: list[Bounds],
    secondary_cta: Bounds,
    primary_cta: Bounds,
) -> None:
    if not cards:
        raise VisualFailure("No wallet cards were found")
    for previous, current in zip(cards, cards[1:]):
        gap = current.top - previous.bottom - 1
        if gap < 8:
            raise VisualFailure(f"Wallet cards are separated by only {gap}px")
    if secondary_cta.top - cards[-1].bottom < 24:
        raise VisualFailure("Bottom actions overlap or crowd the wallet list")
    if primary_cta.top <= secondary_cta.bottom:
        raise VisualFailure("Create New Wallet must sit below Restore Wallet")
    if primary_cta.bottom > PRIME_SIZE[1] - 8:
        raise VisualFailure("Primary wallet action is clipped by the screen edge")


def assert_detail_panel_spacing(panel: Bounds, rows: list[Bounds]) -> None:
    if panel.height < 150:
        raise VisualFailure("Cake connection panel is too cramped")
    if len(rows) != 2:
        raise VisualFailure("Cake connection panel must contain exactly two rows")
    for label, row, minimum in zip(
        ("Connection", "Guidance"),
        rows,
        (84, 68),
    ):
        if row.height < minimum:
            raise VisualFailure(
                f"{label} row is only {row.height}px high; text needs more vertical space"
            )


def assert_monero_card_treatment(image: Image.Image, card: Bounds) -> None:
    rgb = image.convert("RGB")
    inset = Bounds(card.left + 8, card.top + 8, card.right - 8, card.bottom - 8)
    pixels = [
        rgb.getpixel((x, y))
        for y in range(inset.top, inset.bottom + 1)
        for x in range(inset.left, inset.right + 1)
    ]
    vivid = sum(
        near(pixel, CAKE_MONERO_CARD_SOLID, tolerance=32)
        for pixel in pixels
    )
    if vivid / len(pixels) < 0.35:
        raise VisualFailure("Monero wallet card is not using the vivid Cake orange")

    near_white = sum(
        pixel[0] >= 235 and pixel[1] >= 185 and pixel[2] >= 150
        for pixel in pixels
    )
    if near_white / len(pixels) > 0.08:
        raise VisualFailure("Monero inlay is too white instead of softly shaded")


def ocr_text(path: Path) -> str:
    if shutil.which("tesseract") is None:
        raise VisualFailure("tesseract is required for Prime visual text checks")
    resolved_path = path.resolve()
    result = subprocess.run(
        ["tesseract", str(resolved_path), "stdout", "--psm", "6"],
        check=True,
        capture_output=True,
        text=True,
    )
    return " ".join(result.stdout.lower().split())


def assert_text(path: Path, expected: list[str]) -> None:
    text = ocr_text(path)
    for value in expected:
        if " ".join(value.lower().split()) not in text:
            raise VisualFailure(f"Expected visible text {value!r}; OCR saw: {text!r}")


def assert_text_absent(path: Path, unexpected: list[str]) -> None:
    text = ocr_text(path)
    for value in unexpected:
        if " ".join(value.lower().split()) in text:
            raise VisualFailure(f"Unexpected visible text {value!r}; OCR saw: {text!r}")


def assert_text_in_region(
    path: Path,
    region: Bounds,
    expected: list[str],
    *,
    threshold: int = 110,
) -> None:
    image = Image.open(path).convert("L").crop(
        (region.left, region.top, region.right + 1, region.bottom + 1)
    )
    image = image.point(lambda value: 255 if value > threshold else 0)
    with tempfile.NamedTemporaryFile(suffix=".png") as temporary:
        image.save(temporary.name)
        assert_text(Path(temporary.name), expected)


def check_wallet_list(path: Path, expected: list[str]) -> Bounds:
    image = Image.open(path)
    if image.size != PRIME_SIZE:
        raise VisualFailure(f"Expected a 480x800 Prime screenshot, got {image.size}")
    card_predicate = lambda pixel: near(pixel, CAKE_LIST_CARD, tolerance=14)
    cards = locate_surfaces(
        image,
        card_predicate,
        min_height=60,
        y_min=100,
        y_max=520,
        max_row_gap=6,
    )
    if not cards:
        raise VisualFailure("No independent wallet cards were found")
    for index, card in enumerate(cards, start=1):
        assert_rounded(image, card, card_predicate, f"Wallet card {index}")
        assert_glyph_centered(
            image,
            Bounds(card.right - 48, card.top, card.right, card.bottom),
            [CAKE_ON_SURFACE_SOFT],
            card.center_y,
            f"Wallet row {index} chevron",
        )
        network_icon = locate_predicate_glyph(
            image,
            Bounds(card.left + 12, card.top, card.left + 68, card.bottom),
            is_orange,
            min_pixels=120,
        )
        if network_icon.width < 30 or network_icon.height < 30:
            raise VisualFailure(
                f"Wallet row {index} Monero network icon renders too small"
            )

    secondary_predicate = lambda pixel: near(
        pixel, CAKE_SURFACE_CARD_SOLID, tolerance=14
    )
    secondary_cta = locate_surface(
        image,
        secondary_predicate,
        min_width=340,
        min_height=35,
        y_min=520,
        max_row_gap=6,
    )
    primary_predicate = lambda pixel: near(pixel, CAKE_BLUE, tolerance=16)
    primary_cta = locate_surface(
        image,
        primary_predicate,
        min_width=340,
        min_height=45,
        y_min=600,
        max_row_gap=16,
    )
    assert_rounded(image, secondary_cta, secondary_predicate, "Restore wallet action")
    assert_rounded(image, primary_cta, primary_predicate, "Create wallet action")
    assert_wallet_list_layout(cards, secondary_cta, primary_cta)
    assert_text(
        path,
        ["Wallets", "Monero Wallets", "Restore Wallet", "Create New Wallet", *expected],
    )
    return cards[0]


def check_wallet_detail(path: Path, expected: list[str]) -> tuple[Bounds, Bounds]:
    image = Image.open(path)
    if image.size != PRIME_SIZE:
        raise VisualFailure(f"Expected a 480x800 Prime screenshot, got {image.size}")

    header_icon_colors = [
        PRIME_ICON_LIGHT,
        PRIME_ICON_MUTED,
    ]
    assert_glyph_centered(
        image,
        Bounds(8, STATUS_BAR_HEIGHT, 76, 112),
        header_icon_colors,
        72,
        "Wallet detail back icon",
        tolerance=5,
    )
    assert_glyph_centered(
        image,
        Bounds(404, STATUS_BAR_HEIGHT, 471, 112),
        header_icon_colors,
        72,
        "Wallet detail menu icon",
        tolerance=5,
    )

    orange = locate_surface(
        image,
        is_orange,
        min_height=150,
        max_row_gap=16,
    )
    assert_rounded(image, orange, is_orange, "Monero wallet card")
    assert_monero_card_treatment(image, orange)

    panel_predicate = lambda pixel: near(pixel, CAKE_LIST_CARD, tolerance=14)
    panel = locate_surface(
        image,
        panel_predicate,
        min_height=90,
        y_min=orange.bottom + 12,
        max_row_gap=14,
    )
    assert_rounded(image, panel, panel_predicate, "Cake connection panel")
    if panel.top <= orange.bottom:
        raise VisualFailure("Cake connection panel overlaps the Monero wallet card")

    rgb = image.convert("RGB")
    divider_rows = []
    for y in range(panel.top + 30, panel.bottom - 20):
        count = sum(
            near(rgb.getpixel((x, y)), CAKE_DIVIDER, tolerance=14)
            for x in range(panel.left + 12, panel.right - 12)
        )
        if count >= 180:
            divider_rows.append(y)
    rows = row_bounds(panel, divider_rows)
    assert_detail_panel_spacing(panel, rows)
    for label, row, colors in zip(
        ("Bluetooth", "Status"),
        rows,
        (
            [CAKE_SUCCESS],
            [CAKE_SUCCESS],
        ),
    ):
        assert_glyph_centered(
            image,
            Bounds(panel.left + 12, row.top, panel.left + 60, row.bottom),
            colors,
            row.center_y,
            f"{label} icon",
        )
    assert_text(path, ["Cake Wallet", *expected])
    card_top_region = Bounds(
        orange.left,
        orange.top,
        min(orange.right, orange.left + 320),
        min(orange.bottom, orange.top + 90),
    )
    assert_text_in_region(
        path,
        card_top_region,
        ["Primary account"],
    )
    card_bottom_region = Bounds(
        orange.left,
        max(orange.top, orange.bottom - 90),
        min(orange.right, orange.left + 320),
        orange.bottom,
    )
    assert_text_in_region(
        path,
        card_bottom_region,
        ["Key generated on Passport"],
    )
    assert_text_absent(
        path,
        [
            "Created on Prime",
            "Recoverable from this device seed",
            "Key generated by Passport",
        ],
    )
    return orange, panel


def compare_baseline(actual_path: Path, baseline_path: Path) -> None:
    if not baseline_path.exists():
        raise VisualFailure(f"Visual baseline is missing: {baseline_path}")
    actual = Image.open(actual_path).convert("RGB")
    baseline = Image.open(baseline_path).convert("RGB")
    if actual.size != baseline.size:
        raise VisualFailure("Visual baseline dimensions changed")

    actual.paste((0, 0, 0), (0, 0, actual.width, STATUS_BAR_HEIGHT))
    baseline.paste((0, 0, 0), (0, 0, baseline.width, STATUS_BAR_HEIGHT))
    difference = ImageChops.difference(actual, baseline)
    histogram = difference.histogram()
    squared = sum((index % 256) ** 2 * count for index, count in enumerate(histogram))
    rms = math.sqrt(squared / (actual.width * actual.height * 3))
    pixels = (
        difference.get_flattened_data()
        if hasattr(difference, "get_flattened_data")
        else difference.getdata()
    )
    changed = sum(1 for pixel in pixels if max(pixel) > 18)
    changed_fraction = changed / (actual.width * actual.height)
    if rms > 9.0 or changed_fraction > 0.035:
        raise VisualFailure(
            f"Visual baseline changed: rms={rms:.2f}, changed={changed_fraction:.2%}"
        )


def driver_command(driver: Path, *arguments: str) -> None:
    attempts = 3 if arguments and arguments[0] == "screenshot" else 1
    for attempt in range(attempts):
        try:
            subprocess.run([str(driver), *arguments], check=True)
            return
        except subprocess.CalledProcessError:
            if attempt + 1 == attempts:
                raise
            time.sleep(0.4)


def capture_suite(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    list_path = output / "wallet-list.png"
    detail_path = output / "wallet-detail.png"

    driver_command(args.driver, "screenshot", "--output", str(list_path))
    wallet_names = args.wallet_name or ["Passport Prime"]
    list_bounds = check_wallet_list(list_path, wallet_names)
    first_row_y = list_bounds.top + min(39, list_bounds.height // 2)
    driver_command(args.driver, "tap", "240", str(first_row_y))
    time.sleep(args.wait)
    driver_command(args.driver, "screenshot", "--output", str(detail_path))
    check_wallet_detail(detail_path, args.detail_text)

    baseline_dir = args.baseline_dir.resolve()
    if args.update_baselines:
        baseline_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(list_path, baseline_dir / list_path.name)
        shutil.copy2(detail_path, baseline_dir / detail_path.name)
    else:
        compare_baseline(list_path, baseline_dir / list_path.name)
        compare_baseline(detail_path, baseline_dir / detail_path.name)

    driver_command(args.driver, "tap", "48", "88")
    print(f"Prime visual QA passed. Artifacts: {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="check one existing screenshot")
    check.add_argument("screen", choices=("wallet-list", "wallet-detail"))
    check.add_argument("image", type=Path)
    check.add_argument("--expect-text", action="append", default=[])
    check.add_argument("--baseline", type=Path)

    capture = subparsers.add_parser(
        "capture-suite",
        help="capture wallet list/detail from a connected, unlocked Prime",
    )
    capture.add_argument(
        "--driver",
        type=Path,
        default=Path("target/debug/passport-drive"),
    )
    capture.add_argument("--output", type=Path, default=Path("/tmp/prime-cake-visual"))
    capture.add_argument(
        "--baseline-dir",
        type=Path,
        default=Path("apps/gui-app-cake-signer/tests/visual/baselines"),
    )
    capture.add_argument("--wallet-name", action="append", default=[])
    capture.add_argument("--detail-text", action="append", default=[])
    capture.add_argument("--wait", type=float, default=1.0)
    capture.add_argument("--update-baselines", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "check":
            if args.screen == "wallet-list":
                check_wallet_list(args.image, args.expect_text)
            else:
                check_wallet_detail(args.image, args.expect_text)
            if args.baseline:
                compare_baseline(args.image, args.baseline)
            print(f"Prime visual QA passed: {args.image}")
        else:
            capture_suite(args)
        return 0
    except (OSError, subprocess.CalledProcessError, VisualFailure) as error:
        print(f"Prime visual QA failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
