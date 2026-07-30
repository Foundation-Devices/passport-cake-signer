#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

from PIL import Image, ImageDraw

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "prime_visual_qa.py"
SPEC = importlib.util.spec_from_file_location("prime_visual_qa", MODULE_PATH)
assert SPEC and SPEC.loader
VISUAL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VISUAL
SPEC.loader.exec_module(VISUAL)


class PrimeVisualQaTests(unittest.TestCase):
    def test_rounded_card_passes(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((24, 130, 455, 285), radius=20, fill=VISUAL.CAKE_LIST_CARD)
        bounds = VISUAL.locate_surface(
            image,
            lambda pixel: VISUAL.near(pixel, VISUAL.CAKE_LIST_CARD, tolerance=2),
            min_height=70,
        )
        VISUAL.assert_rounded(
            image,
            bounds,
            lambda pixel: VISUAL.near(pixel, VISUAL.CAKE_LIST_CARD, tolerance=2),
            "Synthetic card",
        )

    def test_square_card_fails(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rectangle((24, 130, 455, 285), fill=VISUAL.CAKE_LIST_CARD)
        bounds = VISUAL.locate_surface(
            image,
            lambda pixel: VISUAL.near(pixel, VISUAL.CAKE_LIST_CARD, tolerance=2),
            min_height=70,
        )
        with self.assertRaises(VISUAL.VisualFailure):
            VISUAL.assert_rounded(
                image,
                bounds,
                lambda pixel: VISUAL.near(pixel, VISUAL.CAKE_LIST_CARD, tolerance=2),
                "Synthetic card",
            )

    def test_secondary_button_uses_a_roundable_solid_surface(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle(
            (24, 650, 455, 709),
            radius=12,
            fill=VISUAL.CAKE_SURFACE_CARD_SOLID,
        )
        predicate = lambda pixel: VISUAL.near(
            pixel,
            VISUAL.CAKE_SURFACE_CARD_SOLID,
            tolerance=2,
        )
        bounds = VISUAL.locate_surface(
            image,
            predicate,
            min_height=45,
            y_min=600,
        )
        VISUAL.assert_rounded(image, bounds, predicate, "Secondary action")

    def test_grouped_wallet_rows_are_checked_as_one_rounded_surface(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle(
            (24, 130, 455, 285),
            radius=20,
            fill=VISUAL.CAKE_LIST_CARD,
        )
        draw.rectangle((84, 207, 443, 208), fill=VISUAL.CAKE_DIVIDER)
        group_predicate = lambda pixel: (
            VISUAL.near(pixel, VISUAL.CAKE_LIST_CARD, tolerance=2)
            or VISUAL.near(pixel, VISUAL.CAKE_DIVIDER, tolerance=2)
        )
        card_predicate = lambda pixel: VISUAL.near(
            pixel,
            VISUAL.CAKE_LIST_CARD,
            tolerance=2,
        )
        bounds = VISUAL.locate_surface(
            image,
            group_predicate,
            min_height=70,
        )
        self.assertEqual(bounds.height, 156)
        VISUAL.assert_rounded(
            image,
            bounds,
            card_predicate,
            "Synthetic wallet group",
        )

    def test_separated_wallet_cards_are_independent_surfaces(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((24, 130, 455, 207), radius=20, fill=VISUAL.CAKE_LIST_CARD)
        draw.rounded_rectangle((24, 220, 455, 297), radius=20, fill=VISUAL.CAKE_LIST_CARD)
        surfaces = VISUAL.locate_surfaces(
            image,
            lambda pixel: VISUAL.near(pixel, VISUAL.CAKE_LIST_CARD, tolerance=2),
            min_height=60,
            max_row_gap=2,
        )
        self.assertEqual(
            surfaces,
            [
                VISUAL.Bounds(24, 130, 455, 207),
                VISUAL.Bounds(24, 220, 455, 297),
            ],
        )

    def test_wallet_list_layout_rejects_crowded_cards(self) -> None:
        cards = [
            VISUAL.Bounds(24, 130, 455, 207),
            VISUAL.Bounds(24, 212, 455, 289),
        ]
        with self.assertRaisesRegex(VISUAL.VisualFailure, "separated"):
            VISUAL.assert_wallet_list_layout(
                cards,
                VISUAL.Bounds(24, 600, 455, 659),
                VISUAL.Bounds(24, 672, 455, 731),
            )

    def test_detail_panel_spacing_rejects_old_cramped_rows(self) -> None:
        with self.assertRaisesRegex(VISUAL.VisualFailure, "too cramped"):
            VISUAL.assert_detail_panel_spacing(
                VISUAL.Bounds(24, 394, 455, 535),
                [
                    VISUAL.Bounds(24, 394, 455, 471),
                    VISUAL.Bounds(24, 473, 455, 535),
                ],
            )
        VISUAL.assert_detail_panel_spacing(
            VISUAL.Bounds(24, 394, 455, 551),
            [
                VISUAL.Bounds(24, 394, 455, 479),
                VISUAL.Bounds(24, 481, 455, 551),
            ],
        )

    def test_vivid_monero_card_with_shaded_inlay_passes(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        bounds = VISUAL.Bounds(24, 128, 455, 377)
        draw.rounded_rectangle(
            (bounds.left, bounds.top, bounds.right, bounds.bottom),
            radius=18,
            fill=VISUAL.CAKE_MONERO_CARD_SOLID,
        )
        draw.ellipse(
            (230, 140, 500, 410),
            outline=(0xF9, 0x73, 0x3E),
            width=18,
        )
        VISUAL.assert_monero_card_treatment(image, bounds)

    def test_overly_white_monero_inlay_fails(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        bounds = VISUAL.Bounds(24, 128, 455, 377)
        draw.rounded_rectangle(
            (bounds.left, bounds.top, bounds.right, bounds.bottom),
            radius=18,
            fill=VISUAL.CAKE_MONERO_CARD_SOLID,
        )
        draw.rectangle(
            (250, bounds.top + 8, bounds.right - 8, bounds.bottom - 8),
            fill=(0xFA, 0xE4, 0xD8),
        )
        with self.assertRaisesRegex(VISUAL.VisualFailure, "too white"):
            VISUAL.assert_monero_card_treatment(image, bounds)

    def test_wallet_detail_separates_wallet_and_account_identity(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "wallet-detail"
            / "page.slint"
        ).read_text(encoding="utf-8")
        self.assertIn("title: Callbacks.wallet-label;", source)
        self.assertIn('left-icon: "chevron-left";', source)
        self.assertIn('text: "Primary account";', source)
        self.assertIn('"Key generated on Passport"', source)
        self.assertIn('"Imported Key"', source)
        self.assertNotIn('"Created on Prime"', source)
        self.assertNotIn('"Recoverable from this device seed"', source)
        self.assertNotIn('"Key generated by Passport"', source)
        self.assertNotIn('name: root.archived ? "archive"', source)
        hero_start = source.index("component WalletHeroCard")
        primary_index = source.index('text: "Primary account";', hero_start)
        spacer_index = source.index("Rectangle { }", primary_index)
        provenance_index = source.index(
            'text: root.archived ? "Archived"',
            spacer_index,
        )
        self.assertLess(
            primary_index,
            spacer_index,
        )
        self.assertLess(spacer_index, provenance_index)
        hero_end = source.index("component CakeConnectionPanel", hero_start)
        self.assertNotIn("wallet-name", source[hero_start:hero_end])

    def test_seed_screen_gates_words_behind_warning_modal(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "seed"
            / "page.slint"
        ).read_text(encoding="utf-8")
        self.assertIn("property <bool> is-seed-warning-open: true;", source)
        self.assertIn("if is-seed-warning-open: Modal {", source)
        self.assertIn('title: "Keep your recovery seed private";', source)
        self.assertIn("text: TR2.lookup(TrId.SeedWarning);", source)
        self.assertIn('label: "I understand";', source)
        self.assertNotIn("CakeStatusBanner", source)
        self.assertNotIn("Showing seed for", source)

    def test_seed_word_cards_use_solid_clipped_surfaces(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "seed"
            / "page.slint"
        ).read_text(encoding="utf-8")
        component_start = source.index("component SeedWordItem")
        component_end = source.index("// Wallet recovery phrase", component_start)
        component = source[component_start:component_end]
        self.assertIn("background: Cake.wallet-list-card;", component)
        self.assertIn("border-radius: Cake.cta-radius;", component)
        self.assertIn("clip: true;", component)
        self.assertNotIn("background: Cake.surface-card;", component)

    def test_review_screen_uses_reliable_scroll_and_solid_surfaces(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "review"
            / "page.slint"
        ).read_text(encoding="utf-8")
        self.assertIn("ScrollBody {", source)
        self.assertNotIn("Flickable {", source)
        self.assertNotIn("background: Cake.monero-card-solid;", source)
        self.assertIn("background: Cake.surface-card-solid;", source)
        self.assertIn("HeadingXl {", source)
        self.assertIn("text: Callbacks.amount-xmr;", source)
        self.assertIn('text: "XMR";', source)
        scroll_start = source.index(
            "ScrollBody {", source.index("export component ReviewPagePage")
        )
        review_body = source[
            scroll_start:source.index("ButtonSection {", scroll_start)
        ]
        self.assertRegex(
            review_body,
            r"p-y: Size\.sz3;\s+VerticalLayout \{\s+if review-step == 0",
        )

    def test_review_paginates_full_addresses_before_signing(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "review"
            / "page.slint"
        ).read_text(encoding="utf-8")
        self.assertIn("property <int> review-step: 0;", source)
        self.assertIn("Step 1 of 2 - Recipients", source)
        self.assertIn("Step 2 of 2 - Transaction details", source)
        self.assertIn("for recipient[index] in Callbacks.dest-addresses", source)
        self.assertNotIn("Callbacks.dest-address-labels", source)
        self.assertIn('height: detail == "" ? 208px : 252px;', source)
        self.assertIn("padding-bottom: Size.sz5;", source)
        self.assertIn('if detail != "": Rectangle {', source)
        self.assertIn("height: Size.sz2;", source)
        self.assertIn("width: 152px;", source)
        self.assertIn('label: "Continue";', source)
        self.assertIn('label: "Back";', source)
        self.assertLess(
            source.index('label: "Continue";'),
            source.index("CakeSlideToSign {"),
        )

    def test_review_formats_addresses_in_contrasting_four_character_blocks(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "review"
            / "page.slint"
        ).read_text(encoding="utf-8")
        callbacks = (
            Path(__file__).parents[1] / "ui" / "callbacks.slint"
        ).read_text(encoding="utf-8")
        main = (
            Path(__file__).parents[1] / "src" / "main.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("component AddressBlockLine", source)
        self.assertIn(
            "Callbacks.format-address-row(address, row-index)", source
        )
        self.assertIn(
            "color: Math.mod(row-index * 6 + index, 2) == 0", source
        )
        self.assertEqual(source.count("AddressBlockLine { address: value;"), 4)
        self.assertIn("horizontal-stretch: 1;", source)
        self.assertIn("height: root.visible ? 36px : 0px;", source)
        self.assertIn(
            "pure callback format-address-row(string, int) -> [string];",
            callbacks,
        )
        self.assertIn("const CHARS_PER_BLOCK: usize = 4;", main)
        self.assertIn("const BLOCKS_PER_ROW: usize = 6;", main)
        self.assertIn("HeadingXl {", source)

    def test_ql_signing_has_progress_and_acknowledged_success_states(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "pages"
            / "review"
            / "page.slint"
        ).read_text(encoding="utf-8")
        callbacks = (
            Path(__file__).parents[1] / "ui" / "callbacks.slint"
        ).read_text(encoding="utf-8")
        main = (
            Path(__file__).parents[1] / "src" / "main.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("component SigningProgress", source)
        self.assertIn("component SigningSuccess", source)
        self.assertIn("if Callbacks.signing: SigningProgress", source)
        self.assertIn(
            "Callbacks.signed-ok && Callbacks.tx-via-quantum-link: SigningSuccess",
            source,
        )
        self.assertIn("component SigningProgress inherits BasePage", source)
        self.assertIn("component SigningSuccess inherits BasePage", source)
        progress_start = source.index("component SigningProgress")
        success_start = source.index("component SigningSuccess")
        progress = source[progress_start:success_start]
        success = source[
            success_start:source.index("export component ReviewPagePage")
        ]
        self.assertNotIn("TimerLoader", progress)
        self.assertIn("Keep both devices nearby", progress)
        self.assertGreaterEqual(
            progress.count("x: (parent.width - self.width) / 2;"), 2
        )
        self.assertIn("size: IconSize.px48;", progress)
        self.assertNotIn("WrappedIcon", success)
        self.assertIn(
            'source: @image-url("../../../assets/icons/birthday-cake.png");',
            success,
        )
        self.assertIn("x: (parent.width - self.width) / 2;", success)
        self.assertNotIn("CakeCard", success)
        cake_asset = (
            Path(__file__).parents[1]
            / "assets"
            / "icons"
            / "birthday-cake.png"
        )
        self.assertTrue(cake_asset.exists())
        self.assertEqual(cake_asset.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        self.assertIn(
            "The signed transaction was returned to Cake Wallet over QuantumLink.",
            source,
        )
        self.assertIn(
            "std::thread::sleep(std::time::Duration::from_millis(120));",
            main,
        )
        self.assertIn("Callbacks.finish-transaction-review();", source)
        self.assertIn("callback finish-transaction-review();", callbacks)
        success_index = main.index(
            'ui.global::<Callbacks>().set_signed_ok(true);'
        )
        signing_done_index = main.index(
            'ui.global::<Callbacks>().set_signing(false);', success_index
        )
        self.assertLess(success_index, signing_done_index)

    def test_review_uses_full_source_address(self) -> None:
        callbacks = (
            Path(__file__).parents[1] / "ui" / "callbacks.slint"
        ).read_text(encoding="utf-8")
        main = (
            Path(__file__).parents[1] / "src" / "main.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("// full source wallet address", callbacks)
        self.assertIn("cb.set_primary_address(address.clone().into());", main)
        self.assertNotIn("cb.set_primary_address(truncate(&address).into());", main)

    def test_review_actions_use_solid_rounded_surfaces_and_fixed_alignment(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "ui"
            / "cake-widgets.slint"
        ).read_text(encoding="utf-8")
        slider_start = source.index("export component CakeSlideToSign")
        slider = source[slider_start:]
        self.assertIn("border-radius: Cake.cta-radius;", slider)
        self.assertIn("background: Cake.surface-card-solid;", slider)
        self.assertIn("background: Cake.monero-card-solid;", slider)
        self.assertIn("width: 84px;", slider)
        self.assertIn("y: (parent.height - self.height) / 2 + 2px;", slider)
        self.assertNotIn("background: Cake.monero-card;", slider)

        button_start = source.index("export component CakeButton")
        button_end = source.index("export component CakeCard", button_start)
        button = source[button_start:button_end]
        self.assertIn("Cake.surface-card-pressed-solid", button)
        self.assertIn("Cake.surface-card-solid", button)
        self.assertNotIn("Cake.surface-card-pressed :", button)

    def test_text_sized_row_gaps_do_not_split_a_card_surface(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle(
            (24, 120, 455, 275),
            radius=20,
            fill=VISUAL.CAKE_LIST_CARD,
        )
        for top in (155, 233):
            draw.rectangle(
                (80, top, 319, top + 4),
                fill=(0xF2, 0xF5, 0xFD),
            )

        group_predicate = lambda pixel: VISUAL.near(
            pixel,
            VISUAL.CAKE_LIST_CARD,
            tolerance=2,
        )
        bounds = VISUAL.locate_surface(
            image,
            group_predicate,
            min_height=70,
        )
        self.assertEqual(bounds, VISUAL.Bounds(24, 120, 455, 275))

    def test_logo_sized_gaps_can_be_bridged_explicitly(self) -> None:
        image = Image.new("RGB", (480, 800), (0x1B, 0x28, 0x4A))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle(
            (24, 128, 455, 377),
            radius=20,
            fill=(0xE9, 0x4B, 0x17),
        )
        draw.rectangle((240, 262, 455, 275), fill=(0xF4, 0x98, 0x78))
        orange_predicate = lambda pixel: VISUAL.is_orange(pixel)

        with self.assertRaises(VISUAL.VisualFailure):
            VISUAL.locate_surface(
                image,
                orange_predicate,
                min_height=150,
            )

        bounds = VISUAL.locate_surface(
            image,
            orange_predicate,
            min_height=150,
            max_row_gap=16,
        )
        self.assertEqual(bounds, VISUAL.Bounds(24, 128, 455, 377))

    def test_screenshot_transport_is_retried(self) -> None:
        failure = VISUAL.subprocess.CalledProcessError(1, ["passport-drive"])
        with mock.patch.object(
            VISUAL.subprocess,
            "run",
            side_effect=[failure, None],
        ) as run:
            with mock.patch.object(VISUAL.time, "sleep"):
                VISUAL.driver_command(
                    Path("passport-drive"),
                    "screenshot",
                    "--output",
                    "/tmp/prime.png",
                )
        self.assertEqual(run.call_count, 2)

    def test_icon_alignment_uses_rendered_glyph_bounds(self) -> None:
        image = Image.new("RGB", (120, 90), VISUAL.CAKE_LIST_CARD)
        draw = ImageDraw.Draw(image)
        region = VISUAL.Bounds(80, 10, 110, 79)
        draw.rectangle((92, 40, 97, 49), fill=VISUAL.CAKE_ON_SURFACE_SOFT)
        VISUAL.assert_glyph_centered(
            image,
            region,
            [VISUAL.CAKE_ON_SURFACE_SOFT],
            44.5,
            "Centered icon",
        )

    def test_misaligned_icon_fails(self) -> None:
        image = Image.new("RGB", (120, 90), VISUAL.CAKE_LIST_CARD)
        draw = ImageDraw.Draw(image)
        region = VISUAL.Bounds(80, 10, 110, 79)
        draw.rectangle((92, 15, 97, 24), fill=VISUAL.CAKE_ON_SURFACE_SOFT)
        with self.assertRaisesRegex(
            VISUAL.VisualFailure,
            "vertically misaligned",
        ):
            VISUAL.assert_glyph_centered(
                image,
                region,
                [VISUAL.CAKE_ON_SURFACE_SOFT],
                44.5,
                "Misaligned icon",
            )

    def test_monero_network_icon_is_high_resolution_vector(self) -> None:
        asset = Path(__file__).parents[1] / "assets" / "icons" / "monero-network.svg"
        source = asset.read_text(encoding="utf-8")
        self.assertIn("<svg", source)
        self.assertIn('viewBox="0 0 250 250"', source)
        self.assertIn("<linearGradient", source)


if __name__ == "__main__":
    unittest.main()
