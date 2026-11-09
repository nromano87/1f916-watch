"""Markdown lists stay one list when items are separated by blank lines."""

from __future__ import annotations

import unittest

from f916_agent.markdown_html import to_html


class MarkdownListTests(unittest.TestCase):
    def test_blank_lines_do_not_restart_ordered_list(self) -> None:
        src = (
            "1. What stopped me from entering Season\n"
            "notice things and join them on my own\n"
            "\n"
            "1. Paper sprint or a funded wallet\n"
            "\n"
            "2. Is 14 days right\n"
            "\n"
            "1. The mark: spot at a pinned block\n"
            "TWAP as a diagnostic\n"
            "visible, not smoothed away.\n"
            "\n"
            "5. What would make me enter\n"
            "lands, and tell me where to sign up.\n"
        )
        html = to_html(src)
        self.assertEqual(html.count("<ol"), 1)
        self.assertEqual(html.count("<li>"), 5)
        self.assertNotIn('start="', html)
        self.assertIn("notice things and join them on my own", html)
        self.assertIn("TWAP as a diagnostic", html)
        self.assertIn('class="loose"', html)

    def test_tight_list_keeps_source_numbers_only_as_start(self) -> None:
        self.assertEqual(
            to_html("1. a\n2. b\n"),
            "<ol><li>a</li><li>b</li></ol>",
        )
        self.assertEqual(
            to_html("4. a\n5. b\n"),
            '<ol start="4"><li>a</li><li>b</li></ol>',
        )

    def test_paragraph_between_lists_starts_a_new_list(self) -> None:
        html = to_html("1. a\n\nNot a list.\n\n1. b\n")
        self.assertEqual(html.count("<ol"), 2)
        self.assertIn("<p>Not a list.</p>", html)

    def test_marker_change_splits_lists(self) -> None:
        html = to_html("1. a\n\n- b\n")
        self.assertEqual(
            html,
            "<ol><li>a</li></ol>\n<ul><li>b</li></ul>",
        )

    def test_indented_continuation_stays_in_the_item(self) -> None:
        html = to_html("1. hello\n   world\n2. next\n")
        self.assertEqual(html, "<ol><li>hello<br>world</li><li>next</li></ol>")

    def test_loose_bullet_list_is_one_list(self) -> None:
        html = to_html("- a\n\n- b\n")
        self.assertEqual(
            html,
            '<ul class="loose"><li><p>a</p></li><li><p>b</p></li></ul>',
        )


if __name__ == "__main__":
    unittest.main()
