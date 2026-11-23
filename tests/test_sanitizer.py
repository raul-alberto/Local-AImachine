"""Regression tests for the reply sanitizer and RAG citation escaping.

These cover the HTML paths that reach innerHTML in the browser:
AI replies rendered from stored chat history, freshly formatted Markdown
replies, and the sources block appended to them. Run with:

    python -m pytest
"""

import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import (  # noqa: E402  (path bootstrap must run first)
    format_ai_response,
    normalize_chats,
    sanitize_chat_history,
    sanitize_reply_html,
)

# Mirrors ALLOWED_REPLY_TAGS in app.py.
ALLOWED_TAGS = {
    "a", "blockquote", "br", "code", "em", "h1", "h2", "h3", "h4", "h5",
    "h6", "hr", "li", "ol", "p", "pre", "strong", "table", "tbody", "td",
    "th", "thead", "tr", "ul",
}
DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:")


class _MarkupInspector(HTMLParser):
    """Collect the tags and attributes an HTML string actually contains."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_startendtag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


def inspect(html):
    parser = _MarkupInspector()
    parser.feed(html)
    parser.close()
    return parser


def assert_inert(html):
    """Fail if the markup can run script: unknown tags, on* handlers, bad URLs."""
    parser = inspect(html)
    assert set(parser.tags) <= ALLOWED_TAGS, f"unexpected tags: {parser.tags!r}"
    for name, value in parser.attributes:
        assert not name.lower().startswith("on"), f"event handler kept: {name}"
        if value:
            assert not value.strip().lower().startswith(DANGEROUS_SCHEMES), (
                f"dangerous URL kept: {name}={value!r}"
            )


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<script src='https://evil.test/x.js'></script>",
        "<iframe src='https://evil.test/frame'>fallback</iframe>",
        "<img src=x onerror='alert(1)'>",
        "<svg onload=alert(1)><circle cx=1 cy=1 r=1 /></svg>",
        "<div onclick='alert(1)'>click</div>",
        "<a href='javascript:alert(1)'>link</a>",
        "<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>link</a>",
        "<style>body{background:url(javascript:alert(1))}</style>",
        "<math><mtext><script>alert(1)</script></mtext></math>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    ],
)
def test_sanitize_reply_html_strips_executable_markup(payload):
    out = sanitize_reply_html(payload)
    assert_inert(out)
    # Payloads lived in script bodies, event handlers or URL attributes; all gone.
    assert "alert(" not in out
    assert "<" + "script" not in out.lower()
    assert "<" + "iframe" not in out.lower()
    assert "<" + "img" not in out.lower()
    assert "<" + "svg" not in out.lower()


def test_sanitize_reply_html_drops_script_bodies_and_iframe_attributes():
    out = sanitize_reply_html(
        "<p>before</p><script>stealSecrets()</script>"
        "<iframe src='https://evil.test' onload='steal()'>injectedFrameBody</iframe>"
        "<p>after</p>"
    )
    # Script bodies disappear entirely; disallowed elements lose tags and
    # attributes, and their text falls back to inert text.
    assert "stealSecrets" not in out
    assert "evil.test" not in out
    assert "steal()" not in out
    assert "injectedFrameBody" in out
    assert "before" in out and "after" in out
    assert_inert(out)


def test_sanitize_reply_html_keeps_allowed_formatting():
    out = sanitize_reply_html(
        '<h2>Heading</h2><p><strong>bold</strong> <em>italic</em> '
        '<a href="https://example.test/doc" title="doc">link</a></p>'
        '<pre><code class="language-python">print(1)</code></pre>'
        "<ul><li>one</li></ul>"
        "<table><thead><tr><th>h</th></tr></thead><tbody><tr><td>c</td></tr></tbody></table>"
    )
    assert "<h2>Heading</h2>" in out
    assert "<strong>bold</strong>" in out
    assert '<code class="language-python">' in out
    assert '<a href="https://example.test/doc"' in out
    assert 'rel="noopener noreferrer"' in out
    assert "<table>" in out and "<td>c</td>" in out
    assert_inert(out)


def test_sanitize_reply_html_is_idempotent():
    payload = "<p>keep</p><img src=x onerror=alert(1)><script>alert(2)</script>"
    once = sanitize_reply_html(payload)
    assert sanitize_reply_html(once) == once


def test_sanitize_reply_html_escapes_lone_angle_brackets():
    out = sanitize_reply_html("<p>1 &lt; 2 and 3 &gt; 2</p>")
    assert "1 &lt; 2" in out and "3 &gt; 2" in out


def test_format_ai_response_sanitizes_markdown_but_keeps_structure():
    out = format_ai_response(
        "**bold**\n\n```python\nprint('hi')\n```\n\n"
        "<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>"
    )
    assert "<strong>bold</strong>" in out
    assert '<code class="language-python">' in out
    assert "<pre>" in out
    assert_inert(out)


def test_format_ai_response_drops_javascript_link_target():
    out = format_ai_response("[click me](javascript:alert(1))")
    assert "click me" in out
    assert_inert(out)
    assert "javascript:" not in out.lower()


def test_markdown_reply_survives_history_sanitizing_unchanged():
    # Write-time output must not carry markup the render-time allowlist would strip.
    reply = format_ai_response("**bold**\n\n```python\nprint(1)\n```")
    cleaned = sanitize_chat_history([{"title": "t", "messages": [{"type": "ai", "message": reply}]}])
    assert cleaned[0]["messages"][0]["message"] == reply


def test_import_pipeline_sanitizes_before_the_client_renders():
    imported = normalize_chats(
        [
            {
                "title": "Imported",
                "messages": [
                    {"type": "ai", "message": "<p>kept</p><img src=x onerror=alert(1)>"},
                    {"type": "user", "message": {"not": "text"}},
                ],
            },
            "not a chat",
        ]
    )
    cleaned = sanitize_chat_history(imported)

    assert len(cleaned) == 1
    assert "kept" in cleaned[0]["messages"][0]["message"]
    assert_inert(cleaned[0]["messages"][0]["message"])
    # Non-string messages are dropped instead of crashing nh3 on the chat page.
    assert cleaned[0]["messages"][1]["message"] == ""


def test_sanitize_chat_history_resanitizes_stored_ai_replies():
    legacy_payload = (
        "<p>old reply</p><img src=x onerror=alert(1)>"
        "<script>alert('history')</script>"
        "<a href='javascript:alert(1)'>bad link</a>"
    )
    chats = [
        {
            "title": "Legacy",
            "messages": [
                {"type": "ai", "message": legacy_payload, "sources": [{"id": 1}]},
                {"type": "user", "message": "<b>typed by hand</b>", "sources": []},
            ],
        }
    ]

    cleaned = sanitize_chat_history(chats)
    cleaned_reply = cleaned[0]["messages"][0]["message"]

    assert "old reply" in cleaned_reply
    assert "bad link" in cleaned_reply
    assert_inert(cleaned_reply)
    assert "alert('history')" not in cleaned_reply
    # User text is rendered with textContent in the browser, so it stays as typed.
    assert cleaned[0]["messages"][1]["message"] == "<b>typed by hand</b>"
    # Chat metadata and message fields are preserved.
    assert cleaned[0]["title"] == "Legacy"
    assert cleaned[0]["messages"][0]["sources"] == [{"id": 1}]
    # The stored history is not mutated in place.
    assert chats[0]["messages"][0]["message"] == legacy_payload
