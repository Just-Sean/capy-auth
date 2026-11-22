"""Checks shared by the tests that request the module's pages."""

import re
from html.parser import HTMLParser

from tests.test_csp import blocked_in

# Elements allowed in <head>; anything else makes the browser end the head early.
HEAD_ELEMENTS = {"meta", "link", "title", "script", "style", "base", "noscript", "template"}


class HeadElements(HTMLParser):
    """The start tags between <head> and </head>."""

    def __init__(self):
        super().__init__()
        self.in_head = False
        self.tags = set()

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self.in_head = True
        elif self.in_head:
            self.tags.add(tag)

    def handle_endtag(self, tag):
        if tag == "head":
            self.in_head = False


def head_tags(page):
    parser = HeadElements()
    parser.feed(page)
    return parser.tags


def dangling_describedby(page):
    """aria-describedby ids that no element on the page has."""
    ids = set(re.findall(r'\sid="([^"]+)"', page))
    return [
        ref
        for value in re.findall(r'aria-describedby="([^"]*)"', page)
        for ref in value.split()
        if ref not in ids
    ]


def check_page(response, status=200):
    """The page is a full page in layout.html that the strict policy allows."""
    assert response.status_code == status
    assert "Content-Security-Policy" in response.headers
    page = response.content.decode()
    assert '<div role="status">' in page  # layout.html's messages region
    assert '<main id="main" tabindex="-1">' in page
    assert len(re.findall(r"<h1[\s>]", page)) == 1
    title = re.search(r"<title>(.*?)</title>", page, re.DOTALL).group(1).strip()
    assert title and title != "Untitled page"
    assert "Menu:" not in page  # allauth's own menu is left out
    assert blocked_in(page) == {}
    assert head_tags(page) <= HEAD_ELEMENTS
    assert dangling_describedby(page) == []
    for form in re.findall(r'<form[^>]*method="post"[^>]*>.*?</form>', page, re.DOTALL):
        assert "csrfmiddlewaretoken" in form
    return page
