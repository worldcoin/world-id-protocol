#!/usr/bin/env python3
"""Strip leading YAML front matter from mdBook chapters."""

import json
import re
import sys


FRONT_MATTER_RE = re.compile(r"^\s*---\s*\n.*?\n---\s*\n", re.DOTALL)


def strip_front_matter(content: str) -> str:
    """Remove one leading `--- ... ---` front-matter block."""
    return FRONT_MATTER_RE.sub("", content, count=1)


def process_items(items: list[dict]) -> None:
    for item in items:
        if "Chapter" not in item:
            continue

        chapter = item["Chapter"]
        if chapter.get("content"):
            chapter["content"] = strip_front_matter(chapter["content"])
        process_items(chapter.get("sub_items", []))


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        return

    _context, book = json.load(sys.stdin)
    process_items(book["items"])
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()
