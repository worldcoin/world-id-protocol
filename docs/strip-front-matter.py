"""Load the WIP table as mdBook chapters and strip leading YAML front matter."""

import json
import re
import sys
from pathlib import Path

FRONT_MATTER_RE = re.compile(r"^\s*---\s*\n.*?\n---\s*\n", re.DOTALL)


def add_wip_chapters(context: dict, book: dict) -> None:
    """Include the WIP index and local specs that mdBook ignores inside a table."""
    source = Path(context["root"]) / context["config"]["book"]["src"]
    summary = (source / "SUMMARY.md").read_text(encoding="utf-8")
    heading = "# World ID Improvement Proposals"
    _, table = summary.split(heading, 1)
    chapters = [("WIP index", "wips.md", "SUMMARY.md", heading + table)]
    for name, path, label in re.findall(
        r"^\| \[([^\]]+)\]\((WIPs/[^)]+\.md)\)([^|]*)\|", table, re.MULTILINE
    ):
        name += label.replace("**", "").rstrip()
        chapters.append((name, path, path, (source / path).read_text(encoding="utf-8")))
    for name, path, source_path, content in chapters:
        book["items"].append(
            {
                "Chapter": {
                    "name": name,
                    "content": content,
                    "number": None,
                    "sub_items": [],
                    "path": path,
                    "source_path": source_path,
                    "parent_names": [],
                }
            }
        )


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

    context, book = json.load(sys.stdin)
    add_wip_chapters(context, book)
    process_items(book["items"])
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()
