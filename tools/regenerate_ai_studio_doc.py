"""tools/regenerate_ai_studio_doc.py (VERSION 1.2.0)

Refreshes the embedded source files inside GOOGLE_AI_STUDIO_PROMPT.md so the
spec always carries the current (fully commented) code. Keeps all framing
sections (overview, features, colors, flows, API reference) as-written.

Run from the repo root:  python3 tools/regenerate_ai_studio_doc.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "GOOGLE_AI_STUDIO_PROMPT.md"
FILES = [
    ("app/db.py", "py"),
    ("app/main.py", "py"),
    ("run.py", "py"),
    ("app/static/styles.css", "css"),
    ("app/static/index.html", "html"),
    ("app/static/app.js", "js"),
    ("app/static/scanner.html", "html"),
    ("app/static/scanner.js", "js"),
    ("app/static/dashboard.html", "html"),
    ("app/static/dashboard.js", "js"),
    ("app/static/receipt.html", "html"),
    ("requirements.txt", "txt"),
    ("tests/e2e_test.py", "python"),
]

text = DOC.read_text(encoding="utf-8")
for path, lang in FILES:
    # Heading is followed by an italic one-line description before the fence:
    #   ### File: `app/db.py`
    #   _Python -- ..._
    #
    #   ```py
    pat = re.compile(
        r"(### File: `" + re.escape(path) + r"`\n.*?```[a-z]*\n)(.*?)(\n```)",
        re.S,
    )
    body = (ROOT / path).read_text(encoding="utf-8").rstrip("\n")
    text, n = pat.subn(lambda mm: mm.group(1) + body + mm.group(3), text)
    print(f"{path}: {'updated' if n else 'NOT FOUND'}")

DOC.write_text(text, encoding="utf-8")
print("doc refreshed:", DOC, len(text), "bytes")
