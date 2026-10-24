"""Statik yayın: ders → Markdown (YAML frontmatter) → aynı şablonlarla statik HTML site → GitHub Pages.

  export  ders + kayıtlı AI analizi → content/lessons/<CVE>.md   (GitHub'da da okunur)
  build   content/ → _site/   (lesson.html'in yayın modu; Ayarlar, Analizler, formlar yok; içindekiler)

Uygulamada (ders sayfası → YAYIN): ÖNİZLEME yalnızca yerelde (/onizleme/) üretir; YAYINLA dersi
yayın reposuna commit'ler (pdt_web/ghpub.py), repodaki Actions engine/ ile build edip Pages'e koyar.
data/publish/content/ yayındaki derslerin yerel kopyasıdır: yalnızca YAYINLA denenler.
Site göreli bağlantılar kullanır; Pages'in /<repo>/ alt yolunda ve /onizleme/'de aynen çalışır.

    python -m pdt_web.publish export CVE-2004-1019 --content data/publish/content
    python -m pdt_web.publish build data/publish/content data/publish/_site
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader

from . import tplenv
from .catalog import CATEGORIES
from .diffview import from_patch, lesson_notes

HERE = Path(__file__).parent
MARKER = ".pdt-site"          # build yalnızca bu işareti taşıyan klasörü silip yeniden yazar
FORMAT = 1

# Markdown gövdesindeki bölümler ↔ veri yolu. Geri kalan her şey frontmatter'da.
PROSE = [("Bağlam", ("context",)), ("Kök neden", ("answer", "root_cause")),
         ("Yamanın etkisi", ("answer", "patch_effect")), ("Not", ("notes",)),
         ("AI özeti", ("ai", "summary")), ("AI kök neden", ("ai", "root_cause"))]
DIFF_SECTION = "Düzeltme diff'i"


def _pop(d: dict[str, Any], path: tuple[str, ...]) -> Any:
    for k in path[:-1]:
        d = d.get(k) if isinstance(d.get(k), dict) else {}
    return d.pop(path[-1], None)


def _put(d: dict[str, Any], path: tuple[str, ...], val: Any) -> None:
    for k in path[:-1]:
        d = d.setdefault(k, {})
    d[path[-1]] = val


def _fence(text: str) -> str:
    runs = [len(m) for m in re.findall(r"`{3,}", text)]
    return "`" * max(3, max(runs, default=0) + 1)


# --- export ------------------------------------------------------------------

def lesson_to_md(lesson: dict[str, Any], analysis: dict[str, Any] | None = None,
                 published_at: str | None = None, updated_at: str | None = None) -> str:
    """analysis: {"model", "created_at", "result": {...}} (uygulamadaki son kayıtlı analiz) ya da None."""
    fm = json.loads(json.dumps(lesson))          # derin kopya
    if analysis and analysis.get("result"):
        fm["ai"] = {"model": analysis.get("model"), "created_at": analysis.get("created_at"),
                    **json.loads(json.dumps(analysis["result"]))}
    fm["published"] = {"at": published_at or dt.date.today().isoformat(), "format": FORMAT}
    if updated_at:
        fm["published"]["updated"] = updated_at
    diff = (fm.get("fix") or {}).pop("diff", None)
    body = [f"# {lesson.get('alias') or lesson['id']} · {lesson['id']}", ""]
    def prose(sections: list[tuple[str, tuple[str, ...]]]) -> None:
        for title, path in sections:
            val = _pop(fm, path)
            if isinstance(val, str) and val.strip():
                body.extend([f"## {title}", "", val.strip(), ""])
            elif val is not None:
                _put(fm, path, val)        # boş ya da metin olmayan değer frontmatter'da kalır

    prose(PROSE[:3])
    if diff:
        f = _fence(diff)
        body += [f"## {DIFF_SECTION}", "", f"{f}diff", diff.rstrip("\n"), f, ""]
    prose(PROSE[3:])
    head = yaml.safe_dump(fm, allow_unicode=True, sort_keys=False, width=110)
    return f"---\n{head}---\n\n" + "\n".join(body)


def md_to_lesson(text: str) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    """→ (ders, analiz ya da None, yayın bilgisi). lesson_to_md'nin tersi."""
    if not text.startswith("---\n"):
        raise ValueError("frontmatter yok")
    end = text.index("\n---\n", 4)
    fm = yaml.safe_load(text[4:end]) or {}
    sections: dict[str, list[str]] = {}
    cur = None
    for line in text[end + 5:].splitlines():
        m = re.match(r"^## (.+?)\s*$", line)
        if m and (cur != DIFF_SECTION or not _in_fence(sections.get(cur, []))):
            cur = m.group(1)
            sections[cur] = []
        elif cur:
            sections[cur].append(line)
    titles = dict(PROSE)
    for title, lines in sections.items():
        if title == DIFF_SECTION:
            fm.setdefault("fix", {})["diff"] = _unfence(lines)
        elif title in titles:
            _put(fm, titles[title], "\n".join(lines).strip())
    pub = fm.pop("published", {}) or {}
    ai = fm.pop("ai", None)
    analysis = None
    if ai:
        analysis = {"model": ai.pop("model", None), "created_at": ai.pop("created_at", None), "result": ai}
    return fm, analysis, pub


def _in_fence(lines: list[str]) -> bool:
    opened = None
    for l in lines:
        m = re.match(r"^(`{3,})", l)
        if m and (opened is None or m.group(1) == opened):
            opened = None if opened else m.group(1)
    return opened is not None


def _unfence(lines: list[str]) -> str:
    start = next(i for i, l in enumerate(lines) if l.startswith("```"))
    f = re.match(r"^(`{3,})", lines[start]).group(1)
    stop = next(i for i in range(start + 1, len(lines)) if lines[i] == f)
    return "\n".join(lines[start + 1:stop]) + "\n"




def lesson_md_from_db(con: sqlite3.Connection, cve: str, previous: str | None = None) -> str:
    """Dersin ve son kayıtlı AI analizinin Markdown'u. previous: yayındaki sürüm (ilk yayın tarihi korunur)."""
    r = con.execute("SELECT data FROM lesson WHERE id=?", (cve,)).fetchone()
    if r is None:
        raise KeyError(cve)
    a = con.execute("SELECT model, created_at, result FROM analysis WHERE lesson_id=? ORDER BY id DESC LIMIT 1",
                    (cve,)).fetchone()
    analysis = {"model": a[0], "created_at": a[1], "result": json.loads(a[2])} if a else None
    today = dt.date.today().isoformat()
    first = md_to_lesson(previous)[2].get("at") if previous else None
    return lesson_to_md(json.loads(r[0]), analysis, published_at=first or today,
                        updated_at=today if first and first != today else None)


def export_from_db(con: sqlite3.Connection, cve: str, content: Path) -> Path:
    out = content / "lessons" / f"{cve}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    prev = out.read_text(encoding="utf-8") if out.exists() else None
    out.write_text(lesson_md_from_db(con, cve, prev), encoding="utf-8")
    return out


# --- build -------------------------------------------------------------------

def _env(timezone: str) -> Environment:
    env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=True)
    return tplenv.configure(env, timezone)


def _reset(out: Path) -> None:
    if out.exists():
        if any(out.iterdir()) and not (out / MARKER).exists():
            raise RuntimeError(f"{out} boş değil ve bir yayın klasörü değil; silinmedi")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / MARKER).write_text("patchdiff-tutor statik yayın çıktısı; build her seferinde yeniden yazar\n",
                              encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")   # GitHub Pages Jekyll'den geçirmesin


def load_content(content: Path, drafts: dict[str, str] | None = None) -> list[tuple[dict, dict | None, dict]]:
    """content/lessons/*.md; drafts (CVE → Markdown) aynı adlı dosyanın yerine geçer ya da eklenir."""
    texts = {f.stem: f.read_text(encoding="utf-8") for f in (content / "lessons").glob("CVE-*.md")}
    texts.update(drafts or {})
    return [md_to_lesson(texts[k]) for k in sorted(texts)]


def build(content: Path, out: Path, timezone: str = "Europe/Istanbul", site_name: str = "statik yayın",
          drafts: dict[str, str] | None = None) -> list[str]:
    """drafts: yayımlanmamış (önizlenen) dersler; sayfalarında ÖNİZLEME uyarısı çıkar."""
    items = load_content(content, drafts)
    draft_ids = set(drafts or {})
    env = _env(timezone)
    _reset(out)
    shutil.copytree(HERE / "static", out / "static")
    ids = {l["id"] for l, _, _ in items}
    common = {"public": True, "page": "katalog", "public_addr": site_name, "worker": {"online": False},
              "request": SimpleNamespace(query_params={})}
    for lesson, analysis, pub in items:
        result = (analysis or {}).get("result")
        fix = lesson.get("fix") or {}
        view = from_patch(fix["diff"], lesson_notes(result), "AI") if fix.get("diff") else None
        html = env.get_template("lesson.html").render(
            **common, root="../../", status_info=f"yayın · {pub.get('updated') or pub.get('at', '')}",
            ai_model=(analysis or {}).get("model") or "—", draft=lesson["id"] in draft_ids, pub=pub,
            l=lesson, cat=CATEGORIES[lesson["category"]], analysis=analysis, result=result, view=view,
            hints=lesson.get("hints") or [], hints_used=0, step=2, in_cat=ids, ajob=None, a_error=None,
            budget={"blocks": False}, est=None, attempts=[], latest=None, best=None, runs=[], sugg=[])
        d = out / "lessons" / lesson["id"]
        d.mkdir(parents=True)
        (d / "index.html").write_text(html, encoding="utf-8")
    rows = sorted((l for l, _, _ in items), key=lambda l: (l.get("year") or 0, l["id"]))
    toc = [{"code": c, "name": v["name"], "lessons": [l for l in rows if l["category"] == c]}
           for c, v in CATEGORIES.items() if any(l["category"] == c for l in rows)]
    tabs = [{"code": g["code"], "label": CATEGORIES[g["code"]]["short"], "count": len(g["lessons"])} for g in toc]
    html = env.get_template("public_index.html").render(
        **common, root="./", status_info=f"{len(rows)} ders", ai_model="—", rows=rows, tabs=tabs, toc=toc,
        analyzed={l["id"] for l, a, _ in items if a}, drafts=draft_ids,
        updated=max((p.get("updated") or p.get("at") or "" for _, _, p in items), default=""))
    (out / "index.html").write_text(html, encoding="utf-8")
    return sorted(ids)


# --- yayın reposu ------------------------------------------------------------
# Repo düzeni: content/lessons/*.md (yalnızca "YAYINLA" denen dersler), engine/ (bu modülün render için
# gereken alt kümesi; Actions bununla build eder), .github/workflows/pages.yml, README.md.

ENGINE_PY = {"pdt_web": ["__init__.py", "publish.py", "tplenv.py", "textfmt.py", "catalog.py", "diffview.py"],
             "pdt": ["__init__.py", "difftools.py", "sinks.py"]}
ENGINE_TEMPLATES = ["base.html", "_macros.html", "lesson.html", "public_index.html"]
ENGINE_REQUIREMENTS = "jinja2==3.1.6\nmarkupsafe==3.0.4\npyyaml==6.0.3\ntzdata==2026.5\n"
PRUNE = ("engine/",)

WORKFLOW = """\
# patchdiff-tutor tarafından yazılır; content/ değişince siteyi engine/ ile üretip Pages'e koyar.
name: pages
on:
  push:
    branches: [{branch}]
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
concurrency:
  group: pages
  cancel-in-progress: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r engine/requirements.txt
      - run: python -m pdt_web.publish build ../content ../_site
        working-directory: engine
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: _site
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{{{ steps.deploy.outputs.page_url }}}}
    steps:
      - id: deploy
        uses: actions/deploy-pages@v4
"""

README = """\
# patchdiff — açıklık dersleri

Güvenlik yamalarını diff'leyerek öğrenmek için ders sayfaları: yamasız ve yamalı kodun farkı, kök nedeni
önce kendin tahmin et, sonra cevap anahtarı ve AI açıklamasıyla karşılaştır.

**Site:** {pages}

Dersler yalnızca kök nedeni ve yamanın etkisini anlatır; exploit, PoC ya da tetikleyici girdi içermez.

## Düzen

| Yol | İçerik |
|---|---|
| `content/lessons/<CVE>.md` | Yayımlanan dersler: YAML frontmatter (künye, ipuçları, kaynaklar, AI satır yorumları) + Markdown bölümler |
| `engine/` | Sayfaları üreten render motoru (patchdiff-tutor'dan kopyalanır; elle değiştirme) |
| `.github/workflows/pages.yml` | Her push'ta `content/`'i `engine/` ile statik siteye çevirip GitHub Pages'e koyar |

Yerelde üretmek için:

```bash
pip install -r engine/requirements.txt
cd engine && python -m pdt_web.publish build ../content ../_site
```

Bu repo patchdiff-tutor'un YAYINLA düğmesiyle güncellenir.
"""


def repo_files(branch: str, pages: str) -> dict[str, bytes]:
    """Yayın reposundaki ders dışı dosyalar (sıra önemli: boş repoda ilk dosya README olur)."""
    import importlib
    files = {"README.md": README.format(pages=pages).encode(),
             ".gitignore": b"_site/\n__pycache__/\n",
             ".github/workflows/pages.yml": WORKFLOW.format(branch=branch).encode(),
             "engine/requirements.txt": ENGINE_REQUIREMENTS.encode()}
    for pkg, names in ENGINE_PY.items():
        root = Path(importlib.import_module(pkg).__file__).parent
        for n in names:
            files[f"engine/{pkg}/{n}"] = (root / n).read_bytes()
    for n in ENGINE_TEMPLATES:
        files[f"engine/pdt_web/templates/{n}"] = (HERE / "templates" / n).read_bytes()
    for f in sorted((HERE / "static").rglob("*")):
        if f.is_file():
            files[f"engine/pdt_web/static/{f.relative_to(HERE / 'static').as_posix()}"] = f.read_bytes()
    return files


def main(argv: list[str] | None = None) -> int:
    import os
    ap = argparse.ArgumentParser(prog="python -m pdt_web.publish")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="dersi (ve kayıtlı AI analizini) Markdown'a aktar")
    e.add_argument("cve", nargs="+")
    e.add_argument("--content", type=Path, default=None)
    b = sub.add_parser("build", help="content/ → statik site")
    b.add_argument("content", type=Path)
    b.add_argument("out", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "export":
        from . import db
        from .config import Config
        cfg = Config.from_env()
        content = a.content or cfg.data_dir / "publish" / "content"
        with db.closing(db.connect(cfg.db_path)) as c:
            for cve in a.cve:
                print(export_from_db(c, cve, content))
        return 0
    ids = build(a.content, a.out, os.environ.get("PDT_TZ", "Europe/Istanbul"))
    print(f"{len(ids)} ders → {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
