"""Jinja ortamı: web uygulaması ve statik yayın (publish) aynı filtre ve global'leri kullanır."""
from __future__ import annotations

from typing import Any

from jinja2 import Environment, pass_context

from . import textfmt
from .catalog import BUG_CLASSES, CATEGORIES, DIFFICULTIES, ERAS, RELATIONS, SOURCE_TYPES, STATUSES
from .diffview import bar


@pass_context
def href(ctx: Any, kind: str, arg: str = "") -> str:
    """Sayfa içi bağlantılar. Uygulamada mutlak yol; statik yayında sayfaya göre göreli yol
    (`root`), böylece site GitHub Pages'in /<repo>/ alt yolunda da çalışır."""
    if not ctx.get("public"):
        return {"home": "/", "cat": f"/?cat={arg}", "lesson": f"/lessons/{arg}",
                "static": f"/static/{arg}"}[kind]
    root = ctx.get("root", "./")
    return {"home": root, "cat": f"{root}?cat={arg}", "lesson": f"{root}lessons/{arg}/",
            "static": f"{root}static/{arg}"}[kind]


def configure(env: Environment, timezone: str, solved: int | None = None) -> Environment:
    """Statik yayın motoruna da kopyalanır: yalnızca catalog/diffview/textfmt ve pdt.sinks'e dayanır."""
    from pdt.sinks import SINK_CLASSES
    env.filters["tr_upper"] = textfmt.tr_upper
    env.filters["tr_lower"] = textfmt.tr_lower
    env.filters["dt"] = lambda iso, style="date": textfmt.fmt_dt(iso, timezone, style)
    env.filters["usd"] = lambda v: "—" if v is None else f"{v:,.2f} $".replace(",", "X").replace(".", ",").replace("X", ".")
    env.filters["num"] = lambda v: f"{int(v):,}".replace(",", ".") if v is not None else "—"
    env.globals.update(SINK_CLASSES=SINK_CLASSES, href=href, public=False)
    env.globals.update(CATEGORIES=CATEGORIES, ERAS=ERAS, BUG_CLASSES=BUG_CLASSES, DIFFICULTIES=DIFFICULTIES,
                       STATUSES=STATUSES, SOURCE_TYPES=SOURCE_TYPES, RELATIONS=RELATIONS, bar=bar,
                       shade="░░▒▒▓▓▒▒" * 60, SOLVED=solved)
    return env
