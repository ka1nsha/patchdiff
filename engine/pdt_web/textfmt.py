"""Şablon metin biçimleri (Türkçe büyük/küçük harf, tarih). Statik yayın motoruna da kopyalanır;
veritabanına ya da uygulamaya bağımlı olmamalı."""
from __future__ import annotations

import datetime as dt
from typing import Any
from zoneinfo import ZoneInfo


def tr_upper(s: Any) -> str:
    """Türkçe büyük harf: i→İ, ı→I (DESIGN.md §3)."""
    return str(s or "").replace("i", "İ").replace("ı", "I").upper()


def tr_lower(s: Any) -> str:
    return str(s or "").replace("I", "ı").replace("İ", "i").lower()


def fmt_dt(iso: str | None, tz: str, style: str = "date") -> str:
    try:
        t = dt.datetime.fromisoformat(iso) if iso else None
    except ValueError:
        t = None
    if t is None:
        return "—"
    try:
        local = t.astimezone(ZoneInfo(tz))
        today = dt.datetime.now(ZoneInfo(tz)).date()
    except Exception:  # noqa: BLE001 - tzdata yoksa UTC
        local, today = t, dt.datetime.now(dt.timezone.utc).date()
    if style == "date":
        return local.strftime("%d.%m.%Y")
    if style == "time":
        if local.date() == today:
            return local.strftime("%H:%M")
        if (today - local.date()).days == 1:
            return "dün " + local.strftime("%H:%M")
        return local.strftime("%d.%m %H:%M")
    return local.strftime("%d.%m.%Y %H:%M")
