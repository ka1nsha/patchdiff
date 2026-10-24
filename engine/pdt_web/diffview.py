"""Diff görüntüleyicinin satır modeli (DESIGN.md §5.9).

İki kaynak aynı satır yapısına çevrilir:
  - ders sayfasındaki düzeltme commit'i (birleşik/unified diff metni)
  - pdt raporundaki eski/yeni decompile fonksiyon (pdt.difftools.side_by_side)

Satır türleri: code (o/n numaralı kod), fold (katlanmış değişmeyen satırlar),
note (AI/KURAL yorumu), file (dosya başlığı), hunk (@@ başlığı).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from pdt.difftools import side_by_side

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")
CONTEXT = 3          # değişikliğin çevresinde gösterilen değişmeyen satır
MIN_FOLD = 4         # bundan kısa değişmeyen bloklar katlanmaz


@dataclass
class Row:
    kind: str                 # code | fold | note | file | hunk
    o: str = ""
    n: str = ""
    mark: str = " "           # + | − | boşluk
    text: str = ""
    cls: str = ""             # d-add | d-del | ""
    label: str = ""           # note: "AI" | "KURAL"
    fold: int = 0             # bu satır hangi katlama grubuna ait (0 = görünür)
    count: int = 0            # fold satırı: kaç satır gizli


@dataclass
class SRow:
    """Yan yana görünümde tek satır."""
    kind: str                 # code | note | file | hunk | fold
    o: str = ""
    otext: str = ""
    ocls: str = ""
    n: str = ""
    ntext: str = ""
    ncls: str = ""
    onote: str = ""
    nnote: str = ""
    label: str = ""
    text: str = ""
    fold: int = 0
    count: int = 0


@dataclass
class DiffView:
    unified: list[Row] = field(default_factory=list)
    split: list[SRow] = field(default_factory=list)
    notes: int = 0
    added: int = 0
    removed: int = 0


def _fold(rows: list, is_change, keep_extra=lambda r: False, make_fold=None) -> list:
    """Değişikliğe/yoruma CONTEXT satırdan uzak değişmeyen blokları katla."""
    keep = [False] * len(rows)
    for i, r in enumerate(rows):
        if r.kind != "code" or is_change(r) or keep_extra(r):
            for k in range(max(0, i - CONTEXT), min(len(rows), i + CONTEXT + 1)):
                keep[k] = True
    out, i, group = [], 0, 0
    while i < len(rows):
        if keep[i] or rows[i].kind != "code":
            out.append(rows[i])
            i += 1
            continue
        j = i
        while j < len(rows) and not keep[j] and rows[j].kind == "code":
            j += 1
        block = rows[i:j]
        if len(block) < MIN_FOLD:
            out.extend(block)
        else:
            group += 1
            out.append(make_fold(len(block), group))
            for r in block:
                r.fold = group
                out.append(r)
        i = j
    return out


# --- Birleşik diff metni (ders) -------------------------------------------

def lesson_notes(result: dict | None) -> dict[int, str]:
    """Ders AI analizindeki diff_lines → {ham diff satırı: yorum}."""
    notes: dict[int, str] = {}
    for item in (result or {}).get("diff_lines") or []:
        try:
            notes[int(item["line"])] = (notes.get(int(item["line"]), "") + " " + item["comment"]).strip()
        except (KeyError, TypeError, ValueError):
            pass
    return notes


def from_patch(diff: str, notes: dict[int, str] | None = None, label: str = "AI") -> DiffView:
    """notes: ham diff metnindeki 1 tabanlı satır numarası → yorum."""
    notes = notes or {}
    view = DiffView()
    o = n = 0
    pending_del: list[tuple[int, str, int]] = []   # yan yana eşleştirme için (no, metin, ham satır)
    pending_add: list[tuple[int, str, int]] = []

    def flush_pairs():
        for k in range(max(len(pending_del), len(pending_add))):
            d = pending_del[k] if k < len(pending_del) else None
            a = pending_add[k] if k < len(pending_add) else None
            view.split.append(SRow("code", o=str(d[0]) if d else "", otext=d[1] if d else "",
                                   ocls="d-del" if d else "d-empty",
                                   n=str(a[0]) if a else "", ntext=a[1] if a else "",
                                   ncls="d-add" if a else "d-empty"))
            on = notes.get(d[2]) if d else None
            nn = notes.get(a[2]) if a else None
            if on or nn:
                view.split.append(SRow("note", onote=on or "", nnote=nn or "", label=label))
        pending_del.clear()
        pending_add.clear()

    for raw_no, line in enumerate(diff.splitlines(), 1):
        if line.startswith("diff --git"):
            flush_pairs()
            name = line.split(" b/", 1)[-1] if " b/" in line else line[11:]
            view.unified.append(Row("file", text=name))
            view.split.append(SRow("file", text=name))
            continue
        if line.startswith(("index ", "--- ", "+++ ", "new file", "deleted file", "similarity", "rename ")):
            continue
        m = _HUNK.match(line)
        if m:
            flush_pairs()
            o, n = int(m.group(1)), int(m.group(2))
            txt = line
            view.unified.append(Row("hunk", text=txt))
            view.split.append(SRow("hunk", text=txt))
            continue
        if line.startswith("\\"):
            continue
        tag, body = (line[:1], line[1:]) if line else (" ", "")
        if tag == "-":
            view.unified.append(Row("code", o=str(o), mark="−", text=body, cls="d-del"))
            pending_del.append((o, body, raw_no))
            o += 1
            view.removed += 1
        elif tag == "+":
            view.unified.append(Row("code", n=str(n), mark="+", text=body, cls="d-add"))
            pending_add.append((n, body, raw_no))
            n += 1
            view.added += 1
        else:
            flush_pairs()
            view.unified.append(Row("code", o=str(o), n=str(n), text=body))
            view.split.append(SRow("code", o=str(o), otext=body, n=str(n), ntext=body))
            if raw_no in notes:
                view.split.append(SRow("note", onote="", nnote=notes[raw_no], label=label))
            o += 1
            n += 1
        if raw_no in notes:
            view.unified.append(Row("note", text=notes[raw_no], label=label))
            view.notes += 1
    flush_pairs()
    return view


# --- Decompile fonksiyonu (pdt raporu) --------------------------------------

def from_function(old_code: str, new_code: str, old_notes: dict[str, str] | None = None,
                  new_notes: dict[str, str] | None = None, label: str = "AI") -> DiffView:
    old_notes, new_notes = old_notes or {}, new_notes or {}
    view = DiffView()
    sbs = side_by_side(old_code, new_code)
    uni: list[Row] = []
    split: list[SRow] = []
    for r in sbs:
        on = old_notes.get(str(r.old_no)) if r.old_no else None
        nn = new_notes.get(str(r.new_no)) if r.new_no else None
        if r.tag == "equal":
            uni.append(Row("code", o=str(r.old_no), n=str(r.new_no), text=r.old_text))
            split.append(SRow("code", o=str(r.old_no), otext=r.old_text, n=str(r.new_no), ntext=r.new_text))
            for t in (on, nn):
                if t:
                    uni.append(Row("note", text=t, label=label))
        else:
            if r.old_no:
                uni.append(Row("code", o=str(r.old_no), mark="−", text=r.old_text, cls="d-del"))
                view.removed += 1
                if on:
                    uni.append(Row("note", text=on, label=label))
            split.append(SRow("code", o=str(r.old_no or ""), otext=r.old_text,
                              ocls="d-del" if r.old_no else "d-empty",
                              n=str(r.new_no or ""), ntext=r.new_text, ncls="d-add" if r.new_no else "d-empty"))
            if r.new_no:
                uni_add = Row("code", n=str(r.new_no), mark="+", text=r.new_text, cls="d-add")
                uni.append(uni_add)
                view.added += 1
                if nn:
                    uni.append(Row("note", text=nn, label=label))
        if on or nn:
            split.append(SRow("note", onote=on or "", nnote=nn or "", label=label))
    view.notes = sum(1 for r in uni if r.kind == "note")
    view.unified = _fold(uni, lambda r: r.mark != " ",
                         make_fold=lambda c, g: Row("fold", count=c, fold=0, text=str(g)))
    view.split = _fold(split, lambda r: bool(r.ocls or r.ncls),
                       make_fold=lambda c, g: SRow("fold", count=c, fold=0, text=str(g)))
    return view


def bar(n: int, m: int, cells: int = 10) -> str:
    """Blok karakterli ilerleme çubuğu (DESIGN.md §5.8)."""
    if m <= 0:
        return "·" * cells
    f = max(0, min(cells, round(n / m * cells)))
    return "▓" * f + "░" * (cells - f)
