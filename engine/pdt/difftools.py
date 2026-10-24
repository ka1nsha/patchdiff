"""Decompile kod üzerinde satır bazlı karşılaştırma yardımcıları."""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

_WS = re.compile(r"\s+")
# Yığın çerçevesi değişince kayan isimler/yorumlar: gerçek mantık farkı değildir
_STACK_NOISE = [
    (re.compile(r"\b(local|uStack|auStack|iStack|lStack|pcStack|puStack|in_stack)_[0-9a-fA-F]+\b"), r"\1_X"),
    (re.compile(r"//\s*\[bp-0x[0-9a-fA-F]+\].*$"), ""),               # angr: // [bp-0x48]
    (re.compile(r";\s*//\s*[a-z0-9]{2,5}\s*$"), ";"),                    # angr: // rbx (yazmaç)
    (re.compile(r"\b(LAB|DAT|PTR|FUN|switchD|caseD)_[0-9a-fA-F]{6,}\b"), r"\1_X"),  # Ghidra adres etiketleri
]


def norm(line: str) -> str:
    """Karşılaştırma için satırı sadeleştir: boşluklar ve stack/adres kaynaklı
    isim kaymaları yok sayılır. Ekranda orijinal satır gösterilir."""
    for pat, rep in _STACK_NOISE:
        line = pat.sub(rep, line)
    return _WS.sub(" ", line).strip()


def changed_lines(old_code: str, new_code: str) -> tuple[list[int], list[int]]:
    """Eski kodda silinen ve yeni kodda eklenen satırların 1 tabanlı numaraları."""
    a = old_code.splitlines()
    b = new_code.splitlines()
    sm = difflib.SequenceMatcher(None, [norm(x) for x in a], [norm(x) for x in b], autojunk=False)
    removed, added = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(range(i1 + 1, i2 + 1))
        if tag in ("replace", "insert"):
            added.extend(range(j1 + 1, j2 + 1))
    return removed, added


def similarity(old_code: str, new_code: str) -> float:
    a = [norm(x) for x in old_code.splitlines()]
    b = [norm(x) for x in new_code.splitlines()]
    return round(difflib.SequenceMatcher(None, a, b, autojunk=False).ratio(), 3)


@dataclass
class Row:
    """Yan yana görünümde tek satır. Satır yoksa numara None."""
    old_no: int | None
    old_text: str
    new_no: int | None
    new_text: str
    tag: str  # equal | replace | delete | insert


def side_by_side(old_code: str, new_code: str) -> list[Row]:
    a = old_code.splitlines()
    b = new_code.splitlines()
    sm = difflib.SequenceMatcher(None, [norm(x) for x in a], [norm(x) for x in b], autojunk=False)
    rows: list[Row] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append(Row(i1 + k + 1, a[i1 + k], j1 + k + 1, b[j1 + k], "equal"))
        else:
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                oi, nj = i1 + k, j1 + k
                rows.append(Row(
                    oi + 1 if oi < i2 else None, a[oi] if oi < i2 else "",
                    nj + 1 if nj < j2 else None, b[nj] if nj < j2 else "",
                    tag,
                ))
    return rows


def numbered_excerpt(code: str, focus: list[int], context: int = 30, max_lines: int = 400) -> str:
    """Kodu satır numaralarıyla döndür. Uzunsa yalnızca değişen satırların
    çevresini al; atlanan kısımları '...' ile göster. Numaralar orijinal kalır,
    böylece modelin verdiği satır yorumları doğru satıra oturur."""
    lines = code.splitlines()
    width = len(str(len(lines)))
    if len(lines) <= max_lines or not focus:
        keep = set(range(1, min(len(lines), max_lines) + 1))
    else:
        keep = set()
        for f in focus:
            keep.update(range(max(1, f - context), min(len(lines), f + context) + 1))
        keep.update(range(1, min(len(lines), 6) + 1))  # imza her zaman görünsün
    out, prev = [], 0
    for no in sorted(keep):
        if no != prev + 1 and prev != 0:
            out.append(" " * width + " | ...")
        out.append(f"{no:>{width}} | {lines[no - 1]}")
        prev = no
    if len(lines) > max(keep, default=0):
        out.append(" " * width + " | ...")
    return "\n".join(out)
