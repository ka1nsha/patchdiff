"""Açıklık kataloğu: sabitler, tohum (seed) şeması ve doğrulama.

Her ders `seed/<kategori>/<CVE>.json` dosyasında tutulur (PLAN.md §4.1). Bu modül
web bağımlılığı olmadan çalışır, böylece katalog dosyaları tek başına doğrulanabilir:

    python -m pdt_web.catalog seed/
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# --- Sabitler (PLAN.md §3.2, §3.3, §3.4) ------------------------------------

CATEGORIES: dict[str, dict[str, Any]] = {
    "os": {"name": "İşletim sistemleri", "short": "İşletim sistemleri",
           "subcategories": {"linux": "Linux kernel", "windows": "Windows", "apple": "macOS/iOS",
                             "android": "Android"}},
    "sys": {"name": "Sistem yazılımları ve kütüphaneler", "short": "Sistem yazılımları", "subcategories": {}},
    "websrv": {"name": "Web sunucuları ve altyapı", "short": "Web sunucuları", "subcategories": {}},
    "runtime": {"name": "Dil çalışma zamanları", "short": "Dil çalışma zamanları", "subcategories": {}},
    "webapp": {"name": "Web framework'leri ve uygulamalar", "short": "Web framework'leri", "subcategories": {}},
    "pkg": {"name": "Paket ekosistemleri", "short": "Paket ekosistemleri", "subcategories": {}},
}

ERAS: dict[str, dict[str, Any]] = {
    "e1": {"start": 2000, "end": 2005, "years": "2000–2005", "title": "KORUMASIZ DÖNEM",
           "desc": "Stack overflow, format string, double free.",
           "protections": "Stack canary yaygınlaşıyor; NX ve ASLR yeni ve kısmi."},
    "e2": {"start": 2006, "end": 2012, "years": "2006–2012", "title": "WEB'İN YÜKSELİŞİ",
           "desc": "SQL injection, XSS, CGI, zayıf randomness.",
           "protections": "NX ve ASLR yaygın; tarayıcı sandbox'ları geliyor."},
    "e3": {"start": 2013, "end": 2018, "years": "2013–2018", "title": "BÜYÜK İSİMLİ AÇIKLAR",
           "desc": "Parser hataları, deserialization, framework RCE.",
           "protections": "Stack canary, NX, ASLR, sandbox; ilk CFI uygulamaları."},
    "e4": {"start": 2019, "end": 9999, "years": "2019–bugün", "title": "YENİ NESİL HATALAR",
           "desc": "Kernel UAF, supply chain, mobil zero-click, regresyonlar.",
           "protections": "CFI, MTE, hardened heap allocator'lar."},
}

# Öğrenme yolu sırası (PLAN.md §3.4). path=None: yolun dışında, ayrı listelenir.
BUG_CLASSES: dict[str, dict[str, Any]] = {
    "oob": {"name": "Out-of-bounds read/write", "path": 1},
    "int": {"name": "Integer overflow", "path": 2},
    "uaf": {"name": "Use-after-free", "path": 3},
    "race": {"name": "Race condition", "path": 4},
    "logic": {"name": "Logic bug", "path": 5},
    "inj": {"name": "Injection", "path": 5},
    "mem": {"name": "Diğer memory corruption hataları", "path": None},
    "supply": {"name": "Supply chain", "path": None},
}
PATH_STEPS: list[dict[str, Any]] = [
    {"step": 1, "name": "Out-of-bounds read/write", "classes": ["oob"]},
    {"step": 2, "name": "Integer overflow", "classes": ["int"]},
    {"step": 3, "name": "Use-after-free (UAF)", "classes": ["uaf"]},
    {"step": 4, "name": "Race condition", "classes": ["race"]},
    {"step": 5, "name": "Logic bug ve injection", "classes": ["logic", "inj"]},
]
OFF_PATH: list[dict[str, Any]] = [
    {"step": None, "name": "Diğer memory corruption hataları", "classes": ["mem"]},
    {"step": None, "name": "Supply chain", "classes": ["supply"]},
]

DIFFICULTIES = {"baslangic": "başlangıç", "orta": "orta", "ileri": "ileri"}
STATUSES = {"aday": "aday", "taslak": "taslak", "onayli": "onaylı"}
DIFF_TYPES = {"binary+kaynak", "kaynak", "binary"}   # binary: kaynak kodu yok (Windows vb.)
SOURCE_PACKAGES = ("wordpress", "pypi", "npm", "rubygems", "maven", "packagist", "go", "github", "nuget")   # kaynak diff
BINARY_SOURCES = ("debian", "winbindex", "url") + SOURCE_PACKAGES
SOURCE_TYPES = {"duyuru": "DUYURU", "duzeltme": "DÜZELTME", "analiz": "ANALİZ"}
RELATIONS = {"regresyon": "regresyon", "atlatma": "yamanın atlatılması", "aile": "aynı hata ailesi"}

# Kapsam (PLAN.md §3.1): kaynak listelerinde exploit/PoC deposu olmaz.
EXPLOIT_URL = re.compile(
    r"exploit-db\.com|exploitdb|packetstorm|0day\.today|sploitus|cxsecurity|vulhub|"
    r"rapid7\.com/db/modules|metasploit|github\.com/[^/]+/[^/]*(exploit|poc|PoC|POC)|"
    r"/(exploits?|pocs?)(/|$)|[-_](exploit|poc)[-_./]",
    re.IGNORECASE)

CVE_ID = re.compile(r"^CVE-(\d{4})-\d{4,}$")
CWE_ID = re.compile(r"^CWE-\d+$")
MAX_DIFF_LINES = 160


def era_for_year(year: int) -> str:
    for code, e in ERAS.items():
        if e["start"] <= year <= e["end"]:
            return code
    raise ValueError(f"{year} için dönem yok (2000'den önce mi?)")


# --- Doğrulama --------------------------------------------------------------

@dataclass
class Problem:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def _nonempty_str(d: dict, key: str) -> bool:
    return isinstance(d.get(key), str) and d[key].strip() != ""


def _looks_like_unified_diff(text: str) -> bool:
    lines = text.splitlines()
    return any(l.startswith("@@") for l in lines) and all(
        l == "" or l[0] in " +-@\\" or l.startswith(("diff ", "index ", "--- ", "+++ ", "new file", "deleted file"))
        for l in lines)


def validate_lesson(d: dict[str, Any], where: str = "") -> list[Problem]:
    """Tek bir ders kaydını doğrula. Boş liste = geçerli."""
    p: list[Problem] = []

    def bad(msg: str) -> None:
        p.append(Problem(where, msg))

    lid = d.get("id", "")
    m = CVE_ID.match(lid) if isinstance(lid, str) else None
    if not m:
        bad(f"id bir CVE kimliği olmalı (ör. CVE-2014-0160), gelen: {lid!r}")
    for key in ("alias", "component", "teaser", "context"):
        if not _nonempty_str(d, key):
            bad(f"'{key}' boş olamaz")

    cat = d.get("category")
    if cat not in CATEGORIES:
        bad(f"category şunlardan biri olmalı: {', '.join(CATEGORIES)}")
    else:
        subs = CATEGORIES[cat]["subcategories"]
        if subs and d.get("subcategory") not in subs:
            bad(f"'{cat}' kategorisinde subcategory şunlardan biri olmalı: {', '.join(subs)}")

    year = d.get("year")
    if not isinstance(year, int) or not (2000 <= year <= 2100):
        bad("year 2000 veya sonrası bir tamsayı olmalı (duyuru yılı)")
    elif d.get("era") != era_for_year(year):
        bad(f"era {year} yılı için {era_for_year(year)} olmalı")

    cwe = d.get("cwe")
    if cwe is not None and not (isinstance(cwe, str) and CWE_ID.match(cwe)):
        bad("cwe 'CWE-<sayı>' biçiminde ya da null olmalı (doğrulanamadıysa null)")
    if d.get("bug_class") not in BUG_CLASSES:
        bad(f"bug_class şunlardan biri olmalı: {', '.join(BUG_CLASSES)}")
    if not _nonempty_str(d, "bug_detail"):
        bad("bug_detail boş olamaz (ör. 'heap taşması', 'komut enjeksiyonu')")
    if d.get("difficulty") not in DIFFICULTIES:
        bad(f"difficulty şunlardan biri olmalı: {', '.join(DIFFICULTIES)}")
    if d.get("status") not in STATUSES:
        bad(f"status şunlardan biri olmalı: {', '.join(STATUSES)}")
    if d.get("diff_type") not in DIFF_TYPES:
        bad(f"diff_type şunlardan biri olmalı: {', '.join(sorted(DIFF_TYPES))}")

    kev = d.get("kev")
    if kev not in (True, False, None):
        bad("kev true, false ya da null (doğrulanmadı) olmalı")
    if kev is True and not _nonempty_str(d, "kev_source"):
        bad("kev true ise kev_source (CISA KEV veya Project Zero bağlantısı) gerekli")

    for key in ("affected_versions", "fixed_versions", "protections"):
        if d.get(key) is not None and not isinstance(d.get(key), str):
            bad(f"{key} metin ya da null olmalı")

    sources = d.get("sources")
    if not isinstance(sources, list) or not sources:
        bad("sources en az bir kaynak içermeli (PLAN.md §5: en az bir resmi kaynak)")
        sources = []
    for i, s in enumerate(sources):
        if not isinstance(s, dict) or s.get("type") not in SOURCE_TYPES or not _nonempty_str(s, "url") \
                or not _nonempty_str(s, "title"):
            bad(f"sources[{i}] {{type: {'|'.join(SOURCE_TYPES)}, title, url}} olmalı")
            continue
        if EXPLOIT_URL.search(s["url"]):
            bad(f"sources[{i}] exploit/PoC kaynağı olamaz: {s['url']}")
    if not any(isinstance(s, dict) and s.get("type") == "duyuru" for s in sources):
        bad("en az bir 'duyuru' türünde resmi kaynak gerekli (üretici duyurusu, NVD, dağıtım duyurusu)")

    fix = d.get("fix")
    if fix is not None:
        if not isinstance(fix, dict):
            bad("fix bir nesne ya da null olmalı")
        else:
            for key in ("url", "file", "diff"):
                if not _nonempty_str(fix, key):
                    bad(f"fix.{key} boş olamaz")
            diff = fix.get("diff") or ""
            n = len(diff.splitlines())
            if n > MAX_DIFF_LINES:
                bad(f"fix.diff {n} satır; en fazla {MAX_DIFF_LINES} (yalnızca ilgili hunk'lar)")
            if diff and not _looks_like_unified_diff(diff):
                bad("fix.diff birleşik (unified) diff biçiminde olmalı (@@ başlıkları, +/-/boşluk önekli satırlar)")
            if EXPLOIT_URL.search(fix.get("url") or ""):
                bad("fix.url exploit/PoC kaynağı olamaz")

    ans = d.get("answer")
    if not isinstance(ans, dict) or not _nonempty_str(ans, "root_cause") or not _nonempty_str(ans, "patch_effect"):
        bad("answer {root_cause, patch_effect, key_points} gerekli")
    else:
        kp = ans.get("key_points")
        if not isinstance(kp, list) or not (2 <= len(kp) <= 6) or not all(isinstance(x, str) and x.strip() for x in kp):
            bad("answer.key_points 2-6 maddelik bir metin listesi olmalı")

    hints = d.get("hints")
    if not isinstance(hints, list) or not (1 <= len(hints) <= 4) or not all(isinstance(h, str) and h.strip() for h in hints):
        bad("hints 1-4 maddelik bir metin listesi olmalı (cevabı söylemeyen kademeli ipuçları)")

    for i, ln in enumerate(d.get("lineage") or []):
        if not isinstance(ln, dict) or not (isinstance(ln.get("cve"), str) and CVE_ID.match(ln["cve"])) \
                or ln.get("relation") not in RELATIONS or not _nonempty_str(ln, "source"):
            bad(f"lineage[{i}] {{cve, relation: {'|'.join(RELATIONS)}, note, source}} olmalı; kaynaksız bağlantı eklenmez")

    if d.get("sink") is not None:
        for msg in validate_sink(d["sink"]):
            bad(f"sink: {msg}")

    binaries = d.get("binaries")
    if binaries is not None:
        for msg in validate_binaries(binaries):
            bad(f"binaries: {msg}")
    if d.get("diff_type") == "binary":
        # Kaynağı olmayan (Windows vb.) derste cevap anahtarı yayımlanmış bir kök neden analizine dayanır.
        if not binaries:
            bad("diff_type 'binary' ise binaries (indirilecek yama öncesi/sonrası çifti) gerekli")
        if not any(isinstance(s, dict) and s.get("type") == "analiz" for s in sources):
            bad("diff_type 'binary' ise cevap anahtarının dayandığı en az bir 'analiz' kaynağı gerekli")
    elif d.get("status") in ("taslak", "onayli") and fix is None:
        bad("taslak/onaylı derste fix (düzeltme diff'i) bulunmalı; yoksa status 'aday' olmalı")

    ver = d.get("verification")
    if not isinstance(ver, dict) or not _nonempty_str(ver, "checked_at") or not _nonempty_str(ver, "notes"):
        bad("verification {checked_at: YYYY-AA-GG, notes: hangi alan hangi kaynaktan doğrulandı} gerekli")

    if m and isinstance(where, str) and where and Path(where).stem != lid:
        bad(f"dosya adı ders kimliğiyle aynı olmalı: {lid}.json")
    return p


def validate_sink(sk: Any) -> list[str]:
    """`sink` alanı: yamanın kapattığı source → sink yolu ve eklediği guard (cevap anahtarının parçası)."""
    from pdt.sinks import SINK_CLASSES
    if not isinstance(sk, dict):
        return ["bir nesne olmalı"]
    p = []
    if sk.get("class") not in SINK_CLASSES:
        p.append(f"class şunlardan biri olmalı: {', '.join(SINK_CLASSES)}")
    if not _nonempty_str(sk, "sink"):
        p.append("sink gerekli (ör. \"$wpdb->get_results()\", \"Runtime.exec\", \"memcpy\")")
    for k in ("source", "guard"):
        if sk.get(k) is not None and not isinstance(sk.get(k), str):
            p.append(f"{k} metin ya da null olmalı")
    return p


def validate_binaries(b: Any) -> list[str]:
    """`binaries` alanı: pdt.fetch'in indireceği yama öncesi/sonrası çifti (ağ erişimi yapmaz)."""
    if not isinstance(b, dict):
        return ["bir nesne olmalı"]
    src = b.get("source")
    if src not in BINARY_SOURCES:
        return [f"source şunlardan biri olmalı: {', '.join(BINARY_SOURCES)}"]
    p: list[str] = []
    if src == "debian":
        for k in ("old", "new"):
            if not _nonempty_str(b, k):
                p.append(f"debian kaynağında '{k}' gerekli")
        for k in ("package", "path"):
            if not (_nonempty_str(b, k) or (_nonempty_str(b, f"old_{k}") and _nonempty_str(b, f"new_{k}"))):
                p.append(f"debian kaynağında '{k}' (ya da old_{k} + new_{k}) gerekli")
        if b.get("old") and b.get("old") == b.get("new"):
            p.append("old ve new aynı sürüm olamaz")
    elif src in SOURCE_PACKAGES:
        for k in ("package", "old", "new"):
            if not _nonempty_str(b, k):
                p.append(f"{src} kaynağında '{k}' gerekli")
        if src == "wordpress" and not re.fullmatch(r"(plugin|theme):[a-z0-9-]+|core", str(b.get("package", ""))):
            p.append("wordpress paketi 'plugin:<slug>', 'theme:<slug>' ya da 'core' olmalı")
        if src == "maven" and ":" not in str(b.get("package", "")):
            p.append("maven paketi 'groupId:artifactId' olmalı")
        if b.get("old") and b.get("old") == b.get("new"):
            p.append("old ve new aynı sürüm olamaz")
    elif src == "winbindex":
        if not _nonempty_str(b, "file"):
            p.append("winbindex kaynağında 'file' gerekli (ör. afd.sys)")
        if not (_nonempty_str(b, "kb") or (_nonempty_str(b, "old_version") and _nonempty_str(b, "new_version"))):
            p.append("winbindex kaynağında 'kb' ya da 'old_version' + 'new_version' gerekli")
        if b.get("arch", "x64") not in ("x64", "x86", "arm64", "arm"):
            p.append("arch x64, x86, arm64 ya da arm olmalı")
    else:
        if not _nonempty_str(b, "name"):
            p.append("url kaynağında 'name' gerekli")
        for side in ("old", "new"):
            s = b.get(side)
            if not isinstance(s, dict) or not str(s.get("url", "")).startswith("https://") \
                    or not re.fullmatch(r"[0-9a-fA-F]{64}", str(s.get("sha256", ""))):
                p.append(f"{side} {{url: https://..., sha256}} olmalı")
            elif EXPLOIT_URL.search(s["url"]):
                p.append(f"{side}.url exploit/PoC kaynağı olamaz")
    if b.get("function") is not None and not _nonempty_str(b, "function"):
        p.append("function metin olmalı")
    return p


def load_seed(seed_dir: Path) -> tuple[list[dict[str, Any]], list[Problem]]:
    """seed/ altındaki tüm ders dosyalarını oku ve doğrula."""
    lessons: list[dict[str, Any]] = []
    problems: list[Problem] = []
    seen: dict[str, str] = {}
    for f in sorted(seed_dir.rglob("CVE-*.json")):
        rel = str(f.relative_to(seed_dir.parent)) if seed_dir.parent in f.parents else str(f)
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            problems.append(Problem(rel, f"geçerli JSON değil: {e}"))
            continue
        errs = validate_lesson(d, str(f))
        for e in errs:
            e.path = rel
        problems.extend(errs)
        if d.get("category") and f.parent.name != d.get("category"):
            problems.append(Problem(rel, f"dosya seed/{d.get('category')}/ klasöründe olmalı"))
        if d.get("id") in seen:
            problems.append(Problem(rel, f"aynı ders iki kez var: {seen[d['id']]}"))
        seen[d.get("id", "")] = rel
        if not errs:
            lessons.append(d)
    ids = set(seen)
    for d in lessons:
        for ln in d.get("lineage") or []:
            if ln["cve"] not in ids:
                # Katalogda olmayan bir CVE'ye bağlantı geçerlidir; yalnızca not düşülür.
                ln.setdefault("in_catalog", False)
            else:
                ln.setdefault("in_catalog", True)
    return lessons, problems


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if hasattr(sys.stdout, "reconfigure"):   # Windows konsolu cp1252 olabilir
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    seed_dir = Path(args[0] if args else "seed")
    lessons, problems = load_seed(seed_dir)
    for pr in problems:
        print(f"[hata] {pr}")
    by_cat: dict[str, int] = {}
    for d in lessons:
        by_cat[d["category"]] = by_cat.get(d["category"], 0) + 1
    print(f"{len(lessons)} geçerli ders · " + ", ".join(f"{k}: {v}" for k, v in sorted(by_cat.items())))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
