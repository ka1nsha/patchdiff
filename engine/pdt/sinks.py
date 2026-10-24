"""Sink / guard / source kataloğu ve değişen fonksiyonlarda hızlı tarama.

Patch diffing'de en öğretici soru: "Yama hangi sink'in önüne hangi kontrolü (guard) koydu?"
Bu modül satır düzeyinde, düzenli ifadelerle çalışır (hızlı katman). Taint yolu bulmaz;
o iş `pdt/taint.py`'de (Semgrep) yapılır.

  sink    tehlikeli işlem: SQL sorgusu, komut çalıştırma, eval, deserialization, dosya,
          SSRF, yönlendirme, HTML çıktısı; binary'de memcpy/strcpy/free...
  guard   yamaların eklediği kontrol: nonce/yetki kontrolü, escape/sanitize, prepared
          statement, realpath + prefix kontrolü, safe_load...
  source  kullanıcıdan gelen veri: $_GET, request.args, req.query, getParameter...

Desenler kasıtlı olarak geniştir (önce bak listesi); yanlış pozitif olabilir.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

SINK_CLASSES = {
    "sql": "SQL", "cmd": "command", "code": "code eval", "deser": "deserialization", "file": "file/path",
    "ssrf": "SSRF", "redirect": "redirect", "xss": "HTML output (XSS)", "template": "template",
    "state": "state change", "proto": "prototype pollution", "ldap": "JNDI/LDAP lookup",
    "mem": "memory copy", "free": "free", "alloc": "allocation",
}

EXT_LANG = {
    ".php": "php", ".phtml": "php", ".inc": "php", ".module": "php", ".theme": "php",
    ".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".vue": "js", ".java": "java", ".kt": "java", ".scala": "java", ".groovy": "java", ".jsp": "java",
    ".go": "go", ".rb": "ruby", ".erb": "ruby", ".rake": "ruby", ".cs": "cs", ".cshtml": "cs",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".rs": "rust",
}


@dataclass(frozen=True)
class P:
    name: str
    cls: str
    rx: re.Pattern


def _p(name: str, cls: str, rx: str) -> P:
    return P(name, cls, re.compile(rx, re.IGNORECASE))


CATALOG: dict[str, dict[str, list[P]]] = {
    "php": {
        "sinks": [
            _p("$wpdb->query/get_*", "sql", r"\$wpdb->(query|get_results|get_row|get_var|get_col)\s*\((?![^;]*prepare)"),
            _p("mysqli_query / ->query", "sql", r"\b(mysqli_query|mysql_query|pg_query|sqlite_query)\s*\(|->(query|exec|rawQuery|whereRaw|selectRaw|orderByRaw)\s*\("),
            _p("system/exec", "cmd", r"\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$"),
            _p("eval/assert", "code", r"\b(eval|assert|create_function)\s*\(|preg_replace\s*\(\s*['\"][^'\"]*/e['\"]"),
            _p("call_user_func", "code", r"\bcall_user_func(_array)?\s*\(\s*\$|\$\w+\s*\(\s*\$"),
            _p("unserialize", "deser", r"\b(maybe_)?unserialize\s*\("),
            _p("include/require (değişkenli)", "file", r"\b(include|require)(_once)?\b\s*\(?\s*[^'\";]*\$"),
            _p("file operation", "file", r"\b(file_put_contents|fopen|unlink|move_uploaded_file|copy|rename|readfile|file_get_contents|fwrite|mkdir|rmdir|ZipArchive)\b\s*\("),
            _p("HTTP request (SSRF)", "ssrf", r"\b(wp_remote_(get|post|request|head)|wp_safe_remote_\w+|curl_exec|curl_init|fsockopen|download_url)\s*\("),
            _p("redirect", "redirect", r"\bwp_redirect\s*\(|\bheader\s*\(\s*['\"]Location"),
            _p("echo/print (değişken)", "xss", r"\b(echo|print)\b[^;]*\$|<\?=\s*\$"),
            _p("option/user update", "state", r"\b(update_option|add_option|delete_option|update_user_meta|wp_update_user|wp_insert_user|wp_set_password|set_role|add_role|update_post_meta|wp_delete_\w+)\s*\("),
        ],
        "guards": [
            _p("nonce check", "csrf", r"\b(wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\("),
            _p("capability check", "authz", r"\b(current_user_can|user_can|is_super_admin|map_meta_cap)\s*\("),
            _p("escape", "escape", r"\b(esc_(html|attr|url|url_raw|js|textarea|sql|xml)|htmlspecialchars|htmlentities|wp_kses\w*|strip_tags|addslashes|json_encode)\s*\("),
            _p("sanitize", "sanitize", r"\b(sanitize_\w+|absint|intval|floatval|filter_var|filter_input|validate_file|wp_unslash|ctype_\w+)\s*\(|\(\s*int\s*\)\s*\$"),
            _p("prepared statement", "sql", r"\$wpdb->prepare\s*\(|->prepare\s*\(|bind_param\s*\(|bindValue\s*\("),
            _p("shell escaping", "cmd", r"\b(escapeshellarg|escapeshellcmd)\s*\("),
            _p("path validation", "path", r"\b(realpath|basename|wp_normalize_path|path_is_absolute)\s*\(|\bstr_starts_with\s*\(|strpos\s*\([^)]*\)\s*[!=]==\s*0"),
            _p("allowlist", "allowlist", r"\bin_array\s*\([^)]*,\s*true\s*\)|\barray_key_exists\s*\(|\bpreg_match\s*\(\s*['\"]/\^"),
            _p("character stripping", "sanitize", r"\bpreg_replace\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]['\"]|\bstr_replace\s*\([^;]*,\s*['\"]['\"]\s*,"),
            _p("safe redirect", "redirect", r"\bwp_safe_redirect\s*\(|\bwp_validate_redirect\s*\("),
            _p("allowed_classes", "deser", r"allowed_classes"),
        ],
        "sources": [_p("user input", "input", r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|php://input|\bget_query_var\s*\(|\$request->(get_param|get_body|get_json_params)")],
    },
    "python": {
        "sinks": [
            _p("cursor.execute dinamik", "sql", r"\.(execute|executemany|raw|extra)\s*\((?=.*(%|\.format|f['\"]|\+))"),
            _p("os.system/subprocess shell", "cmd", r"\bos\.(system|popen|exec\w*)\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True"),
            _p("eval/exec", "code", r"(?<![.\w])(eval|exec|compile)\s*\("),
            _p("pickle/yaml/marshal", "deser", r"\b(pickle|cPickle|marshal|dill|jsonpickle|shelve)\.loads?\s*\(|\byaml\.(unsafe_)?load\s*\((?![^)]*SafeLoader)"),
            _p("template string", "template", r"\brender_template_string\s*\(|\bTemplate\s*\(\s*[^'\")]|\bjinja2\.Environment\s*\("),
            _p("file operation", "file", r"(?<![.\w])open\s*\(|\bsend_file\s*\(|\bsend_from_directory\s*\(|\bshutil\.\w+\s*\(|\bos\.(remove|unlink|rename|makedirs)\s*\(|\btarfile\.|\bzipfile\."),
            _p("HTTP request (SSRF)", "ssrf", r"\brequests\.(get|post|put|request|head)\s*\(|\burlopen\s*\(|\bhttpx\.\w+\s*\("),
            _p("redirect", "redirect", r"\b(redirect|HttpResponseRedirect)\s*\("),
            _p("mark_safe / Markup", "xss", r"\b(mark_safe|Markup|SafeString)\s*\(|\|\s*safe\b"),
        ],
        "guards": [
            _p("escape", "escape", r"\b(escape|conditional_escape|html\.escape|markupsafe\.escape|quote|urlencode)\s*\("),
            _p("shlex.quote", "cmd", r"\bshlex\.quote\s*\("),
            _p("path validation", "path", r"\b(os\.path\.(realpath|abspath|normpath|commonpath)|safe_join|secure_filename|is_relative_to)\s*\(|\.startswith\s*\("),
            _p("safe_load", "deser", r"\byaml\.safe_load\s*\(|SafeLoader"),
            _p("safe redirect", "redirect", r"\b(url_has_allowed_host_and_scheme|is_safe_url)\s*\("),
            _p("authorization check", "authz", r"@(login_required|permission_required|user_passes_test)|\b(has_perm|check_permission|has_permission)\s*\("),
            _p("input validation", "sanitize", r"(?<![.\w])(int|float)\s*\(|\bre\.(fullmatch|match)\s*\(|\bvalidate\w*\s*\("),
            _p("parameterized query", "sql", r"\.execute\s*\([^,]+,\s*[\[(\{]"),
            _p("character stripping", "sanitize", r"\bre\.sub\s*\([^,]+,\s*['\"]['\"]"),
        ],
        "sources": [_p("user input", "input", r"\brequest\.(args|form|values|json|data|files|cookies|headers|GET|POST|body|query_params|FILES|COOKIES|META)\b")],
    },
    "js": {
        "sinks": [
            _p("child_process", "cmd", r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\(|child_process"),
            _p("eval/Function", "code", r"(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(run\w*|compileFunction)\s*\(|setTimeout\s*\(\s*['\"`]"),
            _p("HTML output", "xss", r"\.(innerHTML|outerHTML)\s*=|\bdocument\.write\s*\(|dangerouslySetInnerHTML|\.html\s*\(\s*[^)]|\bv-html\b"),
            _p("redirect", "redirect", r"\bres\.redirect\s*\(|\blocation(\.href)?\s*=|\bwindow\.open\s*\("),
            _p("file operation", "file", r"\bfs\.(readFile|writeFile|createReadStream|createWriteStream|unlink|rm|readdir|open)\w*\s*\(|\bres\.(sendFile|download)\s*\(|\bpath\.join\s*\("),
            _p("prototype write", "proto", r"__proto__|\bconstructor\s*\]\s*\[|\[\s*\w+\s*\]\s*=\s*[^=]|\b(merge|extend|defaultsDeep|set)\s*\("),
            _p("SQL query", "sql", r"\.(query|raw|execute)\s*\(\s*[`'\"][^`'\"]*\$\{|\.(query|raw)\s*\([^,)]*\+"),
            _p("HTTP request (SSRF)", "ssrf", r"\b(fetch|axios(\.\w+)?|got|request)\s*\(|\bhttps?\.(get|request)\s*\("),
            _p("dynamic RegExp", "code", r"\bnew\s+RegExp\s*\(\s*[^'\"/]"),
        ],
        "guards": [
            _p("escape/sanitize", "escape", r"\b(escape\w*|sanitize\w*|encodeURIComponent|encodeURI|DOMPurify\.sanitize|xss)\s*\("),
            _p("path validation", "path", r"\bpath\.(normalize|resolve|relative)\s*\(|\.startsWith\s*\(|\bisAbsolute\s*\("),
            _p("prototype guard", "proto", r"hasOwnProperty|Object\.create\s*\(\s*null\s*\)|['\"]__proto__['\"]\s*[!=]==|['\"](constructor|prototype)['\"]|Object\.freeze"),
            _p("input validation", "sanitize", r"\b(parseInt|Number|validator\.\w+|isValid\w*|Joi\.|zod\.|z\.)\s*[.(]|\.test\s*\("),
            _p("parameterized query", "sql", r"\.(query|execute)\s*\([^,]+,\s*\["),
            _p("character stripping", "sanitize", r"\.replace(All)?\s*\(\s*/[^/]+/\w*\s*,\s*['\"`]['\"`]"),
            _p("authorization check", "authz", r"\b(isAuthenticated|authorize|requireAuth|checkPermission|hasRole|csrf\w*)\s*\("),
        ],
        "sources": [_p("user input", "input", r"\breq\.(query|body|params|headers|cookies|files)\b|\blocation\.(search|hash)|\bprocess\.argv|\bctx\.(query|request|params)")],
    },
    "java": {
        "sinks": [
            _p("Runtime.exec/ProcessBuilder", "cmd", r"Runtime\.getRuntime\(\)\.exec\s*\(|\bnew\s+ProcessBuilder\s*\("),
            _p("ObjectInputStream/XMLDecoder", "deser", r"\bnew\s+(ObjectInputStream|XMLDecoder)\s*\(|\.readObject\s*\(|\bXStream\b|\.fromXML\s*\(|enableDefaultTyping|activateDefaultTyping"),
            _p("YAML load", "deser", r"\bnew\s+Yaml\s*\(\s*\)|\.load(All)?\s*\("),
            _p("SQL string concat", "sql", r"\b(createStatement|executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\s*\([^)]*\+"),
            _p("expression evaluation", "code", r"\bOgnl\w*\.|OgnlUtil|\.getValue\s*\(|\bparseExpression\s*\(|\bELProcessor\b|\bValueExpression\b|\bScriptEngine\b|\.eval\s*\(|\bStringSubstitutor\b|\bGroovyShell\b"),
            _p("JNDI lookup", "ldap", r"\.lookup\s*\(|\bInitialContext\b|\bJndiLookup\b"),
            _p("file operation", "file", r"\bnew\s+File(InputStream|OutputStream|Reader|Writer)?\s*\(|\bFiles\.(write|read\w*|newInputStream|newOutputStream|copy|delete)\s*\(|\bPaths\.get\s*\("),
            _p("redirect", "redirect", r"\.sendRedirect\s*\("),
            _p("reflection", "code", r"\bClass\.forName\s*\(|\.newInstance\s*\(|\.setAccessible\s*\(\s*true|\.invoke\s*\("),
            _p("HTTP request (SSRF)", "ssrf", r"\bnew\s+URL\s*\(|\.openConnection\s*\(|\bHttpClient\b"),
        ],
        "guards": [
            _p("prepared statement", "sql", r"\bprepareStatement\s*\(|\.set(String|Int|Long|Object)\s*\(\s*\d|setParameter\s*\("),
            _p("path validation", "path", r"\.(normalize|getCanonicalPath|toRealPath)\s*\(|\.startsWith\s*\("),
            _p("allow/deny list", "allowlist", r"(?i)(allow|white|deny|black)list|isAllowed\w*|ObjectInputFilter|setObjectInputFilter|resolveClass|ValidatingObjectInputStream|SafeConstructor|allowTypes|denyTypes|excludedClasses"),
            _p("escape", "escape", r"\b(escapeHtml\w*|encodeFor\w+|StringEscapeUtils\.\w+|HtmlUtils\.\w+|ESAPI)\b"),
            _p("input validation", "sanitize", r"\bPattern\.matches\s*\(|\.matches\s*\(|\bInteger\.parseInt\s*\(|\bisValid\w*\s*\("),
            _p("authorization check", "authz", r"@(PreAuthorize|Secured|RolesAllowed)|\b(checkPermission|hasPermission|isUserInRole|hasRole)\s*\("),
        ],
        "sources": [_p("user input", "input", r"\.(getParameter\w*|getHeader\w*|getCookies|getInputStream|getQueryString|getReader|getPathInfo|getRequestURI)\s*\(|@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)")],
    },
    "go": {
        "sinks": [
            _p("exec.Command", "cmd", r"\bexec\.Command(Context)?\s*\("),
            _p("SQL string concat", "sql", r"\.(Query|QueryRow|Exec)(Context)?\s*\([^)]*(\+|Sprintf)"),
            _p("file operation", "file", r"\bos\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Rename|MkdirAll)\s*\(|\bfilepath\.Join\s*\(|\bhttp\.ServeFile\s*\(|\bioutil\.\w+File\s*\(|\bzip\.\w+|\btar\.\w+"),
            _p("template.HTML", "xss", r"\btemplate\.(HTML|JS|URL)\s*\("),
            _p("redirect", "redirect", r"\bhttp\.Redirect\s*\(|\.Redirect\s*\("),
            _p("HTTP request (SSRF)", "ssrf", r"\bhttp\.(Get|Post|Head|NewRequest)\w*\s*\(|\.Do\s*\(\s*req"),
            _p("unsafe", "mem", r"\bunsafe\.\w+"),
        ],
        "guards": [
            _p("path validation", "path", r"\bfilepath\.(Clean|Rel|IsLocal|Abs|EvalSymlinks)\s*\(|\bstrings\.HasPrefix\s*\(|\bsecurejoin\b|\bfilepath\.IsAbs\s*\("),
            _p("escape", "escape", r"\b(html|template)\.(EscapeString|HTMLEscapeString|JSEscapeString)\s*\(|\burl\.(QueryEscape|PathEscape)\s*\("),
            _p("input validation", "sanitize", r"\bstrconv\.(Atoi|ParseInt|ParseUint)\s*\(|\bregexp\.\w+|\bnetip\.\w+|\.IsLoopback\s*\(|\.IsPrivate\s*\("),
            _p("parameterized query", "sql", r"\.(Query|QueryRow|Exec)(Context)?\s*\([^,]*,\s*\w"),
            _p("authorization check", "authz", r"\b(checkPermission|CanAccess|IsAdmin|HasPermission|requireAuth)\w*\s*\("),
        ],
        "sources": [_p("user input", "input", r"\br\.(URL\.Query|FormValue|PostFormValue|Form|PostForm|Header|Body|Cookie)\b|\bc\.(Param|Query|PostForm|FormValue|Bind\w*)\s*\(|\bctx\.(Params|Query|FormValue)\s*\(")],
    },
    "ruby": {
        "sinks": [
            _p("command execution", "cmd", r"(?<![.\w])(system|exec|spawn)\s*\(|`[^`]*#\{|%x\{|\bIO\.popen\s*\(|\bOpen3\.\w+"),
            _p("eval/send", "code", r"\b(eval|instance_eval|class_eval|module_eval)\b|\.(send|public_send|constantize|safe_constantize)\s*\("),
            _p("YAML/Marshal", "deser", r"\bYAML\.(load|unsafe_load)\b(?!_file)|\bMarshal\.load\b|\bPsych\.load\b"),
            _p("SQL string concat", "sql", r"\b(find_by_sql|where|order|pluck|select|joins|execute|exec_query)\s*\(?\s*['\"][^'\"]*#\{"),
            _p("file operation", "file", r"\bFile\.(open|read|write|delete|join)\b|\bsend_file\b|\bFileUtils\.\w+"),
            _p("redirect", "redirect", r"\bredirect_to\b"),
            _p("HTML output", "xss", r"\.html_safe\b|\braw\s*\(|render\s+inline:|<%==\s"),
        ],
        "guards": [
            _p("escape/sanitize", "escape", r"\b(sanitize|h|html_escape|ERB::Util\.\w+|CGI\.escape\w*)\s*\("),
            _p("safe_load", "deser", r"\bYAML\.safe_load\b|permitted_classes"),
            _p("strong parameters", "sanitize", r"\.permit\s*\(|\brequire\(\s*:"),
            _p("shell escaping", "cmd", r"\bShellwords\.\w+|\.shellescape\b"),
            _p("path validation", "path", r"\bFile\.(expand_path|realpath|basename)\b|\.start_with\?\s*\("),
            _p("authorization check", "authz", r"\b(authorize!?|can\?|cannot\?|authenticate\w*|policy_scope)\b"),
        ],
        "sources": [_p("user input", "input", r"\bparams\s*\[|\brequest\.(params|headers|body|cookies|query_string|env)\b|\bcookies\s*\[")],
    },
    "cs": {
        "sinks": [
            _p("Process.Start", "cmd", r"\bProcess\.Start\s*\(|\bProcessStartInfo\b"),
            _p("deserialization", "deser", r"\b(BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|JavaScriptSerializer)\b|TypeNameHandling\.(All|Auto|Objects)"),
            _p("SQL string concat", "sql", r"\b(SqlCommand|ExecuteSqlRaw|FromSqlRaw|ExecuteReader)\b[^;]*\+"),
            _p("file operation", "file", r"\bFile\.(ReadAll\w*|WriteAll\w*|Open\w*|Delete|Copy|Move)\s*\(|\bPath\.Combine\s*\("),
            _p("redirect", "redirect", r"\bRedirect\s*\("),
            _p("HTML output", "xss", r"\bHtml\.Raw\s*\(|\bMvcHtmlString\b"),
        ],
        "guards": [
            _p("path validation", "path", r"\bPath\.GetFullPath\s*\(|\.StartsWith\s*\("),
            _p("escape", "escape", r"\b(HtmlEncode|UrlEncode|AntiXss|Encoder\.\w+)\s*\("),
            _p("parameterized query", "sql", r"\bParameters\.(Add|AddWithValue)\s*\(|\bSqlParameter\b"),
            _p("authorization check", "authz", r"\[Authorize|\bIsInRole\s*\(|\bValidateAntiForgeryToken\b"),
            _p("type restriction", "deser", r"SerializationBinder|KnownTypes|TypeNameHandling\.None"),
        ],
        "sources": [_p("user input", "input", r"\bRequest\.(Query|Form|QueryString|Headers|Cookies|Body|Params)\b|\[From(Query|Body|Form|Route)\]")],
    },
    "c": {
        "sinks": [
            _p("memory copy", "mem", r"\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|vsprintf|wcscpy|wcscat|gets|RtlCopyMemory|RtlMoveMemory|copy_from_user|copy_to_user|__memcpy_chk|__strcpy_chk)\s*\("),
            _p("alloca", "alloc", r"\b(alloca|_alloca|__builtin_alloca)\s*\("),
            _p("free", "free", r"\b(free|kfree|ExFreePool\w*|HeapFree|RtlFreeHeap|operator_delete)\s*\("),
            _p("allocation", "alloc", r"\b(malloc|calloc|realloc|kmalloc|kzalloc|kvmalloc|ExAllocatePool\w*|HeapAlloc|RtlAllocateHeap|operator_new)\s*\("),
            _p("command execution", "cmd", r"\b(system|popen|execve|execl\w*|CreateProcess\w*|WinExec|ShellExecute\w*)\s*\("),
        ],
        "guards": [],          # C için guard'ları triage kuralları (bounds_check, int_overflow, access_check) bulur
        "sources": [_p("external input", "input", r"\b(recv|recvfrom|read|fread|getenv|copy_from_user|ProbeForRead|NtReadFile)\s*\(")],
    },
}
CATALOG["rust"] = {"sinks": [_p("unsafe", "mem", r"\bunsafe\s*\{|\bptr::(copy|write)\w*|\bfrom_raw_parts\b"),
                             _p("command execution", "cmd", r"\bCommand::new\s*\(")],
                   "guards": [_p("bounds check", "sanitize", r"\.(checked_\w+|get)\s*\(")], "sources": []}


def lang_for(path: str, backend: str = "") -> str:
    if backend in ("ghidriff", "angr"):
        return "c"
    return EXT_LANG.get(PurePosixPath(path.split("::")[0]).suffix.lower(), "")


def scan(code: str, lang: str) -> list[dict[str, Any]]:
    """Kodda sink/guard/source geçen satırlar: [{line, kind, name, cls, text}]."""
    cat = CATALOG.get(lang)
    if not cat:
        return []
    out = []
    for no, line in enumerate(code.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("//", "#", "*", "/*")):
            continue
        for kind in ("sinks", "guards", "sources"):
            for p in cat[kind]:
                if p.rx.search(line):
                    out.append({"line": no, "kind": kind[:-1], "name": p.name, "cls": p.cls, "text": s[:200]})
                    break
    return out


def analyze(old_code: str, new_code: str, removed: list[int], added: list[int], lang: str) -> dict[str, Any]:
    """Değişen bir fonksiyon için sink özeti. Boş sözlük: dil desteklenmiyor."""
    if lang not in CATALOG:
        return {}
    old, new = scan(old_code, lang), scan(new_code, lang)
    added_set, removed_set = set(added), set(removed)
    sinks_new = [h for h in new if h["kind"] == "sink"]
    sinks_old = [h for h in old if h["kind"] == "sink"]
    guards_added = [h for h in new if h["kind"] == "guard" and h["line"] in added_set]
    guards_removed = [h for h in old if h["kind"] == "guard" and h["line"] in removed_set]
    sinks_touched = [h for h in sinks_new if h["line"] in added_set] + \
                    [dict(h, side="old") for h in sinks_old if h["line"] in removed_set]
    old_names = {(h["name"], h["text"]) for h in sinks_old}
    new_names = {(h["name"], h["text"]) for h in sinks_new}
    rem = [h for h in sinks_old if h["line"] in removed_set and (h["name"], h["text"]) not in new_names]
    add = [h for h in sinks_new if h["line"] in added_set and (h["name"], h["text"]) not in old_names]
    # Aynı sink hem silinen hem eklenen satırlarda: çağrı kaldırılmamış, argümanı değiştirilmiş
    both = {h["name"] for h in rem} & {h["name"] for h in add}
    sinks_modified = [h for h in add if h["name"] in both]
    sinks_removed = [h for h in rem if h["name"] not in both]
    sinks_added = [h for h in add if h["name"] not in both]
    sources = [h for h in new if h["kind"] == "source"] or [h for h in old if h["kind"] == "source"]
    summary = []
    sink_classes = sorted({h["cls"] for h in sinks_new + sinks_old})
    if guards_added and (sinks_new or sinks_old):
        summary.append(f"Yama, {', '.join(SINK_CLASSES.get(c, c) for c in sink_classes)} sink'i içeren fonksiyona "
                       f"guard ekledi: {', '.join(sorted({g['name'] for g in guards_added}))}.")
    elif guards_added:
        summary.append(f"Yama guard ekledi: {', '.join(sorted({g['name'] for g in guards_added}))}.")
    if sinks_modified:
        summary.append(f"Sink çağrısının argümanı değiştirildi: {', '.join(sorted({s['name'] for s in sinks_modified}))}.")
    if sinks_removed:
        summary.append(f"Sink çağrısı kaldırıldı: {', '.join(sorted({s['name'] for s in sinks_removed}))}.")
    if sinks_added:
        summary.append(f"Yeni sink çağrısı eklendi: {', '.join(sorted({s['name'] for s in sinks_added}))}.")
    if sources and (sinks_new or sinks_old):
        summary.append("Fonksiyon kullanıcı girdisi (source) okuyor ve aynı fonksiyonda sink var.")
    return {"lang": lang, "sinks_old": sinks_old, "sinks_new": sinks_new, "guards_added": guards_added,
            "guards_removed": guards_removed, "sinks_touched": sinks_touched, "sinks_removed": sinks_removed, "sinks_modified": sinks_modified,
            "sinks_added": sinks_added, "sources": sources[:10], "classes": sink_classes, "summary": summary}
