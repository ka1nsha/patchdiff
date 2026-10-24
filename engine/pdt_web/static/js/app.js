/* patchdiff-tutor · küçük etkileşimler (DESIGN.md §8).
   Sayfalar JS olmadan da çalışır; bu dosya yalnızca kolaylık ekler. */
(function () {
  "use strict";

  function store(key, val) {
    try {
      if (val === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, val);
    } catch (e) { return null; }
  }

  /* --- Diff: yorumları göster/gizle, birleşik / yan yana, katlama --- */
  document.querySelectorAll(".diff").forEach(function (diff) {
    var key = "pdt.notes." + (diff.dataset.key || "diff");
    var modeKey = "pdt.mode." + (diff.dataset.key || "diff");
    var status = document.getElementById("status-info");

    function setNotes(on) {
      diff.classList.toggle("notes-hidden", !on);
      document.querySelectorAll("[data-notes-toggle]").forEach(function (b) {
        b.setAttribute("aria-pressed", on ? "true" : "false");
        if (b.dataset.on) {
          b.textContent = on ? b.dataset.on : b.dataset.off;
          b.classList.toggle("btn-p", !on);
          b.classList.toggle("btn-g", on);
        } else {
          b.textContent = b.textContent.replace(/^\[.\]/, on ? "[■]" : "[ ]");
        }
      });
      if (status) status.textContent = status.textContent.replace(/ai yorumları: \S+/, "ai yorumları: " + (on ? "açık" : "kapalı"));
      store(key, on ? "1" : "0");
    }
    function setMode(mode) {
      diff.dataset.mode = mode;
      diff.querySelectorAll("[data-diff-mode]").forEach(function (b) {
        b.setAttribute("aria-pressed", b.dataset.diffMode === mode ? "true" : "false");
      });
      store(modeKey, mode);
    }
    document.querySelectorAll("[data-notes-toggle]").forEach(function (b) {
      b.addEventListener("click", function () { setNotes(diff.classList.contains("notes-hidden")); });
    });
    diff.querySelectorAll("[data-diff-mode]").forEach(function (b) {
      b.addEventListener("click", function () { setMode(b.dataset.diffMode); });
    });
    diff.querySelectorAll("[data-fold]").forEach(function (b) {
      b.addEventListener("click", function () {
        diff.querySelectorAll('[data-fold-of="' + b.dataset.fold + '"]').forEach(function (r) { r.hidden = false; });
        b.remove();
      });
    });
    if (store(key) === "1") setNotes(true);       // yorumlar varsayılan olarak gizli
    if (store(modeKey) === "split") setMode("split");
  });

  /* --- Katalog: seçim değişince filtre formunu gönder --- */
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form && el.form.submit(); });
  });

  /* --- Ders: AI analizi / değerlendirme bitince sayfayı yenile --- */
  var poll = document.querySelector("[data-poll]");
  if (poll) {
    var url = poll.dataset.poll;
    var tick = function () {
      fetch(url, { headers: { Accept: "application/json" } })
        .then(function (r) { return r.json(); })
        .then(function (j) { if (j.busy) setTimeout(tick, 4000); else location.reload(); })
        .catch(function () { setTimeout(tick, 8000); });
    };
    setTimeout(tick, 4000);
  }

  /* --- Statik yayın · ders: tahmin bu tarayıcıda kalır, ipuçları ve cevap sunucusuz açılır --- */
  document.querySelectorAll("[data-selfcheck]").forEach(function (box) {
    var id = box.dataset.selfcheck;
    var guess = box.querySelector("[data-guess]");
    var list = box.querySelector("[data-hints]");
    var next = box.querySelector("[data-hint-next]");
    var head = document.getElementById("cevap-baslik");
    var answer = head && head.closest("details");
    if (guess) {
      guess.value = store("pdt.guess." + id) || "";
      guess.addEventListener("input", function () { store("pdt.guess." + id, guess.value); });
    }
    function showHints(n) {
      if (!list) return;
      var items = list.querySelectorAll("li");
      n = Math.min(n, items.length);
      items.forEach(function (li, i) { li.hidden = i >= n; });
      list.hidden = n === 0;
      if (next) {
        next.textContent = "? İPUCU AÇ (" + (items.length - n) + " KALDI)";
        next.disabled = n >= items.length;
      }
      store("pdt.hints." + id, String(n));
    }
    showHints(parseInt(store("pdt.hints." + id) || "0", 10) || 0);
    if (next) next.addEventListener("click", function () {
      showHints(list.querySelectorAll("li:not([hidden])").length + 1);
    });
    var open = box.querySelector("[data-open-answer]");
    if (open && answer) open.addEventListener("click", function () {
      answer.open = true;
      answer.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  /* --- Statik yayın · katalog: kategori ve arama süzgeci --- */
  var pub = document.querySelector("[data-pubfilter]");
  if (pub) {
    var rows = document.querySelectorAll("[data-row]");
    var q = pub.querySelector("[data-q]");
    var count = document.querySelector("[data-count]");
    var cat = new URLSearchParams(location.search).get("cat") || "all";
    var apply = function () {
      var term = (q.value || "").toLocaleLowerCase("tr").trim();
      var n = 0;
      rows.forEach(function (r) {
        var ok = (cat === "all" || r.dataset.cat === cat) && (!term || r.dataset.text.indexOf(term) >= 0);
        r.hidden = !ok;
        if (ok) n++;
      });
      if (count) count.textContent = n;
      document.querySelectorAll("[data-group]").forEach(function (g) {
        g.hidden = !document.querySelector('[data-row][data-cat="' + g.dataset.group + '"]:not([hidden])');
      });
      pub.querySelectorAll("[data-cat]").forEach(function (t) {
        if (t.dataset.cat === cat) t.setAttribute("aria-current", "true"); else t.removeAttribute("aria-current");
      });
    };
    pub.querySelectorAll("[data-cat]").forEach(function (t) {
      t.addEventListener("click", function (e) {
        e.preventDefault();
        cat = t.dataset.cat;
        history.replaceState(null, "", cat === "all" ? location.pathname : "?cat=" + cat);
        apply();
      });
    });
    q.addEventListener("input", apply);
    apply();
  }

  /* --- Analizler: iş kuyruğu ve log, 4 sn'de bir --- */
  var queue = document.querySelector("[data-queue]");
  if (queue) {
    var wasActive = (queue.querySelector("#queue") || {}).dataset && queue.querySelector("#queue").dataset.active === "1";
    var refresh = function () {
      fetch(queue.dataset.queue)
        .then(function (r) { return r.text().then(function (t) { return [r, t]; }); })
        .then(function (rt) {
          queue.innerHTML = rt[1];
          var active = rt[0].headers.get("X-Queue-Active") === "1";
          if (active) { wasActive = true; setTimeout(refresh, 4000); }
          else if (wasActive) { location.reload(); }   // iş bitti: raporu göster
        })
        .catch(function () { setTimeout(refresh, 8000); });
    };
    if (wasActive) setTimeout(refresh, 4000);
  }

  /* --- Analizler: dosya bırakma alanı --- */
  function human(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return Math.round(n / 1024) + " KB";
    return (n / 1048576).toFixed(1).replace(".", ",") + " MB";
  }
  document.querySelectorAll("[data-drop]").forEach(function (zone) {
    var input = zone.querySelector("input[type=file]");
    var label = zone.querySelector("[data-fname]");
    var show = function () {
      var f = input.files && input.files[0];
      zone.classList.toggle("has-file", !!f);
      if (f) label.textContent = "✓ " + f.name + " · " + human(f.size);
    };
    input.addEventListener("change", show);
    ["dragenter", "dragover"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("drag"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      zone.addEventListener(ev, function () { zone.classList.remove("drag"); });
    });
    zone.addEventListener("drop", function (e) {
      e.preventDefault();
      if (e.dataTransfer && e.dataTransfer.files.length) { input.files = e.dataTransfer.files; show(); }
    });
  });

  /* --- Ayarlar --- */
  var form = document.getElementById("ayarlar");
  if (form) {
    var radios = form.querySelectorAll('input[name="provider"]');
    var sync = function () {
      var cur = form.querySelector('input[name="provider"]:checked');
      var val = cur ? cur.value : "agent";
      radios.forEach(function (r) {
        var m = r.closest(".opt").querySelector("[data-mark]");
        if (m) m.textContent = r.checked ? "(•)" : "( )";
      });
      form.querySelectorAll("[data-prov]").forEach(function (g) { g.hidden = g.dataset.prov !== val; });
      form.querySelectorAll("[data-prov-price]").forEach(function (g) { g.hidden = !(val === "claude" || val === "openai"); });
    };
    radios.forEach(function (r) { r.addEventListener("change", sync); });

    form.querySelectorAll("[data-key-change]").forEach(function (b) {
      b.addEventListener("click", function () {
        var input = document.getElementById(b.dataset.keyChange);
        input.hidden = false;
        input.focus();
        b.closest("[data-keyrow]").hidden = true;
      });
    });
    var preset = form.querySelector("[data-preset-target]");
    if (preset) preset.addEventListener("change", function () {
      var url = preset.selectedOptions[0].dataset.url;
      if (url) document.getElementById(preset.dataset.presetTarget).value = url;
    });

    var testBtn = form.querySelector("[data-test-conn]");
    var out = document.getElementById("test-result");
    testBtn.addEventListener("click", function () {
      out.className = "test-result";
      out.textContent = "DENENİYOR…";
      testBtn.disabled = true;
      fetch("/settings/test", { method: "POST", body: new FormData(form) })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          out.className = "test-result " + (j.ok ? "ok" : "err");
          out.textContent = (j.ok ? "" : "✗ ") + j.message;
        })
        .catch(function () { out.className = "test-result err"; out.textContent = "✗ SUNUCUYA ULAŞILAMADI"; })
        .finally(function () { testBtn.disabled = false; });
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !e.defaultPrevented) { location.href = "/settings"; }
    });

    var side = document.querySelectorAll(".side a");
    side.forEach(function (a) {
      a.addEventListener("click", function () {
        side.forEach(function (x) { x.removeAttribute("aria-current"); });
        a.setAttribute("aria-current", "true");
      });
    });
  }
})();
