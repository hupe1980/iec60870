/* Load the documentation index on demand. */
(function () {
  var input = document.getElementById("q");
  var panel = document.getElementById("results");
  if (!input || !panel) return;

  var index = null;
  var docs = null;
  var loading = null;

  function load() {
    if (loading) return loading;
    loading = Promise.all([
      new Promise(function (resolve, reject) {
        var s = document.createElement("script");
        s.src = input.dataset.library;
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      }),
      fetch(input.dataset.index).then(function (r) { return r.json(); }),
    ]).then(function (both) {
      var raw = both[1];
      index = elasticlunr.Index.load(raw);
      docs = raw.documentStore.docs;
    }).catch(function (err) {
      loading = null;
      throw err;
    });
    return loading;
  }

  /* A window of body text around the first match, so a result says why it matched. */
  function snippet(body, terms) {
    var lower = body.toLowerCase();
    var at = -1;
    for (var i = 0; i < terms.length && at < 0; i++) at = lower.indexOf(terms[i]);
    if (at < 0) at = 0;
    var start = Math.max(0, at - 60);
    var text = body.slice(start, start + 180).replace(/\s+/g, " ").trim();
    return (start > 0 ? "… " : "") + text + " …";
  }

  function render(query) {
    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    var hits = index.search(query, { bool: "AND", expand: true }).slice(0, 8);

    if (!hits.length) {
      panel.innerHTML = "<p class=\"no-hits\">No matches for “" + escapeHtml(query) + "”.</p>";
      panel.hidden = false;
      return;
    }
    panel.innerHTML = hits
      .map(function (hit) {
        var doc = docs[hit.ref];
        return (
          '<a href="' + escapeHtml(hit.ref) + '">' +
          "<strong>" + escapeHtml(doc.title) + "</strong>" +
          "<span>" + escapeHtml(snippet(doc.body, terms)) + "</span></a>"
        );
      })
      .join("");
    panel.hidden = false;
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  var timer;
  var revision = 0;
  function search() {
    var query = input.value.trim();
    var current = ++revision;
    clearTimeout(timer);
    panel.hidden = true;
    if (query.length < 2) return;
    timer = setTimeout(function () {
      load().then(function () {
        if (current === revision) render(query);
      }).catch(function () {
        if (current !== revision) return;
        panel.textContent = "Search is unavailable. Try again or browse the documentation.";
        panel.hidden = false;
      });
    }, 120);
  }
  input.addEventListener("input", search);
  var initial = new URLSearchParams(location.search).get("q");
  if (initial) {
    input.value = initial;
    search();
  }

  /* Arrow keys walk into the results; the links are ordinary tab stops besides. */
  input.addEventListener("keydown", function (e) {
    if (e.key === "ArrowDown" && !panel.hidden) {
      var first = panel.querySelector("a");
      if (first) {
        e.preventDefault();
        first.focus();
      }
    }
  });
  panel.addEventListener("keydown", function (e) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    var links = Array.prototype.slice.call(panel.querySelectorAll("a"));
    var at = links.indexOf(document.activeElement);
    if (at < 0) return;
    e.preventDefault();
    var next = at + (e.key === "ArrowDown" ? 1 : -1);
    if (next < 0) input.focus();
    else if (links[next]) links[next].focus();
  });

  /* `/` focuses the box, Escape leaves it — the shortcuts a reader already expects. */
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey &&
        !e.target.closest("input, textarea, select, [contenteditable=true]")) {
      e.preventDefault();
      input.focus();
    } else if (e.key === "Escape" && (e.target === input || panel.contains(e.target))) {
      revision++;
      input.focus();
      panel.hidden = true;
    }
  });

  document.addEventListener("click", function (e) {
    if (!panel.contains(e.target) && e.target !== input) {
      revision++;
      panel.hidden = true;
    }
  });
})();
