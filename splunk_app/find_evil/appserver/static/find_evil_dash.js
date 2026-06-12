/* Find Evil — embellissement des dashboards SimpleXML :
   - rend le markdown des cellules "Analyse" (sortie | ai) en HTML élégant,
   - transforme les valeurs verdict/severity en pastilles (pills) colorées.
   Chargé via <dashboard script="find_evil_dash.js">. */
(function () {
  function miniMarkdown(s) {
    var esc = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return esc
      .replace(/^### (.*)$/gm, "<h4>$1</h4>")
      .replace(/^## (.*)$/gm, "<h3>$1</h3>")
      .replace(/^# (.*)$/gm, "<h3>$1</h3>")
      .replace(/^---$/gm, "<hr/>")
      .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/^\s*[-*] (.*)$/gm, "<li>$1</li>")
      .replace(/^\s*\d+\.\s+(.*)$/gm, "<li>$1</li>")
      .replace(/(<li>[\s\S]*?<\/li>)/g, "<ul>$1</ul>")
      .replace(/\n{2,}/g, "<br/><br/>")
      .replace(/\n/g, "<br/>");
  }

  function colIndexes(table) {
    var heads = [].map.call(table.querySelectorAll("thead th"), function (th) {
      return (th.textContent || "").trim().toLowerCase();
    });
    return {
      verdict: heads.indexOf("verdict"),
      severity: heads.indexOf("severity"),
      analysis: heads.findIndex
        ? heads.findIndex(function (h) { return h.indexOf("analyse") >= 0 || h.indexOf("analysis") >= 0; })
        : -1,
    };
  }

  function pill(td, kind) {
    if (td.getAttribute("data-fe")) return;
    td.setAttribute("data-fe", "1");
    var v = (td.textContent || "").trim();
    td.style.background = "transparent";
    td.innerHTML = '<span class="fe-pill fe-pill-' + kind + " fe-" + v.toLowerCase() + '">' + v + "</span>";
  }

  function renderMd(td) {
    if (td.getAttribute("data-fe-md")) return;
    var txt = (td.textContent || "").trim();
    if (txt.length < 40) return; // ignore les cellules courtes
    td.setAttribute("data-fe-md", "1");
    td.innerHTML = '<div class="fe-md">' + miniMarkdown(txt) + "</div>";
  }

  function enhance() {
    [].forEach.call(document.querySelectorAll("table"), function (table) {
      var idx = colIndexes(table);
      [].forEach.call(table.querySelectorAll("tbody tr"), function (tr) {
        var tds = tr.children;
        if (idx.verdict >= 0 && tds[idx.verdict]) pill(tds[idx.verdict], "verdict");
        if (idx.severity >= 0 && tds[idx.severity]) pill(tds[idx.severity], "severity");
        if (idx.analysis >= 0 && tds[idx.analysis]) renderMd(tds[idx.analysis]);
      });
    });
  }

  var obs = new MutationObserver(function () { enhance(); });
  if (document.body) obs.observe(document.body, { childList: true, subtree: true });
  setInterval(enhance, 1500);
})();
