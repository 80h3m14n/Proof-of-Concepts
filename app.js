const els = {
  searchInput: document.getElementById("searchInput"),
  severityFilter: document.getElementById("severityFilter"),
  categoryFilter: document.getElementById("categoryFilter"),
  resultCount: document.getElementById("resultCount"),
  results: document.getElementById("results"),
  detailBody: document.getElementById("detailBody"),
  indexMeta: document.getElementById("indexMeta"),
  schemaWarnings: document.getElementById("schemaWarnings"),
  themeToggle: document.getElementById("themeToggle"),
  refreshBtn: document.getElementById("refreshBtn"),
  detailSheet: document.getElementById("detailSheet"),
  detailSheetBody: document.getElementById("detailSheetBody"),
  detailCloseBtn: document.getElementById("detailCloseBtn"),
};

const state = {
  allEntries: [],
  visibleEntries: [],
  selectedId: null,
  activeIndex: -1,
  fuse: null,
  markdownLibs: null,
  theme: "dark",
};


const THEME_KEY = "poc-atlas-theme";
const mediaDark = window.matchMedia("(prefers-color-scheme: dark)");

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function asArray(value) {
  if (Array.isArray(value)) {
    return value.filter(Boolean);
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

function slugifyEntry(entry) {
  const cve = (entry.cves[0] || "unknown").toLowerCase();
  const product = normalizeString(entry.product)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-");
  return `${cve}-${product}`.replace(/^-+|-+$/g, "");
}

function sanitizeCvePath(inputPath) {
  if (!inputPath || typeof inputPath !== "string") return null;
  const normalized = inputPath.replace(/\\/g, "/").replace(/^\/+/, "");
  if (normalized.includes("..")) return null;
  if (!/^[-A-Za-z0-9_./]+$/.test(normalized)) return null;
  if (!/^CVE-\d{4}-\d{4,}\//.test(normalized)) return null;
  if (!/\/[^/]+$/.test(normalized)) return null;
  return normalized;
}

function inferExploitPath(entry) {
  const explicit = sanitizeCvePath(normalizeString(entry.exploit_path));
  if (explicit) return explicit;

  const rawPocUrl = normalizeString(entry.poc);
  if (!rawPocUrl) return null;

  try {
    const parsed = new URL(rawPocUrl);
    if (!/^(https?):$/i.test(parsed.protocol)) return null;
    const maybePath = sanitizeCvePath(parsed.pathname.replace(/^\//, ""));
    return maybePath;
  } catch {
    return null;
  }
}

function normalizeEntry(raw, idx) {
  const cves = asArray(raw.cves).length ? asArray(raw.cves) : asArray(raw.cve);
  const tags = asArray(raw.tags);
  const references = Array.isArray(raw.references) ? raw.references : [];
  const versionHistory = Array.isArray(raw.version_history)
    ? raw.version_history
    : Array.isArray(raw.versions)
      ? raw.versions
      : [];

  const entry = {
    _idx: idx,
    cves,
    vendor: normalizeString(raw.vendor),
    product: normalizeString(raw.product),
    type: normalizeString(raw.type),
    severity: normalizeString(raw.severity).toLowerCase() || "unknown",
    tags,
    cvss: raw.cvss && typeof raw.cvss === "object" ? raw.cvss : {},
    poc: normalizeString(raw.poc),
    references,
    description: normalizeString(raw.description),
    readmePath:
      sanitizeCvePath(normalizeString(raw.readme_path)) ||
      (cves[0] ? `${cves[0]}/README.md` : null),
    exploitPath: inferExploitPath(raw),
    versionHistory,
    id:
      normalizeString(raw.id) ||
      slugifyEntry({ ...raw, cves }) ||
      `entry-${idx}`,
  };

  entry.searchText = [
    entry.cves.join(" "),
    entry.vendor,
    entry.product,
    entry.type,
    entry.severity,
    entry.tags.join(" "),
    entry.description,
  ]
    .join(" ")
    .toLowerCase();

  return entry;
}

async function loadEntries() {
  const warnings = [];
  let entries = [];

  try {
    const manifestResp = await fetch("data/manifest.json", {
      cache: "no-cache",
    });
    if (!manifestResp.ok) throw new Error("Manifest fetch failed");
    const manifest = await manifestResp.json();

    const shardPaths = Array.isArray(manifest.shards)
      ? manifest.shards.map((s) => s.path).filter(Boolean)
      : [];
    for (const path of shardPaths) {
      try {
        const shardResp = await fetch(path, { cache: "no-cache" });
        if (!shardResp.ok) {
          warnings.push(`Skipped ${path}: HTTP ${shardResp.status}`);
          continue;
        }
        const shardData = await shardResp.json();
        if (!Array.isArray(shardData)) {
          warnings.push(`Skipped ${path}: expected array`);
          continue;
        }
        entries.push(...shardData);
      } catch {
        warnings.push(`Skipped ${path}: parse/fetch error`);
      }
    }

    els.indexMeta.textContent = `Loaded ${entries.length} entries from manifest shards (${manifest.generated_at || "unknown date"}).`;
  } catch {
    try {
      const fallbackResp = await fetch("index.json", { cache: "no-cache" });
      if (!fallbackResp.ok) throw new Error("Fallback missing");
      const fallbackData = await fallbackResp.json();
      entries = Array.isArray(fallbackData) ? fallbackData : [];
      els.indexMeta.textContent = `Loaded ${entries.length} entries from fallback index.json.`;
      warnings.push(
        "Using fallback index.json. data/manifest.json unavailable.",
      );
    } catch {
      els.indexMeta.textContent = "Failed to load manifest and fallback index.";
      entries = [];
    }
  }

  const normalized = entries
    .map(normalizeEntry)
    .filter((e) => e.cves.length > 0);

  if (warnings.length > 0) {
    els.schemaWarnings.textContent = warnings.join(" ");
    els.schemaWarnings.classList.add("show");
  } else {
    els.schemaWarnings.textContent = "";
    els.schemaWarnings.classList.remove("show");
  }

  state.allEntries = normalized;
  buildFuse();
  populateFilters(normalized);
}

async function loadFuseLib() {
  if (window.Fuse) return window.Fuse;
  const mod =
    await import("https://cdn.jsdelivr.net/npm/fuse.js@7.0.0/dist/fuse.min.mjs");
  return mod.default;
}

function buildFuse() {
  state.fuse = null;
}

async function ensureFuse() {
  if (state.fuse) return;
  const Fuse = await loadFuseLib();
  state.fuse = new Fuse(state.allEntries, {
    threshold: 0.32,
    includeScore: true,
    ignoreLocation: true,
    minMatchCharLength: 2,
    keys: [
      { name: "cves", weight: 0.4 },
      { name: "vendor", weight: 0.18 },
      { name: "product", weight: 0.16 },
      { name: "description", weight: 0.14 },
      { name: "tags", weight: 0.08 },
      { name: "type", weight: 0.04 },
    ],
  });
}

function populateFilters(entries) {
  const severities = [
    ...new Set(entries.map((e) => e.severity).filter(Boolean)),
  ].sort();
  const categories = [
    ...new Set(entries.map((e) => e.type).filter(Boolean)),
  ].sort();

  setSelectOptions(els.severityFilter, "All severities", severities);
  setSelectOptions(els.categoryFilter, "All categories", categories);
}

function setSelectOptions(select, allLabel, values) {
  const current = select.value;
  select.innerHTML = "";
  const allOpt = document.createElement("option");
  allOpt.value = "all";
  allOpt.textContent = allLabel;
  select.appendChild(allOpt);

  for (const value of values) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = value;
    select.appendChild(opt);
  }

  if (["all", ...values].includes(current)) {
    select.value = current;
  }
}

function getQueryState() {
  return {
    q: normalizeString(els.searchInput.value),
    sev: els.severityFilter.value || "all",
    cat: els.categoryFilter.value || "all",
    cve: state.selectedId || "",
  };
}

function updateUrlState({ push = false } = {}) {
  const params = new URLSearchParams();
  const q = getQueryState();
  if (q.q) params.set("q", q.q);
  if (q.sev && q.sev !== "all") params.set("sev", q.sev);
  if (q.cat && q.cat !== "all") params.set("cat", q.cat);
  if (q.cve) params.set("cve", q.cve);

  const nextUrl = `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ""}`;
  if (push) {
    history.pushState({ ...q }, "", nextUrl);
  } else {
    history.replaceState({ ...q }, "", nextUrl);
  }
}

function applyUrlState() {
  const params = new URLSearchParams(window.location.search);
  els.searchInput.value = params.get("q") || "";
  els.severityFilter.value = params.get("sev") || "all";
  els.categoryFilter.value = params.get("cat") || "all";
  state.selectedId = params.get("cve") || null;
}

async function getFilteredEntries() {
  const q = normalizeString(els.searchInput.value).toLowerCase();
  const sev = els.severityFilter.value;
  const cat = els.categoryFilter.value;

  let list = state.allEntries;
  if (sev !== "all") list = list.filter((e) => e.severity === sev);
  if (cat !== "all") list = list.filter((e) => e.type === cat);

  if (!q) return list;

  await ensureFuse();
  const searched = state.fuse.search(q).map((r) => r.item);
  const dedup = new Set(list.map((e) => e.id));
  return searched.filter((e) => dedup.has(e.id));
}

function severityClass(sev) {
  const clean = normalizeString(sev).toLowerCase();
  if (["critical", "high", "medium", "low"].includes(clean))
    return `sev-${clean}`;
  return "";
}

function cveDisplay(entry) {
  if (entry.cves.length <= 1) return entry.cves[0] || "-";
  return `${entry.cves[0]} +${entry.cves.length - 1}`;
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderResults() {
  els.results.innerHTML = "";

  state.visibleEntries.forEach((entry, idx) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `result-item${entry.id === state.selectedId ? " active" : ""}`;
    row.setAttribute("role", "option");
    row.setAttribute("id", `result-${entry.id}`);
    row.setAttribute(
      "aria-selected",
      entry.id === state.selectedId ? "true" : "false",
    );
    row.setAttribute("tabindex", idx === state.activeIndex ? "0" : "-1");
    row.dataset.index = String(idx);

    row.innerHTML = `
      <span class="row-cell row-cve">${escapeHtml(cveDisplay(entry))}</span>
      <span class="row-cell">${escapeHtml(entry.vendor || "-")}</span>
      <span class="row-cell">${escapeHtml(entry.product || "-")}</span>
      <span class="row-cell row-severity ${severityClass(entry.severity)}">${escapeHtml(entry.severity || "-")}</span>
      <span class="row-cell row-cvss">${escapeHtml(entry.cvss?.score != null ? String(entry.cvss.score) : "-")}</span>
      <span class="row-cell">${escapeHtml(entry.type || "-")}</span>
    `;

    row.addEventListener("click", () => {
      selectEntry(entry.id, { pushHistory: true, focusRow: true });
    });

    els.results.appendChild(row);
  });

  els.resultCount.textContent = String(state.visibleEntries.length);
  els.results.setAttribute("role", "listbox");
  els.results.setAttribute("tabindex", "0");
  els.results.setAttribute("aria-activedescendant", getActiveDescendantId());

  if (state.visibleEntries.length === 0) {
    els.detailBody.classList.add("empty");
    els.detailBody.textContent = "No entries match the current filters.";
    closeDetailSheet();
  }
}

function getActiveDescendantId() {
  if (state.activeIndex < 0 || state.activeIndex >= state.visibleEntries.length)
    return "";
  return `result-${state.visibleEntries[state.activeIndex].id}`;
}

function selectedEntry() {
  return state.visibleEntries.find((e) => e.id === state.selectedId) || null;
}

function refsHtml(entry) {
  if (!entry.references.length) return "-";
  return entry.references
    .map((ref) => {
      const name = escapeHtml(ref.name || ref.url || "Reference");
      const href = escapeHtml(ref.url || "#");
      return `<a href="${href}" target="_blank" rel="noopener noreferrer">${name}</a>`;
    })
    .join(" | ");
}

function versionHistoryHtml(entry) {
  if (!entry.versionHistory.length) {
    return "<li>No version history listed.</li>";
  }

  return entry.versionHistory
    .map((item) => {
      if (typeof item === "string") return `<li>${escapeHtml(item)}</li>`;
      if (item && typeof item === "object") {
        const version = escapeHtml(item.version || item.name || "Unknown");
        const note = escapeHtml(item.note || item.status || "");
        const date = escapeHtml(item.date || "");
        return `<li><strong>${version}</strong>${date ? ` (${date})` : ""}${note ? ` - ${note}` : ""}</li>`;
      }
      return "";
    })
    .join("");
}

function renderDetail(entry) {
  const cves = entry.cves
    .map((cve) => `<code>${escapeHtml(cve)}</code>`)
    .join(" ");
  const exploitPath = entry.exploitPath
    ? escapeHtml(entry.exploitPath)
    : "Unavailable";
  const pocUrl = entry.poc ? escapeHtml(entry.poc) : "Unavailable";

  const html = `
    <div class="detail-grid">
      <div class="detail-row"><strong>CVEs</strong><span>${cves}</span></div>
      <div class="detail-row"><strong>Vendor</strong><span>${escapeHtml(entry.vendor || "-")}</span></div>
      <div class="detail-row"><strong>Product</strong><span>${escapeHtml(entry.product || "-")}</span></div>
      <div class="detail-row"><strong>Type</strong><span>${escapeHtml(entry.type || "-")}</span></div>
      <div class="detail-row"><strong>Severity</strong><span>${escapeHtml(entry.severity || "-")}</span></div>
      <div class="detail-row"><strong>CVSS</strong><span>${escapeHtml(entry.cvss?.score != null ? `${entry.cvss.score} (${entry.cvss.version || "n/a"})` : "-")}</span></div>
      <div class="detail-row"><strong>Refs</strong><span>${refsHtml(entry)}</span></div>
      <div class="detail-row"><strong>PoC URL</strong><span>${entry.poc ? `<a href="${pocUrl}" target="_blank" rel="noopener noreferrer">${pocUrl}</a>` : "-"}</span></div>
      <div class="detail-row"><strong>Exploit</strong><span>${exploitPath}</span></div>
    </div>
    <div class="copy-bar" aria-label="Copy helpers">
      <button class="ghost-btn copy-btn" data-copy-type="cves">Copy CVE(s)</button>
      <button class="ghost-btn copy-btn" data-copy-type="poc">Copy PoC URL</button>
    </div>
    <p>${escapeHtml(entry.description || "No description provided.")}</p>
    <section class="version-history" aria-label="Version history">
      <h3>Version History</h3>
      <ul>${versionHistoryHtml(entry)}</ul>
    </section>
    <section class="readme" id="readmeContainer">
      <strong>README (sandboxed)</strong>
      <div class="readme-placeholder">README not loaded yet.</div>
      <button class="ghost-btn detail-action" type="button" id="loadReadmeBtn">Load README</button>
    </section>
    <section class="readme" id="pocContainer">
      <strong>PoC Code</strong>
      <p class="exploit-path">Load from GitHub to view source.</p>
      <button class="ghost-btn detail-action" type="button" id="loadPoCBtn">Load PoC</button>
      <div class="poc-body"></div>
    </section>
  `;

  els.detailBody.classList.remove("empty");
  els.detailBody.innerHTML = html;
  wireDetailActions(entry);

  if (window.matchMedia("(max-width: 760px)").matches) {
    openDetailSheet();
  }
}

async function loadMarkdownLibs() {
  if (state.markdownLibs) return state.markdownLibs;

  const [markedMod, purifyMod] = await Promise.all([
    import("https://cdn.jsdelivr.net/npm/marked@13.0.2/lib/marked.esm.js"),
    import("https://cdn.jsdelivr.net/npm/dompurify@3.2.6/dist/purify.es.mjs"),
  ]);

  state.markdownLibs = {
    marked: markedMod.marked,
    DOMPurify: purifyMod.default,
  };

  return state.markdownLibs;
}

function buildReadmeIframeSrcdoc(safeHtml) {
  const inlineCss = `
    body { font-family: system-ui, sans-serif; margin: 0; padding: 0.9rem; line-height: 1.5; color: #10233a; }
    pre { overflow: auto; padding: 0.6rem; border: 1px solid #d0dbe8; border-radius: 6px; background: #f7fbff; }
    code { font-family: ui-monospace, Menlo, monospace; }
    a { color: #0066cc; }
  `;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>${inlineCss}</style></head><body>${safeHtml}</body></html>`;
}

async function loadReadme(entry) {
  const readmeContainer = document.getElementById("readmeContainer");
  if (!readmeContainer) return;

  const target = readmeContainer.querySelector(".readme-placeholder");
  if (!target) return;

  if (!entry.readmePath || !sanitizeCvePath(entry.readmePath)) {
    target.textContent = "README path unavailable or failed validation.";
    return;
  }

  target.textContent = "Loading README...";

  try {
    const [libs, readmeResp] = await Promise.all([
      loadMarkdownLibs(),
      fetch(entry.readmePath, { cache: "no-cache" }),
    ]);

    if (!readmeResp.ok) {
      target.textContent = `README not found (${readmeResp.status}).`;
      return;
    }

    const markdown = await readmeResp.text();
    const parsed = libs.marked.parse(markdown, {
      mangle: false,
      headerIds: false,
    });
    const sanitized = libs.DOMPurify.sanitize(parsed, {
      FORBID_TAGS: ["script", "style", "iframe", "object", "embed", "form"],
      FORBID_ATTR: ["onerror", "onload", "onclick", "style"],
    });

    const iframe = document.createElement("iframe");
    iframe.className = "readme-frame";
    iframe.setAttribute(
      "sandbox",
      "allow-popups allow-popups-to-escape-sandbox",
    );
    iframe.setAttribute("loading", "lazy");
    iframe.setAttribute("title", `Sandboxed README for ${entry.cves[0]}`);
    iframe.srcdoc = buildReadmeIframeSrcdoc(sanitized);

    target.innerHTML = "";
    target.appendChild(iframe);
  } catch {
    target.textContent = "Failed to render README.";
  }
}

function convertGitHubUrlToRaw(url) {
  if (!url || typeof url !== "string") return null;
  const match = url.match(
    /https:\/\/github\.com\/([^\/]+)\/([^\/]+)(?:\/blob\/([^\/]+))?(\/.+)/,
  );
  if (!match) return null;
  const [, owner, repo, branch, path] = match;
  const defaultBranch = branch || "main";
  return `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}${path}`;
}

async function loadPoCPreview(entry) {
  const pocContainer = document.getElementById("pocContainer");
  if (!pocContainer) return;
  const body = pocContainer.querySelector(".poc-body");
  if (!body) return;

  if (!entry.poc || typeof entry.poc !== "string") {
    body.textContent = "PoC URL unavailable.";
    return;
  }

  body.textContent = "Loading PoC code...";

  const rawUrl = convertGitHubUrlToRaw(entry.poc);
  if (!rawUrl) {
    body.textContent = "Unable to convert PoC URL to raw GitHub URL.";
    return;
  }

  try {
    const resp = await fetch(rawUrl, { cache: "no-cache" });
    if (!resp.ok) {
      body.textContent = `Unable to load PoC (${resp.status}).`;
      return;
    }

    const content = await resp.text();
    const pre = document.createElement("pre");
    const code = document.createElement("code");
    code.textContent = content;
    pre.appendChild(code);

    body.innerHTML = "";
    body.appendChild(pre);
  } catch {
    body.textContent = "PoC preview failed.";
  }
}

async function copyDetailValue(type, entry) {
  let text = "";
  if (type === "cves") {
    text = entry.cves.join(", ");
  } else if (type === "poc") {
    text = entry.poc || "";
  }

  if (!text) return;
  await navigator.clipboard.writeText(text);
}

function wireDetailActions(entry) {
  const readmeBtn = document.getElementById("loadReadmeBtn");
  const pocBtn = document.getElementById("loadPoCBtn");

  if (readmeBtn) {
    readmeBtn.addEventListener("click", async () => {
      readmeBtn.disabled = true;
      await loadReadme(entry);
      readmeBtn.disabled = false;
    });
  }

  if (pocBtn) {
    pocBtn.addEventListener("click", async () => {
      pocBtn.disabled = true;
      await loadPoCPreview(entry);
      pocBtn.disabled = false;
    });
  }

  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const type = btn.getAttribute("data-copy-type");
      if (!type) return;
      const previous = btn.textContent;
      try {
        await copyDetailValue(type, entry);
        btn.textContent = "Copied";
      } catch {
        btn.textContent = "Copy failed";
      }
      setTimeout(() => {
        btn.textContent = previous;
      }, 1100);
    });
  });
}

function moveActive(delta) {
  if (!state.visibleEntries.length) return;

  const next =
    state.activeIndex < 0
      ? 0
      : Math.max(
          0,
          Math.min(state.visibleEntries.length - 1, state.activeIndex + delta),
        );
  state.activeIndex = next;
  els.results.setAttribute("aria-activedescendant", getActiveDescendantId());

  document.querySelectorAll(".result-item").forEach((row, idx) => {
    row.setAttribute("tabindex", idx === next ? "0" : "-1");
  });

  const current = document.querySelector(`.result-item[data-index="${next}"]`);
  if (current) {
    current.focus({ preventScroll: false });
    current.scrollIntoView({ block: "nearest" });
  }
}

function selectEntry(entryId, { pushHistory = false, focusRow = false } = {}) {
  const target = state.visibleEntries.find((e) => e.id === entryId);
  if (!target) return;

  state.selectedId = target.id;
  state.activeIndex = state.visibleEntries.findIndex((e) => e.id === target.id);
  renderResults();
  renderDetail(target);
  updateUrlState({ push: pushHistory });

  if (focusRow) {
    const row = document.querySelector(
      `.result-item[data-index="${state.activeIndex}"]`,
    );
    if (row) row.focus({ preventScroll: true });
  }
}

async function refreshView({ pushHistory = false } = {}) {
  state.visibleEntries = await getFilteredEntries();

  if (state.visibleEntries.length === 0) {
    state.selectedId = null;
    state.activeIndex = -1;
    renderResults();
    updateUrlState({ push: false });
    return;
  }

  const hasSelected = state.visibleEntries.some(
    (e) => e.id === state.selectedId,
  );
  if (!hasSelected) {
    state.selectedId = state.visibleEntries[0].id;
    state.activeIndex = 0;
  } else {
    state.activeIndex = state.visibleEntries.findIndex(
      (e) => e.id === state.selectedId,
    );
  }

  renderResults();
  const detail = selectedEntry();
  if (detail) renderDetail(detail);
  updateUrlState({ push: pushHistory });
}

function setTheme(theme, { persist = true } = {}) {
  state.theme = theme;
  document.documentElement.setAttribute("data-theme", theme);
  if (persist) {
    localStorage.setItem(THEME_KEY, theme);
  }
}

function applyThemePreference() {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === "light" || stored === "dark") {
    setTheme(stored, { persist: false });
    return;
  }
  setTheme(mediaDark.matches ? "dark" : "light", { persist: false });
}

function wireTheme() {
  applyThemePreference();

  els.themeToggle.addEventListener("click", () => {
    setTheme(state.theme === "dark" ? "light" : "dark");
  });

  mediaDark.addEventListener("change", (event) => {
    if (localStorage.getItem(THEME_KEY)) return;
    setTheme(event.matches ? "dark" : "light", { persist: false });
  });
}

function openDetailSheet() {
  if (!els.detailSheet) return;
  els.detailSheet.hidden = false;
  els.detailSheet.setAttribute("aria-hidden", "false");
  if (els.detailSheetBody) {
    els.detailSheetBody.innerHTML = els.detailBody.innerHTML;
    duplicateDetailSheetHandlers();
  }
}

function closeDetailSheet() {
  if (!els.detailSheet) return;
  els.detailSheet.hidden = true;
  els.detailSheet.setAttribute("aria-hidden", "true");
}

function duplicateDetailSheetHandlers() {
  if (!els.detailSheetBody) return;
  els.detailSheetBody.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mirroredBtn = document.querySelector(
        `.detail-body .copy-btn[data-copy-type="${btn.getAttribute("data-copy-type")}"]`,
      );
      if (mirroredBtn) mirroredBtn.click();
    });
  });

  const readmeBtn = els.detailSheetBody.querySelector("#loadReadmeBtn");
  if (readmeBtn) {
    readmeBtn.addEventListener("click", () => {
      const primaryBtn = document.querySelector(".detail-body #loadReadmeBtn");
      if (primaryBtn) primaryBtn.click();
      setTimeout(() => {
        if (els.detailSheetBody) {
          els.detailSheetBody.innerHTML = els.detailBody.innerHTML;
          duplicateDetailSheetHandlers();
        }
      }, 200);
    });
  }

  const pocBtn = els.detailSheetBody.querySelector("#loadPoCBtn");
  if (pocBtn) {
    pocBtn.addEventListener("click", () => {
      const primaryBtn = document.querySelector(".detail-body #loadPoCBtn");
      if (primaryBtn) primaryBtn.click();
      setTimeout(() => {
        if (els.detailSheetBody) {
          els.detailSheetBody.innerHTML = els.detailBody.innerHTML;
          duplicateDetailSheetHandlers();
        }
      }, 200);
    });
  }
}

function wireKeyboardNavigation() {
  els.results.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveActive(1);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      moveActive(-1);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const entry = state.visibleEntries[state.activeIndex];
      if (entry) selectEntry(entry.id, { pushHistory: true, focusRow: true });
    }
  });
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(() => {
      // Fail quietly: the app still works online without service worker.
    });
  });
}

function wireEvents() {
  const triggerFilter = async () => {
    await refreshView({ pushHistory: false });
  };

  els.searchInput.addEventListener("input", triggerFilter);
  els.severityFilter.addEventListener("change", triggerFilter);
  els.categoryFilter.addEventListener("change", triggerFilter);

  els.refreshBtn.addEventListener("click", async () => {
    await loadEntries();
    applyUrlState();
    await refreshView({ pushHistory: false });
  });

  window.addEventListener("popstate", async () => {
    applyUrlState();
    await refreshView({ pushHistory: false });
  });

  window.addEventListener("resize", () => {
    if (!window.matchMedia("(max-width: 760px)").matches) {
      closeDetailSheet();
    }
  });

  if (els.detailCloseBtn) {
    els.detailCloseBtn.addEventListener("click", closeDetailSheet);
  }

  if (els.detailSheet) {
    els.detailSheet.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.classList.contains("detail-sheet-backdrop")) {
        closeDetailSheet();
      }
    });
  }

  wireKeyboardNavigation();
}

async function init() {
  wireTheme();
  wireEvents();
  registerServiceWorker();

  await loadEntries();
  applyUrlState();
  await refreshView({ pushHistory: false });
}

init();
