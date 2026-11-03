(function () {
  "use strict";

  var root = document.documentElement;
  var body = document.body;

  function setTheme(theme) {
    root.dataset.theme = theme;
    var toggle = document.querySelector("[data-theme-toggle]");
    if (toggle) {
      var dark = theme === "dark";
      toggle.setAttribute("aria-pressed", String(dark));
      toggle.setAttribute("aria-label", dark ? "Use light theme" : "Use dark theme");
    }
    try { localStorage.setItem("warden-theme", theme); } catch (error) { /* storage is optional */ }
  }

  var storedTheme = null;
  try { storedTheme = localStorage.getItem("warden-theme"); } catch (error) { /* storage is optional */ }
  if (storedTheme === "light" || storedTheme === "dark") setTheme(storedTheme);
  else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) setTheme("dark");
  var themeToggle = document.querySelector("[data-theme-toggle]");
  if (themeToggle) themeToggle.addEventListener("click", function () {
    setTheme(root.dataset.theme === "dark" ? "light" : "dark");
  });

  var menuToggle = document.querySelector("[data-menu-toggle]");
  var mobileMenu = document.querySelector("[data-mobile-menu]");
  function closeMenu() {
    if (!menuToggle || !mobileMenu) return;
    mobileMenu.hidden = true;
    menuToggle.setAttribute("aria-expanded", "false");
    body.classList.remove("menu-open");
  }
  if (menuToggle && mobileMenu) {
    menuToggle.addEventListener("click", function () {
      var open = mobileMenu.hidden;
      mobileMenu.hidden = !open;
      menuToggle.setAttribute("aria-expanded", String(open));
      body.classList.toggle("menu-open", open);
    });
    mobileMenu.querySelectorAll("a").forEach(function (link) { link.addEventListener("click", closeMenu); });
  }

  function activateTabs(buttons, panels, key, selectedClass) {
    buttons.forEach(function (button) {
      button.addEventListener("click", function () {
        var value = button.dataset[key];
        buttons.forEach(function (item) {
          var selected = item === button;
          item.classList.toggle(selectedClass, selected);
          item.setAttribute("aria-selected", String(selected));
        });
        panels.forEach(function (panel) {
          var visible = panel.dataset[key.replace("Tab", "Panel")] === value;
          panel.hidden = !visible;
          panel.classList.toggle("active", visible);
        });
      });
    });
  }

  var demoButtons = Array.from(document.querySelectorAll("[data-demo-tab]"));
  var demoPanels = Array.from(document.querySelectorAll("[data-demo-panel]"));
  demoButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      var value = button.dataset.demoTab;
      demoButtons.forEach(function (item) {
        var selected = item === button;
        item.classList.toggle("active", selected);
        item.setAttribute("aria-selected", String(selected));
      });
      demoPanels.forEach(function (panel) {
        var visible = panel.dataset.demoPanel === value;
        panel.hidden = !visible;
        panel.classList.toggle("active", visible);
      });
    });
  });

  var filterButtons = document.querySelectorAll("[data-severity-filter]");
  var findingRows = document.querySelectorAll("[data-finding-detail]");
  filterButtons.forEach(function (filter) {
    filter.addEventListener("click", function () {
      var value = filter.dataset.severityFilter;
      filterButtons.forEach(function (item) { item.classList.toggle("active", item === filter); });
      findingRows.forEach(function (row) {
        row.hidden = value !== "all" && row.dataset.severity !== value;
      });
    });
  });
  var findingDetailPanel = document.querySelector("[data-finding-detail-panel]");
  findingRows.forEach(function (row) {
    row.addEventListener("click", function () {
      if (findingDetailPanel) findingDetailPanel.textContent = row.dataset.findingDetail;
    });
  });

  var pipelineContent = {
    acquire: { label: "STAGE 01 / ACQUISITION", title: "Acquire the exact release requested.", text: "Warden resolves a concrete (ecosystem, name, version), selects the distribution, applies size and redirect controls, and verifies the registry-published digest against the received bytes.", points: ["HTTPS-only hardened client", "Redirect host allowlist on every hop", "No fallback to an unrequested “latest” version"], route: ["Package request", "Verified bytes"] },
    extract: { label: "STAGE 02 / SAFE EXTRACTION", title: "Treat every archive as hostile input.", text: "Members are checked for traversal, absolute paths, control characters, depth, links and size limits. Magic bytes identify the format; skipped members still count against declared-size limits.", points: ["Path traversal and link protections", "Bounded files, members and retained bytes", "No imports, subprocesses or package execution"], route: ["Hostile archive", "Bounded inventory"] },
    analyze: { label: "STAGE 03 / PARALLEL ANALYSIS", title: "Turn package contents into findings.", text: "Sixteen registered analyzers run concurrently with per-analyzer timeouts. Each emits a normalised Finding with severity, confidence, location, mappings, remediation and observation provenance.", points: ["AST behaviour and install vectors", "Secrets are redacted in evidence", "Unavailable optional tools are explicit"], route: ["Inventory + code", "Normalised findings"] },
    correlate: { label: "STAGE 04 / CORRELATION", title: "Connect weak signals carefully.", text: "The correlation engine matches findings against attack-chain templates. Capability-grade observations need corroboration, so an ordinary SDK is not mislabeled simply because it reads credentials and makes HTTPS calls.", points: ["Credential access → exfiltration", "Install-time droppers and loaders", "MITRE ATT&CK tactic per step"], route: ["Finding set", "Attack-chain context"] },
    decide: { label: "STAGE 05 / POLICY DECISION", title: "Make an explainable allow, warn or block decision.", text: "Separate risk dimensions flow into policy-as-code. Thresholds, deny rules, confidence and scoped exceptions determine the outcome; critical chains, known malware and hash mismatches are non-overridable.", points: ["Environment-specific thresholds", "Unknown intelligence warns, never becomes zero", "SARIF, Markdown and HTML reports"], route: ["Evidence + policy", "Allow / Warn / Block"] }
  };
  var pipelineButtons = document.querySelectorAll("[data-pipeline]");
  var pipelineDetail = document.querySelector("[data-pipeline-detail]");
  function renderPipeline(key) {
    var stage = pipelineContent[key];
    if (!stage || !pipelineDetail) return;
    pipelineButtons.forEach(function (button) {
      var selected = button.dataset.pipeline === key;
      button.classList.toggle("active", selected);
      button.setAttribute("aria-selected", String(selected));
    });
    pipelineDetail.innerHTML = '<span class="mono label">' + stage.label + '</span>' +
      '<h3>' + stage.title + '</h3><p>' + stage.text + '</p>' +
      '<div class="detail-points">' + stage.points.map(function (point) { return '<span><i>✓</i> ' + point + '</span>'; }).join("") + '</div>' +
      '<div class="pipeline-route"><span>' + stage.route[0] + '</span><b>→</b><span>' + stage.route[1] + '</span></div>';
  }
  pipelineButtons.forEach(function (button) { button.addEventListener("click", function () { renderPipeline(button.dataset.pipeline); }); });

  var architectureCopy = {
    cli: ["CLI", "The local command surface runs the same analysis engines in-process without requiring the API."],
    action: ["GitHub Action", "Manifest hygiene and dependency-confusion checks can upload SARIF to code scanning."],
    console: ["Security console", "The React + TypeScript console exposes dashboards, scans, projects, policies, events and audit verification."],
    proxy: ["PEP 503 proxy", "The inline gateway audits or enforces decisions before pip or uv receives the artifact."],
    postgres: ["PostgreSQL", "Durable scan results, project data, security events and the append-only audit chain live here."],
    redis: ["Redis", "Caching and best-effort event-stream notifications support the API without replacing durable rows."],
    worker: ["Monitoring worker", "A lease-based worker checks watched packages for releases and stores behaviour diffs."],
    intel: ["Security intelligence", "OSV, CISA KEV and FIRST EPSS are inputs; optional NVD and Trivy remain explicitly optional."]
  };
  var archDetail = document.querySelector("[data-arch-detail]");
  document.querySelectorAll("[data-arch]").forEach(function (button) {
    button.addEventListener("click", function () {
      var copy = architectureCopy[button.dataset.arch];
      if (archDetail && copy) archDetail.innerHTML = "<strong>" + copy[0] + "</strong><br>" + copy[1];
    });
  });

  var workflowCopy = {
    cli: '<span class="code-comment"># scan a package without installing it</span>\nwarden scan requests==2.32.3\n\n<span class="code-comment"># gate an install before it runs</span>\nwarden run pip install requests==2.32.3\n\n<span class="code-comment"># scan project manifests</span>\nwarden project scan ./my-app\n\n<span class="code-comment"># generate a CycloneDX SBOM</span>\nwarden sbom generate ./my-app --format cyclonedx -o bom.json',
    action: 'permissions:\n  contents: read\n  security-events: write\nsteps:\n  - uses: actions/checkout@&lt;full-commit-sha&gt;\n    with: { persist-credentials: false }\n  - uses: rakshit-737/warden-supply-chain-security@&lt;full-commit-sha&gt;\n    with:\n      path: .\n      fail-on: high',
    proxy: '<span class="code-comment"># point the installer at the PEP 503 gateway</span>\npip install \\\n  --index-url https://warden.example/api/v1/proxy/pypi/simple/ \\\n  --trusted-host warden.example \\\n  requests==2.32.3\n\n<span class="code-comment"># choose audit or enforce mode in policy</span>\nmode: enforce',
    reports: '<span class="code-comment"># portable outputs for review and code scanning</span>\nwarden scan requests==2.32.3 --format sarif -o results.sarif\nwarden scan requests==2.32.3 --format markdown -o report.md\nwarden scan requests==2.32.3 --format html -o report.html'
  };
  var workflowTabs = document.querySelectorAll("[data-workflow]");
  var workflowPanels = document.querySelectorAll("[data-workflow-copy]");
  var code = document.querySelector("#cli-code code");
  workflowTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      var value = tab.dataset.workflow;
      workflowTabs.forEach(function (item) { var selected = item === tab; item.classList.toggle("active", selected); item.setAttribute("aria-selected", String(selected)); });
      workflowPanels.forEach(function (panel) { panel.hidden = panel.dataset.workflowCopy !== value; });
      if (code && workflowCopy[value]) code.innerHTML = workflowCopy[value];
    });
  });
  var copyButton = document.querySelector("[data-copy-target]");
  if (copyButton) copyButton.addEventListener("click", function () {
    var target = document.getElementById(copyButton.dataset.copyTarget);
    if (!target) return;
    var status = document.querySelector(".copy-status");
    var text = target.textContent;
    var done = function () { copyButton.textContent = "Copied"; if (status) status.textContent = "Copied to clipboard"; window.setTimeout(function () { copyButton.textContent = "Copy"; if (status) status.textContent = ""; }, 1800); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done); });
    else fallbackCopy(text, done);
  });
  function fallbackCopy(text, done) { var area = document.createElement("textarea"); area.value = text; area.style.position = "fixed"; area.style.opacity = "0"; document.body.appendChild(area); area.select(); try { document.execCommand("copy"); done(); } finally { area.remove(); } }

  var lightbox = document.querySelector("[data-lightbox-dialog]");
  var lightboxImage = document.querySelector("[data-lightbox-image]");
  var lightboxCaption = document.querySelector("[data-lightbox-caption]");
  var lastTrigger = null;
  function closeLightbox() { if (!lightbox) return; lightbox.hidden = true; body.classList.remove("menu-open"); if (lastTrigger) lastTrigger.focus(); }
  document.querySelectorAll("[data-lightbox]").forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      if (!lightbox || !lightboxImage) return;
      lastTrigger = trigger; lightboxImage.src = trigger.dataset.lightbox; lightboxImage.alt = trigger.querySelector("img") ? trigger.querySelector("img").alt : ""; if (lightboxCaption) lightboxCaption.textContent = trigger.dataset.caption || ""; lightbox.hidden = false; body.classList.add("menu-open");
      var close = document.querySelector("[data-lightbox-close]"); if (close) close.focus();
    });
  });
  var lightboxClose = document.querySelector("[data-lightbox-close]");
  if (lightboxClose) lightboxClose.addEventListener("click", closeLightbox);
  if (lightbox) lightbox.addEventListener("click", function (event) { if (event.target === lightbox) closeLightbox(); });
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { closeLightbox(); closeMenu(); } });
})();
