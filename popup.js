import {
  COOKIE_FORMATS,
  MESSAGE_TYPES,
  escapeHtml,
  sanitizeFileName,
  sendRuntimeMessage,
  syntaxHighlightJson
} from "./utils.js";

const state = {
  activeFormat: COOKIE_FORMATS.JSON,
  domain: "",
  jsonText: "",
  netscapeText: "",
  count: 0,
  busy: false
};

const elements = {};

document.addEventListener("DOMContentLoaded", () => {
  cacheElements();
  bindEvents();
  renderPreview();
  appendStatus("Ready", "Open an HTTP or HTTPS tab, then export cookies.");
});

function cacheElements() {
  [
    "currentDomain",
    "cookieCount",
    "exportState",
    "importState",
    "exportJsonBtn",
    "exportNetscapeBtn",
    "copyJsonBtn",
    "copyNetscapeBtn",
    "downloadJsonBtn",
    "downloadNetscapeBtn",
    "jsonTabBtn",
    "netscapeTabBtn",
    "previewCode",
    "clearPreviewBtn",
    "importText",
    "pasteImportBtn",
    "simulateBypassBtn",
    "checkAuthBtn",
    "authCheckResults",
    "clearLogsBtn",
    "statusLog",
    "toastRegion"
  ].forEach((id) => {
    elements[id] = document.getElementById(id);
  });
}

function bindEvents() {
  elements.exportJsonBtn.addEventListener("click", () => exportCookies(COOKIE_FORMATS.JSON));
  elements.exportNetscapeBtn.addEventListener("click", () => exportCookies(COOKIE_FORMATS.NETSCAPE));
  elements.copyJsonBtn.addEventListener("click", () => copyExport(COOKIE_FORMATS.JSON));
  elements.copyNetscapeBtn.addEventListener("click", () => copyExport(COOKIE_FORMATS.NETSCAPE));
  elements.downloadJsonBtn.addEventListener("click", () => downloadExport(COOKIE_FORMATS.JSON));
  elements.downloadNetscapeBtn.addEventListener("click", () => downloadExport(COOKIE_FORMATS.NETSCAPE));
  elements.jsonTabBtn.addEventListener("click", () => switchPreview(COOKIE_FORMATS.JSON));
  elements.netscapeTabBtn.addEventListener("click", () => switchPreview(COOKIE_FORMATS.NETSCAPE));
  elements.clearPreviewBtn.addEventListener("click", clearPreview);
  elements.pasteImportBtn.addEventListener("click", pasteAndImport);
  elements.simulateBypassBtn.addEventListener("click", simulateClientSideBypass);
  elements.checkAuthBtn.addEventListener("click", checkActivePageAuthSurface);
  elements.clearLogsBtn.addEventListener("click", () => {
    elements.statusLog.replaceChildren();
    appendStatus("Cleared", "Status log cleared.");
  });
}

async function exportCookies(format) {
  setBusy(true, "Exporting");
  try {
    const result = await sendRuntimeMessage({ type: MESSAGE_TYPES.EXPORT_COOKIES });
    state.domain = result.domain;
    state.jsonText = result.jsonText;
    state.netscapeText = result.netscapeText;
    state.count = result.count;
    state.activeFormat = format;

    elements.currentDomain.textContent = result.domain || "Active tab";
    elements.cookieCount.textContent = String(result.count);
    setExportControlsEnabled(true);
    renderPreview();

    const message = result.count === 1 ? "Exported 1 cookie." : `Exported ${result.count} cookies.`;
    showToast(message, result.count ? "success" : "warning");
    appendStatus("Export complete", `${message} Previewing ${formatLabel(format)}.`);
  } catch (error) {
    showToast(error.message, "error");
    appendStatus("Export failed", error.message);
  } finally {
    setBusy(false, "Ready");
  }
}

async function copyExport(format) {
  const text = getExportText(format);
  if (!text) {
    showToast("Export cookies before copying.", "warning");
    return;
  }

  try {
    await writeClipboardText(text);
    showToast(`${formatLabel(format)} copied.`, "success");
    appendStatus("Copied", `${formatLabel(format)} export copied to clipboard.`);
  } catch (error) {
    showToast(error.message, "error");
    appendStatus("Copy failed", error.message);
  }
}

function downloadExport(format) {
  const text = getExportText(format);
  if (!text) {
    showToast("Export cookies before downloading.", "warning");
    return;
  }

  const domain = sanitizeFileName(state.domain || "domain");
  const extension = format === COOKIE_FORMATS.JSON ? "json" : "txt";
  const mimeType = format === COOKIE_FORMATS.JSON ? "application/json" : "text/plain";
  const filename = `${domain}-cookies.${extension}`;
  const blob = new Blob([text], { type: `${mimeType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);

  showToast(`${filename} downloaded.`, "success");
  appendStatus("Downloaded", filename);
}

async function pasteAndImport() {
  setImportBusy(true, "Importing");
  try {
    const manualText = elements.importText.value.trim();
    const text = manualText || await readClipboardText();

    if (!text.trim()) {
      throw new Error("No cookie content was found in the textarea or clipboard.");
    }

    const result = await sendRuntimeMessage({
      type: MESSAGE_TYPES.IMPORT_COOKIES,
      text
    });

    const summary = `Imported ${result.importedCount}, verified ${result.verifiedCount}, skipped ${result.skippedCount}, failed ${result.failedCount}.`;
    const toastType = result.failedCount || result.skippedCount ? "warning" : "success";
    showToast(summary, toastType);
    appendStatus("Import complete", buildImportSummary(result));

    if (result.domainMismatchCount > 0) {
      showToast(`${result.domainMismatchCount} imported cookies target a different domain than this tab.`, "warning");
    }

    if (result.importedCount > 0 && result.limitationNote) {
      appendStatus("Session note", result.limitationNote);
    }
  } catch (error) {
    showToast(error.message, "error");
    appendStatus("Import failed", error.message);
  } finally {
    setImportBusy(false, "Idle");
  }
}

async function simulateClientSideBypass() {
  /*
   * This button is intentionally limited to localhost:3000 for the educational lab.
   * It demonstrates that a server must not trust an editable client-side cookie for
   * authorization. A secure design validates authorization with server-side session
   * state or cryptographically signed tokens protected by HttpOnly, Secure, and
   * SameSite controls. The Auth Check panel below performs a read-only scan for
   * risky client-side auth signals without modifying the active page.
   */
  setImportBusy(true, "Simulating");
  try {
    const result = await sendRuntimeMessage({ type: MESSAGE_TYPES.SIMULATE_LOCAL_BYPASS });
    showToast("Local admin cookie set; page reloaded.", "success");
    appendStatus("Bypass simulated", `${result.cookieName}=${result.cookieValue} on ${result.target}`);
  } catch (error) {
    showToast(error.message, "error");
    appendStatus("Simulation failed", error.message);
  } finally {
    setImportBusy(false, "Idle");
  }
}

async function checkActivePageAuthSurface() {
  setCheckBusy(true);
  try {
    const result = await sendRuntimeMessage({ type: MESSAGE_TYPES.CHECK_AUTH_SURFACE });
    renderAuthCheckResults(result);
    showToast(result.summary, result.findingCount ? "warning" : "success");
    appendStatus("Auth check complete", `${result.domain}: ${result.summary}`);
  } catch (error) {
    renderAuthCheckError(error.message);
    showToast(error.message, "error");
    appendStatus("Auth check failed", error.message);
  } finally {
    setCheckBusy(false);
  }
}

function switchPreview(format) {
  state.activeFormat = format;
  renderPreview();
}

function clearPreview() {
  state.activeFormat = COOKIE_FORMATS.JSON;
  state.domain = "";
  state.jsonText = "";
  state.netscapeText = "";
  state.count = 0;
  elements.currentDomain.textContent = "No tab selected";
  elements.cookieCount.textContent = "0";
  setExportControlsEnabled(false);
  renderPreview();
  appendStatus("Preview cleared", "Export data removed from popup memory.");
}

function renderPreview() {
  const hasExport = Boolean(state.jsonText || state.netscapeText);
  elements.jsonTabBtn.classList.toggle("active", state.activeFormat === COOKIE_FORMATS.JSON);
  elements.netscapeTabBtn.classList.toggle("active", state.activeFormat === COOKIE_FORMATS.NETSCAPE);
  elements.jsonTabBtn.setAttribute("aria-selected", String(state.activeFormat === COOKIE_FORMATS.JSON));
  elements.netscapeTabBtn.setAttribute("aria-selected", String(state.activeFormat === COOKIE_FORMATS.NETSCAPE));

  if (!hasExport) {
    elements.previewCode.textContent = "Export cookies to preview them here.";
    return;
  }

  if (state.activeFormat === COOKIE_FORMATS.JSON) {
    elements.previewCode.innerHTML = syntaxHighlightJson(state.jsonText);
  } else {
    elements.previewCode.innerHTML = escapeHtml(state.netscapeText);
  }
}

function renderAuthCheckResults(result) {
  elements.authCheckResults.replaceChildren();

  const summaryItem = document.createElement("li");
  summaryItem.className = result.findingCount ? "info" : "muted";
  const summaryTitle = document.createElement("strong");
  const summaryText = document.createElement("span");
  summaryTitle.textContent = "Summary";
  summaryText.textContent = `${result.summary} ${result.disclaimer}`;
  summaryItem.append(summaryTitle, summaryText);
  elements.authCheckResults.append(summaryItem);

  result.findings.forEach((finding) => {
    const item = document.createElement("li");
    item.className = finding.severity || "info";

    const title = document.createElement("strong");
    const detail = document.createElement("span");
    const mitigation = document.createElement("em");

    title.textContent = `[${(finding.severity || "info").toUpperCase()}] ${finding.title}`;
    detail.textContent = finding.detail;
    mitigation.textContent = finding.mitigation;

    item.append(title, detail, mitigation);
    elements.authCheckResults.append(item);
  });
}

function renderAuthCheckError(message) {
  elements.authCheckResults.replaceChildren();
  const item = document.createElement("li");
  item.className = "high";
  const title = document.createElement("strong");
  const detail = document.createElement("span");
  title.textContent = "Check failed";
  detail.textContent = message;
  item.append(title, detail);
  elements.authCheckResults.append(item);
}

function setExportControlsEnabled(enabled) {
  [
    elements.copyJsonBtn,
    elements.copyNetscapeBtn,
    elements.downloadJsonBtn,
    elements.downloadNetscapeBtn,
    elements.clearPreviewBtn
  ].forEach((button) => {
    button.disabled = !enabled;
  });
}

function getExportText(format) {
  return format === COOKIE_FORMATS.JSON ? state.jsonText : state.netscapeText;
}

function setBusy(isBusy, label) {
  state.busy = isBusy;
  elements.exportState.textContent = label;
  [elements.exportJsonBtn, elements.exportNetscapeBtn].forEach((button) => {
    button.disabled = isBusy;
    button.classList.toggle("loading", isBusy);
  });
}

function setImportBusy(isBusy, label) {
  elements.importState.textContent = label;
  [elements.pasteImportBtn, elements.simulateBypassBtn].forEach((button) => {
    button.disabled = isBusy;
    button.classList.toggle("loading", isBusy);
  });
}

function setCheckBusy(isBusy) {
  elements.checkAuthBtn.disabled = isBusy;
  elements.checkAuthBtn.classList.toggle("loading", isBusy);
  if (isBusy) {
    elements.checkAuthBtn.textContent = "Checking";
  } else {
    elements.checkAuthBtn.textContent = "Check Active Page";
  }
}

async function writeClipboardText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // The fallback below handles denied or unavailable async clipboard access.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.append(textarea);
  textarea.select();

  let copied = false;
  try {
    copied = document.execCommand("copy");
  } finally {
    textarea.remove();
  }

  if (!copied) {
    throw new Error("Clipboard copy failed. Select the preview text and copy it manually.");
  }
}

async function readClipboardText() {
  if (!navigator.clipboard?.readText) {
    throw new Error("Clipboard read is unavailable. Paste cookie content into the textarea.");
  }

  try {
    return await navigator.clipboard.readText();
  } catch {
    throw new Error("Clipboard read was blocked. Paste cookie content into the textarea.");
  }
}

function appendStatus(title, message) {
  const item = document.createElement("li");
  const strong = document.createElement("strong");
  const span = document.createElement("span");
  strong.textContent = title;
  span.textContent = message;
  item.append(strong, span);
  elements.statusLog.prepend(item);

  while (elements.statusLog.children.length > 6) {
    elements.statusLog.lastElementChild.remove();
  }
}

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.setAttribute("role", type === "error" ? "alert" : "status");
  toast.textContent = message;
  elements.toastRegion.append(toast);

  window.setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    window.setTimeout(() => toast.remove(), 160);
  }, 4200);
}

function formatLabel(format) {
  return format === COOKIE_FORMATS.JSON ? "JSON" : "Netscape";
}

function buildImportSummary(result) {
  const parts = [
    `${formatLabel(result.format)} detected`,
    `${result.importedCount} imported`,
    `${result.verifiedCount} verified`,
    `${result.skippedCount} skipped`,
    `${result.failedCount} failed`
  ];

  if (result.unverifiedCount) {
    parts.push(`${result.unverifiedCount} unverified`);
  }

  if (result.invalidCount) {
    parts.push(`${result.invalidCount} invalid`);
  }

  if (result.duplicateCount) {
    parts.push(`${result.duplicateCount} duplicate`);
  }

  if (result.malformedLines?.length) {
    parts.push(`malformed lines: ${result.malformedLines.slice(0, 5).join(", ")}`);
  }

  if (result.failurePreview?.length) {
    parts.push(`first failure: ${result.failurePreview[0].reason}`);
  }

  return parts.join("; ");
}
