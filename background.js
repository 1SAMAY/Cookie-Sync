import {
  MESSAGE_TYPES,
  UserFacingError,
  callChromeApi,
  cookieToSetDetails,
  domainMatchesHost,
  formatJsonCookies,
  formatNetscapeCookies,
  getSupportedTabUrl,
  parseCookieImport,
  serializeError,
  summarizeValidationDetails,
  validateImportedCookies
} from "./utils.js";

const DEMO_URL = "http://localhost:3000/";
const DEMO_DASHBOARD_URL = "http://localhost:3000/dashboard";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: serializeError(error) }));

  return true;
});

async function handleMessage(message) {
  switch (message?.type) {
    case MESSAGE_TYPES.EXPORT_COOKIES:
      return exportActiveTabCookies();
    case MESSAGE_TYPES.IMPORT_COOKIES:
      return importCookiesFromText(message.text);
    case MESSAGE_TYPES.CHECK_AUTH_SURFACE:
      return checkActiveTabAuthSurface();
    case MESSAGE_TYPES.SIMULATE_LOCAL_BYPASS:
      return simulateClientSideBypass();
    default:
      throw new UserFacingError("Unsupported extension action.");
  }
}

async function getActiveTab() {
  const tabs = await callChromeApi(chrome.tabs.query.bind(chrome.tabs), {
    active: true,
    currentWindow: true
  });

  if (!tabs || tabs.length === 0) {
    throw new UserFacingError("No active tab is available.");
  }

  return tabs[0];
}

async function exportActiveTabCookies() {
  const tab = await getActiveTab();
  const tabUrl = getSupportedTabUrl(tab);
  const hostname = tabUrl.hostname.toLowerCase();

  const byUrl = await callChromeApi(chrome.cookies.getAll.bind(chrome.cookies), {
    url: tabUrl.href
  });
  const allBrowserCookies = await callChromeApi(chrome.cookies.getAll.bind(chrome.cookies), {});

  const cookies = uniqueCookies([...byUrl, ...allBrowserCookies])
    .filter((cookie) => isCookieRelatedToHost(cookie, hostname))
    .sort(sortCookies);

  const jsonText = formatJsonCookies(cookies);
  const netscapeText = formatNetscapeCookies(cookies);

  return {
    domain: hostname,
    url: tabUrl.href,
    count: cookies.length,
    cookies,
    jsonText,
    netscapeText
  };
}

async function importCookiesFromText(text) {
  const activeTab = await getActiveTab();
  const activeUrl = getSupportedTabUrl(activeTab);
  const parsed = parseCookieImport(text);
  const validation = validateImportedCookies(parsed.cookies);

  let importedCount = 0;
  let verifiedCount = 0;
  let failedCount = 0;
  const failurePreview = [];
  const domainMismatchCount = validation.validCookies.filter((cookie) => !domainMatchesHost(cookie.domain, activeUrl.hostname)).length;

  for (const cookie of validation.validCookies) {
    try {
      const details = cookieToSetDetails(cookie);
      const result = await setCookieWithCompatibilityFallback(details);
      if (result) {
        importedCount += 1;
        const verified = await verifyCookieSet(result);
        if (verified) {
          verifiedCount += 1;
        } else {
          addFailurePreview(failurePreview, cookie, "Cookie was accepted but could not be verified afterward.");
        }
      } else {
        failedCount += 1;
        addFailurePreview(failurePreview, cookie, "Chrome rejected the cookie.");
      }
    } catch (error) {
      failedCount += 1;
      addFailurePreview(failurePreview, cookie, error.message || "Cookie import failed.");
    }
  }

  if (importedCount > 0 && activeTab.id) {
    await callChromeApi(chrome.tabs.reload.bind(chrome.tabs), activeTab.id, {});
  }

  return {
    format: parsed.format,
    detectedCount: parsed.cookies.length,
    importedCount,
    verifiedCount,
    unverifiedCount: Math.max(importedCount - verifiedCount, 0),
    skippedCount: validation.skippedCount,
    invalidCount: validation.invalid.length,
    duplicateCount: validation.duplicate.length,
    failedCount,
    domainMismatchCount,
    malformedLines: parsed.malformedLines || [],
    failurePreview,
    validationPreview: summarizeValidationDetails(validation),
    limitationNote: "Some modern sites also require server-side session validity, device binding, localStorage, IndexedDB, service workers, or re-authentication. Cookies alone may not recreate the same page."
  };
}

async function checkActiveTabAuthSurface() {
  const tab = await getActiveTab();
  const tabUrl = getSupportedTabUrl(tab);
  const hostname = tabUrl.hostname.toLowerCase();

  const cookies = await callChromeApi(chrome.cookies.getAll.bind(chrome.cookies), {
    url: tabUrl.href
  });

  const cookieFindings = analyzeCookieAuthSurface(cookies);
  let pageSurface = {
    storageFindings: [],
    domSignals: [],
    scriptSignals: [],
    scanError: ""
  };

  if (tab.id) {
    try {
      const injectionResults = await callChromeApi(chrome.scripting.executeScript.bind(chrome.scripting), {
        target: { tabId: tab.id },
        func: inspectPageAuthSurface
      });
      pageSurface = injectionResults?.[0]?.result || pageSurface;
    } catch (error) {
      pageSurface.scanError = error.message || "The page script surface could not be inspected.";
    }
  }

  const findings = [
    ...cookieFindings,
    ...pageSurface.storageFindings,
    ...pageSurface.domSignals,
    ...pageSurface.scriptSignals
  ].slice(0, 24);

  if (pageSurface.scanError) {
    findings.push({
      severity: "info",
      title: "Page script scan unavailable",
      detail: pageSurface.scanError,
      mitigation: "Try the check on a normal HTTP or HTTPS page where extension script injection is allowed."
    });
  }

  return {
    url: tabUrl.href,
    domain: hostname,
    checkedAt: new Date().toISOString(),
    cookieCount: cookies.length,
    storageFindingCount: pageSurface.storageFindings.length,
    findingCount: findings.length,
    findings,
    summary: summarizeAuthSurface(findings),
    disclaimer: "This checker reports client-side signals only. It cannot prove a bypass; confirm authorization enforcement on the backend."
  };
}

async function simulateClientSideBypass() {
  /*
   * Local security lab note:
   * The demo server intentionally trusts a plaintext browser cookie named user_role.
   * That design is insecure because client-side state is user-controlled; any extension,
   * devtools user, proxy, or script with sufficient access can rewrite it to admin.
   * Production systems should keep authorization decisions on the server, use robust
   * server-side sessions, and protect any client-carried tokens with cryptographic
   * signing, short lifetimes, Secure, HttpOnly, and SameSite attributes.
   */
  await callChromeApi(chrome.cookies.set.bind(chrome.cookies), {
    url: DEMO_URL,
    name: "user_role",
    value: "admin",
    path: "/",
    sameSite: "lax",
    secure: false,
    httpOnly: false,
    expirationDate: Math.floor(Date.now() / 1000) + 3600
  });

  const tab = await getActiveTab();
  if (tab?.id) {
    let isDemoTab = false;
    try {
      const tabUrl = new URL(tab.url);
      isDemoTab = tabUrl.protocol === "http:" && tabUrl.hostname === "localhost" && tabUrl.port === "3000";
    } catch {
      isDemoTab = false;
    }

    if (isDemoTab) {
      await callChromeApi(chrome.tabs.reload.bind(chrome.tabs), tab.id, {});
    } else {
      await callChromeApi(chrome.tabs.update.bind(chrome.tabs), tab.id, {
        url: DEMO_DASHBOARD_URL
      });
    }
  }

  return {
    cookieName: "user_role",
    cookieValue: "admin",
    target: DEMO_URL
  };
}

function analyzeCookieAuthSurface(cookies) {
  const findings = [];
  const authNamePattern = /(role|admin|auth|login|logged|session|token|jwt|access|refresh|user|permission|privilege)/i;
  const roleNamePattern = /(role|admin|isadmin|logged|login|permission|privilege)/i;
  const simpleAuthValuePattern = /^(admin|true|false|1|0|yes|no|user|guest|member|owner)$/i;

  cookies.forEach((cookie) => {
    if (!authNamePattern.test(cookie.name)) {
      return;
    }

    if (!cookie.httpOnly) {
      const isSimpleRoleState = roleNamePattern.test(cookie.name) || simpleAuthValuePattern.test(cookie.value || "");
      findings.push({
        severity: isSimpleRoleState ? "high" : "medium",
        title: `Script-readable auth-like cookie: ${cookie.name}`,
        detail: isSimpleRoleState
          ? "The cookie name or value shape suggests editable client-side role/login state."
          : "The cookie appears auth-related and is readable by page JavaScript because HttpOnly is not set.",
        mitigation: "Do not trust this cookie for authorization. Use server-side sessions or signed tokens and set HttpOnly where possible."
      });
    }

    if (!cookie.secure) {
      findings.push({
        severity: "medium",
        title: `Auth-like cookie missing Secure: ${cookie.name}`,
        detail: "The cookie can be sent over plain HTTP on matching origins.",
        mitigation: "Serve the application over HTTPS and set Secure on session or token cookies."
      });
    }

    if (cookie.sameSite === "no_restriction" || cookie.sameSite === "unspecified") {
      findings.push({
        severity: "low",
        title: `Review SameSite for cookie: ${cookie.name}`,
        detail: `Current SameSite value is ${cookie.sameSite || "unspecified"}.`,
        mitigation: "Prefer SameSite=Lax or SameSite=Strict unless cross-site use is explicitly required."
      });
    }
  });

  return findings;
}

function summarizeAuthSurface(findings) {
  const high = findings.filter((finding) => finding.severity === "high").length;
  const medium = findings.filter((finding) => finding.severity === "medium").length;
  const low = findings.filter((finding) => finding.severity === "low").length;

  if (high > 0) {
    return `${high} high-risk signal${high === 1 ? "" : "s"} found. Prioritize backend authorization review.`;
  }

  if (medium > 0) {
    return `${medium} medium-risk signal${medium === 1 ? "" : "s"} found. Review token and cookie handling.`;
  }

  if (low > 0) {
    return `${low} low-risk signal${low === 1 ? "" : "s"} found. Harden cookie policy where practical.`;
  }

  return "No obvious client-side auth bypass signals were found.";
}

function inspectPageAuthSurface() {
  const authKeyPattern = /(auth|token|session|jwt|role|admin|login|logged|user|permission|privilege|access|refresh)/i;
  const simpleAuthValuePattern = /^(admin|true|false|1|0|yes|no|user|guest|member|owner)$/i;
  const storageFindings = [];
  const domSignals = [];
  const scriptSignals = [];

  try {
    scanStorage("localStorage", window.localStorage, storageFindings);
  } catch {
    storageFindings.push({
      severity: "info",
      title: "localStorage unavailable",
      detail: "The page blocked localStorage inspection.",
      mitigation: "Review storage behavior directly in devtools for this origin if needed."
    });
  }

  try {
    scanStorage("sessionStorage", window.sessionStorage, storageFindings);
  } catch {
    storageFindings.push({
      severity: "info",
      title: "sessionStorage unavailable",
      detail: "The page blocked sessionStorage inspection.",
      mitigation: "Review storage behavior directly in devtools for this origin if needed."
    });
  }

  const passwordFieldCount = document.querySelectorAll("input[type='password']").length;
  const loginFormCount = [...document.forms].filter((form) => {
    const text = `${form.id} ${form.className} ${form.getAttribute("action") || ""}`.toLowerCase();
    return text.includes("login") || text.includes("signin") || form.querySelector("input[type='password']");
  }).length;

  if (passwordFieldCount > 0 || loginFormCount > 0) {
    domSignals.push({
      severity: "info",
      title: "Login UI detected",
      detail: `${passwordFieldCount} password field(s) and ${loginFormCount} login-like form(s) were found.`,
      mitigation: "Verify protected data is enforced server-side, not only by hiding or showing UI components."
    });
  }

  const bodyText = document.body?.innerText?.slice(0, 50000) || "";
  if (/\b(access denied|unauthorized|forbidden|login required|please log in)\b/i.test(bodyText)) {
    domSignals.push({
      severity: "low",
      title: "Client-visible access gate text detected",
      detail: "The page contains access-denied or login-required language.",
      mitigation: "Confirm the backend returns 401/403 for protected APIs without relying only on front-end route guards."
    });
  }

  const scripts = [...document.scripts].slice(0, 100);
  const suspiciousScriptNames = scripts
    .map((script) => script.src || "")
    .filter((src) => /(auth|login|session|token|guard|route)/i.test(src))
    .slice(0, 5);

  if (suspiciousScriptNames.length > 0) {
    scriptSignals.push({
      severity: "info",
      title: "Auth-related front-end scripts detected",
      detail: `${suspiciousScriptNames.length} script URL(s) include auth, session, token, guard, or route terms.`,
      mitigation: "Review the corresponding source to ensure UI guards are backed by server-side checks."
    });
  }

  return {
    storageFindings,
    domSignals,
    scriptSignals,
    scanError: ""
  };

  function scanStorage(areaName, storage, output) {
    if (!storage) {
      return;
    }

    const maxItems = Math.min(storage.length, 200);
    for (let index = 0; index < maxItems; index += 1) {
      const key = storage.key(index);
      if (!key) {
        continue;
      }

      let value = "";
      try {
        value = String(storage.getItem(key) || "");
      } catch {
        value = "";
      }

      if (!authKeyPattern.test(key) && !looksAuthLikeValue(value)) {
        continue;
      }

      const valueKind = classifyStorageValue(value);
      const keyLooksRoleBased = /(role|admin|logged|login|permission|privilege)/i.test(key);
      const severity = areaName === "localStorage" && (keyLooksRoleBased || valueKind !== "short value")
        ? "high"
        : "medium";

      output.push({
        severity,
        title: `${areaName} auth-like key: ${truncateText(key, 72)}`,
        detail: `Detected ${valueKind}. Values are not displayed to avoid exposing secrets.`,
        mitigation: keyLooksRoleBased
          ? "Do not authorize users from local role/login flags. Enforce authorization on the backend."
          : "Avoid long-lived readable tokens in web storage. Prefer HttpOnly session cookies or short-lived tokens with strict controls."
      });
    }
  }

  function looksAuthLikeValue(value) {
    const trimmed = value.trim();
    return simpleAuthValuePattern.test(trimmed) || isJwtLike(trimmed) || trimmed.length > 96 && /(bearer|token|session|refresh|access)/i.test(trimmed);
  }

  function classifyStorageValue(value) {
    const trimmed = value.trim();
    if (isJwtLike(trimmed)) {
      return "JWT-like token";
    }
    if (simpleAuthValuePattern.test(trimmed)) {
      return "simple role/login flag";
    }
    if (trimmed.length > 96) {
      return "long token-like value";
    }
    return "short value";
  }

  function isJwtLike(value) {
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
  }

  function truncateText(value, maxLength) {
    const text = String(value || "");
    return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
  }
}

function uniqueCookies(cookies) {
  const map = new Map();
  cookies.forEach((cookie) => {
    const key = [
      cookie.storeId || "",
      cookie.name,
      cookie.domain,
      cookie.path,
      JSON.stringify(cookie.partitionKey || {})
    ].join("|");
    map.set(key, cookie);
  });
  return [...map.values()];
}

function isCookieRelatedToHost(cookie, hostname) {
  return domainMatchesHost(cookie.domain, hostname) || domainMatchesHost(hostname, cookie.domain);
}

function sortCookies(left, right) {
  return (
    left.domain.localeCompare(right.domain) ||
    left.path.localeCompare(right.path) ||
    left.name.localeCompare(right.name)
  );
}

function addFailurePreview(failures, cookie, reason) {
  if (failures.length >= 8) {
    return;
  }

  failures.push({
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    reason
  });
}

async function setCookieWithCompatibilityFallback(details) {
  try {
    return await callChromeApi(chrome.cookies.set.bind(chrome.cookies), details);
  } catch (error) {
    const fallbackDetails = { ...details };
    let shouldRetry = false;

    if (fallbackDetails.partitionKey) {
      delete fallbackDetails.partitionKey;
      shouldRetry = true;
    }

    if (fallbackDetails.storeId) {
      delete fallbackDetails.storeId;
      shouldRetry = true;
    }

    if (fallbackDetails.sameSite === "unspecified") {
      delete fallbackDetails.sameSite;
      shouldRetry = true;
    }

    if (!shouldRetry) {
      throw error;
    }

    return callChromeApi(chrome.cookies.set.bind(chrome.cookies), fallbackDetails);
  }
}

async function verifyCookieSet(setCookie) {
  try {
    const query = {
      name: setCookie.name
    };

    if (setCookie.storeId) {
      query.storeId = setCookie.storeId;
    }

    const candidates = await callChromeApi(chrome.cookies.getAll.bind(chrome.cookies), query);
    return candidates.some((candidate) => (
      candidate.name === setCookie.name &&
      candidate.domain === setCookie.domain &&
      candidate.path === setCookie.path &&
      candidate.value === setCookie.value
    ));
  } catch {
    return false;
  }
}
