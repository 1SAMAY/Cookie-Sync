export const COOKIE_FORMATS = Object.freeze({
  JSON: "json",
  NETSCAPE: "netscape"
});

export const MESSAGE_TYPES = Object.freeze({
  EXPORT_COOKIES: "EXPORT_COOKIES",
  IMPORT_COOKIES: "IMPORT_COOKIES",
  CHECK_AUTH_SURFACE: "CHECK_AUTH_SURFACE",
  SIMULATE_LOCAL_BYPASS: "SIMULATE_LOCAL_BYPASS"
});

export class UserFacingError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "UserFacingError";
    this.details = details;
  }
}

const SAME_SITE_VALUES = new Set(["no_restriction", "lax", "strict", "unspecified"]);
const MAX_COOKIE_EXPIRATION = 253402300799;

export function callChromeApi(apiFunction, ...args) {
  return new Promise((resolve, reject) => {
    try {
      apiFunction(...args, (result) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          reject(new Error(lastError.message || "Chrome API request failed."));
          return;
        }
        resolve(result);
      });
    } catch (error) {
      reject(error);
    }
  });
}

export function sendRuntimeMessage(message) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          reject(new Error(lastError.message || "Extension service worker is unavailable."));
          return;
        }
        if (!response) {
          reject(new Error("No response was returned by the extension service worker."));
          return;
        }
        if (!response.ok) {
          const error = new UserFacingError(response.error?.message || "The request failed.", response.error?.details || {});
          reject(error);
          return;
        }
        resolve(response.result);
      });
    } catch (error) {
      reject(error);
    }
  });
}

export function serializeError(error) {
  return {
    name: error?.name || "Error",
    message: error?.message || "An unexpected error occurred.",
    details: error?.details || {}
  };
}

export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function sanitizeFileName(value, fallback = "cookies") {
  const cleaned = String(value || fallback)
    .trim()
    .replace(/^\.+/, "")
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .slice(0, 80);

  return cleaned || fallback;
}

export function getSupportedTabUrl(tab) {
  if (!tab || typeof tab.url !== "string") {
    throw new UserFacingError("No active browser tab was found.");
  }

  let url;
  try {
    url = new URL(tab.url);
  } catch {
    throw new UserFacingError("The active tab URL is invalid.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new UserFacingError("Cookies can only be managed for HTTP and HTTPS pages.");
  }

  return url;
}

export function normalizePath(path) {
  if (typeof path !== "string" || path.trim() === "") {
    return "/";
  }
  return path.startsWith("/") ? path : `/${path}`;
}

export function normalizeDomainForHost(domain) {
  const host = String(domain || "")
    .trim()
    .replace(/^\.+/, "")
    .toLowerCase();

  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

export function isLocalhost(hostname) {
  const host = normalizeDomainForHost(hostname);
  return host === "localhost" || host.endsWith(".localhost");
}

export function isIPv4Address(hostname) {
  const host = normalizeDomainForHost(hostname);
  const parts = host.split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

export function isIPv6Address(hostname) {
  const host = normalizeDomainForHost(hostname);
  return host.includes(":") && /^[0-9a-fA-F:]+$/.test(host);
}

export function isDomainLike(hostname) {
  const host = normalizeDomainForHost(hostname);
  if (!host || host.length > 253) {
    return false;
  }

  if (isLocalhost(host) || isIPv4Address(host)) {
    return true;
  }

  return host
    .split(".")
    .every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

export function domainMatchesHost(cookieDomain, host) {
  const normalizedDomain = normalizeDomainForHost(cookieDomain);
  const normalizedHost = normalizeDomainForHost(host);
  return normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`);
}

export function formatJsonCookies(cookies) {
  const stableCookies = cookies.map((cookie) => {
    const ordered = {};
    [
      "name",
      "value",
      "domain",
      "hostOnly",
      "path",
      "secure",
      "httpOnly",
      "sameSite",
      "session",
      "expirationDate",
      "storeId",
      "priority",
      "sameParty",
      "sourceScheme",
      "sourcePort",
      "partitionKey"
    ].forEach((key) => {
      if (Object.prototype.hasOwnProperty.call(cookie, key) && cookie[key] !== undefined) {
        ordered[key] = cookie[key];
      }
    });

    Object.keys(cookie)
      .sort()
      .forEach((key) => {
        if (!Object.prototype.hasOwnProperty.call(ordered, key) && cookie[key] !== undefined) {
          ordered[key] = cookie[key];
        }
      });

    return ordered;
  });

  return JSON.stringify(stableCookies, null, 2);
}

export function formatNetscapeCookies(cookies) {
  const header = [
    "# Netscape HTTP Cookie File",
    "# Generated locally by Cookie Session Sync & Security Lab.",
    "# This file is intended for user-controlled browser cookie backup and restoration.",
    ""
  ];

  const lines = cookies.map((cookie) => {
    const httpOnlyPrefix = cookie.httpOnly ? "#HttpOnly_" : "";
    const domain = `${httpOnlyPrefix}${cookie.domain || ""}`;
    const includeSubdomains = cookie.hostOnly ? "FALSE" : "TRUE";
    const path = normalizePath(cookie.path);
    const secure = cookie.secure ? "TRUE" : "FALSE";
    const expiration = cookie.session || !Number.isFinite(Number(cookie.expirationDate))
      ? "0"
      : String(Math.floor(Number(cookie.expirationDate)));

    return [
      domain,
      includeSubdomains,
      path,
      secure,
      expiration,
      cookie.name || "",
      cookie.value || ""
    ].join("\t");
  });

  return header.concat(lines).join("\n");
}

export function syntaxHighlightJson(jsonText) {
  const escaped = escapeHtml(jsonText);
  return escaped.replace(
    /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    (match) => {
      let className = "token-number";
      if (/^"/.test(match)) {
        className = /:$/.test(match) ? "token-key" : "token-string";
      } else if (/true|false/.test(match)) {
        className = "token-boolean";
      } else if (/null/.test(match)) {
        className = "token-null";
      }
      return `<span class="${className}">${match}</span>`;
    }
  );
}

export function parseCookieImport(text) {
  const source = String(text || "").trim();
  if (!source) {
    throw new UserFacingError("Import content is empty.");
  }

  if (source.startsWith("[") || source.startsWith("{")) {
    return parseJsonCookieImport(source);
  }

  return parseNetscapeCookieImport(source);
}

function parseJsonCookieImport(source) {
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new UserFacingError("Malformed JSON cookie import.", { reason: error.message });
  }

  if (!Array.isArray(parsed)) {
    throw new UserFacingError("JSON import must be an array of cookie objects.");
  }

  return {
    format: COOKIE_FORMATS.JSON,
    cookies: parsed
  };
}

function parseNetscapeCookieImport(source) {
  const cookies = [];
  const malformedLines = [];

  source.split(/\r?\n/).forEach((rawLine, index) => {
    const trimmedRight = rawLine.replace(/\s+$/g, "");
    const trimmed = trimmedRight.trim();
    if (!trimmed) {
      return;
    }

    let line = trimmedRight;
    let httpOnly = false;

    if (line.startsWith("#HttpOnly_")) {
      httpOnly = true;
      line = line.slice("#HttpOnly_".length);
    } else if (trimmed.startsWith("#")) {
      return;
    }

    let fields = line.split("\t");
    if (fields.length < 7) {
      fields = trimmed.split(/\s+/);
    }

    if (fields.length < 7) {
      malformedLines.push(index + 1);
      return;
    }

    const [domain, includeSubdomains, path, secure, expiration, name, ...valueParts] = fields;
    const expirationNumber = Number(expiration);
    cookies.push({
      name,
      value: valueParts.join(fields.length > 7 && rawLine.includes("\t") ? "\t" : " "),
      domain,
      path,
      secure: /^TRUE$/i.test(secure),
      httpOnly,
      sameSite: "unspecified",
      session: !Number.isFinite(expirationNumber) || expirationNumber <= 0,
      expirationDate: Number.isFinite(expirationNumber) && expirationNumber > 0 ? expirationNumber : undefined,
      hostOnly: !/^TRUE$/i.test(includeSubdomains)
    });
  });

  if (cookies.length === 0) {
    throw new UserFacingError("Unsupported cookie import format.", { malformedLines });
  }

  return {
    format: COOKIE_FORMATS.NETSCAPE,
    cookies,
    malformedLines
  };
}

export function validateImportedCookies(cookies) {
  const validCookies = [];
  const invalid = [];
  const duplicate = [];
  const seen = new Set();

  cookies.forEach((candidate, index) => {
    const validation = validateCookieCandidate(candidate, index);
    if (!validation.valid) {
      invalid.push(validation);
      return;
    }

    const key = [
      validation.cookie.storeId || "",
      canonicalCookieIdentityDomain(validation.cookie),
      normalizePath(validation.cookie.path),
      validation.cookie.name
    ].join("|");

    if (seen.has(key)) {
      duplicate.push({
        index,
        reason: "Duplicate cookie identity.",
        cookie: validation.cookie
      });
      return;
    }

    seen.add(key);
    validCookies.push(validation.cookie);
  });

  return {
    validCookies,
    invalid,
    duplicate,
    skippedCount: invalid.length + duplicate.length
  };
}

function validateCookieCandidate(candidate, index) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    return invalid(index, "Cookie entry must be an object.");
  }

  if (typeof candidate.name !== "string" || candidate.name.length === 0) {
    return invalid(index, "Cookie name is required.");
  }

  if (typeof candidate.value !== "string") {
    return invalid(index, "Cookie value must be a string.");
  }

  if (typeof candidate.domain !== "string" || candidate.domain.trim() === "") {
    return invalid(index, "Cookie domain is required.");
  }

  if (candidate.domain.includes("://") || /[\s/\\]/.test(candidate.domain)) {
    return invalid(index, "Cookie domain is malformed.");
  }

  const host = normalizeDomainForHost(candidate.domain);
  if (!isDomainLike(host) && !isIPv6Address(host)) {
    return invalid(index, "Cookie domain is not a valid host.");
  }

  if (typeof candidate.path !== "string" || candidate.path.trim() === "") {
    return invalid(index, "Cookie path is required.");
  }

  const expirationDate = Number(candidate.expirationDate);
  const isSession = Boolean(candidate.session) || !Number.isFinite(expirationDate);
  if (!isSession && (expirationDate <= 0 || expirationDate > MAX_COOKIE_EXPIRATION)) {
    return invalid(index, "Cookie expirationDate is outside the supported range.");
  }

  const sameSite = typeof candidate.sameSite === "string" && SAME_SITE_VALUES.has(candidate.sameSite)
    ? candidate.sameSite
    : "unspecified";

  const hostOnly = typeof candidate.hostOnly === "boolean"
    ? candidate.hostOnly
    : !String(candidate.domain).trim().startsWith(".");

  return {
    valid: true,
    cookie: {
      name: candidate.name,
      value: candidate.value,
      domain: candidate.domain.trim(),
      hostOnly,
      path: normalizePath(candidate.path),
      secure: Boolean(candidate.secure),
      httpOnly: Boolean(candidate.httpOnly),
      sameSite,
      session: isSession,
      expirationDate: isSession ? undefined : Math.floor(expirationDate),
      storeId: typeof candidate.storeId === "string" && candidate.storeId ? candidate.storeId : undefined,
      partitionKey: candidate.partitionKey && typeof candidate.partitionKey === "object" ? candidate.partitionKey : undefined
    }
  };
}

function invalid(index, reason) {
  return {
    valid: false,
    index,
    reason
  };
}

function canonicalCookieIdentityDomain(cookie) {
  const host = normalizeDomainForHost(cookie.domain);
  return cookie.hostOnly ? host : `.${host}`;
}

export function cookieToSetDetails(cookie) {
  const host = normalizeDomainForHost(cookie.domain);
  const protocol = cookie.secure ? "https:" : "http:";
  const path = normalizePath(cookie.path);
  const urlHost = isIPv6Address(host) && !host.startsWith("[") ? `[${host}]` : host;
  const details = {
    url: `${protocol}//${urlHost}${path}`,
    name: cookie.name,
    value: cookie.value,
    path,
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: SAME_SITE_VALUES.has(cookie.sameSite) ? cookie.sameSite : "unspecified"
  };

  const shouldOmitDomain = cookie.hostOnly || isLocalhost(host) || isIPv4Address(host) || isIPv6Address(host);
  if (!shouldOmitDomain) {
    details.domain = host;
  }

  if (!cookie.session && Number.isFinite(Number(cookie.expirationDate))) {
    details.expirationDate = Math.floor(Number(cookie.expirationDate));
  }

  if (cookie.storeId) {
    details.storeId = cookie.storeId;
  }

  if (cookie.partitionKey) {
    details.partitionKey = cookie.partitionKey;
  }

  return details;
}

export function summarizeValidationDetails(validation) {
  return {
    invalidPreview: validation.invalid.slice(0, 8).map((entry) => ({
      index: entry.index,
      reason: entry.reason
    })),
    duplicatePreview: validation.duplicate.slice(0, 8).map((entry) => ({
      index: entry.index,
      name: entry.cookie?.name,
      domain: entry.cookie?.domain,
      path: entry.cookie?.path
    }))
  };
}
