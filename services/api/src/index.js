import cors from "cors";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import express from "express";
import jwt from "jsonwebtoken";

const PORT = Number(process.env.PORT || 8787);
const DATABASE_PATH = process.env.DATABASE_PATH || "/data/app.db";
const MAILHOG_API_BASE = process.env.MAILHOG_API_BASE || "http://mailhog:8025";
const ADMIN_KEY = process.env.ADMIN_KEY || "change-me";
const JWT_SECRET = process.env.JWT_SECRET || "change-me-too";
const SMTP_MX_HOST = process.env.SMTP_MX_HOST || "mail.example.com";
const POSTFIX_SYNC_SIGNAL_PATH =
  process.env.POSTFIX_SYNC_SIGNAL_PATH || "/data/postfix-sync.signal";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database(DATABASE_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL UNIQUE,
  verify_token TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  verified_at TEXT
);

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  domain TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS message_state (
  message_id TEXT NOT NULL,
  address TEXT NOT NULL,
  seen INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (message_id, address)
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  permissions_json TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  last_used_at TEXT
);
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(
  express.static(path.join(__dirname, "../public"), {
    maxAge: 0,
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "no-store");
    }
  })
);

const stmtInsertDomain = db.prepare(`
INSERT INTO domains (domain, verify_token, status, created_at)
VALUES (@domain, @verifyToken, 'pending', @createdAt)
`);
const stmtGetDomainByName = db.prepare("SELECT * FROM domains WHERE domain = ?");
const stmtGetDomainById = db.prepare("SELECT * FROM domains WHERE id = ?");
const stmtListDomains = db.prepare("SELECT * FROM domains ORDER BY id DESC");
const stmtGetFirstVerifiedDomain = db.prepare(
  "SELECT * FROM domains WHERE status = 'verified' ORDER BY id ASC LIMIT 1"
);
const stmtVerifyDomain = db.prepare(`
UPDATE domains
SET status = 'verified', verified_at = @verifiedAt
WHERE id = @id
`);
const stmtDeleteDomain = db.prepare("DELETE FROM domains WHERE id = ?");

const stmtInsertAccount = db.prepare(`
INSERT INTO accounts (id, address, password_hash, domain, created_at, expires_at)
VALUES (@id, @address, @passwordHash, @domain, @createdAt, @expiresAt)
`);
const stmtGetAccountByAddress = db.prepare("SELECT * FROM accounts WHERE address = ?");
const stmtGetAccountById = db.prepare("SELECT * FROM accounts WHERE id = ?");
const stmtDeleteAccount = db.prepare("DELETE FROM accounts WHERE id = ?");
const stmtListAccounts = db.prepare("SELECT id, address, domain, created_at, expires_at FROM accounts ORDER BY created_at DESC");
const stmtCountAccounts = db.prepare("SELECT COUNT(*) AS c FROM accounts");
const stmtCountDomainsAll = db.prepare("SELECT COUNT(*) AS c FROM domains");
const stmtCountDomainsVerified = db.prepare("SELECT COUNT(*) AS c FROM domains WHERE status = 'verified'");

const stmtInsertApiKey = db.prepare(`
INSERT INTO api_keys (id, name, token_prefix, token_hash, permissions_json, is_active, created_at, expires_at)
VALUES (@id, @name, @tokenPrefix, @tokenHash, @permissionsJson, 1, @createdAt, @expiresAt)
`);
const stmtListApiKeys = db.prepare(`
SELECT id, name, token_prefix, permissions_json, is_active, created_at, expires_at, last_used_at
FROM api_keys
ORDER BY created_at DESC
`);
const stmtDeleteApiKey = db.prepare("DELETE FROM api_keys WHERE id = ?");
const stmtFindApiKeyByHash = db.prepare("SELECT * FROM api_keys WHERE token_hash = ?");
const stmtTouchApiKey = db.prepare("UPDATE api_keys SET last_used_at = @lastUsedAt WHERE id = @id");
const stmtCountApiKeys = db.prepare("SELECT COUNT(*) AS c FROM api_keys WHERE is_active = 1");

const stmtGetMessageState = db.prepare(`
SELECT * FROM message_state WHERE message_id = ? AND address = ?
`);
const stmtUpsertMessageState = db.prepare(`
INSERT INTO message_state (message_id, address, seen, deleted)
VALUES (@messageId, @address, @seen, @deleted)
ON CONFLICT(message_id, address)
DO UPDATE SET seen = excluded.seen, deleted = excluded.deleted
`);

function nowIso() {
  return new Date().toISOString();
}

async function markPostfixSyncNeeded(reason) {
  try {
    await fs.writeFile(
      POSTFIX_SYNC_SIGNAL_PATH,
      `${nowIso()} ${String(reason || "domain-change")}\n`,
      "utf8"
    );
  } catch (error) {
    console.error("[postfix-sync] unable to write signal", error?.message || error);
  }
}

function sanitizeDomain(raw) {
  if (typeof raw !== "string") return "";
  return raw.trim().toLowerCase().replace(/\.$/, "");
}

function emailFromHeader(raw) {
  if (!raw) return "";
  const matched = raw.match(/<([^>]+)>/);
  return (matched?.[1] || raw).trim();
}

function parseAuthToken(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return "";
  return auth.slice("Bearer ".length).trim();
}

function hashKey(raw) {
  return crypto.createHash("sha256").update(String(raw)).digest("hex");
}

function issueUserToken(account) {
  return jwt.sign(
    {
      sub: account.id,
      address: account.address,
      domain: account.domain
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function generateApiKey() {
  const body = crypto.randomBytes(24).toString("base64url");
  return `dk_${body}`;
}

function generateMailboxLocalPart(size = 10) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < size; i += 1) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

function isValidAddress(address) {
  return /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(address);
}

function parsePermissions(raw) {
  if (!Array.isArray(raw)) return [];
  return [...new Set(raw.map((v) => String(v).trim()).filter(Boolean))];
}

function resolveApiKey(token) {
  if (!token || !token.startsWith("dk_")) return null;
  const row = stmtFindApiKeyByHash.get(hashKey(token));
  if (!row || !row.is_active) return null;
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return null;
  stmtTouchApiKey.run({ id: row.id, lastUsedAt: nowIso() });
  return {
    id: row.id,
    name: row.name,
    permissions: JSON.parse(row.permissions_json || "[]")
  };
}

function hasPermission(apiKey, permissionId) {
  const permissions = Array.isArray(apiKey?.permissions) ? apiKey.permissions : [];
  return permissions.includes(permissionId);
}

async function ensureMailboxAccount(address, expiresIn = 0) {
  const normalized = String(address || "").trim().toLowerCase();
  if (!isValidAddress(normalized)) {
    throw new Error("Invalid address");
  }
  const [, domain] = normalized.split("@");
  const domainRow = stmtGetDomainByName.get(domain);
  if (!domainRow || domainRow.status !== "verified") {
    throw new Error("Domain not available or not verified");
  }

  const existing = stmtGetAccountByAddress.get(normalized);
  if (existing) {
    const expired =
      existing.expires_at && new Date(existing.expires_at).getTime() < Date.now();
    if (!expired) {
      return { account: existing, created: false };
    }
    stmtDeleteAccount.run(existing.id);
  }

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(
    crypto.randomBytes(18).toString("base64url"),
    10
  );
  const createdAt = nowIso();
  const expiresAt =
    expiresIn > 0 ? new Date(Date.now() + expiresIn * 1000).toISOString() : null;

  stmtInsertAccount.run({
    id,
    address: normalized,
    passwordHash,
    domain,
    createdAt,
    expiresAt
  });
  const createdRow = stmtGetAccountById.get(id);
  return { account: createdRow, created: true };
}

function requireAdmin(req, res, next) {
  const fromHeader = req.headers["x-admin-key"];
  const fromBearer = parseAuthToken(req);
  const key = String(fromHeader || fromBearer || "");
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: "Admin auth failed" });
  }
  return next();
}

function requireUser(req, res, next) {
  const token = parseAuthToken(req);
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const account = stmtGetAccountById.get(payload.sub);
    if (!account) return res.status(401).json({ error: "Account not found" });

    if (account.expires_at && new Date(account.expires_at).getTime() < Date.now()) {
      return res.status(401).json({ error: "Account expired" });
    }

    req.user = {
      id: account.id,
      address: account.address,
      domain: account.domain
    };
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function domainDnsHints(domain, verifyToken) {
  return {
    txt: {
      name: `_duckmail-challenge.${domain}`,
      value: verifyToken
    },
    mx: {
      name: domain,
      value: SMTP_MX_HOST,
      priority: 10
    }
  };
}

async function verifyDomainByDns(domain, verifyToken) {
  const challengeHost = `_duckmail-challenge.${domain}`;
  try {
    const txtRecords = await dns.resolveTxt(challengeHost);
    const flattened = txtRecords.map((parts) => parts.join("")).map((v) => v.trim());
    const matched = flattened.includes(verifyToken);
    return { matched, found: flattened, challengeHost };
  } catch (error) {
    return { matched: false, found: [], challengeHost, error: String(error.message || error) };
  }
}

function makeHydraCollection(items) {
  return {
    "hydra:member": items,
    "hydra:totalItems": items.length
  };
}

function decodeMimeEncodedWords(raw) {
  return String(raw || "").replace(
    /=\?([^?]+)\?([bqBQ])\?([^?]+)\?=/g,
    (_matched, _charset, mode, payload) => {
      try {
        if (String(mode).toUpperCase() === "B") {
          return Buffer.from(String(payload || ""), "base64").toString("utf8");
        }
        const qDecoded = String(payload || "")
          .replace(/_/g, " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (_hexToken, hex) =>
            String.fromCharCode(Number.parseInt(hex, 16))
          );
        return qDecoded;
      } catch {
        return String(payload || "");
      }
    }
  );
}

function decodeBase64TextChunk(rawChunk) {
  const compact = String(rawChunk || "").replace(/\s+/g, "");
  if (!compact || compact.length < 8) return "";
  if (!/^[A-Za-z0-9+/=]+$/.test(compact)) return "";
  try {
    const decoded = Buffer.from(compact, "base64").toString("utf8");
    if (!decoded) return "";
    const controlChars = (decoded.match(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g) || [])
      .length;
    if (controlChars > Math.max(4, Math.floor(decoded.length / 6))) {
      return "";
    }
    return decoded;
  } catch {
    return "";
  }
}

function decodeDeclaredBase64Sections(raw) {
  const lines = String(raw || "")
    .replace(/\r\n?/g, "\n")
    .split("\n");
  const decoded = [];
  let base64Declared = false;
  let inPayload = false;
  let chunk = [];

  const flushChunk = () => {
    if (!chunk.length) return;
    const text = decodeBase64TextChunk(chunk.join(""));
    if (text) decoded.push(text);
    chunk = [];
  };

  for (const line of lines) {
    const trimmed = String(line || "").trim();
    if (/^Content-Transfer-Encoding:\s*base64\b/i.test(trimmed)) {
      flushChunk();
      base64Declared = true;
      inPayload = false;
      continue;
    }
    if (!base64Declared) continue;

    if (!inPayload) {
      if (!trimmed) {
        inPayload = true;
        continue;
      }
      if (/^[A-Za-z-]+:/.test(trimmed)) {
        continue;
      }
      if (/^--/.test(trimmed)) {
        base64Declared = false;
        inPayload = false;
        continue;
      }
      inPayload = true;
    }

    if (/^--/.test(trimmed)) {
      flushChunk();
      base64Declared = false;
      inPayload = false;
      continue;
    }
    if (!trimmed) {
      flushChunk();
      continue;
    }
    if (/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
      chunk.push(trimmed);
      continue;
    }
    flushChunk();
  }

  flushChunk();
  return decoded;
}

function decodeHeaderText(raw) {
  return decodeMimeEncodedWords(raw).replace(/\r\n?/g, " ").trim();
}

function decodeBodyText(raw) {
  const source = String(raw || "");
  const decodedSections = decodeDeclaredBase64Sections(source);
  if (decodedSections.length) {
    return decodedSections.join("\n\n").trim();
  }
  return decodeMimeEncodedWords(source).trim();
}

function stripHtmlToText(raw) {
  let text = String(raw || "");
  text = text.replace(/<style[\s\S]*?<\/style>/gi, " ");
  text = text.replace(/<script[\s\S]*?<\/script>/gi, " ");
  text = text.replace(/<\/(?:p|div|li|tr|h[1-6])>/gi, "\n");
  text = text.replace(/<br\s*\/?>/gi, "\n");
  text = text.replace(/<li[^>]*>/gi, "- ");
  text = text.replace(/<[^>]+>/g, " ");
  text = text
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");
  return text
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

function decodeMimePartBody(part) {
  const partBody = typeof part?.Body === "string" ? part.Body : "";
  if (!partBody) return "";
  const partHeaders = part?.Headers || {};
  const cteRaw = partHeaders["Content-Transfer-Encoding"];
  const cteValues = Array.isArray(cteRaw)
    ? cteRaw
    : typeof cteRaw === "string"
      ? [cteRaw]
      : [];
  const isBase64Part = cteValues.some((v) => /base64/i.test(String(v || "")));
  if (isBase64Part) {
    const decoded = decodeBase64TextChunk(partBody);
    if (decoded) return decodeMimeEncodedWords(decoded).trim();
  }
  return decodeBodyText(partBody);
}

function partContentType(part) {
  const partHeaders = part?.Headers || {};
  const raw = partHeaders["Content-Type"];
  const values = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  return values.join("; ").toLowerCase();
}

function joinMessageChunks(chunks) {
  return chunks
    .map((v) => String(v || "").trim())
    .filter(Boolean)
    .join("\n\n")
    .trim();
}

function pickBestMessageText(plainChunks, htmlChunks, fallbackChunks) {
  const plainText = joinMessageChunks(plainChunks);
  if (plainText) return plainText;

  const htmlText = joinMessageChunks(htmlChunks);
  if (htmlText) return stripHtmlToText(htmlText);

  return joinMessageChunks(fallbackChunks);
}

function parseMultipartBodyText(raw) {
  const source = String(raw || "");
  const normalized = source.replace(/\r\n?/g, "\n");
  const headerBoundaryMatch = normalized.match(
    /^\s*Content-Type:\s*multipart\/[^\n;]+(?:;[^\n]*)?\bboundary="?([^";\n]+)"?/im
  );
  const lineBoundaryMatch = normalized.match(/^--([A-Za-z0-9'()+_,./:=?-]{8,})\s*$/m);
  const boundary = headerBoundaryMatch?.[1] || lineBoundaryMatch?.[1] || "";
  if (!boundary) return "";

  const delimiter = `--${boundary}`;
  if (!normalized.includes(delimiter)) return "";

  const plainChunks = [];
  const htmlChunks = [];
  const fallbackChunks = [];
  const segments = normalized.split(delimiter).slice(1);

  for (const segmentRaw of segments) {
    let segment = String(segmentRaw || "").trim();
    if (!segment || segment === "--") continue;
    if (segment.startsWith("--")) {
      segment = segment.slice(2).trim();
      if (!segment) continue;
    }

    const separatorIndex = segment.indexOf("\n\n");
    const headerBlock = separatorIndex >= 0 ? segment.slice(0, separatorIndex) : "";
    const bodyBlock = separatorIndex >= 0 ? segment.slice(separatorIndex + 2) : segment;
    if (!bodyBlock.trim()) continue;

    const headers = {};
    for (const line of headerBlock.split("\n")) {
      const matched = line.match(/^([A-Za-z-]+):\s*(.*)$/);
      if (!matched) continue;
      headers[matched[1].toLowerCase()] = matched[2];
    }

    const contentType = String(headers["content-type"] || "").toLowerCase();
    const transferEncoding = String(headers["content-transfer-encoding"] || "").toLowerCase();
    let decoded = "";
    if (/base64/.test(transferEncoding)) {
      decoded = decodeBase64TextChunk(bodyBlock);
    }
    if (!decoded) {
      decoded = decodeBodyText(bodyBlock);
    }
    decoded = String(decoded || "").trim();
    if (!decoded) continue;

    if (/text\/plain/.test(contentType)) {
      plainChunks.push(decoded);
    } else if (/text\/html/.test(contentType)) {
      htmlChunks.push(decoded);
    } else {
      fallbackChunks.push(decoded);
    }
  }

  return pickBestMessageText(plainChunks, htmlChunks, fallbackChunks);
}

function cleanTextForCodeExtraction(raw) {
  let text = decodeMimeEncodedWords(raw);
  const decodedBase64Sections = decodeDeclaredBase64Sections(text);
  if (decodedBase64Sections.length) {
    text += `\n${decodedBase64Sections.join("\n")}`;
  }
  text = text.replace(/\r\n?/g, "\n");
  text = text.replace(/^--[A-Za-z0-9'()+_,./:=?-]{8,}\s*$/gm, " ");
  text = text.replace(/^Content-(?:Type|Transfer-Encoding|Disposition):.*$/gim, " ");
  text = text.replace(/^MIME-Version:.*$/gim, " ");
  text = text.replace(/<style[\s\S]*?<\/style>/gi, " ");
  text = text.replace(/<script[\s\S]*?<\/script>/gi, " ");
  text = text.replace(/<[^>]+>/g, " ");
  text = text
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">");
  return text;
}

function isLikelyDateNumber(source, index, token) {
  const end = index + token.length;
  const before = source.slice(Math.max(0, index - 8), index);
  const after = source.slice(end, Math.min(source.length, end + 8));

  if (/[\/\-.]\d{1,2}\s*$/.test(before)) return true;
  if (/^\s*\d{1,2}[\/\-.]/.test(after)) return true;
  if (/^(19|20)\d{2}$/.test(token) && /^\s*[\/\-.]\s*\d{1,2}/.test(after)) return true;
  return false;
}

function normalizeCandidate(raw) {
  return String(raw || "").trim().replace(/\s+/g, "");
}

function isPlausibleCodeToken(token, source = "", index = 0) {
  const normalized = normalizeCandidate(token);
  if (!normalized) return false;
  if (normalized.length < 4 || normalized.length > 12) return false;
  if (!/\d/.test(normalized)) return false;

  if (/^\d+$/.test(normalized)) {
    if (/^0+$/.test(normalized)) return false;
    if (isLikelyDateNumber(source, index, normalized)) return false;
  }

  return true;
}

function parseCodes(text, customRegex) {
  if (!text) return [];

  const cleaned = cleanTextForCodeExtraction(text);
  const fromRegex = [];
  const fromKeyword = [];
  const sixDigits = [];
  const otherDigits = [];

  if (customRegex) {
    try {
      const reg = new RegExp(customRegex, "gi");
      for (const m of cleaned.matchAll(reg)) {
        let picked = m[0];
        if (Array.isArray(m) && m.length > 1) {
          const captured = m.slice(1).find((v) => String(v || "").trim());
          if (captured) picked = captured;
        }
        const token = normalizeCandidate(picked);
        const idx = typeof m.index === "number" ? m.index : 0;
        if (isPlausibleCodeToken(token, cleaned, idx)) {
          fromRegex.push(token);
        }
      }
    } catch {
      // ignore invalid regex
    }
  }

  const keywordRegex =
    /(?:验证码|校验码|动态码|提取码|otp|one[-\s]?time(?:\s+password)?|verification(?:\s+code)?|security\s+code|code)\D{0,24}([A-Za-z0-9]{4,10})/gi;
  for (const m of cleaned.matchAll(keywordRegex)) {
    const token = normalizeCandidate(m[1] || "");
    const idx = typeof m.index === "number" ? m.index : 0;
    if (isPlausibleCodeToken(token, cleaned, idx)) {
      fromKeyword.push(token);
    }
  }

  for (const m of cleaned.matchAll(/\b\d{6}\b/g)) {
    const token = m[0];
    const idx = typeof m.index === "number" ? m.index : 0;
    if (isPlausibleCodeToken(token, cleaned, idx)) {
      sixDigits.push(token);
    }
  }
  for (const m of cleaned.matchAll(/\b\d{4,8}\b/g)) {
    const token = m[0];
    const idx = typeof m.index === "number" ? m.index : 0;
    if (token.length === 6) continue;
    if (isPlausibleCodeToken(token, cleaned, idx)) {
      otherDigits.push(token);
    }
  }

  const ordered = [...fromRegex, ...fromKeyword, ...sixDigits, ...otherDigits];
  return [...new Set(ordered)];
}

function messageHeaderValues(message, headerName) {
  const headers = message?.Content?.Headers || {};
  const value = headers[headerName];
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [value];
  return [];
}

function messageBody(message) {
  const parts = message?.MIME?.Parts;
  if (Array.isArray(parts)) {
    const plainChunks = [];
    const htmlChunks = [];
    const fallbackChunks = [];

    for (const part of parts) {
      const decoded = decodeMimePartBody(part);
      if (!decoded) continue;
      const contentType = partContentType(part);
      if (/text\/plain/.test(contentType)) {
        plainChunks.push(decoded);
      } else if (/text\/html/.test(contentType)) {
        htmlChunks.push(decoded);
      } else {
        fallbackChunks.push(decoded);
      }
    }
    const fromParts = pickBestMessageText(plainChunks, htmlChunks, fallbackChunks);
    if (fromParts) return fromParts;
  }

  const directBody = message?.Content?.Body;
  if (typeof directBody === "string" && directBody.length > 0) {
    const multipartText = parseMultipartBodyText(directBody);
    if (multipartText) return multipartText;

    const decoded = decodeBodyText(directBody);
    if (/<[a-z][\s\S]*>/i.test(decoded)) {
      return stripHtmlToText(decoded);
    }
    return decoded;
  }

  return "";
}

function getMessageState(messageId, address) {
  return stmtGetMessageState.get(messageId, address) || { seen: 0, deleted: 0 };
}

function mapMessageForAccount(message, address) {
  const id = message?.ID || "";
  const fromHeader = decodeHeaderText(messageHeaderValues(message, "From")[0] || "");
  const subject = decodeHeaderText(messageHeaderValues(message, "Subject")[0] || "(no subject)");
  const body = messageBody(message);
  const createdAt = message?.Created || nowIso();
  const state = getMessageState(id, address);

  return {
    id,
    "@id": `/messages/${id}`,
    "@type": "Message",
    from: {
      address: emailFromHeader(fromHeader),
      name: fromHeader
    },
    to: [{ address }],
    subject,
    intro: body.replace(/\s+/g, " ").slice(0, 160),
    seen: Boolean(state.seen),
    isDeleted: Boolean(state.deleted),
    hasAttachments: false,
    size: body.length,
    downloadUrl: `/messages/${id}`,
    createdAt
  };
}

function messageBelongsToAddress(message, address) {
  const target = String(address || "").toLowerCase();
  const targets = [
    ...messageHeaderValues(message, "To"),
    ...messageHeaderValues(message, "Cc"),
    ...messageHeaderValues(message, "Delivered-To")
  ]
    .join(",")
    .toLowerCase();
  return targets.includes(target);
}

async function fetchMailhogMessages(limit = 200, start = 0) {
  const url = new URL("/api/v2/messages", MAILHOG_API_BASE);
  url.searchParams.set("limit", String(limit));
  url.searchParams.set("start", String(start));

  const response = await fetch(url.toString());
  if (!response.ok) {
    throw new Error(`MailHog API error: ${response.status}`);
  }
  const data = await response.json();
  return Array.isArray(data?.items) ? data.items : [];
}

async function listMessagesForAccount(address) {
  const source = await fetchMailhogMessages(500, 0);
  return source
    .filter((m) => messageBelongsToAddress(m, address))
    .map((m) => mapMessageForAccount(m, address))
    .filter((m) => !m.isDeleted)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

app.get("/", (_req, res) => {
  res.redirect("/admin.html");
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "duckmail-selfhost-api",
    time: nowIso()
  });
});

app.post("/admin/login", (req, res) => {
  const key = String(req.body?.key || "");
  if (key !== ADMIN_KEY) {
    return res.status(401).json({ error: "Invalid admin key" });
  }
  return res.json({ ok: true });
});

app.get("/admin/stats", requireAdmin, (_req, res) => {
  const totalDomains = stmtCountDomainsAll.get().c;
  const verifiedDomains = stmtCountDomainsVerified.get().c;
  const apiKeys = stmtCountApiKeys.get().c;
  const accounts = stmtCountAccounts.get().c;
  return res.json({
    totalDomains,
    verifiedDomains,
    apiKeys,
    accounts
  });
});

app.get("/admin/domains", requireAdmin, (_req, res) => {
  const rows = stmtListDomains.all().map((row) => ({
    ...row,
    dns: domainDnsHints(row.domain, row.verify_token)
  }));
  return res.json(rows);
});

app.post("/admin/domains", requireAdmin, (req, res) => {
  const domain = sanitizeDomain(req.body?.domain);
  if (!domain || !/^[a-z0-9.-]+$/.test(domain) || !domain.includes(".")) {
    return res.status(400).json({ error: "Invalid domain" });
  }
  if (stmtGetDomainByName.get(domain)) {
    return res.status(409).json({ error: "Domain already exists" });
  }

  const verifyToken = crypto.randomBytes(16).toString("hex");
  const createdAt = nowIso();
  stmtInsertDomain.run({ domain, verifyToken, createdAt });
  const created = stmtGetDomainByName.get(domain);
  return res.status(201).json({
    ...created,
    dns: domainDnsHints(created.domain, created.verify_token)
  });
});

app.delete("/admin/domains/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const row = stmtGetDomainById.get(id);
  if (!row) return res.status(404).json({ error: "Domain not found" });
  stmtDeleteDomain.run(id);
  await markPostfixSyncNeeded(`domain-deleted:${row.domain}`);
  return res.status(204).end();
});

app.post("/admin/domains/:id/verify", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const row = stmtGetDomainById.get(id);
  if (!row) return res.status(404).json({ error: "Domain not found" });

  const check = await verifyDomainByDns(row.domain, row.verify_token);
  if (!check.matched) {
    return res.status(400).json({
      ok: false,
      error: "TXT verification failed",
      challengeHost: check.challengeHost,
      expected: row.verify_token,
      found: check.found
    });
  }

  stmtVerifyDomain.run({ id, verifiedAt: nowIso() });
  await markPostfixSyncNeeded(`domain-verified:${row.domain}`);
  const updated = stmtGetDomainById.get(id);
  return res.json({
    ok: true,
    domain: updated
  });
});

app.get("/admin/accounts", requireAdmin, (_req, res) => {
  return res.json(stmtListAccounts.all());
});

app.get("/api-keys/permissions", (_req, res) => {
  return res.json({
    permissions: [
      { id: "domains:read", label: "Read domains" },
      { id: "accounts:create", label: "Create accounts" },
      { id: "messages:read", label: "Read messages" }
    ]
  });
});

app.get("/admin/api-keys", requireAdmin, (_req, res) => {
  const rows = stmtListApiKeys.all().map((r) => ({
    id: r.id,
    name: r.name,
    tokenPrefix: r.token_prefix,
    keyPrefix: r.token_prefix,
    permissions: JSON.parse(r.permissions_json || "[]"),
    isActive: Boolean(r.is_active),
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    lastUsedAt: r.last_used_at
  }));
  return res.json({ apiKeys: rows });
});

app.post("/admin/api-keys", requireAdmin, (req, res) => {
  const name = String(req.body?.name || "").trim();
  const permissions = parsePermissions(req.body?.permissions || []);
  const expiresInDays = Number(req.body?.expiresInDays || 0);
  const expiresAtRaw = req.body?.expiresAt;
  if (!name) {
    return res.status(400).json({ error: "name is required" });
  }
  const token = generateApiKey();
  const tokenHash = hashKey(token);
  const tokenPrefix = `${token.slice(0, 9)}***`;
  const id = crypto.randomUUID();
  const createdAt = nowIso();
  let expiresAt = null;
  if (typeof expiresAtRaw === "string" && expiresAtRaw.trim()) {
    const parsed = Date.parse(expiresAtRaw);
    if (Number.isNaN(parsed)) {
      return res.status(400).json({ error: "expiresAt is invalid" });
    }
    expiresAt = new Date(parsed).toISOString();
  } else if (expiresInDays > 0) {
    expiresAt = new Date(Date.now() + expiresInDays * 24 * 3600 * 1000).toISOString();
  }

  stmtInsertApiKey.run({
    id,
    name,
    tokenPrefix,
    tokenHash,
    permissionsJson: JSON.stringify(permissions),
    createdAt,
    expiresAt
  });

  return res.status(201).json({
    id,
    name,
    token,
    plainKey: token,
    tokenPrefix,
    keyPrefix: tokenPrefix,
    permissions,
    createdAt,
    expiresAt,
    warning: "API 密钥只展示一次，请立即保存。",
    apiKey: {
      id,
      name,
      keyPrefix: tokenPrefix,
      permissions,
      isActive: true,
      createdAt,
      expiresAt,
      lastUsedAt: null
    }
  });
});

app.delete("/admin/api-keys/:id", requireAdmin, (req, res) => {
  stmtDeleteApiKey.run(String(req.params.id));
  return res.status(204).end();
});

app.get("/domains", (_req, res) => {
  const apiKeyToken = parseAuthToken(_req);
  const apiKey = resolveApiKey(apiKeyToken);
  if (apiKeyToken && !apiKey) {
    return res.status(401).json({ message: "Invalid API key" });
  }
  if (apiKeyToken && apiKey && !hasPermission(apiKey, "domains:read")) {
    return res.status(403).json({ message: "Missing permission: domains:read" });
  }
  const items = stmtListDomains
    .all()
    .filter((d) => d.status === "verified")
    .map((d) => ({
      "@id": `/domains/${d.id}`,
      "@type": "Domain",
      id: d.id,
      domain: d.domain,
      isActive: true,
      isVerified: true,
      isPrivate: false,
      createdAt: d.created_at,
      updatedAt: d.verified_at || d.created_at
    }));
  return res.json(makeHydraCollection(items));
});

app.post("/accounts", async (req, res) => {
  const apiKeyToken = parseAuthToken(req);
  const apiKey = resolveApiKey(apiKeyToken);
  if (apiKeyToken && !apiKey) {
    return res.status(401).json({ message: "Invalid API key" });
  }
  if (apiKeyToken && apiKey && !hasPermission(apiKey, "accounts:create")) {
    return res.status(403).json({ message: "Missing permission: accounts:create" });
  }

  const address = String(req.body?.address || "").trim().toLowerCase();
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const expiresIn = Number(req.body?.expiresIn ?? 0);

  if (!isValidAddress(address)) {
    return res.status(422).json({ message: "Invalid address" });
  }
  if (password && password.length < 6) {
    return res.status(422).json({ message: "Password too short" });
  }

  const [, domain] = address.split("@");
  const domainRow = stmtGetDomainByName.get(domain);
  if (!domainRow || domainRow.status !== "verified") {
    return res.status(422).json({ message: "Domain not available or not verified" });
  }
  if (stmtGetAccountByAddress.get(address)) {
    return res.status(422).json({ message: "Email address already exists" });
  }

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(
    password || crypto.randomBytes(18).toString("base64url"),
    10
  );
  const createdAt = nowIso();
  const expiresAt =
    expiresIn > 0 ? new Date(Date.now() + expiresIn * 1000).toISOString() : null;

  stmtInsertAccount.run({
    id,
    address,
    passwordHash,
    domain,
    createdAt,
    expiresAt
  });

  return res.status(201).json({
    "@id": `/accounts/${id}`,
    "@type": "Account",
    id,
    address,
    quota: 100,
    used: 0,
    isDisabled: false,
    isDeleted: false,
    createdAt,
    updatedAt: createdAt
  });
});

app.post("/mailboxes/open", async (req, res) => {
  const apiKeyToken = parseAuthToken(req);
  const apiKey = resolveApiKey(apiKeyToken);
  if (apiKeyToken && !apiKey) {
    return res.status(401).json({ message: "Invalid API key" });
  }
  if (apiKeyToken && apiKey && !hasPermission(apiKey, "accounts:create")) {
    return res.status(403).json({ message: "Missing permission: accounts:create" });
  }

  const addressInput = String(req.body?.address || "").trim().toLowerCase();
  const domainInput = sanitizeDomain(req.body?.domain || "");
  const expiresIn = Number(req.body?.expiresIn ?? 0);
  let address = addressInput;

  if (!address) {
    let domainRow = null;
    if (domainInput) {
      domainRow = stmtGetDomainByName.get(domainInput);
    } else {
      domainRow = stmtGetFirstVerifiedDomain.get();
    }
    if (!domainRow || domainRow.status !== "verified") {
      return res.status(422).json({ message: "No verified domain available" });
    }

    let generated = "";
    for (let i = 0; i < 25; i += 1) {
      const candidate = `${generateMailboxLocalPart(10)}@${domainRow.domain}`;
      if (!stmtGetAccountByAddress.get(candidate)) {
        generated = candidate;
        break;
      }
    }
    if (!generated) {
      return res.status(500).json({ message: "Unable to allocate random mailbox" });
    }
    address = generated;
  }

  try {
    const { account, created } = await ensureMailboxAccount(address, expiresIn);
    const token = issueUserToken(account);
    return res.json({
      id: account.id,
      address: account.address,
      token,
      created,
      random: !addressInput,
      expiresAt: account.expires_at || null
    });
  } catch (error) {
    return res.status(422).json({
      message: String(error?.message || "Unable to open mailbox")
    });
  }
});

app.post("/token", async (req, res) => {
  const address = String(req.body?.address || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!isValidAddress(address)) {
    return res.status(422).json({ message: "Invalid address" });
  }

  if (!password) {
    try {
      const expiresIn = Number(req.body?.expiresIn ?? 0);
      const { account, created } = await ensureMailboxAccount(address, expiresIn);
      const token = issueUserToken(account);
      return res.json({
        id: account.id,
        address: account.address,
        token,
        created,
        mode: "passwordless"
      });
    } catch (error) {
      return res.status(422).json({
        message: String(error?.message || "Unable to issue token")
      });
    }
  }

  const account = stmtGetAccountByAddress.get(address);

  if (!account) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  if (account.expires_at && new Date(account.expires_at).getTime() < Date.now()) {
    return res.status(401).json({ message: "Account expired" });
  }

  const ok = await bcrypt.compare(password, account.password_hash);
  if (!ok) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = issueUserToken(account);
  return res.json({ id: account.id, token });
});

app.get("/me", requireUser, (req, res) => {
  const [localPart] = req.user.address.split("@");
  return res.json({
    id: req.user.id,
    address: req.user.address,
    username: localPart,
    name: localPart,
    domain_quota: 20,
    domain_used: 0,
    trust_level: 1
  });
});

app.get("/messages", requireUser, async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const all = await listMessagesForAccount(req.user.address);
  const pageSize = 30;
  const start = (page - 1) * pageSize;
  const items = all.slice(start, start + pageSize);
  return res.json({
    ...makeHydraCollection(items)
  });
});

app.get("/messages/:id", requireUser, async (req, res) => {
  const allRaw = await fetchMailhogMessages(500, 0);
  const foundRaw = allRaw.find(
    (m) => String(m?.ID) === String(req.params.id) && messageBelongsToAddress(m, req.user.address)
  );
  if (!foundRaw) return res.status(404).json({ message: "Message not found" });

  const mapped = mapMessageForAccount(foundRaw, req.user.address);
  const text = messageBody(foundRaw);
  const codes = parseCodes(text);

  return res.json({
    ...mapped,
    text,
    html: "",
    codes
  });
});

app.patch("/messages/:id", requireUser, (req, res) => {
  const seen = Boolean(req.body?.seen);
  const current = getMessageState(req.params.id, req.user.address);
  stmtUpsertMessageState.run({
    messageId: req.params.id,
    address: req.user.address,
    seen: seen ? 1 : current.seen,
    deleted: current.deleted || 0
  });
  return res.json({ seen });
});

app.delete("/messages/:id", requireUser, (req, res) => {
  const current = getMessageState(req.params.id, req.user.address);
  stmtUpsertMessageState.run({
    messageId: req.params.id,
    address: req.user.address,
    seen: current.seen || 0,
    deleted: 1
  });
  return res.status(204).end();
});

app.get("/messages/:id/code", requireUser, async (req, res) => {
  const allRaw = await fetchMailhogMessages(500, 0);
  const foundRaw = allRaw.find(
    (m) => String(m?.ID) === String(req.params.id) && messageBelongsToAddress(m, req.user.address)
  );
  if (!foundRaw) return res.status(404).json({ message: "Message not found" });

  const text = messageBody(foundRaw);
  const regex = typeof req.query.regex === "string" ? req.query.regex : "";
  const codes = parseCodes(text, regex);
  return res.json({
    messageId: req.params.id,
    codes,
    code: codes[0] || null
  });
});

app.get("/codes/latest", requireUser, async (req, res) => {
  const regex = typeof req.query.regex === "string" ? req.query.regex : "";
  const allRaw = await fetchMailhogMessages(500, 0);
  const related = allRaw
    .filter((m) => messageBelongsToAddress(m, req.user.address))
    .sort((a, b) => new Date(b?.Created || 0).getTime() - new Date(a?.Created || 0).getTime());

  for (const foundRaw of related) {
    const text = messageBody(foundRaw);
    const codes = parseCodes(text, regex);
    if (codes.length > 0) {
      const subject = messageHeaderValues(foundRaw, "Subject")[0] || "(no subject)";
      return res.json({
        messageId: foundRaw?.ID || null,
        subject,
        code: codes[0],
        codes
      });
    }
  }
  return res.status(404).json({ message: "No verification code found" });
});

app.delete("/accounts/:id", requireUser, (req, res) => {
  if (req.params.id !== req.user.id) {
    return res.status(403).json({ message: "Cannot delete other account" });
  }
  stmtDeleteAccount.run(req.user.id);
  return res.status(204).end();
});

app.use((err, _req, res, _next) => {
  console.error("[unhandled]", err);
  return res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`duckmail-selfhost-api listening on :${PORT}`);
});
