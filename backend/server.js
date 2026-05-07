const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();
const vault = require("./vaultClient");

const app = express();
app.use(express.json());
app.use(cors());

const AUTH_SECRET = process.env.AUTH_SECRET || "dev-secret-change-me";
const USERS_JSON = process.env.USERS_JSON;

const REGISTRY_PREFIX = "_registry/apps";
const USER_REGISTRY_PREFIX = "_registry/users";

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replaceAll("=", "")
    .replaceAll("+", "-")
    .replaceAll("/", "_");
}

function base64UrlDecode(input) {
  const padded = input.replaceAll("-", "+").replaceAll("_", "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  const withPadding = padded + "=".repeat(padLength);
  return Buffer.from(withPadding, "base64").toString("utf8");
}

function hmacSha256Base64Url(input, secret) {
  const digest = crypto.createHmac("sha256", secret).update(input).digest();
  return base64UrlEncode(digest);
}

function signToken(payload, expiresInSeconds = 60 * 60 * 8) {
  const header = { alg: "HS256", typ: "JWT" };
  const nowSeconds = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: nowSeconds, exp: nowSeconds + expiresInSeconds };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(body));
  const toSign = `${encodedHeader}.${encodedPayload}`;
  const signature = hmacSha256Base64Url(toSign, AUTH_SECRET);
  return `${toSign}.${signature}`;
}

function verifyToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, signature] = parts;
  const toSign = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = hmacSha256Base64Url(toSign, AUTH_SECRET);

  const signatureBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expectedSignature);
  if (signatureBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(signatureBuf, expectedBuf)) return null;

  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload));
  } catch {
    return null;
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload?.exp !== "number" || payload.exp <= nowSeconds) return null;
  return payload;
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
}

function loadUsers() {
  if (USERS_JSON) {
    const parsed = JSON.parse(USERS_JSON);
    if (!Array.isArray(parsed)) throw new Error("USERS_JSON must be an array");
    return parsed.map((u) => ({
      username: u.username,
      role: u.role,
      password: u.password,
      salt: u.salt,
      passwordHash: u.passwordHash,
    }));
  }

  return [
    { username: "admin", password: "admin123", role: "admin" },
    { username: "dev", password: "dev123", role: "developer" },
  ];
}

function findUserInConfig(username) {
  const users = loadUsers();
  return users.find((u) => u.username === username) || null;
}

function verifyPassword(user, password) {
  if (!user) return false;
  if (typeof user.passwordHash === "string" && typeof user.salt === "string") {
    const computed = hashPassword(password, user.salt);
    const a = Buffer.from(computed);
    const b = Buffer.from(user.passwordHash);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }
  return typeof user.password === "string" && user.password === password;
}

function authRequired(req, res, next) {
  const raw = req.headers.authorization;
  const token = typeof raw === "string" && raw.startsWith("Bearer ") ? raw.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  const payload = verifyToken(token);
  if (!payload?.sub || !payload?.role) return res.status(401).json({ message: "Invalid token" });

  req.user = { username: payload.sub, role: payload.role };
  next();
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user?.role) return res.status(401).json({ message: "Unauthorized" });
    if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden" });
    next();
  };
}

function normalizeUsername(username) {
  if (typeof username !== "string") return null;
  const trimmed = username.trim();
  if (!trimmed) return null;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$/.test(trimmed)) return null;
  return trimmed;
}

function normalizeRole(role) {
  if (typeof role !== "string") return null;
  const trimmed = role.trim().toLowerCase();
  if (trimmed !== "admin" && trimmed !== "developer") return null;
  return trimmed;
}

function normalizeAppName(appName) {
  if (typeof appName !== "string") return null;
  const trimmed = appName.trim();
  if (!trimmed) return null;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,62}$/.test(trimmed)) return null;
  return trimmed;
}

async function registryGet(appName) {
  try {
    const res = await vault.get(`/v1/kv/data/${REGISTRY_PREFIX}/${encodeURIComponent(appName)}`);
    return res.data?.data?.data || null;
  } catch (err) {
    if (err?.response?.status === 404) return null;
    throw err;
  }
}

async function registryPut(appName, data) {
  await vault.post(`/v1/kv/data/${REGISTRY_PREFIX}/${encodeURIComponent(appName)}`, { data });
}

async function registryDelete(appName) {
  try {
    await vault.delete(`/v1/kv/metadata/${REGISTRY_PREFIX}/${encodeURIComponent(appName)}`);
  } catch (err) {
    if (err?.response?.status === 404) return;
    throw err;
  }
}

async function registryListAll() {
  try {
    const res = await vault.get(`/v1/kv/metadata/${REGISTRY_PREFIX}?list=true`);
    const keys = res.data?.data?.keys;
    return Array.isArray(keys) ? keys : [];
  } catch (err) {
    if (err?.response?.status === 404) return [];
    throw err;
  }
}

async function userRegistryGet(username) {
  try {
    const res = await vault.get(`/v1/kv/data/${USER_REGISTRY_PREFIX}/${encodeURIComponent(username)}`);
    return res.data?.data?.data || null;
  } catch (err) {
    if (err?.response?.status === 404) return null;
    throw err;
  }
}

async function userRegistryPut(username, data) {
  await vault.post(`/v1/kv/data/${USER_REGISTRY_PREFIX}/${encodeURIComponent(username)}`, { data });
}

async function userRegistryDelete(username) {
  try {
    await vault.delete(`/v1/kv/metadata/${USER_REGISTRY_PREFIX}/${encodeURIComponent(username)}`);
  } catch (err) {
    if (err?.response?.status === 404) return;
    throw err;
  }
}

async function userRegistryListAll() {
  try {
    const res = await vault.get(`/v1/kv/metadata/${USER_REGISTRY_PREFIX}?list=true`);
    const keys = res.data?.data?.keys;
    return Array.isArray(keys) ? keys : [];
  } catch (err) {
    if (err?.response?.status === 404) return [];
    throw err;
  }
}

async function assertAppOwnershipOrAdmin(req, appName) {
  const meta = await registryGet(appName);
  if (!meta) return { ok: false, status: 404, message: "App not found" };
  if (req.user.role === "admin") return { ok: true, meta };
  if (meta.owner !== req.user.username) return { ok: false, status: 403, message: "Forbidden" };
  return { ok: true, meta };
}

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  try {
    const normalized = normalizeUsername(username);
    if (!normalized) return res.status(401).json({ message: "Invalid credentials" });

    let registryUser = null;
    try {
      registryUser = await userRegistryGet(normalized);
    } catch {
      registryUser = null;
    }
    const user = registryUser
      ? { username: normalized, role: registryUser.role, salt: registryUser.salt, passwordHash: registryUser.passwordHash }
      : findUserInConfig(normalized);

    if (!verifyPassword(user, password)) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken({ sub: user.username, role: user.role });
    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.get("/me", authRequired, (req, res) => {
  res.json({ user: req.user });
});

app.post("/users", authRequired, requireRole(["admin"]), async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const role = normalizeRole(req.body?.role);
  const password = req.body?.password;

  if (!username) return res.status(400).json({ message: "Invalid username" });
  if (!role) return res.status(400).json({ message: "Invalid role" });
  if (typeof password !== "string" || password.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters" });
  }

  try {
    const existingInRegistry = await userRegistryGet(username);
    if (existingInRegistry) return res.status(409).json({ message: "User already exists" });

    const existingInConfig = findUserInConfig(username);
    if (existingInConfig) return res.status(409).json({ message: "User already exists" });

    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = hashPassword(password, salt);

    await userRegistryPut(username, {
      role,
      salt,
      passwordHash,
      createdAt: new Date().toISOString(),
      createdBy: req.user.username,
    });

    res.json({ user: { username, role } });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.get("/users", authRequired, requireRole(["admin"]), async (req, res) => {
  try {
    const keys = await userRegistryListAll();
    const users = await Promise.all(
      keys.map(async (key) => {
        const username = key.endsWith("/") ? key.slice(0, -1) : key;
        const data = await userRegistryGet(username);
        if (!data) return null;
        return { username, role: data.role, createdAt: data.createdAt, createdBy: data.createdBy };
      })
    );
    res.json({ users: users.filter(Boolean) });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.put("/users/:username", authRequired, requireRole(["admin"]), async (req, res) => {
  const username = normalizeUsername(req.params.username);
  if (!username) return res.status(400).json({ message: "Invalid username" });

  const role = req.body?.role !== undefined ? normalizeRole(req.body?.role) : undefined;
  const password = req.body?.password;

  if (req.body?.role !== undefined && !role) return res.status(400).json({ message: "Invalid role" });
  if (password !== undefined && (typeof password !== "string" || password.length < 6)) {
    return res.status(400).json({ message: "Password must be at least 6 characters" });
  }
  if (role === undefined && password === undefined) return res.status(400).json({ message: "Nothing to update" });

  try {
    const existing = await userRegistryGet(username);
    if (!existing) return res.status(404).json({ message: "User not found" });

    const next = { ...existing };
    if (role !== undefined) next.role = role;
    if (password !== undefined) {
      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = hashPassword(password, salt);
      next.salt = salt;
      next.passwordHash = passwordHash;
    }
    next.updatedAt = new Date().toISOString();
    next.updatedBy = req.user.username;

    await userRegistryPut(username, next);
    res.json({ user: { username, role: next.role } });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.delete("/users/:username", authRequired, requireRole(["admin"]), async (req, res) => {
  const username = normalizeUsername(req.params.username);
  if (!username) return res.status(400).json({ message: "Invalid username" });
  if (username === req.user.username) return res.status(400).json({ message: "Cannot delete current user" });

  try {
    const existing = await userRegistryGet(username);
    if (!existing) return res.status(404).json({ message: "User not found" });
    await userRegistryDelete(username);
    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

// ==============================
// USER SELF-SERVICE
// ==============================
app.post("/me/change-password", authRequired, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const username = req.user.username;

  if (typeof newPassword !== "string" || newPassword.length < 6) {
    return res.status(400).json({ message: "New password must be at least 6 characters" });
  }

  try {
    const existing = await userRegistryGet(username);
    if (!existing) return res.status(404).json({ message: "User not found in registry" });

    // Verify old password
    if (!verifyPassword(existing, oldPassword)) {
      return res.status(401).json({ message: "Current password incorrect" });
    }

    // Update password
    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = hashPassword(newPassword, salt);

    const next = {
      ...existing,
      salt,
      passwordHash,
      updatedAt: new Date().toISOString(),
      updatedBy: username
    };

    await userRegistryPut(username, next);
    res.json({ message: "Password changed successfully" });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.get("/apps", authRequired, async (req, res) => {
  try {
    const keys = await registryListAll();
    const metas = await Promise.all(
      keys.map(async (key) => {
        const appName = key.endsWith("/") ? key.slice(0, -1) : key;
        const meta = await registryGet(appName);
        return meta ? { appName, ...meta } : null;
      })
    );

    const filtered = metas.filter(Boolean).filter((m) => {
      if (req.user.role === "admin") return true;
      return m.owner === req.user.username;
    });

    filtered.sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));
    res.json({ apps: filtered });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.get("/apps/:appName", authRequired, async (req, res) => {
  const appName = normalizeAppName(req.params.appName);
  if (!appName) return res.status(400).json({ message: "Invalid app name" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });
    res.json({ appName, ...ownership.meta });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

app.get("/apps/:appName/secrets", authRequired, async (req, res) => {
  const appName = normalizeAppName(req.params.appName);
  if (!appName) return res.status(400).json({ message: "Invalid app name" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    try {
      const secret = await vault.get(`/v1/kv/data/${appName}/config`);
      const data = secret.data?.data?.data || {};
      if (req.user.role === "admin") return res.json({ appName, keys: Object.keys(data) });
      res.json({ appName, secrets: data });
    } catch (err) {
      if (err?.response?.status === 404) {
        if (req.user.role === "admin") return res.json({ appName, keys: [] });
        return res.json({ appName, secrets: {} });
      }
      return res.status(500).json(err.response?.data || err.message);
    }
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

// ==============================
// CREATE APP
// ==============================
app.post("/create-app", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.body?.appName);
  console.log(`[CreateApp] Request received for app: ${appName} by user: ${req.user.username}`);

  if (!appName) return res.status(400).json({ message: "Invalid app name" });

  try {
    const existing = await registryGet(appName);
    if (existing) {
      console.log(`[CreateApp] App ${appName} already exists in registry`);
      return res.status(409).json({ message: "App already exists" });
    }

    // 1. Create Policy
    console.log(`[CreateApp] Creating policy for ${appName}...`);
    const policy = `
      path "kv/data/${appName}/*" {
        capabilities = ["read"]
      }
    `;

    try {
      await vault.put(`/v1/sys/policies/acl/${appName}-policy`, { policy });
    } catch (err) {
      console.error(`[CreateApp] Error creating policy:`, err.response?.data || err.message);
      throw err;
    }

    // 2. Create AppRole
    console.log(`[CreateApp] Creating AppRole for ${appName}...`);
    try {
      await vault.post(`/v1/auth/approle/role/${appName}`, {
        token_policies: `${appName}-policy`,
        token_ttl: "1h",
        token_max_ttl: "4h",
      });
    } catch (err) {
      console.error(`[CreateApp] Error creating AppRole:`, err.response?.data || err.message);
      throw err;
    }

    // 3. Get Role ID
    console.log(`[CreateApp] Fetching RoleID for ${appName}...`);
    let roleId;
    try {
      roleId = await vault.get(`/v1/auth/approle/role/${appName}/role-id`);
    } catch (err) {
      console.error(`[CreateApp] Error fetching RoleID:`, err.response?.data || err.message);
      throw err;
    }

    // 4. Get Secret ID
    console.log(`[CreateApp] Generating SecretID for ${appName}...`);
    let secretId;
    try {
      secretId = await vault.post(`/v1/auth/approle/role/${appName}/secret-id`, {});
    } catch (err) {
      console.error(`[CreateApp] Error generating SecretID:`, err.response?.data || err.message);
      throw err;
    }

    console.log(`[CreateApp] Updating registry for ${appName}...`);
    await registryPut(appName, {
      owner: req.user.username,
      createdAt: new Date().toISOString(),
      role_id: roleId.data.data.role_id,
    });

    console.log(`[CreateApp] Successfully created app: ${appName}`);
    res.json({
      appName,
      role_id: roleId.data.data.role_id,
      secret_id: secretId.data.data.secret_id,
    });
  } catch (err) {
    console.error(`[CreateApp] Global error creating app ${appName}:`, err.response?.data || err.message);
    res.status(500).json(err.response?.data || err.message);
  }
});

async function safeVaultMerge(appName, newPairs) {
  // 1. Fetch current secrets (the "data" object inside Vault's response)
  let currentSecrets = {};
  try {
    const response = await vault.get(`/v1/kv/data/${encodeURIComponent(appName)}/config`);
    currentSecrets = response.data?.data?.data || {};
  } catch (e) {
    // If 404, it's a new app with no secrets yet, so we start with empty object
    if (e.response?.status !== 404) throw e;
  }

  // 2. Merge: New pairs overwrite existing ones, others are kept
  const mergedData = { ...currentSecrets, ...newPairs };

  // 3. Save back to Vault
  await vault.post(`/v1/kv/data/${encodeURIComponent(appName)}/config`, {
    data: mergedData
  });

  return mergedData;
}

// ==============================
// ADD/ROTATE SECRETS (SAFE MERGE)
// ==============================
app.post("/add-secret", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.body?.appName);
  const { key, value } = req.body || {};
  if (!appName) return res.status(400).json({ message: "Invalid app name" });
  if (typeof key !== "string" || !key) return res.status(400).json({ message: "Invalid key" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    await safeVaultMerge(appName, { [key]: value });
    res.json({ message: "Secret updated" });
  } catch (err) {
    console.error(`[AddSecret] Error:`, err.response?.data || err.message);
    res.status(500).json(err.response?.data || err.message);
  }
});

app.post("/add-secrets-batch", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.body?.appName);
  const secrets = req.body?.secrets;
  if (!appName) return res.status(400).json({ message: "Invalid app name" });
  if (!Array.isArray(secrets)) return res.status(400).json({ message: "Invalid secrets" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    const batchPayload = {};
    secrets.forEach(({ key, value }) => {
      if (typeof key === "string" && key) {
        batchPayload[key] = value;
      }
    });

    await safeVaultMerge(appName, batchPayload);
    res.json({ message: "Secrets updated successfully" });
  } catch (err) {
    console.error(`[BatchSecret] Error:`, err.response?.data || err.message);
    res.status(500).json(err.response?.data || err.message);
  }
});

app.post("/rotate-secret", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.body?.appName);
  const { key, newValue } = req.body || {};
  if (!appName) return res.status(400).json({ message: "Invalid app name" });
  if (typeof key !== "string" || !key) return res.status(400).json({ message: "Invalid key" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    await safeVaultMerge(appName, { [key]: newValue });
    res.json({ message: "Secret rotated" });
  } catch (err) {
    console.error(`[RotateSecret] Error:`, err.response?.data || err.message);
    res.status(500).json(err.response?.data || err.message);
  }
});

app.delete("/apps/:appName/secrets/:key", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.params.appName);
  const key = req.params.key;

  console.log(`[DeleteSecretKey] Request for App: ${appName}, Key: ${key}`);

  if (!appName || !key) return res.status(400).json({ message: "Invalid parameters" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    // 1. Fetch current
    let currentData = {};
    try {
      const existing = await vault.get(`/v1/kv/data/${encodeURIComponent(appName)}/config`);
      currentData = existing.data?.data?.data || {};
    } catch (e) {
      if (e.response?.status !== 404) throw e;
    }

    // 2. Delete the key
    if (currentData[key] !== undefined) {
      delete currentData[key];
      // 3. Save the remaining (using POST to KV-V2 data path)
      await vault.post(`/v1/kv/data/${encodeURIComponent(appName)}/config`, { data: currentData });
      console.log(`[DeleteSecretKey] Successfully deleted key: ${key}`);
    } else {
      console.log(`[DeleteSecretKey] Key not found: ${key}`);
    }

    res.json({ message: `Secret key '${key}' deleted successfully.` });
  } catch (err) {
    console.error(`[DeleteSecretKey] Error:`, err.response?.data || err.message);
    res.status(500).json(err.response?.data || err.message);
  }
});

// ==============================
// REGENERATE SECRET ID (WITH REVOCATION)
// ==============================
app.post("/regenerate-secret-id", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.params.appName || req.body?.appName);
  if (!appName) return res.status(400).json({ message: "Invalid app name" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    // 1. List all existing Secret ID accessors
    // Note: In Vault AppRole, the LIST method on '/secret-id' returns the accessors
    console.log(`[RotateSecretID] Listing existing accessors for ${appName}...`);
    try {
      const listRes = await vault.list(`/v1/auth/approle/role/${appName}/secret-id`);
      const accessors = listRes.data?.data?.keys || [];

      if (accessors.length > 0) {
        console.log(`[RotateSecretID] Found ${accessors.length} old accessors. Destroying all...`);
        // 2. Destroy each secret ID using its accessor
        for (const accessor of accessors) {
          // Correct endpoint for accessors is /secret-id-accessor/destroy
          await vault.post(`/v1/auth/approle/role/${appName}/secret-id-accessor/destroy`, {
            secret_id_accessor: accessor
          });
          console.log(`[RotateSecretID] Successfully destroyed accessor: ${accessor}`);
        }
      } else {
        console.log(`[RotateSecretID] No existing Secret IDs to revoke.`);
      }
    } catch (e) {
      // 404 means no Secret IDs currently exist, which is fine
      if (e.response?.status === 404) {
        console.log(`[RotateSecretID] No Secret IDs found (404).`);
      } else {
        console.error(`[RotateSecretID] Revocation error:`, e.response?.data || e.message);
      }
    }

    // 3. Generate fresh Secret ID
    console.log(`[RotateSecretID] Generating new replacement Secret ID...`);
    const response = await vault.post(`/v1/auth/approle/role/${appName}/secret-id`, {});
    const newSecretId = response.data.data.secret_id;

    res.json({
      secret_id: newSecretId,
      message: "Rotation successful: All previous IDs destroyed."
    });
  } catch (err) {
    console.error(`[RotateSecretID] Global failure:`, err.response?.data || err.message);
    res.status(500).json(err.response?.data || err.message);
  }
});

app.delete("/apps/:appName", authRequired, requireRole(["developer"]), async (req, res) => {
  const appName = normalizeAppName(req.params.appName);
  if (!appName) return res.status(400).json({ message: "Invalid app name" });

  try {
    const ownership = await assertAppOwnershipOrAdmin(req, appName);
    if (!ownership.ok) return res.status(ownership.status).json({ message: ownership.message });

    await vault.delete(`/v1/auth/approle/role/${appName}`);
    await vault.delete(`/v1/sys/policies/acl/${appName}-policy`);

    try {
      await vault.delete(`/v1/kv/metadata/${encodeURIComponent(appName)}`);
    } catch (err) {
      if (err?.response?.status !== 404) throw err;
    }

    await registryDelete(appName);
    res.json({ message: "App deleted" });
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

// ==============================
app.listen(process.env.PORT, () => {
  console.log("Backend running on port", process.env.PORT);
});
