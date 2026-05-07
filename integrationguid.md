# 🔌 Application Integration Guide

This guide explains how to integrate your own applications with the **Vault Centralized Secret Manager**.

---

## 🛠 Step 1: Get Your Credentials
Before coding, you must register your app in the Dashboard to get your unique identity:
1.  Log in to the **Vault Admin UI**.
2.  Create a new app (e.g., `my-service`).
3.  **Copy the Role ID and Secret ID**. You will need these for your `.env` file.
4.  Add your secrets (e.g., `DB_PASSWORD`, `API_KEY`) via the "Add Secrets" panel.

---

## 💻 Step 2: Implementation Logic
Every integrated app follows this 2-step flow:
1.  **Auth**: Use `role_id` and `secret_id` to get a temporary `client_token` from Vault.
2.  **Fetch**: Use the `client_token` to read your secrets.

### Example Node.js Implementation
```javascript
const axios = require('axios');

async function getVaultSecrets() {
  const VAULT_ADDR = process.env.VAULT_ADDR; // e.g., https://127.0.0.1:8200
  const ROLE_ID = process.env.ROLE_ID;
  const SECRET_ID = process.env.SECRET_ID;

  // 1. Login to Vault via AppRole
  const auth = await axios.post(`${VAULT_ADDR}/v1/auth/approle/login`, {
    role_id: ROLE_ID,
    secret_id: SECRET_ID
  });
  
  const token = auth.data.auth.client_token;

  // 2. Fetch secrets (path is always kv/data/<APP_NAME>/config)
  const secrets = await axios.get(`${VAULT_ADDR}/v1/kv/data/my-service/config`, {
    headers: { 'X-Vault-Token': token }
  });

  return secrets.data.data.data;
}
```

---

## 🤖 AI Agent Integration Prompts
If you are using an AI agent (like Trae, Cursor, or ChatGPT) to develop your app, use these prompts to ensure a perfect integration:

### Prompt 1: Initial Setup
> "I am developing a Node.js app that needs to fetch its secrets from a HashiCorp Vault instance. The Vault uses AppRole authentication. Please set up a basic connection logic that uses `VAULT_ADDR`, `ROLE_ID`, and `SECRET_ID` from environment variables to authenticate and fetch secrets from the path `v1/kv/data/<MY_APP_NAME>/config`."

### Prompt 2: Secure Caching (Advanced)
> "Refactor my Vault integration logic to be more production-ready. I want a `vaultClient.js` module that handles AppRole login, caches the `client_token` in memory, and automatically refreshes it before it expires (based on the `lease_duration`). All subsequent API calls in my app should use this cached token."

### Prompt 3: Environment Configuration
> "Create a `.env.example` file for my project. It should include placeholders for `VAULT_ADDR`, `ROLE_ID`, and `SECRET_ID`. Also, add `NODE_TLS_REJECT_UNAUTHORIZED=0` because we are using a self-signed certificate for local development."

---

## 📋 Integration Checklist
- [ ] App registered in Dashboard.
- [ ] `ROLE_ID` and `SECRET_ID` saved in `.env`.
- [ ] `VAULT_ADDR` set to `https://127.0.0.1:8200`.
- [ ] App logic fetches from `v1/kv/data/<APP_NAME>/config`.
- [ ] `NODE_TLS_REJECT_UNAUTHORIZED=0` added (for local dev only).

---

## 🔄 Secret ID Rotation (Security Enforcement)
When you click **Rotate Secret ID** in the Dashboard, the following happens:
1.  **Immediate Revocation**: The system identifies and **destroys** every previous Secret ID associated with your app.
2.  **Access Cutoff**: Any app currently running with an old `SECRET_ID` will fail to authenticate with Vault the next time it tries to log in.
3.  **New Identity**: A fresh `SECRET_ID` is generated and displayed.

**Developer Action Required**: 
- You **must** update your app's `.env` file with the new `SECRET_ID` immediately.
- If your app caches the token, it will continue to work until the token expires (usually 1h), but it will fail to refresh its token until you update the environment variable and restart the app.
