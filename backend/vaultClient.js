const axios = require("axios");

class VaultClient {
  constructor() {
    this.vaultAddr = process.env.VAULT_ADDR;
    this.roleId = process.env.BACKEND_ROLE_ID;
    this.secretId = process.env.BACKEND_SECRET_ID;
    this.token = null;
    this.expiry = null;
  }

  /**
   * Performs login using AppRole and caches the token
   */
  async login() {
    if (!this.roleId || !this.secretId) {
      throw new Error("Missing BACKEND_ROLE_ID or BACKEND_SECRET_ID in environment");
    }

    try {
      console.log("[VaultClient] Authenticating with AppRole...");
      const response = await axios.post(`${this.vaultAddr}/v1/auth/approle/login`, {
        role_id: this.roleId,
        secret_id: this.secretId,
      });

      const { client_token, lease_duration } = response.data.auth;
      this.token = client_token;
      
      // Set expiry with a 60-second buffer
      this.expiry = Date.now() + (lease_duration - 60) * 1000;
      
      console.log("[VaultClient] Successfully authenticated. Token lease:", lease_duration, "s");
      return this.token;
    } catch (err) {
      console.error("[VaultClient] Login failed:", err.response?.data || err.message);
      throw new Error("Vault authentication failed");
    }
  }

  /**
   * Returns a valid token, refreshing it if necessary
   */
  async getToken() {
    if (!this.token || !this.expiry || Date.now() >= this.expiry) {
      await this.login();
    }
    return this.token;
  }

  /**
   * Generic request wrapper that injects the current token
   */
  async request(config) {
    const token = await this.getToken();
    const headers = {
      ...config.headers,
      "X-Vault-Token": token,
    };

    try {
      return await axios({
        ...config,
        url: `${this.vaultAddr}${config.url}`,
        headers,
      });
    } catch (err) {
      // If we get a 403, maybe the token was revoked externally? 
      // Force a re-login on next attempt.
      if (err.response?.status === 403) {
        this.token = null;
      }
      throw err;
    }
  }

  // Helper methods to match the existing server.js logic
  async get(url, config = {}) {
    return this.request({ ...config, method: "GET", url });
  }

  async post(url, data, config = {}) {
    return this.request({ ...config, method: "POST", url, data });
  }

  async put(url, data, config = {}) {
    return this.request({ ...config, method: "PUT", url, data });
  }

  async patch(url, data, config = {}) {
    return this.request({ 
      ...config, 
      method: "PATCH", 
      url, 
      data,
      headers: { ...config.headers, "Content-Type": "application/merge-patch+json" }
    });
  }

  async delete(url, config = {}) {
    return this.request({ ...config, method: "DELETE", url });
  }

  async list(url, config = {}) {
    return this.request({ ...config, method: "LIST", url });
  }
}

module.exports = new VaultClient();
