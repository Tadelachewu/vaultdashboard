# 🏭 Vault Setup Guide (Production-like with Raft & TLS)

This guide helps you set up a local HashiCorp Vault instance specifically configured for this project.

## 🧭 Phase 1 — Create Structure
1. Create the main folder and subdirectories:
   ```powershell
   mkdir C:\vault
   cd C:\vault
   mkdir data
   mkdir tls
   mkdir logs
   ```

## 🔐 Phase 2 — Generate TLS (Self-Signed)
1. Generate the private key and certificate:
   ```powershell
   openssl genrsa -out C:\vault\tls\key.pem 2048
   openssl req -new -x509 -key C:\vault\tls\key.pem -out C:\vault\tls\cert.pem -days 365
   ```
   *Note: Use `127.0.0.1` for the Common Name (CN).*

## ⚙️ Phase 3 — Configuration
1. Create `C:\vault\config.hcl` with the following content:
   ```hcl
   ui = true

   storage "raft" {
     path    = "C:/vault/data"
     node_id = "node1"
   }

   listener "tcp" {
     address       = "127.0.0.1:8200"
     tls_cert_file = "C:/vault/tls/cert.pem"
     tls_key_file  = "C:/vault/tls/key.pem"
   }

   api_addr     = "https://127.0.0.1:8200"
   cluster_addr = "https://127.0.0.1:8201"

   disable_mlock = true
   ```

## 🚀 Phase 4 — Start & Initialize
1. Start the Vault server:
   ```powershell
   vault server -config=C:\vault\config.hcl
   ```
2. In a **new** PowerShell window, set environment variables:
   ```powershell
   $env:VAULT_ADDR="https://127.0.0.1:8200"
   $env:VAULT_SKIP_VERIFY="true"
   ```
3. Initialize Vault:
   ```powershell
   vault operator init
   ```
   *Note: If you get "Vault is already initialized", it means data exists in `C:\vault\data`. See Troubleshooting below if you lost your keys.*
   **CRITICAL: Save the Unseal Keys and Root Token securely.**
4. Unseal Vault (repeat 3 times with different keys):
   ```powershell
   vault operator unseal
   ```
5. Login with the Root Token:
   ```powershell
   vault login <ROOT_TOKEN>
   ```

## 📦 Phase 5 — Enable Features
1. Enable the KV-V2 engine (at path `kv` as expected by the apps):
   ```powershell
   vault secrets enable -path=kv kv-v2
   ```
2. Enable AppRole authentication:
   ```powershell
   vault auth enable approle
   ```
3. Enable audit logging:
   ```powershell
   vault audit enable file file_path=C:\vault\logs\audit.log
   ```

## 🔑 Phase 6 — App-Specific Configuration

### 1. Contact App Setup
1. Store secrets for the contact app:
   ```powershell
   vault kv put kv/contact/config `
     DB_USER="admin" `
     DB_PASS="Strong@123" `
     JWT_SECRET="supersecret"
   ```
2. Create policy `C:\vault\contact-policy.hcl`:
   ```hcl
   path "kv/data/contact/config" {
     capabilities = ["read"]
   }
   ```
3. Apply the policy:
   ```powershell
   vault policy write contact-policy C:\vault\contact-policy.hcl
   ```
4. Create AppRole for the app:
   ```powershell
   vault write auth/approle/role/contact-app `
     token_policies="contact-policy" `
     token_ttl=1h `
     token_max_ttl=4h
   ```
5. Retrieve RoleID and SecretID (needed for `.env`):
   ```powershell
   vault read auth/approle/role/contact-app/role-id
   vault write -f auth/approle/role/contact-app/secret-id
   ```

### 2. Backend Registry Setup
The backend service now uses **AppRole** authentication instead of a static token.

1. Create policy `C:\vault\backend-policy.hcl`:
   ```hcl
   # Manage policies and AppRoles for other apps
   path "sys/policies/acl/*" {
     capabilities = ["create", "read", "update", "delete", "list"]
   }
   path "auth/approle/role/*" {
     capabilities = ["create", "read", "update", "delete", "list"]
   }
   path "auth/approle/role/*/role-id" {
     capabilities = ["read"]
   }
   path "auth/approle/role/*/secret-id" {
     capabilities = ["create", "update"]
   }

   # Manage registry data
   path "kv/data/_registry/*" {
     capabilities = ["create", "read", "update", "delete", "list"]
   }
   path "kv/metadata/_registry/*" {
     capabilities = ["list", "delete"]
   }

   # Manage all app secrets (required for the dashboard view)
   path "kv/data/*" {
     capabilities = ["create", "read", "update", "delete", "list"]
   }
   path "kv/metadata/*" {
     capabilities = ["list", "delete"]
   }
   ```
2. Apply the policy:
   ```powershell
   vault policy write backend-policy C:\vault\backend-policy.hcl
   ```
3. Create the AppRole for the Backend:
   ```powershell
   vault write auth/approle/role/backend-role `
     token_policies="backend-policy" `
     token_ttl=24h `
     token_max_ttl=72h
   ```
4. Generate credentials for `backend/.env`:
   ```powershell
   # Get Role ID
   vault read auth/approle/role/backend-role/role-id

   # Get Secret ID
   vault write -f auth/approle/role/backend-role/secret-id
   ```
5. Update `backend/.env` with these values:
   ```env
   BACKEND_ROLE_ID="<ROLE_ID>"
   BACKEND_SECRET_ID="<SECRET_ID>"
   ```

## 🌐 Summary of App Environments
| App | Variable | Value |
|---|---|---|
| **All** | `VAULT_ADDR` | `https://127.0.0.1:8200` |
| **Contact App** | `ROLE_ID` | *from Step 6.5* |
| **Contact App** | `SECRET_ID` | *from Step 6.5* |
| **Backend** | `VAULT_TOKEN` | *Root Token or Backend-specific token* |

## 🆘 Disaster Recovery & Restarts

### 1. Does Vault lose data if it stops?
**No.** Because we configured the `raft` storage, all secrets, policies, and AppRoles are saved permanently in `C:\vault\data`. When the process stops, the data stays on your hard drive.

### 2. What happens to the Apps?
When Vault stops or restarts:
- **Connection Errors**: Apps will get "Connection Refused" errors.
- **Sealing**: Every time Vault starts, it is **SEALED** by default. Even if the process is running, it will return errors until you unseal it.
- **Tokens**: Any temporary client tokens in the apps' memory will become invalid if Vault is down for longer than their lease, or if you reset the Vault data.

### 3. The "Vault Restart" Checklist
If your computer restarts or Vault crashes, follow these steps in order:

1. **Start the Server**:
   ```powershell
   vault server -config=C:\vault\config.hcl
   ```
2. **Unseal (The most important step)**:
   Open a new terminal and run:
   ```powershell
   $env:VAULT_ADDR="https://127.0.0.1:8200"
   $env:VAULT_SKIP_VERIFY="true"
   vault operator unseal
   ```
   *(Enter your 3 unseal keys. Vault will not work until this is done!)*
3. **Check Apps**:
   Once unsealed, the `vaultClient.js` in the backend will automatically attempt to re-authenticate the next time it needs a token. You might need to restart the backend if it crashed due to the initial connection loss.

## 🛠 Troubleshooting

### ❌ Error: "Vault is already initialized"
This happens if you run `vault operator init` but the `C:\vault\data` folder is not empty.

**Option A: If you HAVE the keys**
Simply skip initialization and proceed to **Unseal**:
```powershell
vault operator unseal
```

**Option B: If you LOST the keys (Reset Vault)**
If you lost your unseal keys/root token and want to start fresh:
1. Stop the Vault process (Ctrl+C).
2. Delete the contents of the data folder:
stop first
   ```powershell
   Remove-Item -Path "C:\vault\data\*" -Recurse -Force
   ```
3. Start the server again and run `vault operator init`.

### ❌ Error: "connection refused" or "TLS handshake error"
1. Ensure the Vault server is actually running in another terminal.
2. Ensure you set the environment variables:
   ```powershell
   $env:VAULT_ADDR="https://127.0.0.1:8200"
   $env:VAULT_SKIP_VERIFY="true"
   ```
