# 🛑 Vault Stop & Recovery Guide

This document explains what happens when Vault stops, how to recover, and provides test scenarios to verify that your data is safe.

## 🧠 The "Vault Reality"
1. **Data is Persistent**: Everything (secrets, apps, users) is stored in `C:\vault\data`.
2. **Sealing is Automatic**: Every time Vault starts, it is **LOCKED (Sealed)**. It cannot read its own data until you provide the unseal keys.
3. **Apps are Resilient**: The `vaultClient.js` in the backend is designed to handle temporary connection losses.

---

## 🆘 Recovery Procedure (The "Quick Fix")

If Vault stops, follow these steps to restore service:

1. **Start the Process**:
   ```powershell
   vault server -config=C:\vault\config.hcl
   ```
2. **Unseal (Repeat 3 times)**:
   ```powershell
   $env:VAULT_ADDR="https://127.0.0.1:8200"
   $env:VAULT_SKIP_VERIFY="true"
   vault operator unseal
   ```
   *(Enter your unique Unseal Keys)*.
3. **Verify**: Check the Dashboard. Everything should reappear.

---

## 🧪 Test Scenarios (Verify it yourself)

### Scenario 1: The "Accidental Crash"
**Goal**: Prove that secrets and dashboard data survive a process kill.
1. **Setup**: Create a new app in the Dashboard (e.g., "Test-App") and add one secret.
2. **The Stop**: Go to the terminal running Vault and press `Ctrl+C` (or kill the process).
3. **The Check**: Refresh the Dashboard. It should show an error or a loading spinner (Backend can't talk to Vault).
4. **The Recovery**: Start Vault and **Unseal** it.
5. **The Result**: Refresh the Dashboard. "Test-App" and its secret should still be there.

### Scenario 2: The "Sealed Security"
**Goal**: Prove that data is inaccessible while Vault is started but not yet unsealed.
1. **The Stop**: Stop the Vault server.
2. **The Start**: Start the Vault server again, but **DO NOT** run the unseal command.
3. **The Check**: Try to log into the Dashboard or fetch secrets.
4. **The Result**: You should get an error. This proves that even if someone starts your Vault process, they cannot see your data without your keys.
5. **Finalize**: Run the unseal command and watch the Dashboard come back to life.

### Scenario 3: The "Backend Auto-Reconnect"
**Goal**: Verify the `vaultClient.js` automatically gets a new token after a restart.
1. **Setup**: Ensure everything is running.
2. **The Stop**: Stop Vault.
3. **The Start**: Start and Unseal Vault.
4. **The Check**: Without restarting the Backend server, try to add a new secret in the Dashboard.
5. **The Result**: The Backend should detect the 403/Connection error, re-authenticate using its AppRole (`role_id`/`secret_id`), and complete the request successfully.

---

## ⚠️ Warning: The only way to LOSE data
You will only lose your data if:
1. You delete the `C:\vault\data` folder.
2. You lose your **Unseal Keys** (If Vault is sealed and you lose the keys, the data is encrypted forever and cannot be recovered).
