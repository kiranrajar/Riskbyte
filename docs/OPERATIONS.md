# RiskByte SOC Agent — Enterprise Operations Manual

## 1. Cryptographic Key Management & Rotation

### RSA-4096 Instance Keypair
On initial deployment, the platform generates a unique 4096-bit RSA instance keypair stored in `/data/keys/instance_private.pem` (permissions `0600`).
- **Private Key:** Stays locked inside the enclave. Never leaves the host.
- **Public Key:** Exportable via the **Admin & License** view or CLI:
  ```bash
  python -m riskbyte.tools.export_key --out /tmp/riskbyte_public.pem
  ```

### Audit Hash-Chain Verification
The audit trail is sequentially linked using SHA-256 hash chains (`H_n = SHA256(H_{n-1} || payload_n)`). Every 50 records, a block digest is signed with the instance RSA private key using RSASSA-PSS with MGF1.

To verify audit chain integrity via CLI:
```bash
docker compose exec app python -c "from riskbyte.core.db import Database; db = Database('/data/riskbyte.db'); print(db.verify_audit_chain())"
```

---

## 2. Backup and Disaster Recovery

### Data Directory Backup
```bash
# 1. Take consistent SQLite/PostgreSQL snapshot
docker compose exec postgres pg_dump -U riskbyte -d riskbyte -F c -f /tmp/backup.dump
docker cp riskbyte-postgres:/tmp/backup.dump /opt/backups/riskbyte_pg_$(date +%F).dump

# 2. Archive instance keys and audit logs
tar -czf /opt/backups/riskbyte_keys_$(date +%F).tar.gz /data/keys /data/license.rbl
```

### Restoration Runbook
1. Re-deploy the stack with `deploy/install.sh`.
2. Stop the core services: `docker compose stop app worker`.
3. Restore the PostgreSQL dump:
   ```bash
   docker compose exec -T postgres pg_restore -U riskbyte -d riskbyte < /opt/backups/riskbyte_pg.dump
   ```
4. Restore `/data/keys` and start services: `docker compose start`.

---

## 3. Human-in-the-Loop Incident Response Runbook
When RiskByte AI recommends a containment or eradication action:
1. The action is placed in the **HITL Response Gate** (`/api/approvals`).
2. An authorized analyst inspects:
   - **Blast Radius Preview:** Identifies targeted host, IP, active user sessions, and service dependencies.
   - **AI Rationale & Cited Evidence:** Direct links to the primary telemetry records.
   - **Reversibility:** Indicates whether host un-isolation or firewall rule rollback is supported.
3. The analyst provides step-up authentication (MFA re-verification).
4. The action executes via the appropriate connector (e.g. Wazuh Active Response or Suricata command socket).
5. The full execution, analyst ID, and result are recorded into the signed audit log.
