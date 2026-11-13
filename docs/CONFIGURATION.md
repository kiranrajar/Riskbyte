# RiskByte SOC Agent — Enterprise Configuration Reference

## 1. Modular Sensor Connectors
RiskByte SOC Agent normalizes telemetry from all enterprise sensors into the **OCSF v1.1.0** schema with Community ID v1 flow hashing.

### Wazuh Connector (EDR & Manager)
- **API Endpoint:** `https://wazuh.internal:55000`
- **Indexer Endpoint:** `https://wazuh-indexer.internal:9200`
- **Capabilities:** Agent inventory, vulnerability scanning, FIM (File Integrity Monitoring), CIS SCA benchmarks, and active response execution.
- **Authentication:** JWT retrieved from `/security/user/authenticate`. Credential stored in RiskByte database using AES-256-GCM envelope encryption wrapped by the platform's RSA-4096 instance key.

### Suricata Connector (Network IDS/IPS)
- **Input Method:** EVE JSON file stream (`/var/log/suricata/eve.json`) or syslog.
- **Active Response:** Unix Domain Command Socket (`/var/run/suricata/suricata-command.socket`) to add dynamic IP drop rules.

### Zeek Connector (Network Security Monitor)
- **Input Method:** JSON log stream reader for `conn.log`, `dns.log`, `ssl.log`, and `notice.log`.
- **Correlation:** Computes SHA-1 Community ID v1 flow hashes to link Zeek connections with Suricata alerts and host socket telemetry.

### TheHive 5 & Cortex Connector (SOAR & Incident Tracking)
- **API Endpoint:** `https://thehive.internal:9000`
- **Bidirectional Sync:** Cases opened in RiskByte sync to TheHive; observables and tasks sync back to RiskByte.
- **Cortex:** Dispatches on-premises analyzers (YARA, Cuckoo Sandbox, ClamAV) and responders.

### Splunk Enterprise / Enterprise Security Connector
- **Search API:** `https://splunk.internal:8089/services/search/jobs`
- **HEC Forwarding:** `https://splunk.internal:8088/services/collector/event`
- **Use Case:** Historical correlation, correlation searches, and notable events.

### MISP Threat Intelligence Connector
- **API Endpoint:** `https://misp.internal`
- **Local Caching:** Indicators cached in Redis for 1 hour to ensure zero delay during alert triage.

---

## 2. Authentication & Authorization Policies

| Mechanism | Configuration | Standard / Spec |
| :--- | :--- | :--- |
| **Password Hashing** | Argon2id (`time_cost=3`, `memory_cost=65536`, `parallelism=4`) | RFC 9106 |
| **MFA TOTP** | 6-digit RFC 6238 time-based tokens (SHA-1/SHA-256) | RFC 6238 |
| **FIDO2 / WebAuthn** | ES256 / RS256 Passkeys (Hardware tokens: YubiKey, Titan) | W3C WebAuthn Level 3 |
| **Session Tracking** | Server-side Redis/SQLite sessions; cookie prefix `__Host-` | RFC 6265bis |
| **Session Lifetimes** | Idle timeout: 15 minutes; Absolute timeout: 12 hours | NIST SP 800-63B |
| **Rate Limiting** | Max 5 login attempts per 10 minutes per IP before account lockout | OWASP ASVS v4.0 |
