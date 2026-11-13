# RiskByte SOC Agent — Air-Gapped Deployment Runbook

## 1. Zero Telemetry Egress Policy
RiskByte SOC Agent is architecturally barred from transmitting data outside the customer perimeter:
- Cloud AI providers (OpenAI, Anthropic, Google Gemini) are strictly disabled.
- No analytics, telemetry, crash reporting, or phone-home requests are compiled into the binary.
- Network policy enforces outbound packet drops for any IP outside internal ranges.

---

## 2. Importing Offline Model Weights (Ollama / vLLM)

In an air-gapped facility, LLM weights must be transferred via secure removable media (bastion/jump host).

### Step 1: Export Model Weights on an Internet-Connected Staging Machine
```bash
# Pull desired open-weights model
ollama pull llama3.1:8b

# Locate Ollama blobs directory
# Linux: ~/.ollama/models
tar -czvf llama3.1-8b-weights.tar.gz -C ~/.ollama/models .
```

### Step 2: Transfer to Air-Gapped Host via Secure USB / Optical Media
Verify SHA-256 checksum of `llama3.1-8b-weights.tar.gz` prior to copying into the air-gapped datacenter.

### Step 3: Extract into Ollama Volume
```bash
# Copy into the persistent volume mounted by the ollama container
docker compose stop ollama
tar -xzvf llama3.1-8b-weights.tar.gz -C /var/lib/docker/volumes/riskbyte_ollama-models/_data/
docker compose start ollama
```

### Step 4: Verify Local Model Availability
```bash
docker compose exec ollama ollama list
# Output:
# NAME            ID              SIZE      MODIFIED
# llama3.1:8b     7f3828738a75    4.7 GB    2 minutes ago
```

---

## 3. Installing Offline License File (.rbl)

1. Receive the vendor-signed `.rbl` license file from RiskByte Customer Operations.
2. Place `license.rbl` into `/data/license.rbl`.
3. Ensure vendor public key `vendor_public.pem` is present in `/data/vendor_public.pem`.
4. The offline validator checks the 4096-bit RSA signature against the customer tenant ID, seat allowance, and expiry timestamp. Zero internet access is required.
