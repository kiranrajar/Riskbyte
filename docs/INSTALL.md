# RiskByte SOC Agent — Enterprise Installation Guide

## 1. Overview
RiskByte SOC Agent is a commercial, self-hosted security operations center automation platform designed to run completely inside the customer's secure network perimeter with **zero external telemetry egress**.

---

## 2. System Prerequisites

| Component | Minimum Requirement (Eval) | Recommended (Production) |
| :--- | :--- | :--- |
| **CPU Architecture** | 4 Cores (x86_64) | 16–32 Cores (x86_64) |
| **System Memory (RAM)** | 16 GB | 64 GB – 128 GB |
| **Storage** | 100 GB NVMe SSD | 1 TB – 4 TB NVMe (RAID 10) |
| **Operating System** | Linux (RHEL 9, Ubuntu 22.04+, Debian 12+) or Windows Server 2022 | Enterprise Linux (RHEL 9+, Rocky 9+, Ubuntu 22.04 LTS) |
| **Container Engine** | Docker Engine 24+ & Compose v2 | Kubernetes 1.28+ (OpenShift, EKS Anywhere, Tanzu) |
| **Inference Accelerator** | CPU (AVX2/AVX-512) | 1x NVIDIA A10G / L4 / A100 (24GB+ VRAM) |

---

## 3. Installation Method A: Docker Compose (Evaluation & Mid-Market)

### Step 1: Clone Repository or Extract Release Tarball
```bash
git clone https://github.com/kiranrajar/Riskbyte.git /opt/riskbyte
cd /opt/riskbyte
```

### Step 2: Run Automated Installer
```bash
chmod +x deploy/install.sh
sudo ./deploy/install.sh
```

The automated installer will:
1. Validate Docker and Docker Compose v2.
2. Create directories for platform databases, audit keys, and certificates.
3. Generate a 4096-bit self-signed TLS certificate for Nginx.
4. Generate cryptographically strong random credentials for PostgreSQL and Redis in `.env`.
5. Launch the 7-container stack (`riskbyte-app`, `riskbyte-worker`, `postgres`, `redis`, `opensearch`, `ollama`, `proxy`).

### Step 3: Access Console
Navigate to `https://<host-ip>:443` in your browser. Accept the internal TLS certificate and follow the **First-Run Setup Wizard**.

---

## 4. Installation Method B: Kubernetes via Helm (Enterprise Production)

### Step 1: Add or Package Helm Chart
```bash
cd /opt/riskbyte/deploy/helm/riskbyte
helm dependency update
```

### Step 2: Configure `values.yaml`
Review and edit `values.yaml` with your internal enterprise settings:
- Provide your enterprise Ingress class (`ingressClassName: "nginx"`).
- Set storage class (`storageClass: "enterprise-nvme"`).
- Confirm strict egress denial (`denyExternalEgress: true`).

### Step 3: Deploy to Kubernetes Cluster
```bash
kubectl create namespace riskbyte-soc
helm install riskbyte . \
  --namespace riskbyte-soc \
  --values values.yaml
```

### Step 4: Verify Pod Status
```bash
kubectl get pods -n riskbyte-soc
```
All pods (`app`, `worker`, `postgresql`, `redis`, `ollama`) should reach `Running` state within 60–90 seconds.
