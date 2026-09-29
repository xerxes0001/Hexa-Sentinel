# HexaSentinel — Setup Guide

> Qualcomm Snapdragon AI Lab Challenge 2026  
> Aniket Anand Khot · PVGCOET, Pune

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **CPU** | Snapdragon X Plus HP AI PC | **Snapdragon X Elite HP AI PC** |
| **RAM** | 16 GB | 32 GB |
| **Storage** | 5 GB free | 10 GB free |
| **OS** | Windows 11 22H2 ARM64 | **Windows 11 24H2 ARM64** |
| **Python** | 3.11 | 3.12 |
| **Node.js** | 18 LTS | 20 LTS |
| **Npcap** | 1.79+ | 1.79+ |

**Tested HP AI PC fleet (Slide 9):**
- HP OmniBook X 14 — Snapdragon X Elite, 16 GB RAM, Win 11 24H2
- HP EliteBook Ultra G1q — Snapdragon X Elite, 32 GB RAM, Win 11 24H2

---

## Quick Start

### Option A — One-click (recommended)

```
setup.bat
```

Run as **Administrator** for live packet capture.  
Total time: **8–12 minutes** (governed by Llama 3.2 3B download from Qualcomm AI Hub, ~2.1 GB).  
Subsequent warm launches: **< 20 seconds**.

### Option B — Manual (two terminals)

**Terminal 1 — Backend:**
```bash
pip install -r backend/requirements.txt

# Generate ONNX classifier (30 seconds, no download):
pip install scikit-learn skl2onnx
python scripts/generate_synthetic_model.py

# Download Llama 3.2 3B from Qualcomm AI Hub (~2.1 GB, one-time):
python -c "from qai_hub_models.models.llama_v3_2_3b_chat_quantized import Model; Model.from_pretrained()"

# Start the server (run as Administrator for live capture):
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
npm install
npm run dev
# → Open http://localhost:5173
```

---

## The 5-Stage Silicon Pipeline (Slide 5)

```
Stage 1  Passive Ingestion     Scapy/WinPcap hook   Host NIC/CPU   Rolling 30s ring
Stage 2  Feature Extraction    80-feature vector     CPU            ~12ms
Stage 3  NPU Screening         ONNX GBDT Classifier  Hexagon NPU    < 3ms
Stage 4  Deep Reasoning        Llama 3.2 3B Instruct Hexagon NPU    8–12s
Stage 5  SOC Triage            React + FastAPI WS    Localhost      < 50ms
```

**Conditional branching (Score S ∈ [0.0, 1.0]):**
- `S < 0.85` → Normal branch — buffer purged, LLM not woken, 0% NPU waste
- `S ≥ 0.85` → Threat branch — structured JSON assembled, LLM queue signalled

**Energy profile:** 0.015 Wh/incident · 3–5W NPU (vs 15–20W CPU)

---

## ONNX Model Setup

### Option A — Synthetic (30 seconds, offline)
```bash
pip install scikit-learn skl2onnx
python scripts/generate_synthetic_model.py
```

### Option B — Full CICIDS-2018 training (5–10 minutes, needs internet)
```bash
pip install -r scripts/train_requirements.txt
python scripts/train_classifier.py
# F1 > 0.97 on CICIDS-2018 test set
```

Model is saved to `backend/models/anomaly_classifier.onnx` and loaded automatically.

---

## Npcap Installation (for live capture)

1. Download Npcap 1.79+: https://npcap.com/#download
2. Run installer as Administrator
3. Check **"Install Npcap in WinPcap API-compatible mode"**
4. Restart HexaSentinel

Without Npcap, HexaSentinel auto-activates **simulation mode** — all features work, events are synthetic.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/api/health`        | Backend status, NPU stats, provider info |
| `POST` | `/api/chat`          | Llama-powered conversational query |
| `POST` | `/api/analyze`       | On-demand incident analysis |
| `POST` | `/api/reports/certin`| CERT-In format report generation |
| `POST` | `/api/reports/isp`   | ISP NOC notification draft |
| `POST` | `/api/voice`         | Whisper + Llama voice query |
| `GET`  | `/api/voice/status`  | Whisper model availability |
| `WS`   | `/ws`                | Real-time threat event stream |

---

## Privacy Guarantees (Slide 6)

- **Process Boundary:** UI talks strictly to `127.0.0.1:8000` — zero outbound cloud telemetry
- **Silicon Boundary:** ML models execute exclusively inside Hexagon NPU memory
- **Privacy-by-Design:** Raw packet payload discarded immediately at Stage 1 ingestion
- **DPDP Act 2023 compliant:** Only statistical flow metadata processed, stored in RAM only

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `QnnHtp.dll not found` | Missing QNN Runtime | Install Qualcomm AI Stack from the Snapdragon developer portal |
| `No packets captured` | Missing Npcap / not Admin | Install Npcap, run as Administrator |
| `Llama model not found` | Download not run | Run `python scripts/generate_synthetic_model.py` for fallback |
| `Port 8000 in use` | Another process | `taskkill /f /im uvicorn.exe` then restart |
| Dashboard blank | Backend not running | Start Terminal 1 first, wait 4s, then Terminal 2 |

---

*Submitted by Aniket Anand Khot — PVGCOET, Savitribai Phule Pune University*  
*khotaniket3006@gmail.com*
