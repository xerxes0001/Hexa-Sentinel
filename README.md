<p align="center">
  <h1 align="center">🛡️ HexaSentinel</h1>
</p>

<p align="center">
  <strong>Privacy-First, On-Device Security Intelligence for Snapdragon® AI PCs</strong>
</p>

<p align="center">
  <strong>Detect locally. Correlate intelligently. Explain privately.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-research%20%2F%20competition%20prototype-7C3AED?style=for-the-badge" alt="Project status">
  <img src="https://img.shields.io/badge/platform-Windows%20ARM64-0078D4?style=for-the-badge&logo=windows" alt="Windows ARM64">
  <img src="https://img.shields.io/badge/architecture-on--device%20AI-16A34A?style=for-the-badge" alt="On-device AI">
  <img src="https://img.shields.io/badge/NPU-Snapdragon-FF6B00?style=for-the-badge" alt="Snapdragon NPU">
  <img src="https://img.shields.io/badge/privacy-local--first-16A34A?style=for-the-badge" alt="Privacy">
  <img src="https://img.shields.io/badge/license-MIT-111827?style=for-the-badge" alt="License">
</p>

<p align="center">
  <a href="#-project-status">Status</a> •
  <a href="#-overview">Overview</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-competition-demo">Demo</a> •
  <a href="#-validation">Validation</a> •
  <a href="#-roadmap">Roadmap</a>
</p>

---

## 📌 Project Status

> **This is a research / competition prototype**, built for a Qualcomm Snapdragon AI PC challenge. Model choices, performance numbers, and runtime paths below are **targets to validate**, not measured results — see [Validation](#-validation) and the [caveat](#-a-note-on-honesty) at the bottom before citing any figure publicly.

| Component | Status |
|---|---|
| Architecture & pipeline design | ✅ Defined |
| Event collection (network / process / system) | 🔲 Not yet implemented |
| Behavioral anomaly model | 🔲 Not yet implemented |
| Event correlation engine | 🔲 Not yet implemented |
| On-device LLM investigation layer | 🔲 Not yet implemented |
| NPU-accelerated inference (Hexagon) | 🔲 Not yet validated |
| Dashboard / UI | 🔲 Not yet implemented |
| Benchmarks (precision/recall/latency/power) | 🔲 Not yet measured |

---

## 🧭 Overview

Modern security tooling drowns analysts in disconnected signals: network flows, DNS lookups, process spawns, authentication events. The hard problem was never *detecting an event* — it's figuring out **which events belong together and what they mean**.

**HexaSentinel** turns a Snapdragon-powered HP AI PC into a small, continuously running security analyst that:

1. Collects **privacy-preserving, local-only** behavioral signals (metadata, not payloads)
2. Flags abnormal behavior with a lightweight, always-on AI model
3. Correlates related anomalies into a single **incident**
4. Hands that incident — not raw telemetry — to an **on-device generative model** for a human-readable explanation

```
Suspicious activity
        ↓
Local signal collection  →  Anomaly detection  →  Correlation  →  On-device explanation
        ↓                                                              ↓
   No cloud upload                                          Human-readable incident report
```

The core bet: **privacy is an architectural property here, not a UI claim.** Raw security telemetry never has to leave the device, and the generative model only ever sees a small, structured evidence package — never a live packet stream.

---

## 🏗️ Architecture

### Why Snapdragon

A Snapdragon X-series SoC exposes three distinct compute resources, and HexaSentinel is designed to route work to the one best suited for it:

```
                 Snapdragon SoC
                       │
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
       CPU            GPU            NPU
        │              │              │
  Collection,      Dashboard      AI inference
  orchestration,   rendering &    (behavioral model +
  DB, API           graphs        on-device LLM)
```

| Compute | Workload |
|---|---|
| **CPU** | Event collection, feature extraction, app logic, database ops, API/UI |
| **Hexagon NPU** | Behavioral classification, quantized inference, on-device generative inference (model/runtime TBD — see [Validation](#-validation)) |
| **GPU** | Incident graphs, network visualizations, dashboard rendering |

The pitch isn't *"runs on Snapdragon"* — it's **the pipeline is designed around heterogeneous Snapdragon compute, with AI workloads specifically targeted at the Hexagon NPU.**

### End-to-end pipeline

```
             DATA SOURCES
                  │
       ┌──────────┼──────────┐
       ↓          ↓          ↓
    Network    Processes    System
       │          │          │
       └──────────┼──────────┘
                  ↓
          Privacy Sanitizer
                  ↓
          Feature Extraction
                  ↓
       Behavioral AI Model
                  ↓
          Anomaly Detection
                  ↓
         Event Correlation
                  ↓
          Incident Creation
                  ↓
        Evidence Construction
                  ↓
        On-device AI Analyst
                  ↓
          Explanation + Risk
                  ↓
           Local Dashboard
```

#### 1. Collection

Only metadata and behavioral signals — never full packet payloads.

- **Network:** timestamp, protocol, src/dst, port, flow counts, connection duration, bytes transferred, DNS behavior, connection frequency
- **Process:** name, PID, parent process, start time, lifetime, network-activity relationship, resource behavior
- **System:** new-process events, adapter changes, application events, auth events, config changes

#### 2. Privacy sanitization

Real hostnames and identifiers are hashed/pseudonymized locally *before* anything reaches the AI layer. The model gets enough signal to reason about behavior without seeing private content — it doesn't need to know what a user typed to notice an unusual connection pattern.

#### 3. Feature extraction

Raw events are converted into numerical behavioral features, e.g.:

```
connection_count       = 37
unique_destinations    = 14
mean_connection_duration = 0.83
dns_request_rate       = 12.4
destination_entropy    = 0.71
connection_burstiness  = 0.82
process_network_ratio  = 0.43
```

The exact feature set should be determined **experimentally**, not copied wholesale from prior work.

#### 4. Behavioral AI (small, always-on)

A lightweight model — small enough to run continuously on the NPU — scores each window of activity:

```
Behavioral Model
     │
 ┌───┼───┐
 ↓   ↓   ↓
Normal Anomalous High-risk
0.91   0.06      0.03
```

#### 5. Why not run the LLM on every event?

Because it's wasteful and the wrong tool for the job:

```
10,000 events → small behavioral model → 37 suspicious events
             → correlation → 2 incidents → LLM investigation
```

The generative model is the **investigator**, not the packet filter.

#### 6. Event correlation

Independent anomalies (a process spawn, a new DNS destination, a connection burst) are linked into an incident graph rather than reported as isolated alerts — closer to how a human analyst actually thinks.

#### 7. Evidence construction

A structured object is built for the LLM — never a raw event stream:

```json
{
  "incident_id": "INC-1042",
  "risk": 0.89,
  "process_events": 3,
  "network_events": 7,
  "dns_events": 2,
  "behavioral_anomalies": 4,
  "timeline": ["...", "...", "..."]
}
```

#### 8. On-device AI investigation

The generative model consumes that evidence package and produces a structured explanation: severity, observed behavior, supporting evidence, and recommended next steps. It is explicitly **not** the original detector — it's the explanation layer, invoked only when an incident already exists.

---

## ✨ Features

- **Local-first by design** — no requirement to send security telemetry to a cloud service for analysis
- **Two-tier AI** — a cheap always-on behavioral model filters noise; a larger generative model only runs on the handful of events that become incidents
- **Incident correlation, not alert spam** — related anomalies are graphed into a single incident rather than surfaced as disconnected alerts
- **Human-readable explanations** — incidents come with a plain-language summary and recommended investigation steps, not just a risk score
- **Heterogeneous compute story** — CPU for orchestration, NPU for inference, GPU for visualization
- **Chronological incident timeline** and a **security graph view** for demo/judging clarity

---

## 🚀 Quick Start

> ⚠️ The pipeline above is the design target. Implementation is in progress — this section will be filled in as components land (setup, dependencies, ARM64 build steps, model download/conversion instructions).

```bash
# placeholder — to be completed once the collection/inference pipeline is implemented
git clone <repo-url>
cd hexasentinel
```

---

## 🎥 Competition Demo

**Demo storyline:** a suspicious application is executed → makes an unusual DNS request → opens repeated outbound connections → the behavioral model flags each step → the correlation engine links them into one incident → the on-device model explains it in plain language — all without a single byte of security telemetry leaving the machine.

Dashboard concept:

```
╔══════════════════════════════════════════════════════╗
║                 HEXASENTINEL                          ║
║         ON-DEVICE SECURITY COPILOT                    ║
╠══════════════════════════════════════════════════════╣
║   SYSTEM STATUS             AI ENGINE                 ║
║   ● PROTECTED               ● ONLINE                  ║
║   Network      Normal        NPU      Active          ║
║   Processes    Normal        Model    Ready            ║
║   Incidents    1             Cloud    OFF              ║
╠══════════════════════════════════════════════════════╣
║                 INCIDENT TIMELINE                      ║
║  14:31  Process anomaly                                ║
║  14:31  DNS anomaly                                    ║
║  14:31  Network anomaly                                ║
║  14:31  INCIDENT CREATED                                ║
╠══════════════════════════════════════════════════════╣
║                 AI INVESTIGATION                       ║
║  HIGH RISK                                              ║
║  Unusual relationship between a process and             ║
║  outbound network activity.                             ║
║  [VIEW EVIDENCE]       [RESPONSE OPTIONS]               ║
╚══════════════════════════════════════════════════════╝
```

**What this demonstrates to judges:** the story isn't *"we called an LLM from a security app."* It's *"we built a local security intelligence pipeline specifically designed around what a Snapdragon AI PC can do."*

---

## 🧪 Validation

1. **Confirm the runtime path** — the exact Qualcomm AI Hub model(s), Windows ARM64 runtime, NPU execution provider, and supported operators, checked against current Qualcomm documentation (not assumed from prior projects).
2. **Establish every performance number experimentally**, rather than reusing figures from other proposals. That includes:
   - **AI quality:** precision, recall, F1, false-positive rate, detection rate
   - **NPU performance:** inference latency, throughput, NPU/CPU utilization, memory footprint
   - **System performance:** event processing rate, dashboard latency, startup time, battery/power impact
   - **Privacy claim:** measured count of external network connections initiated by HexaSentinel itself (target: 0 application-telemetry destinations), clearly separated from normal OS/network traffic

A dashboard that says "100% private" is a claim. A benchmark showing zero outbound telemetry connections during a monitored session is evidence — the latter is what should ship.

---

## 🗺️ Roadmap

- [ ] Implement local event collectors (network / process / system)
- [ ] Build and validate the privacy sanitization layer
- [ ] Finalize feature set via experimentation
- [ ] Train/select the behavioral anomaly model; benchmark on NPU vs CPU
- [ ] Implement correlation engine and incident graph construction
- [ ] Select and validate the on-device generative model + Qualcomm runtime path
- [ ] Build the dashboard (timeline + security graph)
- [ ] Run full benchmark suite (AI quality, NPU perf, system perf, privacy)
- [ ] Prepare competition demo scenario and recording

---

## 👥 Candidate Information

| | |
|---|---|
| **Name** | Indraneel Kiran Rananaware |
| **Institution** | Department of Computer Engineering (B.Tech), Sinhgad Institute of Technology, Lonavala, Savitribai Phule Pune University |
| **Contact** | [indraneeelrananaware4190@gmail.com](mailto:indraneeelrananaware4190@gmail.com) |
| **Competition** | Qualcomm Snapdragon AI Lab Build & Present Challenge 2026 |

---

<p align="center">
  <sub>Built for a Qualcomm Snapdragon AI PC challenge · Local detection, local reasoning, local explanation.</sub>
</p>
