# 🛡️ RazorGuard-AI

### AI-Powered Cybersecurity Threat Analysis & Risk Assessment

RazorGuard-AI is a Python-based cybersecurity analysis system designed to identify suspicious, malicious, and potentially dangerous content in text.

It combines **rule-based security analysis** with an **AI-powered security classifier** to generate an overall risk assessment, security findings, confidence information, and a human-readable security report.

---

## 🚀 Features

- 🔍 Security keyword and pattern detection
- 🛡️ Suspicious behavior identification
- 🚨 Risk scoring from 0–100
- 🔴 Risk levels: LOW, MEDIUM, HIGH, CRITICAL
- 🤖 AI-based security classification
- 📊 AI confidence scoring
- 🧠 Hybrid rule-based + AI analysis pipeline
- 📋 Detailed security findings
- 💾 Analysis history
- 🧪 Automated test suite using Pytest
- 🖥️ Interactive Gradio web interface
- 📁 Security datasets for testing and evaluation

---

## 🧠 How RazorGuard-AI Works

RazorGuard-AI uses a multi-stage analysis pipeline.

```text
                    ┌─────────────────┐
                    │   User Input    │
                    └────────┬────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Rule-Based Analyzer │
                  └──────────┬──────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
      Security Patterns              Risk Calculation
              │                             │
              └──────────────┬──────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │   AI Classifier     │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Final Risk Assessment│
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Security Report     │
                  └─────────────────────┘