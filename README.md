İstədiyin kimi, axırdakı Contributing, License və Contact bölmələrini tamamilə çıxardım. Sənədləşmə birbaşa kodun texniki gücünə və işləmə mexanizminə fokuslandı.

Yeni təmizlənmiş və uzun README.md mətnin aşağıdadır:
Markdown

# 💣 Dependency Bomber

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security Status](https://img.shields.io/badge/security-OSV%20Verified-success.svg)](https://osv.dev/)

An enterprise-grade, lightweight, and dependency-free DevSecOps static analysis tool designed to audit Python `requirements.txt` files. It automatically detects open-source vulnerabilities (via Google's OSV API) and malicious typosquatting attempts before they reach your production environment.

---

## 🌌 Overview & Problem Statement

Modern software development relies heavily on open-source packages. This introduces two critical vectors of supply-chain attacks:
1. **Public Vulnerabilities (CVEs):** Outdated dependencies harboring known exploits.
2. **Typosquatting Attacks:** Malicious actors publishing packages with names visually similar to popular ones (e.g., `reqeusts` instead of `requests`) to execute arbitrary code upon installation.

**Dependency Bomber** acts as an automated security gate within your Software Development Life Cycle (SDLC) to isolate, analyze, and remediate these threats dynamically.

---

## ⚡ Key Features

- **Real-Time Vulnerability Scanning:** Direct serverless integration with Google’s Open Source Vulnerabilities (OSV) API to fetch active vulnerabilities and security advisories.
- **Pure Levenshtein-Driven Typosquatting Detection:** Implements a custom, high-performance distance algorithm without relying on third-party binary libraries. Minimizes pipeline weight.
- **Intelligent Auto-Remediation:** Parses complex API payloads to filter Git commit hashes and upstream OS packages, proposing clean, target `pip` update strings.
- **Hardened CI/CD Security Gate:** Configured with specific Unix standard exit codes (`exit 1` on risk detection) to automatically break faulty pipeline builds.
- **Zero-Dependency Core:** Requires no external setup or extensive runtime configuration.

---

## 🛠️ Architecture & Core Mechanics

The engine undergoes a three-stage sequential analysis:

[Requirements File] ──> [Parser Engine] ──> [Typosquatting Matrix] ──> [OSV API Query] ──> [Security Gate Evaluation]


### 1. Robust RegEx Parsing
The core string tokenizer cleans, processes, and strips inline or block comments (`#`) while normalizing package strings to lower-case to avoid bypass techniques utilizing irregular casings.

### 2. Levenshtein Distance Matrix
Calculates the minimum single-character edits (insertions, deletions, or substitutions) required to change one package name into a verified top-tier package. 
$$\text{distance} \le \text{THRESHOLD}$$ flags the library as an active risk.

### 3. Upstream Telemetry Filtering
Filters dirty data out of raw OSV responses, excluding internal ecosystem markers (e.g., specific OS updates like `300.*` or full 40-character Git shas), yielding strict semantic versioning suggestions.

---

## 🚀 Installation & Local Setup

### Prerequisites
- Python 3.8 or higher installed on your environment.
- Active internet connection (to connect with the OSV API gateway).

### Step-by-Step Deployment
Clone the repository directly into your environment:

git clone https://github.com/AndrielSec/dependency-bomber.git
cd dependency-bomber

Run the framework locally:

python dependency_bomber.py
