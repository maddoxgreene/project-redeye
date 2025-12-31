# Project Redeye

**Project Redeye** is a lightweight reconnaissance and asset discovery tool designed for ethical security testing and learning.

It focuses on **passive discovery first**, then optional active checks, keeping things simple, readable, and transparent.

---

## 🔍 What It Does

Project Redeye helps you:

1. **Enumerate subdomains**
   - crt.sh
   - Wayback Machine
   - HackerTarget

2. **Resolve DNS records**
   - A and AAAA lookups
   - Scope enforcement (no out-of-scope hosts)

3. **Probe web services**
   - HTTP & HTTPS
   - Status codes
   - Final URLs
   - Page titles
   - Server / content-type headers

4. **Optional port scanning**
   - TCP connect scan
   - Common ports by default
   - Custom port ranges supported

5. **Generate reports**
   - JSON (machine-readable)
   - CSV (easy filtering)
   - Markdown (human-readable)

---

## 🚀 Quick Start

### Clone the repository

```bash
git clone https://github.com/maddoxgreene/project-redeye.git
cd project-redeye
