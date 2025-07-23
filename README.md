
---

# AI Agent OSINT Security Analyzer

An autonomous cybersecurity platform that leverages AI agents to perform intelligent OSINT investigations across multiple threat intelligence sources. Powered by Cohere's Command R+ model, it dynamically selects tools, correlates multi-source data, and delivers actionable security assessments.

---

## Features

* **AI-Powered Automation** — Performs multi-step reasoning and selects the optimal tools for each target
* **Adaptive Report Depth** — Choose from Quick Scan, Standard Analysis, Comprehensive Investigation, or Expert Deep Dive
* **Integrated Intelligence Sources** — Supports Shodan, VirusTotal, AbuseIPDB, CVE databases, CISA KEV, and NVD
* **Version-Specific Vulnerability Checks** — Filters vulnerabilities based on software name and version
* **Infrastructure Mapping** — Resolves domain-to-IP mapping, DNS records, service discovery, and hosting details
* **Real-Time Threat Detection** — Identifies active exploits, known indicators of compromise, and critical CVEs
* **Privacy and Security Focused** — No telemetry, no data retention, secure API key handling, and input sanitization

---

## Supported Target Types

* **IP Address** (e.g., `8.8.8.8`) — Service enumeration, reputation scoring, host metadata
* **Domain Name** (e.g., `example.com`) — DNS resolution, subdomain mapping, infrastructure overview
* **CVE ID** (e.g., `CVE-2021-44228`) — Vulnerability details, severity, patch status
* **Software + Version** (e.g., `apache httpd 2.4.62`) — Version-aware vulnerability analysis and CVE lookups

---

## Requirements

* Python 3.8 or higher
* Internet access for API-based OSINT queries
* Free or paid API keys for certain services (see below)

---

## Setup and Installation

### Option 1: Use the Streamlit Web App

Access the hosted interface: [Streamlit App](https://osint-ai.streamlit.app)

---

### Option 2: Run Locally

1. **Clone the repository**

   ```bash
   git clone https://github.com/MRFrazer25/AI-OSINT-Security-Analyzer.git
   cd AI-OSINT-Security-Analyzer
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**

   ```bash
   python setup.py
   cp .env.example .env
   # Then edit .env with your API keys
   ```

4. **Obtain free-tier API keys**

   * [Cohere API](https://dashboard.cohere.ai/api-keys) — for AI reasoning (1,000 calls/month free)
   * [Shodan](https://account.shodan.io/) — for network scanning (100 queries/month free)
   * [VirusTotal](https://www.virustotal.com/gui/join-us) — for file/domain/IP threat intelligence (500 queries/day free)
   * [AbuseIPDB](https://www.abuseipdb.com/api) — for IP reputation checks (1,000 queries/day free)

   *(CVE-Search, CISA KEV, and NVD do not require API keys)*

5. **Launch the app**

   ```bash
   python -m streamlit run app.py
   ```

Visit `http://localhost:8501` in your browser to begin investigations.

---

## How It Works

The AI agent performs the following sequence:

1. Detects the type of input (IP, domain, CVE, or software version)
2. Selects appropriate tools and intelligence sources
3. Executes queries in a logically ordered investigation flow
4. Correlates results across tools and databases
5. Synthesizes a human-readable risk report with prioritization

Each report type uses the same tools; the difference lies in the depth and complexity of the analysis.

---

## Security Model

* **No Data Retention** — All data is processed in-memory; nothing is saved to disk
* **Session-Based API Keys** — API keys are never stored permanently
* **Input Sanitization** — All inputs are sanitized to prevent injection or misuse
* **No Telemetry** — No tracking, logging, or analytics
* **Runs Locally or Self-Hosted** — You control where and how it operates

---

## Troubleshooting

* **Missing Modules:** Ensure dependencies are installed with `pip install -r requirements.txt`
* **API Key Errors:** Check that `.env` or web input contains valid keys
* **Streamlit Not Found:** Install via `pip install streamlit`
* **Tool Failures:** Verify internet access and that API keys are still valid

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This tool is intended strictly for ethical security research, red teaming, and educational use. Do not scan, probe, or investigate systems you do not own or have explicit permission to test. Misuse of this tool may violate laws and terms of service.

---