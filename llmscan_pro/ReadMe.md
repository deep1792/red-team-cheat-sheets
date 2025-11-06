LLMScan Pro — An Open-Source LLM Security Scanner

LLMScan Pro is an AI security toolkit for penetration testing, auditing, and red teaming large language models.
Built to detect vulnerabilities aligned with the OWASP LLM Top 10 (2025) — prompt injection, RAG poisoning, sensitive data leaks, and more.

**Features**
  Supports OWASP LLM Top 10 (2025)
  Scans for prompt injection, RAG/data poisoning, model leaks, unbounded generation, and supply-chain risks
  Offline, Online, and API-ready
  Works with Mock, OpenAI, and Custom adapters
  Generates detailed HTML + JSON reports
  Includes automatic calibration to reduce false positives
  All sensitive data redacted by design

**Quickstart**
  # Clone
  git clone https://github.com/yourgithub/llmscan_pro.git
  cd llmscan_pro
  
  # Setup
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  
  # Run basic mock test
  python -m llmscan_pro.cli --target mock --suite owasp2025 --sample-size 2 --out results --report results/report.html

**Supported Vulnerabilities**
  | OWASP ID | Category                  | Description                                 |
  | -------- | ------------------------- | ------------------------------------------- |
  | LLM01    | Prompt Injection          | Detects direct and indirect injections      |
  | LLM02    | Sensitive Info Disclosure | Flags system prompt leaks                   |
  | LLM03    | Supply Chain              | Detects template-based prompt injection     |
  | LLM04    | Data Poisoning            | Detects hidden malicious data in retrievers |
  | LLM05    | Improper Output Handling  | Finds unsanitized model output              |
  | LLM06    | Excessive Agency          | Detects agent overreach                     |
  | LLM07    | System Prompt Leakage     | Detects context exposure                    |
  | LLM08    | Vector/Embedding Weakness | Detects vector poisoning                    |
  | LLM09    | Misinformation            | Flags hallucination patterns                |
  | LLM10    | Unbounded Consumption     | Detects resource exhaustion attacks         |

**For Researchers**
  Extend probes under llmscan_pro/probes/
  Add custom detectors in llmscan_pro/detectors/
  Integrate with your CI/CD pipeline for continuous LLM security

**License**
  MIT License © 2025 Deepanshu Khanna

