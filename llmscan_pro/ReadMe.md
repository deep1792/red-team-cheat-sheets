**LLMScan Pro — An Open-Source LLM Security Scanner**

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

  # Clone
      git clone https://github.com/yourgithub/llmscan_pro.git
      cd llmscan_pro
  
  # Setup
      python3 -m venv .venv
      source .venv/bin/activate
      pip install -r requirements.txt

  # install pytest if you will run tests
      pip install pytest
  
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

**Complete Commands List**
  **CLI help & quick check**
    
    # show CLI help
      python -m llmscan_pro.cli --help
      
    # quick smoke test (mock adapter, very fast)
      python -m llmscan_pro.cli --target mock --suite basic --sample-size 1 --out results_smoke --report results_smoke/report.html
      
     # open the report (Linux)
      xdg-open results_smoke/report.html

  **Run full OWASP LLM Top-10 (mock safe)**

    # run OWASP LLM Top-10 using the safe mock adapter
    python -m llmscan_pro.cli --target mock --suite owasp2025 --sample-size 2 --out results_owasp_mock --report results_owasp_mock/report.html

    **Open the report:**
      xdg-open results_owasp_mock/report.html

  **Run RAG poisoning / retriever based probes (mock retriever)**
  
    # RAG suite (mock retriever is used by default with --target mock)
    python -m llmscan_pro.cli --target mock --suite rag --sample-size 2 --out results_rag --report results_rag/report.html
    xdg-open results_rag/report.html

  **Run against OpenAI (real model) — SAFELY**
      
    Warning: Only run on systems & data you own. Always use --budget and --max-calls with real models.
    
    Export API key:
    export OPENAI_API_KEY="sk-..."

    python -m llmscan_pro.cli --target openai --model gpt-4o-mini --suite owasp2025 --sample-size 2 --verifier-target openai --max-calls 100 --budget 0.50 --out    results_openai_owasp --report results_openai_owasp/report.html

    Notes:
    --budget is a naive cost cap (dollars) implemented in runner (update if you want real per-token pricing).
    --max-calls stops the run once the number of LLM calls reaches this value.

  **Run with verifier (double-checks suspicious findings)**

    The verifier runs a second model/adapter to confirm FAILs (lowers false positives):
    python -m llmscan_pro.cli --target openai --model gpt-4o-mini --verifier-target openai --suite owasp2025 --sample-size 2 --budget 0.30 --max-calls 80 --out results_verified --report results_verified/report.html
   
    Note - If you want the verifier to be a different model (e.g., safer/smaller), adjust --verifier-target implementation or pass --verifier-model if your CLI supports it.

**Find failures & triage (file system + jq)**

    jq -s '.[] | select(.verdict=="FAIL") | {file:.outfile, probe_id:.probe_id, family:.family, confidence:.confidence, evidence:.evidence_snippet}' results_owasp_mock/*.jsonl

**Advanced: run continuous scans (CI style)**

    # a simple shell-run for nightly or CI-style run
    python -m llmscan_pro.cli --target mock --suite owasp2025 --sample-size 1 --out results_ci --report results_ci/report.html
    
    # then upload results_ci to artifacts or S3 for analysis

![Alt text](https://github.com/deep1792/red-team-cheat-sheets/blob/main/llmscan_pro/images/LLM-generate.png)




