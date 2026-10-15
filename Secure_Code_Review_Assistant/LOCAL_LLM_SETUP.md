# Local LLM Setup Guide for Secure Code Review Assistant

**Case Study 4: Automotive Engineering AI — Secure Code Debugging and Review Assistant**  
**Core Requirement**: *Provide locally hosted AI assistance for code understanding, debugging, review, secure-coding checks, and structured findings without exposing proprietary source code.*

---

## 1. Why Local LLM?
In ECU software development and automotive systems (AUTOSAR, ISO 26262, ISO 21434), source code is classified as proprietary intellectual property. This system runs **100% on-premises**:
- No prompts or code leave your local machine or organization boundary.
- Embeddings are generated locally using `sentence-transformers/all-MiniLM-L6-v2`.
- Knowledge base vector search runs locally on `FAISS`.
- Reviews and audit trails are persisted locally in SQLite (`data/reviews_audit.db`).

---

## 2. Setting Up Ollama on a Laptop (2 Minutes)

### Step 1: Install Ollama
Download and install Ollama for Windows from:
👉 **[https://ollama.ai/download](https://ollama.ai/download)**

### Step 2: Download the Recommended Lightweight C/C++ Model
Open PowerShell or Command Prompt and run:
```powershell
ollama run qwen2.5-coder:1.5b
```

> **Why `qwen2.5-coder:1.5b`?**  
> - **Size**: Only ~1.0 GB download.  
> - **RAM Usage**: Less than 2 GB RAM.  
> - **Performance**: Specifically fine-tuned on C, C++, and Python code; runs at 25+ tokens/second even on basic laptop CPUs without an NVIDIA GPU.

*Alternative models if your laptop has 16GB+ RAM or a dedicated GPU:*
* `ollama run qwen2.5-coder:7b` (Higher reasoning capability)
* `ollama run deepseek-coder:1.3b` (Ultra-compact)

---

## 3. Running the Secure Code Review Assistant

### Option A: Direct Local Python
```powershell
# Activate your environment
.venv\Scripts\Activate.ps1

# Run the Streamlit UI
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### Option B: Docker Container
```powershell
docker compose up --build
```

---

## 4. Verification in the UI

1. Open the UI at `http://localhost:8501`.
2. In the left sidebar:
   - **Active Role**: Choose `Embedded Developer` or `Technical Reviewer / Lead`.
   - **Inference Mode**: Select `Local LLM (Private / On-Premise)`.
   - Click **"Check Local Model Connection"** → You will see:  
     `✅ Ollama is reachable at http://localhost:11434 (Found: qwen2.5-coder:1.5b)`.
3. In the main window:
   - Paste or upload sample ECU code (e.g., from `data/sample_buggy_code.c`).
   - Click **"Analyze Code (Local On-Premise)"**.
4. Disposition & Sign-Off:
   - For any finding, expand **"Reviewer Disposition & Notes"** to mark it as `Accepted (Confirmed Defect)` or `False Positive`.
   - Click **"Formal Review Sign-Off"** to record an immutable ISO 26262 compliant sign-off.
   - Check the **"Audit & Traceability"** tab to view the timestamped audit log.
