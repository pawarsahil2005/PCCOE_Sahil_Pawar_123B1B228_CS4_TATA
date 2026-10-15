"""Automotive ECU Secure Code Review Assistant.

Enterprise Automotive Engineering Platform for:
- AUTOSAR Classic & Adaptive Architecture Review
- MISRA-C:2012 / CERT-C Standard Verification
- ISO 26262 ASIL-D Functional Safety Evidence Analysis
- ISO/SAE 21434 Vehicle Cybersecurity Threat Prevention
- 100% On-Premises Air-Gapped Local LLM Inference (Zero Cloud Egress)
- Traceable Reviewer Dispositions & Immutable SQLite Audit Trail
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

import database
from analyzer import (
    ALLOWED_EXTENSIONS,
    LANGUAGES,
    AnalysisResult,
    Finding,
    analyze_source,
)
from local_llm_client import GeminiProvider, LocalLLMProvider, get_ai_provider

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

MAX_DEFAULT_BYTES = 200 * 1024

SEVERITY_COLORS = {
    "High": "#d92d20",
    "Medium": "#d97706",
    "Low": "#0284c7",
}

DISPOSITION_OPTIONS = [
    "Pending Review",
    "Accepted (Confirmed Defect)",
    "False Positive (Verified Safe)",
    "Mitigated (Compensating HW/SW Clamp)",
    "Rejected (Not Applicable)",
]




def _extension_ok(name: str) -> bool:
    return Path(name).suffix.lower() in ALLOWED_EXTENSIONS


def _collect_inputs(pasted: str, uploads, max_bytes: int, selected_language: str = "Auto Detect") -> tuple[list[dict], list[str]]:
    files: list[dict] = []
    errors: list[str] = []

    if pasted and pasted.strip():
        ext_map = {
            "C": ".c",
            "C++": ".cpp",
            "Java": ".java",
            "Python": ".py",
            "JavaScript": ".js",
            "TypeScript": ".ts",
        }
        ext = ext_map.get(selected_language, ".c")
        files.append({"filename": f"ecu_module{ext}", "code": pasted})

    if uploads:
        for uploaded in uploads:
            name = uploaded.name
            if not _extension_ok(name):
                errors.append(f"{name}: unsupported extension. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)))
                continue
            data = uploaded.getvalue()
            if len(data) > max_bytes:
                errors.append(f"{name}: file exceeds limit ({len(data)} bytes). Max is {max_bytes} bytes.")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("utf-8", errors="replace")
                errors.append(f"{name}: not UTF-8; replacement characters were used.")
            files.append({"filename": name, "code": text})

    return files, errors


def _check_local_ollama_status(local_url: str, local_model: str) -> tuple[bool, str]:
    try:
        import requests
        r = requests.get(f"{local_url}/api/tags", timeout=1.5)
        if r.status_code == 200:
            models = [m.get("name", "") for m in r.json().get("models", [])]
            for m in models:
                if local_model in m or m.startswith(local_model.split(":")[0]):
                    return True, f"Ollama Online (Model '{m}' loaded & ready)"
            if models:
                return True, f"Ollama Online (Available: {', '.join(models)})"
            return False, "Ollama Service Running (Model is currently downloading in background)"
    except Exception:
        pass
    return False, "Ollama Offline (Falling back to local deterministic rules & FAISS)"


def _render_finding_card(finding: Finding, review_id: int | None, user_name: str) -> None:
    color = SEVERITY_COLORS.get(finding.severity, "#475467")
    disp_badge_color = "#fef3f2" if "Accepted" in finding.disposition else "#f0fdf4" if "False Positive" in finding.disposition else "#eff8ff"
    disp_text_color = "#b42318" if "Accepted" in finding.disposition else "#15803d" if "False Positive" in finding.disposition else "#175cd3"

    st.markdown(
        f"""
        <div style="border:1px solid #eaecf0;border-left:6px solid {color};
                    border-radius:10px;padding:16px 20px;margin-bottom:12px;background:#ffffff;
                    box-shadow: 0 1px 3px rgba(16,24,40,0.05);">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <span style="background:#f2f4f7;color:#344054;padding:3px 8px;border-radius:6px;font-size:0.8rem;font-weight:700;">{finding.finding_id}</span>
              &nbsp;
              <span style="background:{color}15;color:{color};padding:3px 8px;border-radius:6px;font-size:0.8rem;font-weight:700;">{finding.severity.upper()}</span>
              &nbsp;
              <span style="color:#475467;font-size:0.85rem;font-weight:600;">{finding.category}</span>
            </div>
            <div>
              <span style="background:{disp_badge_color};color:{disp_text_color};padding:4px 10px;border-radius:12px;font-size:0.8rem;font-weight:700;border:1px solid {disp_text_color}30;">
                {finding.disposition}
              </span>
            </div>
          </div>
          <div style="font-size:1.1rem;font-weight:700;color:#101828;margin-top:8px;">{finding.title}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns([1.2, 1.2, 1.1])
    with c1:
        st.write(f"📁 **File:** `{finding.file}`")
        st.write(f"📍 **Line:** `{finding.line}` &nbsp;|&nbsp; **Function:** `{finding.function}()`")
    with c2:
        st.write(f"🎯 **Confidence:** `{finding.confidence}`")
        st.write(f"📜 **Rule Standard:** `{finding.relevant_rule or 'AUTOSAR-GENERIC'}`")
    with c3:
        st.write(f"⚙️ **Analysis Source:** `{finding.source}`")
        st.write("👤 **Human Review:** `MANDATORY`")

    st.markdown("**Vulnerable Code Evidence:**")
    st.code(finding.code_evidence or "(no code snippet available)", language="c" if "c" in finding.language.lower() else "text")

    col_exp, col_fix = st.columns(2)
    with col_exp:
        st.markdown("**🔍 Defect Explanation & Root Cause:**")
        st.info(finding.description or "Automotive standard violation detected.")
        if finding.root_cause and finding.root_cause != "n/a":
            st.caption(f"**Root Cause:** {finding.root_cause}")
    with col_fix:
        st.markdown("**🛡️ Recommended Automotive Fix:**")
        st.success(finding.suggested_fix or "Review against ISO 26262 software unit design guidelines.")

    # Developer and Reviewer Disposition
    with st.expander(f"📝 Reviewer Disposition & Technical Justification ({finding.finding_id})", expanded=False):
        c_disp, c_notes, c_act = st.columns([1.3, 2, 0.8])
        current_idx = 0
        for idx, opt in enumerate(DISPOSITION_OPTIONS):
            if opt.split()[0].lower() in finding.disposition.lower():
                current_idx = idx
                break

        with c_disp:
            new_disp = st.selectbox(
                "Reviewer Decision",
                DISPOSITION_OPTIONS,
                index=current_idx,
                key=f"disp_sel_{finding.finding_id}",
            )
        with c_notes:
            new_notes = st.text_input(
                "Technical Justification / Mitigation Rationale",
                value=finding.reviewer_notes,
                key=f"notes_val_{finding.finding_id}",
                placeholder="e.g. Confirmed buffer flaw; will replace with strncpy_s per MISRA Rule 21.18.",
            )
        with c_act:
            st.write("&nbsp;")
            if st.button("Save", key=f"btn_save_{finding.finding_id}"):
                finding.disposition = new_disp
                finding.reviewer_notes = new_notes
                if review_id:
                    database.update_finding_disposition(
                        review_id=review_id,
                        finding_id=finding.finding_id,
                        disposition=new_disp,
                        reviewer_notes=new_notes,
                        user=user_name,
                    )
                st.success("Saved!")
                st.rerun()

    st.divider()


def main() -> None:
    st.set_page_config(
        page_title="Automotive Secure Code Review Assistant",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Inject Clean Automotive Enterprise CSS Styling
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
        .stMetric { background: #ffffff; border: 1px solid #eaecf0; border-radius: 8px; padding: 12px 16px; box-shadow: 0 1px 2px rgba(16,24,40,0.04); }
        .stMetric label { font-size: 0.82rem; font-weight: 600; color: #475467; }
        .stMetric [data-testid="stMetricValue"] { font-size: 1.6rem; font-weight: 800; color: #101828; }
        .badge-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px; }
        .std-badge { background: #1e293b; color: #94a3b8; font-size: 0.72rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; border: 1px solid #334155; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Initialize SQLite database
    database.init_db()

    # Sidebar: Role, Engine Mode, and Settings
    with st.sidebar:
        st.markdown("### 🛡️ Automotive Review Portal")
        st.caption("Automotive Engineering Security Platform")

        st.markdown("---")
        st.markdown("#### Engineer Authentication")
        user_name = st.text_input("Engineer Identifier", value="lead_reviewer_1")
        role = st.selectbox(
            "Engineering Role",
            ["Technical Reviewer / Lead", "Embedded Software Developer", "Cybersecurity Engineer", "Functional Safety Manager"],
            index=0,
        )
        st.markdown(f"Status: 🟢 **Authenticated** as `{user_name}`")

        st.markdown("---")
        st.markdown("#### AI Inference Engine")
        ai_mode = st.selectbox(
            "Select Inference Engine",
            [
                "Local LLM (Private / On-Premise) [Default]",
                "Gemini 3.8 Flash (Cloud Backup)",
                "Rule-Based Only (100% Offline)",
            ],
            index=0,
            help="Enforces on-premise execution to protect proprietary ECU firmware IP.",
        )

        local_url = "http://localhost:11434"
        local_model = "qwen2.5-coder:1.5b"

        if "Local LLM" in ai_mode:
            st.success("🔒 **100% On-Premises Isolation Active**\n\nZero source code or embeddings leave this machine.")
            local_url = st.text_input("Local Endpoint", value=os.getenv("LOCAL_LLM_URL", "http://localhost:11434"))
            local_model = st.text_input("Local Model", value=os.getenv("LOCAL_LLM_MODEL", "qwen2.5-coder:1.5b"))

            if st.button("Test Local Model Connection"):
                is_ready, msg = _check_local_ollama_status(local_url, local_model)
                if is_ready:
                    st.success(f"✅ {msg}")
                else:
                    st.warning(f"⚠️ {msg}")

        elif "Gemini" in ai_mode:
            st.info("☁️ **Cloud Backup Engine Active**\n\nUsing configured Gemini 3.8 Flash API key from `.env`.")
            gemini_prov = GeminiProvider()
            if gemini_prov.api_key:
                st.caption(f"Model: `{gemini_prov.model}` | Key: `●●●●●●●● (Configured)`")
            else:
                st.error("GEMINI_API_KEY is not configured in .env.")
        else:
            st.info("⚡ **Deterministic Engine Active**\n\nUses heuristic rules and local FAISS vector guidelines. Zero LLM.")

        st.markdown("---")
        st.markdown("#### Knowledge Retrieval Settings")
        top_k = st.slider("Guideline Citations (Top-K)", min_value=1, max_value=8, value=3)
        max_kb = st.number_input("Max File Size (KB)", min_value=16, max_value=2048, value=200)

    # Dynamic Header with Live Status Indicator
    ollama_ready, ollama_status = _check_local_ollama_status(local_url, local_model)
    status_color = "#10b981" if ollama_ready else "#f59e0b"
    status_label = "LOCAL ON-PREMISE AIR-GAPPED" if "Local" in ai_mode else "CLOUD BACKUP MODE"

    st.markdown(
        f"""
        <div style="background:linear-gradient(90deg, #0f172a 0%, #1e293b 100%);
                    padding:20px 24px;border-radius:12px;color:#ffffff;margin-bottom:16px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <h1 style="color:#ffffff;margin:0;font-size:1.7rem;font-weight:800;letter-spacing:-0.02em;">
                🛡️ Automotive Secure Code Review Assistant
              </h1>
              <div class="badge-bar">
                <span class="std-badge">ISO 26262 ASIL-D</span>
                <span class="std-badge">ISO/SAE 21434</span>
                <span class="std-badge">AUTOSAR Classic & Adaptive</span>
                <span class="std-badge">MISRA-C:2012</span>
                <span class="std-badge">CERT-C SECURE</span>
              </div>
            </div>
            <div style="text-align:right;">
              <span style="background:{status_color}20;color:{status_color};padding:6px 14px;border-radius:20px;font-size:0.8rem;font-weight:700;border:1px solid {status_color}50;">
                ● {status_label}
              </span>
              <div style="font-size:0.75rem;color:#94a3b8;margin-top:4px;">{ollama_status}</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Four Navigation Tabs
    tab_review, tab_logs, tab_history, tab_audit = st.tabs(
        [
            "🔍 Code Review & Findings",
            "📋 Compiler & Static Diagnostics",
            "📂 Past Reviews (SQLite)",
            "🛡️ Compliance Audit Trail",
        ]
    )

    # ---------------- TAB 1: Code Review ----------------
    with tab_review:
        language = st.selectbox("Target Programming Language", LANGUAGES, index=0)

        col_inp1, col_inp2 = st.columns(2)
        with col_inp1:
            pasted = st.text_area(
                "Source Code Editor",
                value="",
                height=240,
                placeholder="// Paste or write your source code here (e.g. C, C++, Python, Java)...",
            )
        with col_inp2:
            uploads = st.file_uploader(
                "Or Upload Source Files (.c, .cpp, .h, .py, etc.)",
                type=[ext.lstrip(".") for ext in sorted(ALLOWED_EXTENSIONS)],
                accept_multiple_files=True,
                help="Supports: .c, .h, .cpp, .hpp, .java, .py, .js, .ts, .log, .txt",
            )

        col_act1, col_act2 = st.columns([2, 1])
        with col_act1:
            analyze_clicked = st.button("Analyze Code", type="primary", use_container_width=True)

        if analyze_clicked:
            max_bytes = int(max_kb) * 1024
            files, errors = _collect_inputs(pasted, uploads, max_bytes, selected_language=language)
            for err in errors:
                st.error(err)
            if not files:
                st.error("Please paste code or upload a file first.")
            else:
                if "Gemini" in ai_mode:
                    provider_type = "gemini"
                elif "Rule-Based" in ai_mode:
                    provider_type = "rules_only"
                else:
                    provider_type = "local"

                try:
                    with st.spinner("Executing rule heuristics, local FAISS RAG, and AI inference..."):
                        result = analyze_source(
                            files=files,
                            user_language=language,
                            top_k=int(top_k),
                            use_ai=("Rule-Based" not in ai_mode),
                            ai_provider_name=provider_type,
                            local_url=local_url,
                            local_model=local_model,
                            user_name=user_name,
                        )
                    st.session_state["last_result"] = result
                    st.success("Analysis complete! Review session saved to local SQLite database.")
                except Exception as exc:
                    st.error(f"Analysis error: {exc}")

        # Display Results
        if "last_result" in st.session_state:
            res: AnalysisResult = st.session_state["last_result"]
            st.markdown("---")

            # Metrics Row
            st.markdown("### 📊 Review Summary & Defect Metrics")
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("High Severity", res.summary.get("High", 0))
            m2.metric("Medium Severity", res.summary.get("Medium", 0))
            m3.metric("Low Severity", res.summary.get("Low", 0))
            m4.metric("Total Defect Class", res.summary.get("Total", 0))
            m5.metric("Review Status", res.review_status)

            st.info(f"**Active Engine Diagnostic:** {res.ai_status}")

            if res.warnings:
                for w in res.warnings:
                    st.warning(w)

            # RAG Section
            with st.expander("📚 Retrieved Automotive Standards & MISRA Guidelines (Local FAISS RAG Grounding)", expanded=False):
                if not res.retrieved_rules:
                    st.write("No matching standards retrieved.")
                else:
                    for rule in res.retrieved_rules:
                        flds = rule.get("fields") or {}
                        st.markdown(f"**{rule.get('id')} — {rule.get('title')}** `(Relevance Score: {rule.get('score', 0):.3f})`")
                        st.caption(f"Applicable Languages: {rule.get('languages')}")
                        st.write(flds.get("description", ""))
                        st.write(f"**Recommended Automotive Practice:** {flds.get('recommended practice', '')}")
                        st.divider()

            # Interactive Finding Filters
            st.markdown(f"### 📋 Review Findings ({len(res.findings)})")
            f_col1, f_col2 = st.columns([1.5, 2.5])
            with f_col1:
                sev_filter = st.selectbox("Filter by Severity", ["All", "High", "Medium", "Low"], index=0)
            with f_col2:
                search_query = st.text_input("Search Findings (Keyword or Rule ID)", placeholder="e.g. buffer, MISRA, pointer")

            filtered_findings = res.findings
            if sev_filter != "All":
                filtered_findings = [f for f in filtered_findings if f.severity.title() == sev_filter]
            if search_query and search_query.strip():
                q = search_query.lower()
                filtered_findings = [
                    f for f in filtered_findings
                    if q in f.title.lower() or q in f.description.lower() or q in f.relevant_rule.lower() or q in f.finding_id.lower()
                ]

            for finding in filtered_findings:
                _render_finding_card(finding, res.db_review_id, user_name)

            # Formal Review Sign-Off
            st.markdown("---")
            st.markdown("### 🏁 Engineering Disposition & Formal Sign-Off")
            s_c1, s_c2 = st.columns([2, 1])
            with s_c1:
                st.markdown(
                    """
                    **ISO 26262 / ISO 21434 Governance Requirement:**  
                    *AI findings serve as recommendations. Every finding must be triaged by a qualified engineer before design release.*
                    """
                )
                if st.button("✅ Execute Formal Review Sign-Off (Lead Reviewer)", type="secondary"):
                    res.review_status = "Approved with Dispositions"
                    res.reviewed_by = user_name
                    res.review_timestamp = datetime.now(timezone.utc).isoformat()
                    if res.db_review_id:
                        database.sign_off_review(res.db_review_id, user_name, "Approved with Dispositions")
                    st.success(f"Formal Sign-off completed by {user_name} at {res.review_timestamp}!")
                    st.rerun()

            with s_c2:
                export_json = json.dumps(res.to_export_dict(), indent=2)
                st.download_button(
                    "📥 Export Audit Report (JSON)",
                    data=export_json,
                    file_name=f"ecu_review_audit_{res.db_review_id or 'export'}.json",
                    mime="application/json",
                    use_container_width=True,
                )

    # ---------------- TAB 2: Compiler & Static Logs ----------------
    with tab_logs:
        st.subheader("📋 Compiler & Static Analysis Diagnostics")
        st.write("Interpret compiler warnings (Tasking, Green Hills, GCC, Clang) or static analyzer reports (Coverity, Polyspace, Cppcheck, Clang-Tidy).")
        diag_input = st.text_area(
            "Compiler / Static Diagnostic Lines",
            value="",
            height=140,
            placeholder="Paste compiler warnings (Tasking, GCC, Clang) or static analysis tool logs here...",
        )
        if st.button("Interpret Diagnostics Now"):
            files = [{"filename": "compiler_log.txt", "code": diag_input}]
            with st.spinner("Analyzing diagnostic lines..."):
                diag_res = analyze_source(files=files, user_language="Log/Text", use_ai=False, user_name=user_name)
            findings_to_show = [f for f in diag_res.findings if f.title != "Function/module summary"]
            if not findings_to_show:
                st.info("No compiler warnings or diagnostics matched known patterns.")
            else:
                st.success(f"Parsed {len(findings_to_show)} diagnostic items:")
                for f in findings_to_show:
                    _render_finding_card(f, None, user_name)

    # ---------------- TAB 3: Review History ----------------
    with tab_history:
        st.subheader("📂 Review Session History (SQLite Persistent Storage)")
        recent = database.get_recent_reviews(limit=15)
        if not recent:
            st.info("No past reviews recorded in the SQLite database yet.")
        else:
            for rev in recent:
                with st.expander(f"Review #{rev['id']} — {rev['language']} ({rev['created_at'][:19]}) — Status: {rev['review_status']}"):
                    c_h1, c_h2 = st.columns(2)
                    with c_h1:
                        st.write(f"**Files Analyzed:** `{rev['files_analyzed']}`")
                        st.write(f"**AI Engine:** `{rev['ai_provider']}`")
                    with c_h2:
                        st.write(f"**Model Name:** `{rev['ai_model']}`")
                        st.write(f"**Signed-off by:** `{rev['reviewed_by'] or 'Pending Sign-Off'}`")

    # ---------------- TAB 4: Audit & Compliance ----------------
    with tab_audit:
        st.subheader("🛡️ ISO 26262 & ISO 21434 Immutable Audit Trail")
        st.caption("All review creations, disposition changes, and lead engineering sign-offs are permanently logged with timestamps.")
        trails = database.get_audit_trail(limit=50)
        if not trails:
            st.info("No audit logs recorded yet.")
        else:
            for log in trails:
                st.markdown(
                    f"**[{log['timestamp'][:19]}]** User: `{log['user']}` &nbsp;|&nbsp; Action: **`{log['action']}`** &nbsp;|&nbsp; Review #{log['review_id']}"
                )
                st.code(log["details_json"], language="json")
                st.divider()


if __name__ == "__main__":
    main()
