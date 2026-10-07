"""Streamlit UI for the Secure Code Debugging and Review Assistant.

This application never executes uploaded source code and never compiles it.
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from analyzer import (
    ALLOWED_EXTENSIONS,
    LANGUAGES,
    AnalysisResult,
    analyze_source,
)
from gemini_client import GeminiProvider

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

MAX_DEFAULT_BYTES = 200 * 1024
SEVERITY_COLORS = {
    "High": "#b42318",
    "Medium": "#b54708",
    "Low": "#175cd3",
}


def _extension_ok(name: str) -> bool:
    return Path(name).suffix.lower() in ALLOWED_EXTENSIONS


def _collect_inputs(
    pasted: str,
    uploads,
    max_bytes: int,
) -> tuple[list[dict], list[str]]:
    files: list[dict] = []
    errors: list[str] = []

    if pasted and pasted.strip():
        files.append({"filename": "pasted_code", "code": pasted})

    if uploads:
        for uploaded in uploads:
            name = uploaded.name
            if not _extension_ok(name):
                errors.append(
                    f"{name}: unsupported extension. Allowed: "
                    + ", ".join(sorted(ALLOWED_EXTENSIONS))
                )
                continue
            data = uploaded.getvalue()
            if len(data) > max_bytes:
                errors.append(
                    f"{name}: file is too large ({len(data)} bytes). "
                    f"Limit is {max_bytes} bytes."
                )
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("utf-8", errors="replace")
                errors.append(f"{name}: was not valid UTF-8; replacement characters were used.")
            files.append({"filename": name, "code": text})

    return files, errors


def _render_finding(finding) -> None:
    color = SEVERITY_COLORS.get(finding.severity, "#344054")
    st.markdown(
        f"""
        <div style="border:1px solid #d0d5dd;border-left:6px solid {color};
                    border-radius:8px;padding:12px 16px;margin-bottom:12px;background:#fff;">
          <strong>{finding.finding_id}</strong>
          &nbsp;·&nbsp; <span style="color:{color};font-weight:700;">{finding.severity}</span>
          &nbsp;·&nbsp; {finding.category}
          <div style="font-size:1.05rem;margin-top:4px;">{finding.title}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, right = st.columns(2)
    with left:
        st.write(f"**Language:** {finding.language}")
        st.write(f"**File:** {finding.file}")
        st.write(f"**Function/method:** {finding.function}")
        st.write(f"**Line:** {finding.line}")
        st.write(f"**Confidence:** {finding.confidence}")
    with right:
        st.write(f"**Relevant rule:** {finding.relevant_rule}")
        st.write(f"**Source:** {finding.source}")
        st.write("**Human Review Required: YES**")
    st.write("**Code evidence**")
    st.code(finding.code_evidence or "(none)", language="text")
    st.write("**Explanation**")
    st.write(finding.description)
    st.write("**Root cause**")
    st.write(finding.root_cause)
    st.write("**Suggested fix**")
    st.write(finding.suggested_fix)


def _render_results(result: AnalysisResult) -> None:
    st.subheader("Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("High", result.summary.get("High", 0))
    c2.metric("Medium", result.summary.get("Medium", 0))
    c3.metric("Low", result.summary.get("Low", 0))
    c4.metric("Total", result.summary.get("Total", 0))
    st.caption(f"Detected language context: {result.language}")

    st.subheader("AI Analysis Status")
    st.info(result.ai_status)
    if result.ai_raw_text and "JSON could not" in result.ai_status:
        with st.expander("Raw AI analysis"):
            st.text(result.ai_raw_text)

    if result.warnings:
        for warning in result.warnings:
            st.warning(warning)

    st.subheader("Retrieved Coding Rules")
    if not result.retrieved_rules:
        st.write("No RAG rules were retrieved. Build the index with `python ingest.py` if it is missing.")
    else:
        for rule in result.retrieved_rules:
            fields = rule.get("fields") or {}
            with st.expander(f"{rule.get('id', '')} — {rule.get('title', '')} (score {rule.get('score', 0):.3f})"):
                st.write(f"**Languages:** {rule.get('languages', '')}")
                st.write(fields.get("description", ""))
                st.write("**Why it matters**")
                st.write(fields.get("why it matters", ""))
                st.write("**Recommended practice**")
                st.write(fields.get("recommended practice", ""))

    st.subheader("Findings")
    st.caption("Human Review Required: YES — AI is an assistant, not an approval system.")
    for finding in result.findings:
        _render_finding(finding)

    export = json.dumps(result.to_export_dict(), indent=2)
    st.download_button(
        "Download structured review results (JSON)",
        data=export,
        file_name="code_review_findings.json",
        mime="application/json",
    )


def main() -> None:
    st.set_page_config(page_title="Secure Code Debugging and Review Assistant", layout="wide")
    st.title("Secure Code Debugging and Review Assistant")
    st.write(
        "AI-assisted multi-language code review using rule-based analysis, RAG, and Gemini."
    )

    with st.expander("Responsible AI and governance", expanded=True):
        st.markdown(
            """
- AI-generated findings are recommendations only.
- All findings and suggested fixes require human review.
- The system does not provide official MISRA compliance certification.
- Educational MISRA-oriented guidance may be retrieved; that is **not** MISRA compliance.
- The system does not replace qualified reviewers or certified static-analysis/security tools.
- Do not submit confidential source code to external AI services unless organizational policy explicitly permits it.
- Uploaded code is **never executed** and **never compiled** by this application.
- AI-generated content must be reviewed by authorized engineering specialists before compliance, design approval, software release, or vehicle validation.
            """
        )

    provider = GeminiProvider()
    with st.sidebar:
        st.header("Settings")
        st.text_input(
            "Gemini Model",
            value=provider.model or "(set GEMINI_MODEL in .env)",
            disabled=True,
            help="Configured from the GEMINI_MODEL environment variable. The API key is never shown.",
        )
        if provider.api_key:
            st.caption("Gemini API key: configured (value hidden)")
        else:
            st.caption("Gemini API key: not set — rule-based mode will be used")

        top_k = st.slider("RAG Top-K", min_value=1, max_value=8, value=3)
        max_kb = st.number_input("Maximum file size (KB)", min_value=16, max_value=2048, value=200)
        st.subheader("Analysis Options")
        include_quality_summaries = st.checkbox("Show module summaries in findings", value=True)
        st.caption("Gemini is always used for analysis when the API key is set in .env.")
        st.subheader("Human Review Warning")
        st.error("Human Review Required: YES for every AI-assisted recommendation.")

    language = st.selectbox("1. Select language / Auto Detect", LANGUAGES, index=0)
    pasted = st.text_area("2. Paste code", height=220, placeholder="Paste source here. It will not be executed.")
    uploads = st.file_uploader(
        "3. Upload file or multiple files",
        type=[ext.lstrip(".") for ext in sorted(ALLOWED_EXTENSIONS)],
        accept_multiple_files=True,
    )

    st.caption(
        "Supported code extensions: .c .h .cpp .hpp .java .py .js .jsx .ts .tsx. "
        "Optional logs: .txt .log (interpreted, never executed)."
    )

    if st.button("4. Analyze Code", type="primary"):
        max_bytes = int(max_kb) * 1024
        files, errors = _collect_inputs(pasted, uploads, max_bytes)
        for err in errors:
            st.error(err)
        if not files:
            st.error("Paste code or upload at least one supported file before analyzing.")
            return
        try:
            with st.spinner("Analyzing with rule-based checks, RAG, and Gemini..."):
                result = analyze_source(
                    files=files,
                    user_language=language,
                    top_k=int(top_k),
                    use_ai=True,
                )
            if not include_quality_summaries:
                result.findings = [f for f in result.findings if f.title != "Function/module summary"]
            st.session_state["last_result"] = result
        except ValueError as exc:
            st.error(str(exc))
            return
        except Exception:
            st.error("Analysis failed unexpectedly. Check that the RAG index exists and try again.")
            return

    if "last_result" in st.session_state:
        _render_results(st.session_state["last_result"])


if __name__ == "__main__":
    main()
