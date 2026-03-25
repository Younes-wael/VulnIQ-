"""
Stack Analysis page — users enter their technology stack and receive a
personalised vulnerability exposure report powered by the NVD database and AI.
"""

import pandas as pd
import streamlit as st

from core.llm import build_stack_report_prompt, check_groq, stream_response
from core.stack_analyzer import analyze_stack

SEVERITY_COLORS = {
    "CRITICAL": "#FF4444",
    "HIGH":     "#FF8800",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#44AA44",
}


def _chip(label: str, color: str) -> str:
    """Return an inline HTML chip span."""
    return (
        f'<span style="background:{color};color:white;padding:3px 10px;'
        f'border-radius:12px;font-size:0.82em;margin:2px;display:inline-block;">'
        f"{label}</span>"
    )


def render_metrics(analysis: dict, tech_list: list[str]):
    """Section A — four metric cards."""
    total     = analysis.get("total", 0)
    critical  = analysis.get("critical", 0)
    high      = analysis.get("high", 0)
    matched   = len(analysis.get("technologies_matched", []))
    entered   = len(tech_list)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total CVEs Found", total)

    with col2:
        label = f":red[{critical}]" if critical > 0 else str(critical)
        st.metric("Critical", label)

    with col3:
        label = f":orange[{high}]" if high > 0 else str(high)
        st.metric("High", label)

    with col4:
        st.metric("Technologies Matched", f"{matched} / {entered}")


def render_tech_chips(analysis: dict):
    """Section B — green/red chips per technology."""
    matched = analysis.get("technologies_matched", [])
    clean   = analysis.get("technologies_clean", [])

    if not matched and not clean:
        return

    st.subheader("Technology Status")

    chips_html = ""
    for tech in matched:
        chips_html += _chip(f"⚠ {tech}", SEVERITY_COLORS["HIGH"])
    for tech in clean:
        chips_html += _chip(f"✓ {tech}", "#44AA44")

    st.markdown(chips_html, unsafe_allow_html=True)
    st.caption("Red = CVEs found  |  Green = No CVEs found")


def render_cve_table(analysis: dict):
    """Section C — top CVEs dataframe."""
    top_cves = analysis.get("top_cves", [])
    if not top_cves:
        st.info("No CVEs matched the provided technologies.")
        return

    st.subheader("Top CVEs by Risk Score")

    rows = []
    for cve in top_cves:
        rows.append({
            "CVE ID":       cve.get("cve_id", ""),
            "Severity":     cve.get("severity", ""),
            "CVSS":         cve.get("cvss_score", 0.0),
            "EPSS Score":   round(cve.get("epss_score", 0.0), 4),
            "Risk Score":   cve.get("risk_score", 0.0),
            "Matched Tech": cve.get("matched_tech", ""),
            "Published":    (cve.get("published_date") or "")[:10],
        })

    df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "CVSS":       st.column_config.NumberColumn(format="%.1f"),
            "EPSS Score": st.column_config.NumberColumn(format="%.4f"),
            "Risk Score": st.column_config.NumberColumn(format="%.2f"),
        },
    )


def render_ai_report(analysis: dict, tech_list: list[str]):
    """Section D — streamed AI risk report."""
    st.subheader("🤖 AI Risk Report")

    ok, model_or_msg = check_groq()
    if not ok:
        st.warning(
            "Groq API key not configured — set the `GROQ_API_KEY` environment variable "
            "to enable the AI risk report."
        )
        return

    system, user = build_stack_report_prompt(analysis, tech_list)
    st.write_stream(stream_response(system, user))


def render():
    """Main Stack Analysis page render function."""
    st.set_page_config(page_title="Stack Analysis", page_icon="🧱", layout="wide")

    st.title("🧱 Tech Stack Analysis")
    st.caption("Enter your technology stack to get a personalised vulnerability exposure report")

    # ------------------------------------------------------------------ input
    stack_input = st.text_area(
        "Your technology stack (one per line)",
        placeholder="python\ndjango\npostgresql\nnginx\nopenssl",
        height=160,
        key="stack_input",
    )
    st.caption("💡 Tip: Use general names — `openssl` not `OpenSSL 3.0.1`")

    col_btn, col_clear = st.columns([1, 5])
    with col_btn:
        analyze_clicked = st.button("Analyze My Stack", type="primary")
    with col_clear:
        if "stack_analysis" in st.session_state:
            if st.button("Clear / Analyze New Stack"):
                del st.session_state["stack_analysis"]
                del st.session_state["stack_techs"]
                st.rerun()

    # --------------------------------------------------------------- analysis
    if analyze_clicked:
        tech_list = [t.strip() for t in stack_input.splitlines() if t.strip()]

        if not tech_list:
            st.warning("Please enter at least one technology before analyzing.")
        else:
            with st.spinner("Matching against NVD database..."):
                result = analyze_stack(tech_list)

            st.session_state["stack_analysis"] = result
            st.session_state["stack_techs"]    = tech_list

    # --------------------------------------------------------------- results
    if "stack_analysis" in st.session_state:
        analysis  = st.session_state["stack_analysis"]
        tech_list = st.session_state["stack_techs"]

        st.divider()
        render_metrics(analysis, tech_list)
        st.divider()
        render_tech_chips(analysis)
        st.divider()
        render_cve_table(analysis)
        st.divider()
        render_ai_report(analysis, tech_list)


render()
