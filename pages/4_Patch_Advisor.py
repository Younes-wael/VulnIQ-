"""
Patch Advisor page — user inputs a CVE ID or description and receives structured mitigation and patch recommendations.
"""

import re

import streamlit as st

from core.advisor import get_full_advisory, stream_advice
from core.llm import check_groq


def render_severity_badge(severity: str) -> str:
    """Render HTML severity badge with color."""
    colors = {
        'CRITICAL': '#FF4444',
        'HIGH': '#FF8800',
        'MEDIUM': '#FFCC00',
        'LOW': '#44AA44'
    }
    color = colors.get(severity, '#888888')
    
    return f'<span style="background:{color};padding:2px 8px;border-radius:4px;color:white;font-weight:bold">{severity}</span>'


def render_risk_card(risk_summary: dict):
    """Render risk assessment metrics and urgency."""
    col1, col2, col3 = st.columns(3)
    
    with col1:
        color = risk_summary['risk_color']
        st.markdown(f"<h3 style='color:{color};margin:0;'>{risk_summary['risk_level']}</h3>", unsafe_allow_html=True)
        st.metric("Risk Level", risk_summary['risk_level'])
    
    with col2:
        st.metric("CVSS Score", risk_summary['cvss_score'] or "N/A")
    
    with col3:
        age = f"{risk_summary['age_days']} days" if risk_summary['age_days'] != -1 else "Unknown"
        st.metric("Age", age)
    
    st.info(risk_summary['urgency'])


def render_cve_details(cve: dict):
    """Render detailed CVE information."""
    st.write(f"**CVE ID:** {cve['cve_id']}")
    st.write(f"**Published:** {cve['published_date'] or 'Unknown'}")
    st.write(f"**Last Modified:** {cve['last_modified'] or 'Unknown'}")
    
    severity = cve.get('severity')
    if severity:
        st.markdown(render_severity_badge(severity), unsafe_allow_html=True)
    
    st.text_area(
        "Description", 
        cve['description'] or '', 
        height=120, 
        disabled=True,
        key="cve_description"
    )
    
    st.write(f"**Vendors:** {', '.join(cve['vendors']) if cve['vendors'] else 'None'}")
    st.write(f"**Products:** {', '.join(cve['products']) if cve['products'] else 'None'}")


def render_related_cves(related_by_vendor: list, related_by_product: list):
    """Render related CVEs in expandable tables."""
    import pandas as pd
    
    col1, col2 = st.columns(2)
    
    with col1:
        with st.expander(f"🏢 Related by Vendor ({len(related_by_vendor)} CVEs)"):
            if related_by_vendor:
                df = pd.DataFrame(related_by_vendor)[['cve_id', 'severity', 'cvss_score', 'published_date']]
                df.columns = ['CVE ID', 'Severity', 'CVSS', 'Published']
                st.dataframe(df, use_container_width=True)
    
    with col2:
        with st.expander(f"📦 Related by Product ({len(related_by_product)} CVEs)"):
            if related_by_product:
                df = pd.DataFrame(related_by_product)[['cve_id', 'severity', 'cvss_score', 'published_date']]
                df.columns = ['CVE ID', 'Severity', 'CVSS', 'Published']
                st.dataframe(df, use_container_width=True)


def render():
    """Main patch advisor page render function."""
    st.set_page_config(page_title="Patch Advisor", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ Patch Advisor")
    st.caption("Enter a CVE ID to get structured risk analysis and AI-powered remediation advice")
    
    # Input section
    col1, col2 = st.columns([0.7, 0.3])
    with col1:
        cve_input = st.text_input("CVE ID", placeholder="e.g. CVE-2021-44228", key="cve_input")
    with col2:
        analyze = st.button("Analyze", type="primary")
    
    # Handle analysis
    if analyze and cve_input.strip():
        cve_id = cve_input.strip().upper()
        
        # Validate CVE ID format
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            st.warning("Please enter a valid CVE ID format: CVE-YYYY-NNNNN")
        else:
            with st.spinner("Loading advisory data..."):
                advisory = get_full_advisory(cve_id)
            
            if not advisory:
                st.error(f"CVE ID not found in database: {cve_id}")
            else:
                # Store in session state
                st.session_state["advisory_cve_id"] = cve_id
                st.session_state["advisory_data"] = advisory
                
                # Section 1: Risk Summary
                st.subheader("⚠️ Risk Assessment")
                render_risk_card(advisory['risk_summary'])
                
                # Section 2: CVE Details
                st.subheader("📋 Vulnerability Details")
                render_cve_details(advisory['cve'])
                
                # Section 3: Related CVEs
                render_related_cves(advisory['related_by_vendor'], advisory['related_by_product'])
                
                # Section 4: AI Recommendations
                st.subheader("🤖 AI Remediation Advice")
                ok, _ = check_groq()
                if not ok:
                    st.error("Groq API key not configured. Set the GROQ_API_KEY environment variable.")
                else:
                    st.write_stream(stream_advice(cve_id))

    # Display cached data if available (but not on new analysis)
    elif "advisory_data" in st.session_state and not analyze:
        advisory = st.session_state["advisory_data"]
        cve_id = st.session_state["advisory_cve_id"]

        st.subheader("⚠️ Risk Assessment")
        render_risk_card(advisory['risk_summary'])

        st.subheader("📋 Vulnerability Details")
        render_cve_details(advisory['cve'])

        render_related_cves(advisory['related_by_vendor'], advisory['related_by_product'])

        st.subheader("🤖 AI Remediation Advice")
        ok, _ = check_groq()
        if not ok:
            st.error("Groq API key not configured. Set the GROQ_API_KEY environment variable.")
        else:
            st.info("Click 'Analyze' again to refresh AI recommendations.")


render()