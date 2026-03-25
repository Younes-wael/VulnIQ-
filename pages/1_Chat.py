"""
Chat page — users ask natural language questions about CVEs and receive RAG-powered answers with source CVE IDs.
"""

import itertools
import threading
import time

import streamlit as st

from core.llm import check_groq, build_chat_prompt, stream_response
from core.retriever import retrieve, format_context


def build_filters(severities, year_from, year_to, vendor):
    """Build filters dict from sidebar values."""
    filters = {}
    
    if severities:
        filters['severities'] = severities
    
    if year_from != 2015:
        filters['year_from'] = year_from
    
    if year_to != 2026:
        filters['year_to'] = year_to
    
    if vendor.strip():
        filters['vendor'] = vendor.strip()
    
    return filters


def check_and_show_groq_status():
    """Check Groq API status and display in sidebar."""
    ok, msg = check_groq()

    if ok:
        st.sidebar.success(f"🟢 Groq: {msg}")
    else:
        st.sidebar.error(f"🔴 Groq: {msg}")
        st.warning("Groq API key not configured. Set the GROQ_API_KEY environment variable.")


def render_message_history():
    """Render all messages from chat history."""
    for msg in st.session_state["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])


def render():
    """Main chat page render function."""
    st.set_page_config(page_title="CVE Chat", page_icon="💬", layout="wide")
    
    # Initialize session state
    if "messages" not in st.session_state:
        st.session_state["messages"] = []
    
    # Check Groq API status
    check_and_show_groq_status()
    
    # Sidebar filters
    with st.sidebar:
        st.header("⚙️ Search Filters")
        st.info("Filters narrow which CVEs are retrieved as context")
        
        severities = st.multiselect(
            "Severity", 
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
        
        col1, col2 = st.columns(2)
        with col1:
            year_from = st.number_input("From Year", 2015, 2026, 2015)
        with col2:
            year_to = st.number_input("To Year", 2015, 2026, 2026)
        
        vendor = st.text_input("Vendor filter")
        
        st.divider()
        
        if st.button("🗑️ Clear Chat"):
            st.session_state["messages"] = []
            st.rerun()
    
    # Main chat interface
    st.title("💬 CVE Security Assistant")
    st.caption("Ask questions about CVE vulnerabilities. Answers are grounded in NVD data.")
    
    # Render message history
    render_message_history()
    
    # Chat input
    if prompt := st.chat_input("Ask about CVE vulnerabilities..."):
        # Add user message to history and display
        st.session_state["messages"].append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Build filters
        filters = build_filters(severities, year_from, year_to, vendor)
        
        # Check Ollama availability
        ok, _ = check_groq()
        if not ok:
            st.error("Groq API key not configured. Set the GROQ_API_KEY environment variable.")
        else:
            with st.chat_message("assistant"):
                status = st.empty()

                # Phase 1: retrieval
                status.markdown("⏳ _Searching CVE knowledge base..._")
                sources = retrieve(prompt, filters=filters)
                context = format_context(sources)
                system_prompt, user_msg = build_chat_prompt(prompt, context)

                # Phase 2: animate dots while waiting for first token
                stop_anim = threading.Event()

                def animate_dots():
                    for dots in itertools.cycle(["", ".", "..", "..."]):
                        if stop_anim.is_set():
                            return
                        status.markdown(f"🤖 _Generating response{dots}_")
                        time.sleep(0.4)

                anim_thread = threading.Thread(target=animate_dots, daemon=True)
                anim_thread.start()

                def stream_with_clear():
                    """Stop animation on first token, clear status, then yield normally."""
                    first = True
                    for token in stream_response(system_prompt, user_msg):
                        if first:
                            stop_anim.set()
                            anim_thread.join(timeout=1)
                            status.empty()
                            first = False
                        yield token
                    stop_anim.set()

                # Phase 3: stream response
                response = st.write_stream(stream_with_clear())

                # Append sources only if response didn't error
                stream_errored = response.startswith("Error connecting to Ollama")
                if sources and not stream_errored:
                    cve_ids = [s['cve_id'] for s in sources]
                    response += f"\n\n**Sources:** {', '.join(cve_ids)}"

            # Add assistant response to history
            st.session_state["messages"].append({"role": "assistant", "content": response})

            # Show sources table only on success
            if sources and not stream_errored:
                with st.expander("📎 Retrieved CVE Sources"):
                    table_data = [
                        {
                            'CVE ID': s['cve_id'],
                            'Severity': s['severity'],
                            'CVSS': s['cvss_score'],
                            'Relevance Score': f"{s['relevance_score']:.3f}",
                            'Vendors': s['vendors'],
                        }
                        for s in sources
                    ]
                    st.dataframe(table_data, use_container_width=True)


render()