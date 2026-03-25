"""
Manages Groq API connection, builds prompts with retrieved CVE context, and streams responses.
Requires GROQ_API_KEY environment variable.
"""

import os
from typing import Generator

import streamlit as st
from dotenv import load_dotenv
from groq import Groq, AuthenticationError, RateLimitError

load_dotenv()

from config import GROQ_MODEL
from core.retriever import retrieve, format_context, get_cve_by_id


@st.cache_resource
def get_groq_client() -> Groq:
    """Create and cache a single Groq client for the app lifetime."""
    return Groq(api_key=os.environ.get("GROQ_API_KEY"))


def check_groq() -> tuple[bool, str]:
    """Check whether GROQ_API_KEY is configured.

    Returns:
        Tuple of (is_available, message)
    """
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        return False, "GROQ_API_KEY not set"
    return True, GROQ_MODEL


def stream_response(system: str, user: str) -> Generator[str, None, None]:
    """Stream a Groq response token by token.

    Args:
        system: System prompt string
        user:   User message string

    Yields:
        Text tokens as they arrive, or an error string
    """
    try:
        client = get_groq_client()
        stream = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            max_tokens=1024,
            stream=True,
        )
        for chunk in stream:
            token = chunk.choices[0].delta.content
            if token:
                yield token
    except AuthenticationError:
        yield "Error: Invalid API key. Check your GROQ_API_KEY."
    except RateLimitError:
        yield "Error: Rate limit reached. Please wait a moment and try again."
    except Exception as e:
        yield f"Error: {e}"


def build_chat_prompt(query: str, context: str) -> tuple[str, str]:
    """Build system and user messages for the chat pipeline.

    Returns:
        Tuple of (system_prompt, user_message)
    """
    system = (
        "You are a cybersecurity expert assistant specialising in CVE vulnerability analysis. "
        "Answer questions using ONLY the CVE data provided. "
        "Always cite specific CVE IDs. "
        "If the context lacks enough information, say so clearly. "
        "Be concise, accurate, and technical."
    )
    user = f"CONTEXT:\n{context}\n\nQUESTION: {query}"
    return system, user


def build_advisor_prompt(cve_id: str, cve_data: dict, similar_cves: list[dict]) -> tuple[str, str]:
    """Build system and user messages for the patch advisor pipeline.

    Returns:
        Tuple of (system_prompt, user_message)
    """
    system = (
        "You are a cybersecurity remediation expert. "
        "Given a CVE and similar past vulnerabilities, provide structured mitigation advice "
        "in this exact format:\n\n"
        "AFFECTED SYSTEMS: (list affected vendors/products)\n"
        "SEVERITY ASSESSMENT: (explain the risk)\n"
        "IMMEDIATE ACTIONS: (numbered list of urgent steps)\n"
        "PATCH RECOMMENDATIONS: (specific patches or workarounds)\n"
        "REFERENCES: (suggest where to find official patches)"
    )

    cve_info = (
        f"CVE ID: {cve_id}\n"
        f"Description: {cve_data['description']}\n"
        f"Severity: {cve_data['severity']}\n"
        f"CVSS Score: {cve_data['cvss_score']}\n"
        f"Vendors: {', '.join(cve_data['vendors'])}\n"
        f"Products: {', '.join(cve_data['products'])}\n"
        f"Published: {cve_data['published_date']}"
    )

    similar_text = "\n\nSIMILAR CVEs:\n" + "".join(
        f"- {c['cve_id']}: {c['document'][:200]}...\n" for c in similar_cves
    )

    return system, cve_info + similar_text


def chat(query: str, filters: dict = None) -> Generator[str, None, None]:
    """Full chat pipeline: retrieve context and stream Groq response."""
    results = retrieve(query, filters=filters)
    context = format_context(results)
    system, user = build_chat_prompt(query, context)

    for token in stream_response(system, user):
        yield token

    if results:
        cve_ids = [r['cve_id'] for r in results]
        yield f"\n\n**Sources:** {', '.join(cve_ids)}"


def advise(cve_id: str) -> Generator[str, None, None]:
    """Full advisor pipeline: analyse a CVE and stream remediation advice."""
    cve_data = get_cve_by_id(cve_id)
    if not cve_data:
        yield "CVE ID not found in database."
        return

    similar_cves = retrieve(cve_data["description"], top_k=3)
    system, user = build_advisor_prompt(cve_id, cve_data, similar_cves)

    for token in stream_response(system, user):
        yield token
