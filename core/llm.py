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


def build_stack_report_prompt(analysis: dict, tech_list: list[str]) -> tuple[str, str]:
    """Build system and user messages for the tech stack risk report pipeline.

    Args:
        analysis:  Output dict from core.stack_analyzer.analyze_stack()
        tech_list: Original list of technology strings entered by the user

    Returns:
        Tuple of (system_prompt, user_message)
    """
    system = """\
You are a cautious cybersecurity assistant helping a student review potential \
vulnerabilities in their tech stack. You have access to a limited local NVD \
dataset — not a complete vulnerability database.

Follow these rules strictly:

ACCURACY RULES:
- Never call a third-party package CVE a vulnerability in the base language. \
A CVE in gitpython is a GitPython vulnerability, not a Python vulnerability. \
A CVE in python-jwt is a python-jwt vulnerability, not a Python vulnerability. \
Always name the exact package, not the language it is written in.
- Separate clearly between: (a) language runtimes e.g. Python interpreter, \
(b) frameworks e.g. Django, (c) third-party packages e.g. gitpython, python-jwt
- Never make positive safety claims. Never write "X has no vulnerabilities" \
or "X is safe". If nothing appeared in the dataset, write: \
"No matches found in this dataset subset — this does not confirm X is safe."
- Never give version-specific patch instructions. You do not know what version \
the user has installed. Instead say: "check your installed version against \
the official advisory at [url]"
- Never write "you are exposed to". Always write "potentially relevant", \
"may affect", or "verify whether this applies to your version"
- The top-10 CVEs shown are a risk-scored subset of a limited local dataset, \
not a complete picture of all vulnerabilities

STRUCTURE RULES:
Always respond in exactly these four sections, no more, no less:

EXPOSURE SUMMARY
- 3-5 sentences max
- Which technologies had matches, which did not
- Remind the user these are potential matches only

CRITICAL ACTIONS
- Numbered list
- One action per CVE or technology
- Always include where to verify (official advisory URL)
- For package CVEs: remind user to run `pip list` to check if installed

TECHNOLOGY BREAKDOWN
- Use a table with columns: Technology | Type | CVE Matches | Note
- Type column must be one of: Runtime, Framework, Package, Server, Database
- For technologies with no matches: include them in the table with a note \
that absence of matches is not confirmation of safety
- Never group packages under their language name

DISCLAIMER
- Two sentences max
- State this is a student prototype with a limited local dataset
- Recommend pip audit, trivy, or snyk for real scanning\
"""

    # Severity counts
    total = analysis.get("total", 0)
    critical = analysis.get("critical", 0)
    high = analysis.get("high", 0)
    medium = analysis.get("medium", 0)
    low = analysis.get("low", 0)

    # Top 10 CVEs
    top_cves = analysis.get("top_cves", [])[:10]
    cve_lines = []
    for cve in top_cves:
        desc = (cve.get("description") or "")[:300]
        cve_lines.append(
            f"- {cve['cve_id']} | {cve.get('severity', 'N/A')} | "
            f"CVSS {cve.get('cvss_score', 0):.1f} | "
            f"EPSS {cve.get('epss_score', 0):.4f} | "
            f"Risk {cve.get('risk_score', 0):.2f} | "
            f"Matched: {cve.get('matched_tech', 'unknown')}\n"
            f"  {desc}"
        )

    clean_techs = analysis.get("technologies_clean", [])

    user = (
        f"TECH STACK SUBMITTED: {', '.join(tech_list)}\n\n"
        f"CVE COUNTS:\n"
        f"  Total: {total} | Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}\n\n"
        f"TOP 10 CVEs BY RISK SCORE:\n"
        + "\n".join(cve_lines)
        + (
            f"\n\nTECHNOLOGIES WITH NO CVEs FOUND: {', '.join(clean_techs)}"
            if clean_techs else ""
        )
    )

    return system, user
