"""
Visualizations page — Plotly charts showing CVE trends over time, severity distribution, top vendors, and CVSS score histogram.
"""

import sqlite3

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from config import SQLITE_PATH


@st.cache_data
def load_stats() -> dict:
    """Load basic statistics for metric cards."""
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        total_cves = pd.read_sql_query("SELECT COUNT(*) FROM cves", conn).iloc[0, 0]
        critical_count = pd.read_sql_query("SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'", conn).iloc[0, 0]
        avg_cvss = pd.read_sql_query("SELECT AVG(cvss_score) FROM cves WHERE cvss_score IS NOT NULL", conn).iloc[0, 0]
        max_year = pd.read_sql_query("SELECT MAX(year) FROM cves", conn).iloc[0, 0]
        
        return {
            "total_cves": total_cves,
            "critical_count": critical_count,
            "avg_cvss": round(avg_cvss, 2) if avg_cvss else 0.0,
            "max_year": max_year
        }
    finally:
        conn.close()


@st.cache_data
def load_cves_per_year() -> pd.DataFrame:
    """Load CVE counts per year."""
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        df = pd.read_sql_query("""
            SELECT year, COUNT(*) as count 
            FROM cves 
            WHERE year IS NOT NULL 
            GROUP BY year 
            ORDER BY year
        """, conn)
        return df
    finally:
        conn.close()


@st.cache_data
def load_severity_distribution() -> pd.DataFrame:
    """Load severity distribution counts."""
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        df = pd.read_sql_query("""
            SELECT severity, COUNT(*) as count 
            FROM cves 
            WHERE severity IS NOT NULL 
            GROUP BY severity
        """, conn)
        return df
    finally:
        conn.close()


@st.cache_data
def load_top_vendors(limit: int = 15) -> pd.DataFrame:
    """Load top affected vendors."""
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        df = pd.read_sql_query(f"""
            SELECT vendor, COUNT(*) as count 
            FROM vendors 
            GROUP BY vendor 
            ORDER BY count DESC 
            LIMIT {limit}
        """, conn)
        return df
    finally:
        conn.close()


@st.cache_data
def load_cvss_distribution() -> pd.DataFrame:
    """Load CVSS score distribution."""
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        df = pd.read_sql_query("""
            SELECT cvss_score 
            FROM cves 
            WHERE cvss_score IS NOT NULL
        """, conn)
        return df
    finally:
        conn.close()


@st.cache_data
def load_severity_by_year() -> pd.DataFrame:
    """Load severity counts by year for trend chart."""
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        df = pd.read_sql_query("""
            SELECT year, severity, COUNT(*) as count 
            FROM cves 
            WHERE year IS NOT NULL AND severity IS NOT NULL 
            GROUP BY year, severity 
            ORDER BY year
        """, conn)
        return df
    finally:
        conn.close()


def make_yearly_line(df: pd.DataFrame) -> go.Figure:
    """Create yearly CVE count line chart."""
    fig = px.line(
        df, 
        x='year', 
        y='count', 
        title="CVEs Reported Per Year",
        markers=True,
        template="plotly_dark"
    )
    fig.update_traces(line_color='#4A9EFF')
    return fig


def make_severity_pie(df: pd.DataFrame) -> go.Figure:
    """Create severity distribution pie chart."""
    color_map = {
        'CRITICAL': '#FF4444',
        'HIGH': '#FF8800', 
        'MEDIUM': '#FFCC00',
        'LOW': '#44AA44'
    }
    
    fig = px.pie(
        df,
        names='severity',
        values='count',
        title="Severity Distribution",
        color='severity',
        color_discrete_map=color_map,
        template="plotly_dark"
    )
    return fig


def make_vendor_bar(df: pd.DataFrame) -> go.Figure:
    """Create top vendors horizontal bar chart."""
    fig = px.bar(
        df,
        x='count',
        y='vendor',
        orientation='h',
        title="Top 15 Most Affected Vendors",
        color='count',
        color_continuous_scale='Reds',
        template="plotly_dark"
    )
    fig.update_layout(yaxis={'categoryorder': 'total ascending'})
    return fig


def make_cvss_histogram(df: pd.DataFrame) -> go.Figure:
    """Create CVSS score histogram."""
    fig = px.histogram(
        df,
        x='cvss_score',
        nbins=20,
        title="CVSS Score Distribution",
        template="plotly_dark"
    )
    fig.update_traces(
        marker_color='#FF8800',
        marker_line_color='black',
        marker_line_width=1
    )
    return fig


def make_severity_trend(df: pd.DataFrame) -> go.Figure:
    """Create severity trend stacked bar chart."""
    color_map = {
        'CRITICAL': '#FF4444',
        'HIGH': '#FF8800',
        'MEDIUM': '#FFCC00',
        'LOW': '#44AA44'
    }
    
    fig = px.bar(
        df,
        x='year',
        y='count',
        color='severity',
        title="Severity Trend Over Years",
        color_discrete_map=color_map,
        template="plotly_dark",
        barmode='stack'
    )
    return fig


def render():
    """Main Streamlit render function."""
    st.set_page_config(page_title="CVE Dashboard", page_icon="📊", layout="wide")
    
    st.title("📊 CVE Vulnerability Dashboard")
    st.subheader("Trends and statistics from the NVD database")
    
    with st.spinner("Loading dashboard data..."):
        stats = load_stats()
        
        # Metric cards
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total CVEs", f"{stats['total_cves']:,}")
        with col2:
            st.metric("Critical CVEs", f"{stats['critical_count']:,}")
        with col3:
            st.metric("Avg CVSS Score", stats['avg_cvss'])
        
        # Row 1: Yearly line and severity pie
        row1_col1, row1_col2 = st.columns(2)
        
        with row1_col1:
            df_year = load_cves_per_year()
            fig = make_yearly_line(df_year)
            st.plotly_chart(fig, use_container_width=True)
        
        with row1_col2:
            df_sev = load_severity_distribution()
            fig = make_severity_pie(df_sev)
            st.plotly_chart(fig, use_container_width=True)
        
        # Row 2: Vendor bar and CVSS histogram
        row2_col1, row2_col2 = st.columns(2)
        
        with row2_col1:
            df_vendor = load_top_vendors()
            fig = make_vendor_bar(df_vendor)
            st.plotly_chart(fig, use_container_width=True)
        
        with row2_col2:
            df_cvss = load_cvss_distribution()
            fig = make_cvss_histogram(df_cvss)
            st.plotly_chart(fig, use_container_width=True)
        
        # Row 3: Severity trend (full width)
        df_trend = load_severity_by_year()
        fig = make_severity_trend(df_trend)
        st.plotly_chart(fig, use_container_width=True)


render()