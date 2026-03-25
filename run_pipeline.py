#!/usr/bin/env python3
"""
CVE Assistant — Data Pipeline Runner
Runs the complete ETL pipeline: download → parse → ingest → embed
"""

import sys

from pipeline.download import main as download_main
from pipeline.parse import main as parse_main
from pipeline.ingest import main as ingest_main
from pipeline.embed import main as embed_main


def main():
    """Run the complete data pipeline."""
    print("=== CVE Assistant — Data Pipeline ===")
    
    steps = [
        ("Download NVD Data", download_main),
        ("Parse and Clean", parse_main),
        ("Ingest to Database", ingest_main),
        ("Generate Embeddings", embed_main)
    ]
    
    for i, (name, func) in enumerate(steps, 1):
        print(f"--- Step {i}/4: {name} ---")
        try:
            func()
            print(f"[OK] Step {i} complete")
        except Exception as e:
            print(f"[FAIL] Step {i} failed: {e}")
            sys.exit(1)
    
    print("\nPipeline complete! Run: streamlit run app.py")


if __name__ == "__main__":
    main()