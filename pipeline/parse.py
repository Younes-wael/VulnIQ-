"""Parses raw NVD JSON files, cleans and flattens CVE records into structured dicts ready for storage."""

import json
from pathlib import Path
from typing import List, Dict, Optional

from tqdm import tqdm

from config import RAW_DATA_PATH, PROCESSED_DATA_PATH, PIPELINE_START_YEAR, PIPELINE_END_YEAR


def parse_cve_item(item: dict) -> Optional[Dict]:
    """Parse a single CVE item from NVD API 2.0 JSON into a clean dict.

    Args:
        item: CVE dict from NVD API 2.0 (the 'cve' object)

    Returns:
        Cleaned CVE dict or None if invalid/missing description
    """
    cve_id = item.get("id", "").strip()
    if not cve_id:
        return None

    # English description
    description = None
    for desc in item.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "").strip()
            break
    if not description:
        return None

    # Dates
    published_date = item.get("published", "").split("T")[0] or None
    last_modified  = item.get("lastModified", "").split("T")[0] or None

    # CVSS — prefer V3.1, then V3.0, then V2
    metrics    = item.get("metrics", {})
    cvss_score = None
    severity   = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        # prefer Primary source
        for entry in sorted(entries, key=lambda e: e.get("type", "") != "Primary"):
            cvss_data  = entry.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity   = cvss_data.get("baseSeverity")
            if cvss_score is not None:
                break
        if cvss_score is not None:
            break

    if cvss_score is None:
        for entry in metrics.get("cvssMetricV2", []):
            cvss_data  = entry.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity   = entry.get("baseSeverity")
            if cvss_score is not None:
                break

    # Vendors and Products from CPE strings: cpe:2.3:<type>:<vendor>:<product>:...
    vendors  = set()
    products = set()

    for config in item.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor  = parts[3].strip().lower()
                    product = parts[4].strip().lower()
                    if vendor  and vendor  != "*":
                        vendors.add(vendor)
                    if product and product != "*":
                        products.add(product)

    # Year from CVE ID
    year = None
    parts = cve_id.split("-")
    if len(parts) >= 2:
        try:
            year = int(parts[1])
        except ValueError:
            pass

    return {
        "cve_id":         cve_id,
        "description":    description,
        "published_date": published_date,
        "last_modified":  last_modified,
        "cvss_score":     cvss_score,
        "severity":       severity,
        "vendors":        list(vendors),
        "products":       list(products),
        "year":           year,
    }


def parse_file(year: int) -> tuple[List[Dict], int, int, int]:
    """Parse one year's raw NVD JSON file.
    
    Args:
        year: Year to parse
        
    Returns:
        Tuple of (parsed_cves, total_items, skipped_no_desc, failed_parsing)
    """
    raw_file = Path(RAW_DATA_PATH) / f"nvdcve-{year}.json"
    if not raw_file.exists():
        print(f"Raw file for {year} not found: {raw_file}")
        return [], 0, 0, 0
    
    try:
        with open(raw_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cve_items = data.get("CVE_Items", [])
        parsed_cves = []
        skipped = 0
        failed = 0
        
        for item in tqdm(cve_items, desc=f"Parsing {year}", unit="CVEs"):
            try:
                result = parse_cve_item(item)
                if result is not None:
                    parsed_cves.append(result)
                else:
                    skipped += 1
            except Exception:
                failed += 1
        
        return parsed_cves, len(cve_items), skipped, failed
        
    except Exception as e:
        print(f"Error parsing {year}: {e}")
        return [], 0, 0, 0


def save_processed(year: int, cves: List[Dict]) -> None:
    """Save cleaned CVE list to processed data directory.
    
    Args:
        year: Year of the data
        cves: List of cleaned CVE dicts
    """
    processed_path = Path(PROCESSED_DATA_PATH)
    processed_path.mkdir(parents=True, exist_ok=True)
    
    output_file = processed_path / f"cves-{year}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)


def parse_all(start_year: int = 2015, end_year: int = 2026) -> None:
    """Parse all years in the specified range.
    
    Args:
        start_year: First year to parse
        end_year: Last year to parse (inclusive)
    """
    print(f"Parsing CVE data from {start_year} to {end_year}...")
    
    for year in range(start_year, end_year + 1):
        cves, total, skipped, failed = parse_file(year)
        if total > 0:
            save_processed(year, cves)
            print(f"Year {year}: {len(cves)} parsed, {skipped} skipped (no desc), {failed} failed")
        else:
            print(f"Year {year}: No data to parse")


def main() -> None:
    """Entry point for the parse pipeline."""
    parse_all(start_year=PIPELINE_START_YEAR, end_year=PIPELINE_END_YEAR)


if __name__ == "__main__":
    main()
