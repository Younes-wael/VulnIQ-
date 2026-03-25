"""Downloads CVE data from the NVD REST API 2.0 by year and saves to data/raw/."""

import json
import time
from datetime import date, timedelta
from pathlib import Path

import requests
from tqdm import tqdm

from config import RAW_DATA_PATH, NVD_API_BASE_URL, PIPELINE_START_YEAR, PIPELINE_END_YEAR

PAGE_SIZE  = 2000  # max results per page allowed by NVD API
CHUNK_DAYS = 90    # NVD API allows max 120 days per request; 90 is a safe margin


def _date_chunks(year: int):
    """Yield (start, end) date-string pairs covering the full year in CHUNK_DAYS windows."""
    start = date(year, 1, 1)
    end_of_year = date(year, 12, 31)
    while start <= end_of_year:
        end = min(start + timedelta(days=CHUNK_DAYS - 1), end_of_year)
        yield (
            f"{start}T00:00:00.000",
            f"{end}T23:59:59.999",
        )
        start = end + timedelta(days=1)


def _fetch_page(params: dict) -> dict | None:
    """Fetch one page from the NVD API with up to 3 retries."""
    for attempt in range(3):
        try:
            response = requests.get(
                NVD_API_BASE_URL,
                params=params,
                timeout=60,
                headers={"Accept": "application/json"},
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                print(f"\n  Rate limited (403), waiting 35s...")
                time.sleep(35)
            else:
                msg = response.headers.get("message", response.text[:120])
                print(f"\n  HTTP {response.status_code}: {msg}")
                time.sleep(5)
        except requests.RequestException as e:
            print(f"\n  Request error: {e}")
            if attempt < 2:
                time.sleep(5)
    return None


def download_year(year: int) -> str:
    """Download all CVEs for a single year via the NVD API 2.0.

    The year is split into 90-day windows to respect the API's 120-day limit.

    Args:
        year: The year to download (e.g., 2023)

    Returns:
        'downloaded' if successful, 'skipped' if already exists, 'failed' if error
    """
    raw_path = Path(RAW_DATA_PATH)
    raw_path.mkdir(parents=True, exist_ok=True)

    filepath = raw_path / f"nvdcve-{year}.json"
    if filepath.exists():
        return 'skipped'

    all_items = []

    try:
        chunks = list(_date_chunks(year))
        with tqdm(desc=f"Year {year}", unit="CVEs", dynamic_ncols=True) as pbar:
            for pub_start, pub_end in chunks:
                start_index = 0
                chunk_total = None

                while True:
                    params = {
                        "pubStartDate":   pub_start,
                        "pubEndDate":     pub_end,
                        "startIndex":     start_index,
                        "resultsPerPage": PAGE_SIZE,
                    }
                    data = _fetch_page(params)
                    if data is None:
                        return 'failed'

                    if chunk_total is None:
                        chunk_total = data.get("totalResults", 0)

                    page_items = data.get("vulnerabilities", [])
                    all_items.extend(page_items)
                    pbar.update(len(page_items))

                    start_index += len(page_items)
                    if start_index >= chunk_total or not page_items:
                        break

                    # NVD rate limit: ~5 requests per 30s without an API key
                    time.sleep(6)

                # Brief pause between chunks
                time.sleep(6)

        # Save in a shape parse.py can read
        output = {"CVE_Items": [v["cve"] for v in all_items]}
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)

        return 'downloaded'

    except Exception as e:
        print(f"Year {year}: Unexpected error - {e}")
        return 'failed'


def download_all(start_year: int = 2015, end_year: int = 2026) -> None:
    """Download CVE data for all years in the specified range.

    Args:
        start_year: First year to download
        end_year: Last year to download (inclusive)
    """
    downloaded = skipped = failed = 0
    print(f"Downloading CVE data from {start_year} to {end_year} via NVD API 2.0...")

    for year in range(start_year, end_year + 1):
        status = download_year(year)
        if status == 'downloaded':
            downloaded += 1
        elif status == 'skipped':
            skipped += 1
        else:
            failed += 1

    print(f"\nDownload Summary:")
    print(f"  Downloaded: {downloaded}")
    print(f"  Skipped:    {skipped}")
    print(f"  Failed:     {failed}")


def main() -> None:
    """Entry point for the download pipeline."""
    download_all(start_year=PIPELINE_START_YEAR, end_year=PIPELINE_END_YEAR)


if __name__ == "__main__":
    main()
