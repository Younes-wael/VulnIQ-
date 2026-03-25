"""Ingests structured CVE data into SQLite database for fast filtering, search, and chart queries."""

import json
import sqlite3
from pathlib import Path
from typing import Dict

from tqdm import tqdm

from config import SQLITE_PATH, PROCESSED_DATA_PATH, PIPELINE_START_YEAR, PIPELINE_END_YEAR


def create_db(conn: sqlite3.Connection) -> None:
    """Create all tables and indexes if they don't exist.
    
    Args:
        conn: SQLite database connection
    """
    cursor = conn.cursor()
    
    # Create cves table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            published_date TEXT,
            last_modified TEXT,
            cvss_score REAL,
            severity TEXT,
            year INTEGER,
            vendors TEXT,
            products TEXT
        )
    """)
    
    # Create vendors table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            vendor TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
    """)
    
    # Create products table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            product TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
    """)
    
    # Create indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_year ON cves(year)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vendor ON vendors(vendor)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_product ON products(product)")
    
    conn.commit()


def insert_cve(conn: sqlite3.Connection, cve: Dict) -> str:
    """Insert or replace a single CVE into the database.
    
    Args:
        conn: SQLite database connection
        cve: Cleaned CVE dict
        
    Returns:
        'inserted', 'updated', or 'skipped'
    """
    cursor = conn.cursor()
    
    cve_id = cve['cve_id']
    
    # Check if CVE already exists
    cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
    exists = cursor.fetchone() is not None
    
    # Prepare data
    vendors_str = ','.join(cve.get('vendors', []))
    products_str = ','.join(cve.get('products', []))
    
    # Insert or replace CVE
    cursor.execute("""
        INSERT OR REPLACE INTO cves 
        (cve_id, description, published_date, last_modified, cvss_score, severity, year, vendors, products)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        cve_id,
        cve.get('description'),
        cve.get('published_date'),
        cve.get('last_modified'),
        cve.get('cvss_score'),
        cve.get('severity'),
        cve.get('year'),
        vendors_str,
        products_str
    ))
    
    # Delete existing vendor/product entries for this CVE
    cursor.execute("DELETE FROM vendors WHERE cve_id = ?", (cve_id,))
    cursor.execute("DELETE FROM products WHERE cve_id = ?", (cve_id,))
    
    # Insert vendors
    for vendor in cve.get('vendors', []):
        cursor.execute("INSERT INTO vendors (cve_id, vendor) VALUES (?, ?)", (cve_id, vendor))
    
    # Insert products
    for product in cve.get('products', []):
        cursor.execute("INSERT INTO products (cve_id, product) VALUES (?, ?)", (cve_id, product))
    
    return 'updated' if exists else 'inserted'


def ingest_file(conn: sqlite3.Connection, year: int) -> tuple[int, int, int]:
    """Load and ingest one processed JSON file.
    
    Args:
        conn: SQLite database connection
        year: Year to ingest
        
    Returns:
        Tuple of (inserted, updated, skipped) counts
    """
    processed_file = Path(PROCESSED_DATA_PATH) / f"cves-{year}.json"
    if not processed_file.exists():
        print(f"Processed file for {year} not found: {processed_file}")
        return 0, 0, 0
    
    try:
        with open(processed_file, 'r', encoding='utf-8') as f:
            cves = json.load(f)
        
        inserted = 0
        updated = 0
        skipped = 0
        
        for cve in tqdm(cves, desc=f"Ingesting {year}", unit="CVEs"):
            status = insert_cve(conn, cve)
            if status == 'inserted':
                inserted += 1
            elif status == 'updated':
                updated += 1
            else:
                skipped += 1
        
        return inserted, updated, skipped
        
    except Exception as e:
        print(f"Error ingesting {year}: {e}")
        return 0, 0, 0


def ingest_all(start_year: int = 2015, end_year: int = 2026) -> None:
    """Ingest all processed CVE files into the database.
    
    Args:
        start_year: First year to ingest
        end_year: Last year to ingest (inclusive)
    """
    # Ensure database directory exists
    db_path = Path(SQLITE_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        create_db(conn)
        
        total_inserted = 0
        total_updated = 0
        total_skipped = 0
        
        print(f"Ingesting CVE data from {start_year} to {end_year}...")
        
        for year in range(start_year, end_year + 1):
            inserted, updated, skipped = ingest_file(conn, year)
            conn.commit()  # Commit after each year
            
            total_inserted += inserted
            total_updated += updated
            total_skipped += skipped
            
            if inserted + updated + skipped > 0:
                print(f"Year {year}: {inserted} inserted, {updated} updated, {skipped} skipped")
            else:
                print(f"Year {year}: No data to ingest")
        
        print(f"\nTotal Summary:")
        print(f"  Inserted: {total_inserted}")
        print(f"  Updated: {total_updated}")
        print(f"  Skipped: {total_skipped}")
        
    finally:
        conn.close()


def main() -> None:
    """Entry point for the ingest pipeline."""
    ingest_all(start_year=PIPELINE_START_YEAR, end_year=PIPELINE_END_YEAR)


if __name__ == "__main__":
    main()
