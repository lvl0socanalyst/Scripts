#!/usr/bin/env python3
"""
Uses the `domain:` field (contacted domains) to find .com.au sites
that have already been scanned by URLScan AND contacted known
blockchain RPC / EtherHiding infrastructure.
Just queries URLScan's existing dataset.

Requirements:
    pip install requests
Usage:
    python etherhiding_hunt.py
Set URLSCAN_API_KEY below or via env var.
Author:
Lvl0socanalyst.github.io
"""

import os
import json
import time
import logging
import requests
from datetime import datetime

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "SET_UR_API_KEY_MATE")

#How far back to search
DATE_FILTER = "now-30d"

#Max results per query (URLScan free = 100, paid = 10000)
PAGE_SIZE = 100

#Output files
RESULTS_FILE = "etherhiding_hits.json"
DOMAINS_FILE = "etherhiding_domains.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

#Specify Etherhiding domains
ETHERHIDING_DOMAINS = [
    "newtdsone.shop",
    "goansgsr.shop"
]

#URLScan API query builder
#Modify this to search across different fields
def build_queries() -> list[dict]:
    queries = []
    for eth_domain in ETHERHIDING_DOMAINS:
        q = (
            f'domain:{eth_domain} AND '
            f'page.domain:*.com.au AND '
            f'date:>{DATE_FILTER}'
        )
        queries.append({
            "label": eth_domain,
            "query": q,
        })
    return queries

#URLScan API call
def search_urlscan(query: str, size: int = PAGE_SIZE) -> list[dict]:
    """
    Run a URLScan search query. Returns list of result items.
    """
    headers = {"API-Key": URLSCAN_API_KEY}
    params = {
        "q": query,
        "size": size,
    }
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params=params,
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("results", [])
        elif resp.status_code == 429:
            log.warning("Rate limited — sleeping 60s")
            time.sleep(60)
            return []
        else:
            log.warning(f" Search failed: {resp.status_code} {resp.text[:150]}")
            return []

    except Exception as e:
        log.error(f" Search error: {e}")
        return []

#Fetches full result from API Call
def fetch_full_result(uuid: str) -> dict | None:
    headers = {"API-Key": URLSCAN_API_KEY}
    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def analyse_hit(result_item: dict, matched_query: str) -> dict:
    #Extract relevant fields from a URLScan search result item.
    page = result_item.get("page", {})
    task = result_item.get("task", {})

    return {
        "domain": page.get("domain", ""),
        "url": page.get("url", ""),
        "scan_date": task.get("time", ""),
        "scan_link": f"https://urlscan.io/result/{task.get('uuid', '')}/",
        "uuid": task.get("uuid", ""),
        "page_title": page.get("title", ""),
        "ip": page.get("ip", ""),
        "server": page.get("server", ""),
        "country": page.get("country", ""),
        "matched_on": matched_query,
        "urlscan_score": result_item.get("verdicts", {}).get("overall", {}).get("score", 0),
        "urlscan_malicious": result_item.get("verdicts", {}).get("overall", {}).get("malicious", False),
        "contacted_eth_domains": [],
    }

def main():
    log.info("=" * 60)
    log.info("EtherHiding Hunter — URLScan Search Mode")
    log.info(f"Looking back: {DATE_FILTER}")
    log.info("=" * 60)

    queries = build_queries()
    log.info(f"Running {len(queries)} queries against URLScan...\n")

    all_hits = {}

    for i, q in enumerate(queries, 1):
        label = q["label"]
        query = q["query"]

        log.info(f"[{i}/{len(queries)}] {label}")
        log.info(f"  Query: {query}")

        results = search_urlscan(query)

        if results:
            log.info(f"  → {len(results)} result(s)")
            for item in results:
                uuid = item.get("task", {}).get("uuid", "")
                if uuid and uuid not in all_hits:
                    hit = analyse_hit(item, label)
                    all_hits[uuid] = hit
                    log.warning(f" {hit['domain']} — {hit['scan_link']}")
        else:
            log.info("  → 0 results")

        #Gotta be friendly.
        time.sleep(1.5)

    log.info("\n" + "=" * 60)
    log.info(f"Total unique suspicious sites found: {len(all_hits)}")

    if all_hits:
        hits_list = list(all_hits.values())

        #Sort by scan date descending
        hits_list.sort(key=lambda x: x["scan_date"], reverse=True)

        #Save results
        with open(RESULTS_FILE, "w") as f:
            json.dump(hits_list, f, indent=2)
        log.info(f"Results saved to {RESULTS_FILE}")

        #Dump domains to a .txt and dedup
        unique_domains = sorted(set(h["domain"] for h in hits_list if h["domain"]))
        with open(DOMAINS_FILE, "w") as f:
            f.write("\n".join(unique_domains) + "\n")
        log.info(f"{len(unique_domains)} unique domains saved to {DOMAINS_FILE}")

        #Print summary table
        log.info("\nSUMMARY:")
        log.info(f"{'Domain':<40} {'Matched On':<35} {'Date':<12}")
        log.info("-" * 90)
        for h in hits_list:
            date_short = h["scan_date"][:10] if h["scan_date"] else "unknown"
            log.info(f"{h['domain']:<40} {h['matched_on']:<35} {date_short}")
    else:
        log.info("No hits found. The date range may be too narrow, or these")
        log.info("sites haven't been submitted to URLScan yet.")
        log.info("\nTip: Try widening DATE_FILTER to 'now-180d' or 'now-1y'")


if __name__ == "__main__":
    main()
