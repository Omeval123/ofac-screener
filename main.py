"""
OFAC Crypto Wallet Screener API
--------------------------------
This API automatically downloads the OFAC Specially Designated Nationals (SDN) list,
extracts all cryptocurrency wallet addresses, and lets you check any wallet address
against that list.

Endpoints:
  GET /check?address=YOUR_WALLET   → Check if a wallet is sanctioned
  GET /status                       → See when the list was last updated
  POST /refresh                     → Manually force a list refresh
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import threading
import time
import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="OFAC Crypto Wallet Screener",
    description="Screens crypto wallet addresses against the OFAC SDN sanctions list",
    version="1.0.0",
)

# Allow Bubble (and any browser/app) to call this API from any domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory store for sanctioned addresses
# ---------------------------------------------------------------------------
# Structure: { "wallet_address_lowercase": { "entity": "...", "currency_type": "..." } }
sanctioned_data: dict = {}
last_updated: str | None = None
is_loading: bool = False
load_error: str | None = None

OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
REFRESH_INTERVAL_HOURS = 24

# ---------------------------------------------------------------------------
# Optional API key protection
# Set the API_KEY environment variable on your hosting platform to enable.
# Leave it unset to allow unauthenticated access.
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("API_KEY")


def verify_api_key(x_api_key: str | None) -> None:
    """Raise 401 if an API key is configured and the request doesn't provide it."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid API key. Pass it as the X-Api-Key header.")


# ---------------------------------------------------------------------------
# Core logic: download + parse the OFAC SDN list
# ---------------------------------------------------------------------------

def download_and_parse_ofac() -> None:
    """
    Downloads the OFAC SDN XML file and extracts every Digital Currency Address entry.
    Runs in a background thread so it never blocks API responses.
    """
    global sanctioned_data, last_updated, is_loading, load_error

    if is_loading:
        logger.info("Already loading — skipping duplicate request.")
        return

    is_loading = True
    load_error = None
    logger.info("Downloading OFAC SDN list from %s ...", OFAC_SDN_URL)

    try:
        response = requests.get(OFAC_SDN_URL, timeout=120)
        response.raise_for_status()
        logger.info("Downloaded %s bytes. Parsing XML ...", f"{len(response.content):,}")

        root = ET.fromstring(response.content)

        # Strip XML namespaces so tag searches work regardless of OFAC schema version
        for elem in root.iter():
            if "}" in elem.tag:
                elem.tag = elem.tag.split("}", 1)[1]

        new_data: dict = {}

        for entry in root.iter("sdnEntry"):
            # Build the entity name (person or organisation)
            name_parts = []
            fn = entry.find("firstName")
            ln = entry.find("lastName")
            if fn is not None and fn.text:
                name_parts.append(fn.text.strip())
            if ln is not None and ln.text:
                name_parts.append(ln.text.strip())
            entity_name = " ".join(name_parts) or "Unknown Entity"

            # Look inside <idList> for Digital Currency Address entries
            id_list = entry.find("idList")
            if id_list is None:
                continue

            for id_elem in id_list.findall("id"):
                id_type_elem = id_elem.find("idType")
                id_number_elem = id_elem.find("idNumber")

                if id_type_elem is None or id_number_elem is None:
                    continue

                id_type = id_type_elem.text or ""
                id_number = id_number_elem.text or ""

                # OFAC labels crypto addresses as e.g. "Digital Currency Address - XBT"
                # XBT = Bitcoin, ETH = Ethereum, XMR = Monero, USDT = Tether, etc.
                if "Digital Currency Address" in id_type and id_number.strip():
                    addr = id_number.strip().lower()
                    new_data[addr] = {
                        "entity": entity_name,
                        "currency_type": id_type.strip(),
                    }

        sanctioned_data = new_data
        last_updated = datetime.now(timezone.utc).isoformat()
        logger.info("Loaded %s sanctioned crypto addresses.", f"{len(sanctioned_data):,}")

    except requests.RequestException as exc:
        load_error = f"Download failed: {exc}"
        logger.error(load_error)
    except ET.ParseError as exc:
        load_error = f"XML parse error: {exc}"
        logger.error(load_error)
    except Exception as exc:
        load_error = f"Unexpected error: {exc}"
        logger.error(load_error)
    finally:
        is_loading = False


def background_refresh_loop() -> None:
    """Runs forever in a background thread, refreshing the list every 24 hours."""
    while True:
        download_and_parse_ofac()
        logger.info("Next auto-refresh in %s hours.", REFRESH_INTERVAL_HOURS)
        time.sleep(REFRESH_INTERVAL_HOURS * 3600)


# ---------------------------------------------------------------------------
# Start the background thread when the server boots
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    thread = threading.Thread(target=background_refresh_loop, daemon=True)
    thread.start()
    logger.info("Background OFAC refresh thread started.")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/", summary="API info")
def root():
    """Returns a quick guide to the available endpoints."""
    return {
        "service": "OFAC Crypto Wallet Screener",
        "endpoints": {
            "check a wallet": "GET /check?address=YOUR_WALLET_ADDRESS",
            "view status":    "GET /status",
            "force refresh":  "POST /refresh",
        },
        "note": "Pass X-Api-Key header if you configured an API_KEY environment variable.",
    }


@app.get("/check", summary="Check a wallet address")
def check_wallet(address: str, x_api_key: str = Header(default=None)):
    """
    Check whether a crypto wallet address appears on the OFAC sanctions list.

    - **address**: The wallet address to check (query parameter)
    - Returns `is_sanctioned: true/false` and match details if found
    """
    verify_api_key(x_api_key)

    address = address.strip()
    if not address:
        raise HTTPException(status_code=400, detail="The 'address' query parameter is required.")

    if not sanctioned_data:
        msg = "Sanctions list is still loading — please wait ~1 minute and try again." \
              if is_loading else \
              "Sanctions list has not loaded yet. Please try again shortly."
        raise HTTPException(status_code=503, detail=msg)

    clean = address.lower()
    hit = sanctioned_data.get(clean)

    return {
        "address": address,
        "is_sanctioned": hit is not None,
        # 'match' is null when clean, or shows the entity name + currency type when flagged
        "match": hit,
        "list_last_updated": last_updated,
        "total_addresses_in_list": len(sanctioned_data),
    }


@app.get("/status", summary="View list status")
def status(x_api_key: str = Header(default=None)):
    """Returns how many addresses are loaded and when the list was last refreshed."""
    verify_api_key(x_api_key)
    return {
        "status": "loading" if is_loading else ("ready" if sanctioned_data else "not_loaded"),
        "total_sanctioned_addresses": len(sanctioned_data),
        "last_updated": last_updated,
        "error": load_error,
        "auto_refresh_every_hours": REFRESH_INTERVAL_HOURS,
    }


@app.post("/refresh", summary="Force a list refresh")
def manual_refresh(background_tasks: BackgroundTasks, x_api_key: str = Header(default=None)):
    """Manually triggers a fresh download of the OFAC list (runs in background)."""
    verify_api_key(x_api_key)
    if is_loading:
        return {"message": "Already refreshing. Check /status for progress."}
    background_tasks.add_task(download_and_parse_ofac)
    return {"message": "Refresh started. Check /status in 1-2 minutes."}
