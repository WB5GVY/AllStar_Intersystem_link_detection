"""QRZ.com XML API client for callsign-to-email lookup.

Uses the QRZ XML Data Interface (spec 1.17) to look up a callsign
and retrieve the operator's email address. Requires a QRZ XML subscription.

Authentication uses a session key obtained on first call, reused for
subsequent lookups until it expires.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Optional

import requests

logger = logging.getLogger(__name__)

QRZ_API_URL = "https://xmldata.qrz.com/xml/current/"


class QRZLookup:
    """QRZ.com callsign lookup client."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self._session_key: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ASL-LinkDetector/1.0"})

    def _login(self) -> bool:
        """Obtain a session key from QRZ."""
        try:
            resp = self.session.get(QRZ_API_URL, params={
                "username": self.username,
                "password": self.password,
            }, timeout=15)
            resp.raise_for_status()

            root = ET.fromstring(resp.text)
            ns = {"q": "http://xmldata.qrz.com"}

            key_el = root.find(".//q:Key", ns)
            if key_el is not None and key_el.text:
                self._session_key = key_el.text
                logger.info("QRZ session key obtained")
                return True

            # Check for error
            error_el = root.find(".//q:Error", ns)
            if error_el is not None:
                logger.error(f"QRZ login error: {error_el.text}")
            else:
                logger.error("QRZ login failed: no session key in response")
            return False

        except Exception as e:
            logger.error(f"QRZ login failed: {e}")
            return False

    def lookup(self, callsign: str) -> Optional[dict]:
        """Look up a callsign and return operator info.

        Returns a dict with keys: callsign, email, fname, name, addr1, addr2,
        state, zip, country, or None on failure.
        """
        # Ensure we have a session key
        if not self._session_key:
            if not self._login():
                return None

        result = self._do_lookup(callsign)
        if result is None:
            # Session key may have expired — retry with fresh login
            logger.info("Retrying QRZ lookup with fresh session key...")
            if self._login():
                result = self._do_lookup(callsign)
        return result

    def _do_lookup(self, callsign: str) -> Optional[dict]:
        """Execute a callsign lookup with the current session key."""
        try:
            resp = self.session.get(QRZ_API_URL, params={
                "s": self._session_key,
                "callsign": callsign,
            }, timeout=15)
            resp.raise_for_status()

            root = ET.fromstring(resp.text)
            ns = {"q": "http://xmldata.qrz.com"}

            # Check for error (e.g., session expired, not found)
            error_el = root.find(".//q:Error", ns)
            if error_el is not None:
                error_text = error_el.text or ""
                if "Session Timeout" in error_text or "Invalid session" in error_text:
                    self._session_key = None
                    return None  # Caller will retry
                logger.warning(f"QRZ lookup for {callsign}: {error_text}")
                return None

            # Extract fields from Callsign record
            rec = root.find(".//q:Callsign", ns)
            if rec is None:
                logger.warning(f"QRZ: no record found for {callsign}")
                return None

            def field(name):
                el = rec.find(f"q:{name}", ns)
                return el.text.strip() if el is not None and el.text else ""

            result = {
                "callsign": field("call"),
                "email": field("email"),
                "fname": field("fname"),
                "name": field("name"),
                "addr1": field("addr1"),
                "addr2": field("addr2"),
                "state": field("state"),
                "zip": field("zip"),
                "country": field("country"),
            }

            if result["email"]:
                logger.info(f"QRZ: {callsign} → {result['fname']} {result['name']}, email on file")
            else:
                logger.info(f"QRZ: {callsign} → {result['fname']} {result['name']}, no email on file")

            return result

        except ET.ParseError as e:
            logger.error(f"QRZ XML parse error for {callsign}: {e}")
            return None
        except Exception as e:
            logger.error(f"QRZ lookup error for {callsign}: {e}")
            return None

    def close(self):
        self.session.close()
