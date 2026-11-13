"""Vercel Serverless Function entry point for Riskbyte."""
from __future__ import annotations
import os, sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from riskbyte import config
from riskbyte.service import Service
from riskbyte.api import get_request_handler

# Ensure Vercel serverless environment defaults
os.environ.setdefault("RISKBYTE_DEV_MODE", "1")
if "VERCEL" in os.environ:
    os.environ.setdefault("RISKBYTE_DATA_DIR", "/tmp")

cfg = config.load()
svc = Service(cfg)
svc.start()

H = get_request_handler(svc)

class handler(H):
    """Top-level BaseHTTPRequestHandler for Vercel Python runtime."""
    pass
