"""
Vercel Serverless Function entrypoint for AgentBreak FastAPI backend.
"""

import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app  # noqa: E402, F401
