"""
Root launcher for AgentBreak FastAPI backend.
Delegates to backend/main.py.
"""

from pathlib import Path
import runpy

if __name__ == "__main__":
    backend_main = Path(__file__).resolve().parent / "backend" / "main.py"
    runpy.run_path(str(backend_main), run_name="__main__")
