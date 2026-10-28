"""
FastAPI + MongoDB Atlas backend for AgentBreak.

Run with:
    python main.py
Or from the repository root:
    python backend/main.py
"""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.errors import ConfigurationError, OperationFailure, PyMongoError

# Ensure backend directory is on sys.path whether run from root or backend/
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from mvp_demo import router as demo_router
from app import storage
from app import platform_store
from app.real_scan import router as real_scan_router
from app.platform_api import router as platform_router
from app.nlp_api import router as nlp_router

# Load environment variables from backend/.env or root .env
load_dotenv(dotenv_path=current_dir / ".env")
load_dotenv(dotenv_path=current_dir.parent / ".env")

MONGODB_URI = os.getenv("MONGODB_URI", "")
DB_NAME = os.getenv("DB_NAME", "AgentBreak")
PORT = int(os.getenv("PORT", "8000"))
CORS_ORIGINS_RAW = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
)
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS_RAW.split(",") if origin.strip()]

client: MongoClient | None = None


def connect() -> MongoClient:
    """Create the client and ping the cluster. Raises if it can't connect."""
    if not MONGODB_URI or "<" in MONGODB_URI or "PASTE" in MONGODB_URI:
        raise RuntimeError("MONGODB_URI is missing or still has placeholders. Check your .env file.")
    c = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=8000)
    c.admin.command("ping")
    return c


def explain(err: Exception) -> str:
    """Turn a connection error into a hint about what to fix."""
    text = str(err)
    if isinstance(err, OperationFailure) or "Authentication failed" in text:
        return "Wrong username or password (URL-encode special characters in the password)."
    if isinstance(err, ConfigurationError) or "DNS" in text:
        return "Cluster address in MONGODB_URI looks wrong, or DNS is blocked on this network."
    if "timed out" in text or "ServerSelectionTimeoutError" in type(err).__name__:
        return "Timed out. Your IP is probably not allowed: check Atlas Network Access (whitelist IP)."
    return text


def ensure_initialized():
    global client
    if client is None:
        client = connect()
        storage.init(client, DB_NAME)
        platform_store.init(client, DB_NAME)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Best-effort DB init; the NLP engine and docs work even without MongoDB.
    try:
        ensure_initialized()
    except Exception as exc:  # noqa: BLE001
        print(f"[startup] MongoDB not initialised yet: {explain(exc)}")
    yield
    if client is not None:
        client.close()


app = FastAPI(title="AgentBreak Backend API", version="1.0.0", lifespan=lifespan)

# Paths that must work without a database connection (NLP engine, health, docs).
_DB_OPTIONAL_PREFIXES = ("/api/nlp", "/health", "/docs", "/openapi.json", "/redoc", "/")


@app.middleware("http")
async def _init_db_middleware(request, call_next):
    path = request.url.path
    needs_db = not any(path == p or path.startswith(p + "/") for p in _DB_OPTIONAL_PREFIXES if p != "/")
    if needs_db and path != "/":
        try:
            ensure_initialized()
        except Exception as exc:  # noqa: BLE001
            from fastapi.responses import JSONResponse

            return JSONResponse(status_code=503, content={"detail": explain(exc)})
    return await call_next(request)


app.include_router(demo_router)
app.include_router(real_scan_router)
app.include_router(platform_router)
app.include_router(nlp_router)

# Enable CORS so frontend can make API calls without being blocked
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "status": "running",
        "service": "AgentBreak API",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    """Pings the cluster and reports database connection status."""
    try:
        client.admin.command("ping")
        return {
            "connected": True,
            "database": DB_NAME,
            "collections_in_db": client[DB_NAME].list_collection_names(),
            "run_count": client[DB_NAME][storage.RUNS].count_documents({}),
        }
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=explain(e))


@app.get("/runs")
def list_runs(limit: int = 20):
    """Most recent scan runs (summaries only), newest first."""
    try:
        return storage.list_runs(limit)
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=explain(e))


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    """One scan run with its full execution trace."""
    try:
        run = storage.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        run["events"] = storage.get_trace(run_id)
        return run
    except PyMongoError as e:
        raise HTTPException(status_code=503, detail=explain(e))


if __name__ == "__main__":
    print("Testing MongoDB connection...")
    try:
        test = connect()
        print(f"SUCCESS: connected. Database '{DB_NAME}'.")
        test.close()
    except Exception as e:
        print(f"FAILED: {explain(e)}")
        sys.exit(1)

    print(f"Starting API at http://127.0.0.1:{PORT} (docs at http://127.0.0.1:{PORT}/docs)")
    uvicorn.run("main:app", host="127.0.0.1", port=PORT, reload=True, app_dir=str(current_dir))