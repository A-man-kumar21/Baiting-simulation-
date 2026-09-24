"""CyberSOC backend — FastAPI application.

SIMULATION SAFETY: this app generates fictional security events and stores
them in a database. It never executes malware, touches real files, scans real
networks, or performs real attacks. Response actions mutate sim_assets rows only.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401  (register models)
from app.api import alerts, auth, events, incidents, misc, scenarios, simulations, users
from app.core.config import get_settings
from app.core.ratelimit import RateLimitMiddleware
from app.db.base import Base
from app.db.session import engine

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables if missing (docker entrypoint / first run). Migrations are
    # out of scope for v1; the schema is created idempotently here.
    Base.metadata.create_all(bind=engine)
    if settings.SEED_DEMO_USERS:
        from app.db.seed import main as seed_main
        try:
            seed_main()
        except Exception:
            pass  # seed is idempotent; never break startup
    yield


app = FastAPI(
    title="CyberSOC API",
    description="Simulation-Based Security Operations Center — training platform. "
                "All attacks, logs, users, IPs and files are simulated.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def secure_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/api/health", tags=["Health"])
def health():
    return {"status": "ok", "service": "cybersoc-api"}


app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(scenarios.router, prefix="/api")
app.include_router(simulations.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(misc.analytics_router, prefix="/api")
app.include_router(misc.mitre_router, prefix="/api")
app.include_router(misc.reports_router, prefix="/api")
app.include_router(misc.ai_router, prefix="/api")
app.include_router(misc.audit_router, prefix="/api")
