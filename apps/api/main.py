"""
Audit Bench API — Main FastAPI Application Entrypoint.
Coordinates security gate orchestration, finding ingestion, policy enforcement,
and GitHub App webhooks.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from apps.api.config import get_settings
from apps.api.routes.health import router as health_router
from apps.api.routes.repositories import router as repositories_router
from apps.api.routes.scans import router as scans_router
from apps.api.routes.findings import router as findings_router
from apps.api.routes.policies import router as policies_router
from apps.api.routes.github import router as github_router
from apps.api.routes.sandbox import router as sandbox_router
from database.session import init_db, SessionLocal
from database.seed import seed_database

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize tables and seed data
    init_db()
    with SessionLocal() as db:
        seed_database(db)
    yield
    # Shutdown logic if needed


app = FastAPI(
    title="Audit Bench DevSecOps Security Platform",
    description=(
        "Production-grade security orchestration and merge-gate platform. "
        "Audits code for OWASP Top 10 vulnerabilities, evaluates risk policies, "
        "publishes GitHub Check Runs, and tracks finding lifecycle."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": str(exc),
            }
        },
    )

# Include Routers under versioned API prefix
prefix = settings.api_v1_prefix
app.include_router(health_router, prefix=prefix, tags=["health"])
app.include_router(repositories_router, prefix=prefix, tags=["repositories"])
app.include_router(scans_router, prefix=prefix, tags=["scans"])
app.include_router(findings_router, prefix=prefix, tags=["findings"])
app.include_router(policies_router, prefix=prefix, tags=["policies"])
app.include_router(github_router, prefix=prefix, tags=["github"])
app.include_router(sandbox_router, prefix=prefix, tags=["sandbox"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("apps.api.main:app", host="0.0.0.0", port=settings.port, reload=True)
