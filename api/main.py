from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.core.config import settings
from api.core.database import engine, Base
from api.models import Account, Finding, Scan

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Multi-cloud security scanner with posture telemetry"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/")
def root():
    return {
        "message" : "CloudSecure API 2.0",
        "docs" : "/docs",
        "health" : "/health"
    }

@app.get("/health")
def health():
    return {
        "status" : "healthy",
        "version" : settings.VERSION
    }


