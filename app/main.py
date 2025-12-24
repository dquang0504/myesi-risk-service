# app/main.py
import asyncio
from fastapi import FastAPI
from app.workers.kafka_consumer import consume_messages
from app.workers.project_rescan_scheduler import start_project_rescan_scheduler
from app.workers.weekly_reports import start_weekly_report_scheduler
from app.api.v1 import reports, risk, vuln_projects
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="MyESI Risk Service",
    description="Compute risk scores from vuln.processed events",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Start Kafka consumer on app startup."""
    asyncio.create_task(consume_messages())
    asyncio.create_task(start_weekly_report_scheduler())
    asyncio.create_task(start_project_rescan_scheduler())
    print("[Init] Kafka async consumer started ✅")


@app.on_event("shutdown")
async def shutdown_event():
    print("[Shutdown] Cleaning up Risk Service")


# Include routers
app.include_router(risk.router)
app.include_router(reports.router)
app.include_router(vuln_projects.router)


@app.get("/")
async def root():
    return {"message": "MyESI Risk Service is running"}
