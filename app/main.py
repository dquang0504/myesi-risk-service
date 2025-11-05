from fastapi import FastAPI
from app.api.v1 import risk, reports

app = FastAPI(
    title="MyESI Risk Service",
    description="Service for computing component risk scores from SBOM + Vulnerability data",
    version="1.0.0",
)

# Include router
app.include_router(risk.router)
app.include_router(reports.router)


# Root test
@app.get("/")
async def root():
    return {"message": "MyESI Risk Service is running"}
