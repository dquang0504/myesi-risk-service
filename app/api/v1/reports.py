import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import session as db_session
from app.services.report_generator import (
    generate_compliance_report,
)
from fastapi.responses import FileResponse
from app.schemas.report import (
    ComplianceRequest,
)


router = APIRouter(prefix="/api/reports", tags=["Reports"])


# ===== COMPLIANCE REPORT =====
@router.post("/compliance")
async def get_compliance_report(
    payload: ComplianceRequest,
    db: Session = Depends(db_session.get_db),
):
    """
    Receive payload from frontend (project_id, project_name, user_id),
    create report compliance and return PDF file.
    """
    try:
        report_path, report_record = await generate_compliance_report(
            db=db,
            project_name=payload.project_name,
            user_id=payload.user_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    if not report_path or not os.path.exists(report_path):
        raise HTTPException(
            status_code=500, detail="Failed to generate compliance report file"
        )

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=f"{payload.project_name}_compliance.pdf",
    )


# ===== VULNERABILITY SUMMARY REPORT =====
# @router.get("/vuln-summary" ,response_model=VulnSummaryResponse)
# async def get_vuln_summary(
#     payload: VulnSummaryRequest,
#     db: Session = Depends(db_session.get_db)
# ):
#     """
#     Receive payload JSON from frontend, create a summarized report on vulnerabilities (vulnerability summary)
#     and return a JSON of the response model.
#     """
#     summary_data = generate_vuln_summary_report(
#         db=db,
#         project_id=payload.project_id,
#         project_name=payload.project_name,
#         user_id=payload.user_id
#     )

#     return summary_data
