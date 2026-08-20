"""FastAPI API routes for PromptShield."""

import time
from fastapi import APIRouter, HTTPException, status
from app.api.schemas import (
    InspectRequest,
    InspectResponse,
    BatchInspectRequest,
    BatchInspectResponse,
    HealthResponse
)
from app.core.engine import engine
from app.core.config import settings

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Monitoring"])
def health_check():
    """Verify service health and loaded detection subsystems."""
    return HealthResponse(
        status="healthy",
        version=settings.version,
        detectors=["rule_engine", "obfuscation", "ml_semantic"]
    )


@router.post("/inspect", response_model=InspectResponse, status_code=status.HTTP_200_OK, tags=["Inspection"])
def inspect_prompt(request: InspectRequest):
    """
    Inspect a single user prompt for prompt injection or system override attempts.
    Returns calculated risk score, level, gate action, taxonomy labels, and explanations.
    """
    try:
        response = engine.inspect(
            text=request.text,
            context=request.context,
            override_thresholds=request.override_thresholds
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inspection failed: {str(e)}"
        )


@router.post("/batch-inspect", response_model=BatchInspectResponse, status_code=status.HTTP_200_OK, tags=["Inspection"])
def batch_inspect_prompts(batch_req: BatchInspectRequest):
    """
    Inspect a batch of prompts efficiently.
    """
    start_time = time.perf_counter()
    results = []
    allowed = 0
    review = 0
    blocked = 0

    for req in batch_req.prompts:
        res = engine.inspect(
            text=req.text,
            context=req.context,
            override_thresholds=req.override_thresholds
        )
        results.append(res)
        if res.gate_action == "ALLOW":
            allowed += 1
        elif res.gate_action == "REVIEW":
            review += 1
        else:
            blocked += 1

    total_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return BatchInspectResponse(
        total=len(results),
        allowed_count=allowed,
        review_count=review,
        blocked_count=blocked,
        results=results,
        total_latency_ms=total_latency_ms
    )
