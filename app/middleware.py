"""
PromptShield FastAPI Middleware
Drop-in middleware to protect any FastAPI application from prompt injection,
jailbreak attempts, and system override payloads before requests reach LLM handlers.
"""

import json
from typing import Callable, Optional, List
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.engine import engine, EngineResponse


class PromptShieldMiddleware(BaseHTTPMiddleware):
    """
    Middleware that intercepts incoming JSON requests containing user prompts,
    evaluates them against PromptShield's multi-tier detection engine, and blocks
    malicious payloads (HTTP 403 Forbidden).
    """

    def __init__(
        self,
        app,
        protected_paths: Optional[List[str]] = None,
        prompt_keys: Optional[List[str]] = None,
        block_on_review: bool = False,
    ):
        super().__init__(app)
        self.protected_paths = protected_paths or ["/chat", "/v1/chat/completions", "/generate", "/query"]
        self.prompt_keys = prompt_keys or ["prompt", "query", "message", "input", "text"]
        self.block_on_review = block_on_review

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method == "POST" and any(request.url.path.startswith(p) for p in self.protected_paths):
            try:
                body_bytes = await request.body()
                if body_bytes:
                    data = json.loads(body_bytes)
                    prompt_text = self._extract_prompt(data)
                    if prompt_text:
                        result: EngineResponse = engine.inspect(prompt_text)
                        
                        is_blocked = (result.gate_action == "BLOCK") or (
                            self.block_on_review and result.gate_action == "REVIEW"
                        )
                        
                        if is_blocked:
                            return JSONResponse(
                                status_code=status.HTTP_403_FORBIDDEN,
                                content={
                                    "error": "Prompt Security Violation",
                                    "message": "The submitted input was blocked by PromptShield.",
                                    "risk_level": result.risk_level,
                                    "risk_score": result.risk_score,
                                    "labels": result.labels,
                                    "request_id": result.request_id,
                                },
                            )
            except Exception:
                # If body parsing fails or format is not JSON, allow request through to standard validation
                pass

        return await call_next(request)

    def _extract_prompt(self, data: dict) -> Optional[str]:
        if isinstance(data, dict):
            for key in self.prompt_keys:
                if key in data and isinstance(data[key], str):
                    return data[key]
            # Check OpenAI messages format
            if "messages" in data and isinstance(data["messages"], list):
                user_msgs = [m.get("content", "") for m in data["messages"] if m.get("role") == "user"]
                if user_msgs:
                    return user_msgs[-1]
        return None
