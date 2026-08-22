"""
Example FastAPI application using PromptShieldMiddleware to safeguard LLM endpoints.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from app.middleware import PromptShieldMiddleware

app = FastAPI(title="My LLM Application (Protected by PromptShield)")

# Add PromptShield middleware to automatically inspect all incoming POST /chat requests
app.add_middleware(
    PromptShieldMiddleware,
    protected_paths=["/chat", "/v1/chat/completions"],
    block_on_review=False,
)


class ChatRequest(BaseModel):
    prompt: str


@app.post("/chat")
def chat_endpoint(req: ChatRequest):
    # This endpoint is only reached if PromptShield passes the input
    return {
        "reply": f"Safely processed prompt: '{req.prompt}'",
        "status": "success",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
