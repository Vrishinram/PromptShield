"""FastAPI Application Entrypoint for PromptShield."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Defensive AI Security Middleware for Real-time Prompt Injection and Jailbreak Detection",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for dashboard integration and microservices
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router, prefix="")


@app.get("/", tags=["Root"])
def root_info():
    return {
        "service": settings.app_name,
        "version": settings.version,
        "status": "online",
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "inspect": "/inspect",
            "batch_inspect": "/batch-inspect"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=True)
