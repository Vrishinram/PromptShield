"""Global configuration and settings for PromptShield."""

import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """PromptShield configuration."""
    # Service settings
    app_name: str = "PromptShield Detector"
    version: str = "1.0.0"
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False

    # Risk Level & Gate Action Thresholds (Configurable via PROMPTSHIELD_LOW_THRESHOLD / PROMPTSHIELD_HIGH_THRESHOLD)
    # Scores < low_threshold -> LOW (ALLOW)
    # Scores between low_threshold and high_threshold -> MEDIUM (REVIEW / FLAG)
    # Scores >= high_threshold -> HIGH (BLOCK)
    low_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    high_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    # Borderline LLM Judge Escalation Settings
    enable_llm_judge_borderline: bool = Field(default=False)
    borderline_min_score: float = Field(default=0.40, ge=0.0, le=1.0)
    borderline_max_score: float = Field(default=0.75, ge=0.0, le=1.0)
    llm_judge_api_key: str = Field(default="")

    # Hybrid Ensemble Weights
    weight_rules: float = Field(default=0.55, ge=0.0, le=1.0)
    weight_ml: float = Field(default=0.45, ge=0.0, le=1.0)
    obfuscation_boost_weight: float = Field(default=0.25, ge=0.0, le=1.0)

    # Floor scores for critical pattern matches to prevent evasion
    high_confidence_rule_floor: float = 0.85
    obfuscated_injection_floor: float = 0.75

    model_config = SettingsConfigDict(
        env_prefix="PROMPTSHIELD_",
        env_file=".env",
        extra="ignore"
    )


settings = Settings()
