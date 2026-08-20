"""Global configuration and settings for PromptShield."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """PromptShield configuration."""
    # Service settings
    app_name: str = "PromptShield Detector"
    version: str = "1.0.0"
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False

    # Risk Level Thresholds
    # Scores < low_threshold -> LOW (ALLOW)
    # Scores between low_threshold and high_threshold -> MEDIUM (REVIEW)
    # Scores >= high_threshold -> HIGH (BLOCK)
    low_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    high_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    # Hybrid Ensemble Weights (normalized in engine if needed)
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

