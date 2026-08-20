"""Hybrid Detection Engine and Risk Model Aggregator."""

import time
from typing import Dict, Any, List, Optional
from app.core.config import settings
from app.detectors.rules import RuleEngineDetector
from app.detectors.obfuscation import ObfuscationDetector
from app.detectors.ml_classifier import MLSemanticDetector
from app.utils.text import clean_text_for_inspection
from app.api.schemas import InspectResponse, SignalDetail, RiskLevel, GateAction


class PromptShieldEngine:
    """
    Central hybrid detection pipeline orchestrating rule heuristics,
    obfuscation scanners, and ML semantic similarity classifiers.
    """

    def __init__(self):
        self.rule_detector = RuleEngineDetector()
        self.obfuscation_detector = ObfuscationDetector(rule_detector=self.rule_detector)
        self.ml_detector = MLSemanticDetector()

    def inspect(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        override_thresholds: Optional[Dict[str, float]] = None
    ) -> InspectResponse:
        start_time = time.perf_counter()

        # 1. Text normalization & feature extraction
        normalized_text, text_meta = clean_text_for_inspection(text)
        meta = {**(context or {}), **text_meta}

        # 2. Run detectors
        rule_res = self.rule_detector.detect(text, normalized_text, meta)
        obfuscation_res = self.obfuscation_detector.detect(text, normalized_text, meta)
        ml_res = self.ml_detector.detect(text, normalized_text, meta)

        # 3. Score aggregation
        w_rule = settings.weight_rules
        w_ml = settings.weight_ml

        # Weighted combination
        raw_combined = (w_rule * rule_res.score) + (w_ml * ml_res.score)

        # Apply obfuscation boost if evasion techniques detected
        if obfuscation_res.triggered:
            raw_combined += (obfuscation_res.score * settings.obfuscation_boost_weight)

        # Apply safety floors for high-confidence indicators
        if rule_res.score >= 0.85:
            raw_combined = max(raw_combined, settings.high_confidence_rule_floor)
        if obfuscation_res.score >= 0.85:
            raw_combined = max(raw_combined, settings.obfuscated_injection_floor)

        final_score = round(min(1.0, max(0.0, raw_combined)), 4)

        # 4. Determine thresholds & Gate Action
        low_th = (
            override_thresholds.get("low_threshold", settings.low_threshold)
            if override_thresholds
            else settings.low_threshold
        )
        high_th = (
            override_thresholds.get("high_threshold", settings.high_threshold)
            if override_thresholds
            else settings.high_threshold
        )

        if final_score < low_th:
            risk_level: RiskLevel = "LOW"
            gate_action: GateAction = "ALLOW"
        elif final_score < high_th:
            risk_level: RiskLevel = "MEDIUM"
            gate_action: GateAction = "REVIEW"
        else:
            risk_level: RiskLevel = "HIGH"
            gate_action: GateAction = "BLOCK"

        # 5. Aggregate labels
        all_labels = set(rule_res.labels + obfuscation_res.labels + ml_res.labels)

        # 6. Build signal details
        signals = {
            "rule_engine": rule_res.score,
            "ml_semantic": ml_res.score,
            "obfuscation": obfuscation_res.score,
        }

        signal_details = [
            SignalDetail(
                name="rule_engine",
                score=rule_res.score,
                weight=w_rule,
                triggered=rule_res.triggered,
                matched_patterns=rule_res.matched_patterns,
                description=rule_res.description,
            ),
            SignalDetail(
                name="ml_semantic",
                score=ml_res.score,
                weight=w_ml,
                triggered=ml_res.triggered,
                matched_patterns=ml_res.matched_patterns,
                description=ml_res.description,
            ),
            SignalDetail(
                name="obfuscation",
                score=obfuscation_res.score,
                weight=settings.obfuscation_boost_weight,
                triggered=obfuscation_res.triggered,
                matched_patterns=obfuscation_res.matched_patterns,
                description=obfuscation_res.description,
            ),
        ]

        # 7. Generate diagnostic explanation
        explanation = self._generate_explanation(
            risk_level=risk_level,
            gate_action=gate_action,
            final_score=final_score,
            labels=sorted(list(all_labels)),
            rule_res=rule_res,
            obfuscation_res=obfuscation_res,
            ml_res=ml_res,
        )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return InspectResponse(
            text=text if len(text) <= 500 else text[:497] + "...",
            risk_score=final_score,
            risk_level=risk_level,
            gate_action=gate_action,
            labels=sorted(list(all_labels)),
            signals=signals,
            signal_details=signal_details,
            explanation=explanation,
            latency_ms=elapsed_ms,
        )

    def _generate_explanation(
        self,
        risk_level: RiskLevel,
        gate_action: GateAction,
        final_score: float,
        labels: List[str],
        rule_res: Any,
        obfuscation_res: Any,
        ml_res: Any,
    ) -> str:
        if risk_level == "LOW":
            return f"Prompt verified clean (Risk: {final_score:.2f}). No adversarial patterns or malicious intent detected."

        primary_reasons = []
        if rule_res.triggered:
            primary_reasons.append(f"rule triggers ({', '.join(rule_res.labels)})")
        if obfuscation_res.triggered:
            primary_reasons.append(f"evasion/obfuscation techniques ({', '.join(obfuscation_res.labels)})")
        if ml_res.triggered:
            primary_reasons.append(f"semantic vector similarity to known injection attacks")

        reasons_str = "; ".join(primary_reasons) if primary_reasons else "elevated risk heuristics"

        if risk_level == "HIGH":
            return f"High-risk prompt injection detected (Risk: {final_score:.2f} | Action: {gate_action}). Identified: {reasons_str}."
        else:
            return f"Borderline / ambiguous input detected (Risk: {final_score:.2f} | Action: {gate_action}). Flagged: {reasons_str}."


# Singleton instance for application lifecycle
engine = PromptShieldEngine()
