"""Obfuscation, encoding, and token-smuggling detector."""

from typing import Dict, Any, List
from app.detectors.base import BaseDetector, DetectorResult
from app.utils.text import normalize_leetspeak


class ObfuscationDetector(BaseDetector):
    """
    Detects evasion techniques such as invisible zero-width characters,
    embedded Base64 payloads containing malicious instructions, and leetspeak substitution.
    """

    def __init__(self, rule_detector=None):
        self.name = "obfuscation"
        # We can pass the rule detector to check inside decoded base64 payloads and de-leeted text
        self.rule_detector = rule_detector

    def detect(self, text: str, normalized_text: str, metadata: Dict[str, Any]) -> DetectorResult:
        matched_labels: List[str] = []
        matched_patterns: List[str] = []
        score = 0.0

        # 1. Zero-width unicode token smuggling check
        zw_removed = metadata.get("zero_width_removed", 0)
        if zw_removed >= 3:
            matched_labels.append("zero_width_smuggling")
            matched_patterns.append(f"Detected {zw_removed} zero-width hidden characters")
            score = max(score, 0.85)

        # 2. Base64 payload inspection
        b64_payloads = metadata.get("base64_payloads", [])
        if b64_payloads:
            for encoded, decoded in b64_payloads:
                matched_labels.append("base64_payload")
                matched_patterns.append(f"Base64 string decoded: '{decoded[:40]}...'")
                score = max(score, 0.60)

                # If rule detector is available, check if decoded content triggers rules
                if self.rule_detector:
                    sub_result = self.rule_detector.detect(decoded, decoded.lower(), {})
                    if sub_result.triggered:
                        matched_labels.append("encoded_injection_payload")
                        matched_labels.extend(sub_result.labels)
                        matched_patterns.extend(sub_result.matched_patterns)
                        score = max(score, 0.95)

        # 3. Leetspeak de-obfuscation check
        de_leeted = normalize_leetspeak(normalized_text)
        if de_leeted != normalized_text and self.rule_detector:
            sub_result = self.rule_detector.detect(de_leeted, de_leeted.lower(), {})
            if sub_result.triggered:
                matched_labels.append("leetspeak_obfuscation")
                matched_labels.extend(sub_result.labels)
                matched_patterns.extend([f"Leetspeak resolved: '{de_leeted[:50]}...'"])
                score = max(score, 0.90)

        triggered = score >= 0.35
        description = (
            f"Obfuscation detector identified evasion techniques: {', '.join(sorted(set(matched_labels)))}"
            if triggered
            else "No obfuscation or payload smuggling detected."
        )

        return DetectorResult(
            name=self.name,
            score=round(score, 4),
            triggered=triggered,
            labels=sorted(list(set(matched_labels))),
            matched_patterns=matched_patterns[:5],
            description=description,
            metadata={"zero_width_count": zw_removed, "base64_count": len(b64_payloads)}
        )
