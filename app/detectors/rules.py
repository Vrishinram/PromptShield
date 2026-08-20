"""Rule-based pattern matching and heuristic detector."""

import re
from typing import Dict, Any, List, Tuple
from app.detectors.base import BaseDetector, DetectorResult


class RuleEngineDetector(BaseDetector):
    """
    Evaluates input text against known prompt injection, jailbreak,
    delimiter hijacking, and system exfiltration heuristics.
    """

    def __init__(self):
        self.name = "rule_engine"
        self._init_rules()

    def _init_rules(self):
        # High-severity direct instruction overrides
        self.override_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|initial|system|earlier|above)?\s*(?:safety\s+)?(?:instructions|prompts?|rules|commands?|directives?|guidelines?|constraints?)\b", re.IGNORECASE),
                "instruction_override",
                0.95
            ),
            (
                re.compile(r"\b(?:you\s+are\s+now\s+free\s+from\s+all\s+(?:constraints|rules|limitations|restrictions|boundaries))\b", re.IGNORECASE),
                "instruction_override",
                0.92
            ),
            (
                re.compile(r"\bfrom\s+now\s+on(?:,\s*|\s+)(?:you\s+(?:must|will|shall)\s+(?:only\s+)?(?:obey|follow|listen\s+to)\s+me|you\s+will\s+obey\s+only\s+me|you\s+are\s+free\s+from\s+all\s+constraints)\b", re.IGNORECASE),
                "instruction_override",
                0.92
            ),
            (
                re.compile(r"\bdisregard\s+(?:the\s+above\s+prompt\s+and\s+system\s+message|everything\s+above)\b", re.IGNORECASE),
                "instruction_override",
                0.92
            ),
            (
                re.compile(r"\bstop\s+(?:following|operating\s+as|being)\s+(?:system\s+rules|an?\s+assistant|your\s+initial\s+programming)\b", re.IGNORECASE),
                "instruction_override",
                0.88
            ),
            (
                re.compile(r"\b(?:new\s+directive|new\s+task|system_compromised)(?:\s*[:.]|\s+from\s+root)\b", re.IGNORECASE),
                "instruction_override",
                0.85
            ),
        ]

        # Jailbreaks and persona hijacks
        self.jailbreak_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"\b(?:act\s+as|you\s+are(?:\s+now)?)\s+(?:DAN|AIM|CHAOS-BOT)\b", re.IGNORECASE),
                "role_switch",
                0.95
            ),
            (
                re.compile(r"\bdeveloper\s+mode\s+(?:enabled|activated|allows\s+you\s+to\s+bypass)\b", re.IGNORECASE),
                "role_switch",
                0.95
            ),
            (
                re.compile(r"\b(?:act\s+as|simulate|pretend\s+you\s+are|you\s+are(?:\s+now)?)\s+an?\s+(?:unfiltered|uncensored|amoral|unrestricted)\s+(?:ai|assistant|model|bot)\b", re.IGNORECASE),
                "role_switch",
                0.92
            ),
            (
                re.compile(r"\b(?:amoral|unrestricted|unfiltered)\s+(?:ai|assistant|model|bot)\s+(?:that\s+answers\s+every\s+request|without\s+(?:hesitation|ethical\s+filters|limitations))\b", re.IGNORECASE),
                "role_switch",
                0.92
            ),
            (
                re.compile(r"\bpretend\s+you\s+have\s+no\s+(?:safety|ethical)\s+(?:filters|guardrails|boundaries|policies)\b", re.IGNORECASE),
                "role_switch",
                0.90
            ),
        ]

        # Delimiter breakouts and system spoofing
        self.delimiter_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"<\s*/?\s*(?:system|system_override|user_override|admin|root_instruction)\s*>", re.IGNORECASE),
                "delimiter_hijack",
                0.95
            ),
            (
                re.compile(r"\[\s*SYSTEM\s+(?:INSTRUCTION|NOTE|ALERT|UPDATE|PROMPT)\s*:?[^\]]*\]", re.IGNORECASE),
                "delimiter_hijack",
                0.92
            ),
            (
                re.compile(r"(?:===|---|###)\s*END\s+OF\s+SYSTEM\s+(?:PROMPT|INSTRUCTIONS?)\s*(?:===|---|###)", re.IGNORECASE),
                "delimiter_hijack",
                0.95
            ),
            (
                re.compile(r"```(?:markdown|json|xml)?\s*\n\s*(?:##\s*SYSTEM\s+UPDATE|SYSTEM\s*:\s*OVERRIDE)", re.IGNORECASE),
                "delimiter_hijack",
                0.90
            ),
        ]

        # System prompt exfiltration & memory dumps
        self.leak_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"\b(?:output|print|reveal|show|dump|repeat|state)\s+(?:your\s+)?(?:complete\s+|exact\s+|initial\s+|entire\s+)?(?:system\s+prompt|system\s+instructions?|internal\s+prompt|developer\s+guidelines?|secret\s+(?:api\s+)?key)\s+(?:verbatim|word\s+for\s+word|from\s+the\s+beginning)?\b", re.IGNORECASE),
                "system_leak",
                0.95
            ),
            (
                re.compile(r"\bwhat\s+were\s+the\s+exact\s+words\s+given\s+to\s+you\s+in\s+(?:your\s+)?system\s+prompt\b", re.IGNORECASE),
                "system_leak",
                0.92
            ),
            (
                re.compile(r"\brepeat\s+everything\s+from\s+the\s+start\s+of\s+this\s+conversation\s+including\s+the\s+initial\s+system\s+instructions\b", re.IGNORECASE),
                "system_leak",
                0.95
            ),
            (
                re.compile(r"\b(?:tell\s+me|reveal)\s+your\s+internal\s+model\s+name,\s*system\s+prompt,\s*and\s*temperature\b", re.IGNORECASE),
                "system_leak",
                0.90
            ),
        ]

        # Hypothetical / Fictional policy bypass framing
        self.policy_bypass_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"\b(?:in\s+a\s+fictional\s+universe|assume\s+a\s+world)\s+where\s+safety\s+policies\s+are\s+(?:illegal|disabled|ignored)\b", re.IGNORECASE),
                "policy_bypass",
                0.88
            ),
            (
                re.compile(r"\bfor\s+educational\s+purposes\s+(?:in\s+an?\s+ai\s+safety\s+class\s*,\s*)?pretend\s+you\s+have\s+no\s+safety\s+filters\b", re.IGNORECASE),
                "policy_bypass",
                0.88
            ),
            (
                re.compile(r"\bplaying\s+a\s+game\s+where\s+you\s+must\s+ignore\s+all\s+safety\s+guidelines\b", re.IGNORECASE),
                "policy_bypass",
                0.90
            ),
        ]

        # Borderline / Educational / Inquiry patterns that warrant review (0.35 - 0.70 score)
        self.borderline_review_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"\b(?:why\s+do\s+some\s+users\s+try\s+to\s+trick\s+llms\s+with|what\s+are\s+jailbreaks\s+like)\s+['\"`]?\s*(?:DAN|Developer\s+Mode)", re.IGNORECASE),
                "borderline_jailbreak_inquiry",
                0.65
            ),
            (
                re.compile(r"\b(?:imagine\s+a\s+hypothetical\s+ai\s+without\s+any\s+guardrails|how\s+would\s+an\s+unguarded\s+model\s+differ)\b", re.IGNORECASE),
                "borderline_safety_inquiry",
                0.60
            ),
        ]

        # Quoted translation check (to mitigate false positives on 'translate "Ignore all previous commands"')
        self.translation_wrapper_pattern = re.compile(
            r"\b(?:translate|translation|how\s+do\s+you\s+say|what\s+does)\b.*['\"`].*['\"`]",
            re.IGNORECASE
        )

    def detect(self, text: str, normalized_text: str, metadata: Dict[str, Any]) -> DetectorResult:
        all_rules = (
            self.override_patterns
            + self.jailbreak_patterns
            + self.delimiter_patterns
            + self.leak_patterns
            + self.policy_bypass_patterns
            + self.borderline_review_patterns
        )

        matched_labels: set[str] = set()
        matched_triggers: List[str] = []
        max_score = 0.0

        # Run checks on normalized text
        for pattern, label, weight in all_rules:
            matches = pattern.findall(normalized_text)
            if matches:
                matched_labels.add(label)
                for m in matches:
                    matched_triggers.append(str(m) if isinstance(m, str) else m[0] if isinstance(m, tuple) else pattern.pattern)
                max_score = max(max_score, weight)

        # Contextual check: Translation or benign meta-query with quoted text
        is_quoted_translation = bool(self.translation_wrapper_pattern.search(text))
        if is_quoted_translation and max_score > 0:
            # Downgrade score to borderline/review level (e.g. 0.50) instead of outright block
            max_score = min(max_score, 0.50)
            matched_labels.add("quoted_suspicious_payload")

        triggered = max_score >= 0.40

        description = (
            f"Rule engine identified {len(matched_triggers)} indicator(s): {', '.join(sorted(matched_labels))}"
            if triggered
            else "No explicit rule-based injection signatures triggered."
        )

        return DetectorResult(
            name=self.name,
            score=round(max_score, 4),
            triggered=triggered,
            labels=sorted(list(matched_labels)),
            matched_patterns=matched_triggers[:5],
            description=description,
            metadata={"match_count": len(matched_triggers), "quoted_translation": is_quoted_translation}
        )
