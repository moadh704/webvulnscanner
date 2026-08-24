#!/usr/bin/env python
"""RED-GREEN tests for AI remediation call counting and capping."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from core.ai_provider import AIEnhancer


class _FakeProvider:
    """Provider that just counts calls without touching any API."""

    def __init__(self):
        self.review_calls = 0
        self.remed_calls  = 0

    def review_finding(self, prompt: str, max_tokens: int = 500) -> str:
        self.review_calls += 1
        # Return PONG for preflight; empty for real reviews so the enhancer
        # falls back to per-item review when needed.
        if "PONG" in prompt.upper():
            return "PONG"
        return ""

    def generate_remediation(self, prompt: str, max_tokens: int = 500) -> str:
        self.remed_calls += 1
        return f"REMED-{self.remed_calls} - Use prepared statements to fix this vulnerability. See OWASP guidelines."


def _make_type1_finding(idx: int) -> dict:
    return {
        'type'            : 'sqli',
        'owasp'           : 'A05:2025 - Injection',
        'url'             : f'/page{idx}',
        'parameter'       : 'id',
        'finding_type'    : 1,
        'confidence'      : 0.8,
        'severity'        : 'High',
        'evidence_static' : 'static',
        'evidence_dynamic': 'dynamic',
    }


def _enhancer_with_fake() -> AIEnhancer:
    """Build an enhancer with a fake provider and an empty cache."""
    config.AI_PROVIDER = "none"
    config.AI_REMEDIATION = True
    config.AI_MAX_FINDINGS = 0
    config.AI_MAX_REMEDIATIONS = 0
    config.TARGET_URL = "http://localhost/"

    enhancer = AIEnhancer()
    enhancer.provider = _FakeProvider()
    enhancer.cache = {}
    enhancer._save_cache = lambda: None  # don't touch filesystem
    return enhancer


def test_calls_made_counts_remediation_calls():
    """Every remediation call must increment the printed calls_made counter."""
    enhancer = _enhancer_with_fake()
    findings = [_make_type1_finding(0), _make_type1_finding(1)]

    result = enhancer.enhance(findings)

    # Type 1 findings are not reviewed, only remediated.
    # calls_made includes 1 preflight check + 2 remediation calls.
    assert enhancer.provider.remed_calls == 2
    assert enhancer.calls_made == 3, (
        f"calls_made should be 3 (preflight + 2 remediations), got {enhancer.calls_made}"
    )
    assert all('REMED-' in f.get('remediation', '') for f in result)


def test_ai_max_remediations_caps_remediation_calls():
    """AI_MAX_REMEDIATIONS limits how many findings get AI remediation."""
    enhancer = _enhancer_with_fake()
    config.AI_MAX_REMEDIATIONS = 1
    findings = [_make_type1_finding(0), _make_type1_finding(1)]

    result = enhancer.enhance(findings)

    assert enhancer.provider.remed_calls == 1, (
        f"expected 1 remediation call, got {enhancer.provider.remed_calls}"
    )
    assert enhancer.calls_made == 2, (
        f"expected calls_made == 2 (preflight + 1 remediation), got {enhancer.calls_made}"
    )
    remediated = [f for f in result
                  if f.get('remediation', '').startswith('REMED-')]
    assert len(remediated) == 1, (
        f"expected 1 AI remediation, got {len(remediated)}"
    )
    # The other finding should still get the default OWASP remediation.
    default = [f for f in result
               if f.get('remediation', '').startswith('Use prepared')]
    assert len(default) == 1


if __name__ == '__main__':
    test_calls_made_counts_remediation_calls()
    test_ai_max_remediations_caps_remediation_calls()
    print('ALL PASS')
