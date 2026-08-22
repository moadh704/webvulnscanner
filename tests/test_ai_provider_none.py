#!/usr/bin/env python
"""RED-GREEN test for AI_PROVIDER=None crash."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from core.ai_provider import get_provider, AIEnhancer, NoAIProvider


def test_none_provider_falls_back_to_noai():
    """AI_PROVIDER=None must disable AI cleanly instead of crashing on
    `.lower()`."""
    config.AI_PROVIDER = None
    provider = get_provider()
    assert isinstance(provider, NoAIProvider), (
        f"Expected NoAIProvider for AI_PROVIDER=None, got {type(provider)}"
    )


def test_enhancer_with_none_provider_uses_defaults():
    """AIEnhancer must not crash when AI_PROVIDER is None; it should
    assign default remediation text and skip all API calls."""
    config.AI_PROVIDER = None
    config.AI_REMEDIATION = True
    config.AI_MAX_FINDINGS = 0
    config.AI_MAX_REMEDIATIONS = 0
    config.TARGET_URL = "http://localhost/"

    enhancer = AIEnhancer()
    findings = [{
        'type'            : 'sqli',
        'owasp'           : 'A05:2025 - Injection',
        'url'             : '/x',
        'parameter'       : 'id',
        'finding_type'    : 3,
        'confidence'      : 0.7,
        'severity'        : 'High',
        'evidence_static' : '',
        'evidence_dynamic': 'error',
    }]
    result = enhancer.enhance(findings)

    assert result[0].get('remediation') is not None
    assert enhancer.calls_made == 0, (
        f"Expected 0 API calls with AI_PROVIDER=None, "
        f"got {enhancer.calls_made}"
    )


if __name__ == '__main__':
    test_none_provider_falls_back_to_noai()
    test_enhancer_with_none_provider_uses_defaults()
    print('ALL PASS')
