# ── core/ai_provider.py ──────────────────────────────────────────────────────

import config


# ── Base interface ────────────────────────────────────────────────────────────

class AIProvider:
    """
    Base interface — all providers implement these two methods.
    Following the Strategy Pattern: swap providers via config.AI_PROVIDER.
    """

    def review_finding(self, prompt: str) -> str:
        raise NotImplementedError

    def generate_remediation(self, prompt: str) -> str:
        raise NotImplementedError


# ── Gemini Provider (default) ─────────────────────────────────────────────────

class GeminiProvider(AIProvider):
    """Default — Google Gemini 2.0 Flash (free tier at aistudio.google.com)."""

    def __init__(self):
        try:
            from google import genai
            self.client = genai.Client(api_key=config.GEMINI_API_KEY)
            self.model  = "gemini-flash-latest"
        except Exception as e:
            raise RuntimeError(f"Gemini init failed: {e}. "
                               f"Check GEMINI_API_KEY in config.py")

    def review_finding(self, prompt: str) -> str:
        try:
            response = self.client.models.generate_content(
                model=self.model, contents=prompt
            )
            return response.text
        except Exception as e:
            return f"REAL (Gemini error: {e})"

    def generate_remediation(self, prompt: str) -> str:
        try:
            response = self.client.models.generate_content(
                model=self.model, contents=prompt
            )
            return response.text
        except Exception as e:
            print(f"  [AI] Gemini error: {e}")
            return "See OWASP guidelines for remediation guidance."


# ── Groq Provider (free, high limits) ────────────────────────────────────────

class GroqProvider(AIProvider):
    """Free provider via Groq API — Llama 3.3 70B, 14400 requests/day free."""

    def __init__(self):
        try:
            from groq import Groq
            self.client = Groq(api_key=config.GROQ_API_KEY)
            self.model  = "llama-3.3-70b-versatile"
        except Exception as e:
            raise RuntimeError(f"Groq init failed: {e}. "
                               f"Check GROQ_API_KEY in config.py")

    def _call(self, prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"See OWASP guidelines for remediation guidance."

    def review_finding(self, prompt: str) -> str:
        return self._call(prompt)

    def generate_remediation(self, prompt: str) -> str:
        return self._call(prompt)

class OllamaProvider(AIProvider):
    """Free local provider via Ollama (offline, no API key required)."""

    def __init__(self):
        self.url   = config.OLLAMA_URL
        self.model = config.OLLAMA_MODEL

    def _call(self, prompt: str) -> str:
        try:
            import requests
            r = requests.post(
                self.url,
                json={
                    "model" : self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )
            return r.json().get('response', '')
        except Exception as e:
            return f"REAL (Ollama error: {e})"

    def review_finding(self, prompt: str) -> str:
        return self._call(prompt)

    def generate_remediation(self, prompt: str) -> str:
        return self._call(prompt)


# ── NoAI Provider (disabled fallback) ────────────────────────────────────────

class NoAIProvider(AIProvider):
    """
    Fallback — AI disabled. Returns static defaults.
    Type 2 findings are retained as warnings without AI review.
    """

    def review_finding(self, prompt: str) -> str:
        return "REAL"   # keep all findings when AI is disabled

    def generate_remediation(self, prompt: str) -> str:
        return "Refer to OWASP guidelines for remediation: https://owasp.org"


# ── Factory function ──────────────────────────────────────────────────────────

def get_provider() -> AIProvider:
    """
    Factory — selects provider from config.AI_PROVIDER.
    Defaults to NoAIProvider if provider name is unrecognized.
    """
    registry = {
        "gemini" : GeminiProvider,
        "groq"   : GroqProvider,
        "ollama" : OllamaProvider,
        "none"   : NoAIProvider,
    }
    provider_class = registry.get(
        config.AI_PROVIDER.lower(), NoAIProvider
    )
    try:
        return provider_class()
    except Exception as e:
        print(f"  [AI] Warning: could not initialize "
              f"'{config.AI_PROVIDER}' provider: {e}")
        print(f"  [AI] Falling back to NoAIProvider.")
        return NoAIProvider()


# ── AI Enhancement Layer ──────────────────────────────────────────────────────

class AIEnhancer:
    """
    Post-processing layer that operates on scored findings.
    Two roles:
    1. False Positive Reviewer — evaluates Type 2 unconfirmed findings
    2. Remediation Generator  — generates context-aware fix advice
    """

    def __init__(self):
        self.provider = get_provider()
        print(f"  [AI] Provider: {config.AI_PROVIDER}")

    def enhance(self, findings: list) -> list:
        """Process all findings through the AI layer."""
        if isinstance(self.provider, NoAIProvider):
            print("  [AI] AI disabled — adding default remediation text.")
            for f in findings:
                f['ai_note']     = None
                f['remediation'] = self._default_remediation(f)
            return findings

        print(f"  [AI] Processing {len(findings)} finding(s)...")

        for i, finding in enumerate(findings):

            # Step 1: Review Type 2 findings for false positives
            if finding.get('finding_type') == 2:
                finding = self._review_false_positive(finding)

            # Step 2: Generate remediation for all retained findings
            if finding.get('status') != 'dismissed':
                finding = self._generate_remediation(finding)

        retained  = sum(1 for f in findings
                        if f.get('status') != 'dismissed')
        dismissed = len(findings) - retained
        print(f"  [AI] Done. {retained} retained, "
              f"{dismissed} dismissed as false positives.")

        return findings

    def _review_false_positive(self, finding: dict) -> dict:
        """Ask AI whether a Type 2 finding is real or a false positive."""
        prompt = f"""A static code scanner flagged this as a potential \
{finding['type']} vulnerability (OWASP {finding['owasp']}):

File     : {finding.get('file', 'unknown')}
Line     : {finding.get('line', 'unknown')}
Code     : {finding.get('code', 'N/A')}
Evidence : {finding.get('evidence_static', 'N/A')}

Is this a REAL vulnerability or a FALSE_POSITIVE?
Reply with exactly REAL or FALSE_POSITIVE followed by one sentence explanation.
"""
        response = self.provider.review_finding(prompt)

        if "FALSE_POSITIVE" in response.upper():
            finding['status']     = 'dismissed'
            finding['ai_note']    = response.strip()
        else:
            finding['status']     = 'warning'
            finding['confidence'] = 0.55   # AI-reviewed, slightly upgraded
            finding['ai_note']    = response.strip()

        return finding

    def _generate_remediation(self, finding: dict) -> dict:
        """Generate context-specific remediation advice."""
        prompt = f"""A {finding['type']} vulnerability (OWASP {finding['owasp']}) \
was detected with the following evidence:

URL            : {finding.get('url', 'N/A')}
Parameter      : {finding.get('parameter', 'N/A')}
Static evidence: {finding.get('evidence_static', 'N/A')}
Dynamic evidence: {finding.get('evidence_dynamic', 'N/A')}
Confidence     : {finding.get('confidence', 0)} \
({finding.get('finding_type', 3)} — \
{'confirmed' if finding.get('finding_type') == 1 else 'unconfirmed'})

Provide a specific remediation in 3 sentences maximum.
Include a concrete code-level fix example if applicable.
"""
        finding['remediation'] = self.provider.generate_remediation(prompt)
        return finding

    def _default_remediation(self, finding: dict) -> str:
        """Return default OWASP remediation when AI is disabled."""
        defaults = {
            'sqli'     : ("Use prepared statements with parameterized queries. "
                          "Never concatenate user input into SQL strings. "
                          "See: https://owasp.org/www-community/attacks/SQL_Injection"),
            'xss'      : ("Encode all user input before rendering in HTML. "
                          "Use htmlspecialchars() in PHP or equivalent. "
                          "See: https://owasp.org/www-community/attacks/xss/"),
            'cmdi'     : ("Never pass user input to OS command functions. "
                          "Use escapeshellarg() if shell calls are unavoidable. "
                          "See: https://owasp.org/www-community/attacks/Command_Injection"),
            'traversal': ("Validate file paths against a whitelist of allowed values. "
                          "Use realpath() and verify the result stays within bounds. "
                          "See: https://owasp.org/www-community/attacks/Path_Traversal"),
            'idor'     : ("Implement server-side authorization checks for all resource access. "
                          "Never rely solely on obscurity of resource identifiers. "
                          "See: https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"),
            'headers'  : ("Configure security headers in your web server or application. "
                          "See: https://owasp.org/www-project-secure-headers/"),
        }
        vuln_type = finding.get('type', 'unknown')
        return defaults.get(vuln_type, "See OWASP guidelines: https://owasp.org")
