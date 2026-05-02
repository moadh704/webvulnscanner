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

    Three roles:
    1. Static False Positive Reviewer — evaluates Type 2 (Candidate) findings
       from the static engine and dismisses those that are clearly safe.
    2. Dynamic False Positive Reviewer — evaluates Type 3 (Detected) findings
       from the dynamic injectors. Targets vulnerability classes prone to
       runtime false positives where the simple "pattern present in response"
       heuristic can misfire.
    3. Remediation Generator — generates context-aware fix advice for every
       retained finding.

    Type 1 (Verified) findings are NEVER reviewed: if both static and dynamic
    pipelines confirmed the same vulnerability at the same endpoint, the
    evidence is strong enough that further review would only add noise.

    Static review is mode-aware: in static-only scans the AI is lenient
    (favours retention so the developer can triage in code review); in
    hybrid/dynamic scans it is strict (the absence of dynamic confirmation
    is a meaningful signal that the static match is likely a false positive).
    """

    def __init__(self):
        self.provider = get_provider()
        # Detect scan context: if no target URL is set, we are in static-only
        # mode; otherwise dynamic evidence is (potentially) available.
        self.static_only_mode = not bool(getattr(config, 'TARGET_URL', ''))
        print(f"  [AI] Provider: {config.AI_PROVIDER}")
        if self.static_only_mode:
            print(f"  [AI] Mode: static-only (lenient review)")
        else:
            print(f"  [AI] Mode: hybrid/dynamic (strict review)")

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
            ftype = finding.get('finding_type')

            # Step 1a: Review Type 2 (Candidate) — static-only matches
            if ftype == 2:
                finding = self._review_static_candidate(finding)

            # Step 1b: Review Type 3 (Detected) — dynamic-only matches
            # for vulnerability classes prone to runtime false positives.
            elif ftype == 3 and self._needs_dynamic_review(finding):
                finding = self._review_dynamic_detection(finding)

            # Step 2: Generate remediation for all retained findings
            if finding.get('status') != 'dismissed':
                finding = self._generate_remediation(finding)

        retained  = sum(1 for f in findings
                        if f.get('status') != 'dismissed')
        dismissed = len(findings) - retained
        print(f"  [AI] Done. {retained} retained, "
              f"{dismissed} dismissed as false positives.")

        return findings

    # ── Type 2 (static candidate) review ──────────────────────────────────────

    def _review_static_candidate(self, finding: dict) -> dict:
        """
        Ask AI whether a Type 2 (Candidate) finding is real or a false positive.
        Uses a context-aware prompt: lenient in static-only mode, strict in
        hybrid mode where the absence of dynamic confirmation is meaningful.
        """
        location = finding.get('url') or finding.get('file', 'unknown')
        evidence = finding.get('evidence_static') or 'no static evidence'

        if self.static_only_mode:
            prompt = f"""A static code scanner flagged this as a potential \
{finding['type']} vulnerability (OWASP {finding['owasp']}):

Location : {location}
Evidence : {evidence}

This scan is in STATIC-ONLY mode — no runtime confirmation is available.
Your job is to help the developer triage findings for code review.

Should this finding be RETAINED for review or is it clearly NOT_VULNERABLE?
Be lenient: when in doubt, retain. Reply with exactly RETAIN or NOT_VULNERABLE
followed by one sentence explanation.
"""
        else:
            prompt = f"""A static code scanner flagged this as a potential \
{finding['type']} vulnerability (OWASP {finding['owasp']}):

Location : {location}
Evidence : {evidence}

This scan is in HYBRID mode — dynamic injection was attempted at the
corresponding endpoint but did NOT confirm exploitation.

Is this still a REAL vulnerability (e.g., dynamically reachable but not
exploited by our payloads) or a FALSE_POSITIVE (e.g., sanitized, dead code,
or unreachable)?

Reply with exactly REAL or FALSE_POSITIVE followed by one sentence explanation.
"""
        response = self.provider.review_finding(prompt)
        upper = response.upper()

        if self.static_only_mode:
            if "NOT_VULNERABLE" in upper:
                finding['status']  = 'dismissed'
                finding['ai_note'] = response.strip()
            else:
                finding['status']     = 'warning'
                finding['confidence'] = 0.55
                finding['ai_note']    = response.strip()
        else:
            if "FALSE_POSITIVE" in upper:
                finding['status']  = 'dismissed'
                finding['ai_note'] = response.strip()
            else:
                finding['status']     = 'warning'
                finding['confidence'] = 0.55
                finding['ai_note']    = response.strip()

        return finding

    # ── Type 3 (dynamic detection) review ─────────────────────────────────────

    def _needs_dynamic_review(self, finding: dict) -> bool:
        """
        Decide whether a Type 3 finding needs a second-pass AI review.
        We focus on vulnerability classes where the simple "pattern present
        in response" heuristic is known to produce false positives:
          - XSS:       payload may appear but be HTML-escaped (e.g., '&lt;'
                       instead of '<'), in which case it is NOT exploitable
          - SQLi:      a generic error message may appear in the page for
                       reasons unrelated to actual SQL behaviour
          - traversal: file path may reflect without actual file disclosure
          - CMDi:      patterns like 'uid=' or 'gid=' may appear as part of
                       normal HTML content (e.g., a logged-in user banner)
                       rather than as command output
          - IDOR:      a difference between sequential IDs may reflect
                       legitimate distinct resources rather than a missing
                       authorization check
        Headers findings are objective (header present or absent) and skip
        review.
        """
        return finding.get('type') in (
            'xss', 'sqli', 'traversal', 'cmdi', 'idor'
        )

    def _review_dynamic_detection(self, finding: dict) -> dict:
        """
        Ask AI whether a Type 3 (Detected) finding represents a real
        exploitation or whether the dynamic injector misread escaped /
        encoded output as successful injection.
        """
        url      = finding.get('url', '?')
        param    = finding.get('parameter', '?')
        payload  = finding.get('payload', '?')
        evidence = finding.get('evidence_dynamic') or 'no dynamic evidence'
        vuln     = finding.get('type', 'unknown')

        # Tailored guidance per vulnerability class to make the AI's job
        # focused rather than generic.
        if vuln == 'xss':
            extra = (
                "An XSS finding is REAL only if the payload appears in the "
                "response with its special characters intact (e.g., literal "
                "'<' and '>'). If the payload was reflected but with characters "
                "HTML-encoded ('&lt;', '&#60;', '&amp;', etc.), the application "
                "is correctly escaping output and the finding is a "
                "FALSE_POSITIVE."
            )
        elif vuln == 'sqli':
            extra = (
                "A SQLi finding is REAL only if the response shows actual "
                "SQL behaviour (database error, structural change in returned "
                "rows, or measurable time delay). A generic 500 error or an "
                "unrelated message echoing the payload is a FALSE_POSITIVE."
            )
        elif vuln == 'traversal':
            extra = (
                "A path-traversal finding is REAL only if the response "
                "contains genuine content from outside the application "
                "directory (e.g., contents of /etc/passwd, win.ini). If the "
                "response merely echoes the path string or returns the same "
                "page as legitimate input, it is a FALSE_POSITIVE."
            )
        elif vuln == 'cmdi':
            extra = (
                "A CMDi finding is REAL only if the response contains output "
                "that could only come from actual command execution (e.g., "
                "the literal string 'www-data' from `whoami`, a directory "
                "listing produced by `dir` or `ls`, the contents of "
                "/etc/passwd from `cat`, or a measurable time delay from "
                "`sleep`). If the matched pattern (e.g., 'uid=', 'gid=', "
                "'/bin/', '/usr/') appears as part of NORMAL HTML content — "
                "such as a logged-in user banner that displays a user's "
                "uid/gid number for display purposes, a navigation menu "
                "item that mentions a path, or a help text that references "
                "a system directory — this is a FALSE_POSITIVE: the command "
                "was never executed, the pattern just happens to be present "
                "in the page text."
            )
        elif vuln == 'idor':
            extra = (
                "An IDOR finding is REAL only if iterating an integer "
                "identifier returns data that should belong to different "
                "users / accounts / resources than the authenticated user "
                "is authorised to see, indicating a missing authorisation "
                "check. If sequential IDs simply return distinct legitimate "
                "resources of the same kind (e.g., /api/Products/1 and "
                "/api/Products/2 both being public product listings), this "
                "is expected catalogue behaviour and a FALSE_POSITIVE."
            )
        else:
            extra = ""

        prompt = f"""A dynamic injector flagged a {vuln} vulnerability \
(OWASP {finding.get('owasp', '')}):

URL              : {url}
Parameter        : {param}
Injected payload : {payload}
Dynamic evidence : {evidence}

{extra}

Based on the evidence above, is this a REAL exploitation or a FALSE_POSITIVE?
Reply with exactly REAL or FALSE_POSITIVE followed by one sentence explanation.
"""
        response = self.provider.review_finding(prompt)
        upper = response.upper()

        if "FALSE_POSITIVE" in upper:
            finding['status']  = 'dismissed'
            finding['ai_note'] = response.strip()
        else:
            # Retained — note the AI's reasoning for transparency in the report
            finding['ai_note'] = response.strip()

        return finding

    # ── Remediation generation ────────────────────────────────────────────────

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