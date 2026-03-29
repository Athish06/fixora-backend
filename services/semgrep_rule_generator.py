# Semgrep Rule Generator - Converts LLM sink_modules.json into custom Semgrep rules
# These rules supplement Semgrep's built-in rules to catch project-specific
# vulnerable wrapper functions that Semgrep wouldn't know about.

import logging
import json
import yaml
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────

VULN_TYPE_TO_CWE: Dict[str, List[str]] = {
    "SQL Injection":        ["CWE-89"],
    "Command Injection":    ["CWE-78"],
    "RCE":                  ["CWE-94"],
    "SSRF":                 ["CWE-918"],
    "Path Traversal":       ["CWE-22"],
    "XSS":                  ["CWE-79"],
    "Deserialization":      ["CWE-502"],
    "XXE":                  ["CWE-611"],
    "Open Redirect":        ["CWE-601"],
    "LDAP Injection":       ["CWE-90"],
    "XPath Injection":      ["CWE-643"],
    "Code Injection":       ["CWE-94"],
    "Template Injection":   ["CWE-1336"],
    "Log Injection":        ["CWE-117"],
    "NoSQL Injection":      ["CWE-943"],
    "Prototype Pollution":  ["CWE-1321"],
}

SEVERITY_TO_SEMGREP = {
    "CRITICAL": "ERROR",
    "HIGH":     "ERROR",
    "MEDIUM":   "WARNING",
    "LOW":      "INFO",
}

LANG_TO_SEMGREP = {
    "python": ["python"],
    "react":  ["javascript", "typescript"],
}

# All JS-family key names the LLM might use regardless of instruction
_JS_LANG_KEYS = {"react", "javascript", "js", "node", "nodejs", "typescript", "ts"}

# Vulnerability type → OWASP Top 10 (2021) mapping
VULN_TYPE_TO_OWASP: Dict[str, List[str]] = {
    "SQL Injection":        ["A03:2021"],
    "Command Injection":    ["A03:2021"],
    "RCE":                  ["A03:2021"],
    "SSRF":                 ["A10:2021"],
    "Path Traversal":       ["A01:2021"],
    "XSS":                  ["A03:2021"],
    "Deserialization":      ["A08:2021"],
    "XXE":                  ["A05:2021"],
    "Open Redirect":        ["A01:2021"],
    "Code Injection":       ["A03:2021"],
    "NoSQL Injection":      ["A03:2021"],
}


# ─────────────────────────────────────────────────────────────────────────────
# RULE GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_custom_rules(
    llm_result: Dict[str, Any],
    manual_review_required: List[Dict[str, Any]] | None = None,
) -> str:
    """
    Generate custom Semgrep YAML rules from the LLM's sink_modules.json output
    and optionally from functions that could not be AI-analysed.

    For each vulnerable wrapper function identified by the LLM, we create a
    Semgrep rule that flags the DEFINITION of the vulnerable function itself.
    Standard call-pattern rules (func(...)) fail for framework endpoints
    (e.g. FastAPI route handlers) that are never called directly in code.
    By matching `def func(...): ...` we catch the vulnerable code block.

    For functions in *manual_review_required* (AI analysis inconclusive or
    request too large), we generate broad "needs manual review" rules so that
    Semgrep at least flags those function definitions for a human to inspect.

    Semgrep's built-in rules already catch direct usage of dangerous APIs
    (e.g. subprocess.run(shell=True)), but they can't see through
    project-specific wrapper abstractions — that's our value-add.

    Returns:
        YAML string ready to write to .fixora-rules.yml, or "" if no rules.
    """
    rules: List[Dict[str, Any]] = []
    results = llm_result.get("results", {})

    # ── LLM-identified vulnerable wrappers ───────────────────────────────
    # Iterate every key the LLM returned — never hardcode ("python", "react").
    # The LLM may use "javascript", "node", etc. for the JS section.
    for lang_key, section in results.items():
        if not section or not isinstance(section, dict):
            continue

        semgrep_langs = _semgrep_langs_for_key(lang_key)
        wrapper_functions = section.get("wrapper_functions", [])

        for wrapper in wrapper_functions:
            rule = _build_wrapper_rule(wrapper, semgrep_langs, lang_key)
            if rule:
                rules.append(rule)

    # ── Manually-flagged functions (AI inconclusive / 413 too large) ──────
    for entry in (manual_review_required or []):
        lang_key   = entry.get("lang", "python")
        func_names = entry.get("function_names", [])
        semgrep_langs = _semgrep_langs_for_key(lang_key)

        for func_name in func_names:
            rule = _build_manual_review_rule(func_name, semgrep_langs, lang_key)
            if rule:
                rules.append(rule)

    if not rules:
        logger.info("No custom Semgrep rules generated (no vulnerable wrappers found)")
        return ""

    # De-duplicate by rule id (same function name in multiple wrappers → one rule)
    seen_ids = set()
    unique_rules = []
    for rule in rules:
        if rule["id"] not in seen_ids:
            seen_ids.add(rule["id"])
            unique_rules.append(rule)

    yaml_output = yaml.dump(
        {"rules": unique_rules},
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    logger.info(f"Generated {len(unique_rules)} custom Semgrep rules from LLM analysis")
    logger.info("=" * 60)
    logger.info("GENERATED CUSTOM SEMGREP RULES (.fixora-rules.yml):")
    logger.info("=" * 60)
    logger.info(yaml_output)
    logger.info("=" * 60)

    return yaml_output


def _build_wrapper_rule(
    wrapper: Dict[str, Any],
    semgrep_langs: List[str],
    lang_key: str,
) -> Dict[str, Any] | None:
    """Build a single Semgrep rule dict for a vulnerable wrapper function."""

    func_name = wrapper.get("function_name", "").strip()
    if not func_name:
        return None

    vuln_type   = wrapper.get("vulnerability_type", "Security Issue")
    severity    = wrapper.get("severity", "MEDIUM").upper()
    reason      = wrapper.get("reason", "Potentially dangerous wrapper function")
    file_path   = wrapper.get("file", "unknown")
    calls       = wrapper.get("calls", [])
    modules     = wrapper.get("modules_used", [])

    # Sanitise function name for rule ID (alphanumeric + hyphens only)
    safe_name = "".join(c if c.isalnum() else "-" for c in func_name).strip("-").lower()
    rule_id = f"fixora-wrapper-{safe_name}"

    semgrep_severity = SEVERITY_TO_SEMGREP.get(severity, "WARNING")
    cwe  = VULN_TYPE_TO_CWE.get(vuln_type, [])
    owasp = VULN_TYPE_TO_OWASP.get(vuln_type, [])

    wraps_text = ", ".join(calls) if calls else "dangerous sink calls"

    # 1. Dynamic Impact Mapping
    impact_map = {
        "SQL Injection": "Can leak the entire database, bypass authentication, or destroy critical records.",
        "Command Injection": "Allows an attacker to execute arbitrary OS commands, leading to full server compromise.",
        "Path Traversal": "Can leak sensitive server files (e.g., /etc/passwd, .env) and application source code.",
        "XSS": "Can steal user session cookies, hijack accounts, or deface the application.",
        "IDOR / Broken Access Control": "Allows attackers to view, edit, or delete private data belonging to other users.",
        "SSRF": "Can force the server to scan internal networks and bypass firewalls.",
        "Insecure Deserialization": "Can lead to Remote Code Execution (RCE) via malicious payload injection."
    }
    impact_text = impact_map.get(vuln_type, "Can allow attackers to bypass intended application logic.")

    # 2. Grab the AI's custom exploit fields (new schema + legacy fallback)
    parameter = str(wrapper.get("vulnerable_parameter", "")).strip() or "input"
    malicious_payload_raw = wrapper.get("malicious_payload", "")
    explanation = str(
        wrapper.get("exploit_explanation") or wrapper.get("attack_explanation") or ""
    ).strip() or "Payload triggers the vulnerability."
    impact_summary = str(wrapper.get("impact_summary", "")).strip()

    if malicious_payload_raw is None:
        malicious_payload = ""
    elif isinstance(malicious_payload_raw, str):
        malicious_payload = malicious_payload_raw.strip()
    else:
        try:
            malicious_payload = json.dumps(malicious_payload_raw, ensure_ascii=True)
        except Exception:
            malicious_payload = str(malicious_payload_raw).strip()

    # Legacy fallback path
    payload = malicious_payload or str(wrapper.get("example_exploit", "")).strip()
    generic_placeholder = (
        not payload
        or "malicious_payload" in payload.lower()
        or "user_input" in payload.lower()
    )
    if generic_placeholder:
        default_exploit_map = {
            "SQL Injection": "bulk_insert(\"users; DROP TABLE users; --\", data)",
            "Command Injection": "execute_background_task(\"ping -c 1 127.0.0.1; cat /etc/passwd\")",
            "Path Traversal": "read_report(\"../../../../etc/passwd\")",
            "XSS": "render_comment(\"<img src=x onerror=alert(document.cookie)>\")",
            "SSRF": "fetch_remote(\"http://169.254.169.254/latest/meta-data/\")",
            "Insecure Deserialization": "load_payload(\"gASV...crafted_pickle...\")",
            "IDOR / Broken Access Control": "get_invoice(\"another-users-invoice-id\")",
        }
        payload = default_exploit_map.get(vuln_type, "<malicious_data>")

    code_lang = "python" if lang_key == "python" else "javascript"

    injected_example = str(wrapper.get("exploit_injected_example", "")).strip()
    if not injected_example:
        injected_example = f"{func_name}({parameter} = {payload})"

    injected_code_block = (
        f"```{code_lang}\\n"
        f"// Target Function: {func_name}()\\n"
        f"// Parameter: {parameter}\\n\\n"
        f"// Attacker executes:\\n"
        f"{injected_example}\\n"
        f"```"
    )

    if not impact_summary:
        impact_summary = impact_text

    # 3. The markdown structure
    message = (
        f"### {vuln_type} via `{parameter}`\n\n"
        f"**Vulnerable Sink:** Passes untrusted data directly to `{wraps_text}`.\n\n"
        f"**Live Exploit Vector:**\n"
        f"{injected_code_block}\n\n"
        f"**Outcome:**\n{explanation}\n\n"
        f"**Data at Risk (Impact):**\n{impact_summary}"
    )

    metadata: Dict[str, Any] = {
        "category": "security",
        "technology": list(semgrep_langs),
        "source": "fixora-ai-analysis",
        "vulnerability_type": vuln_type,
        "confidence": severity,
        "wrapper_defined_in": file_path,
        "wraps": calls,
        "modules_used": modules,
        "vulnerable_parameter": parameter,
        "malicious_payload": payload,
        "exploit_explanation": explanation,
        "exploit_injected_example": injected_example,
        "impact_summary": impact_summary,
    }
    if cwe:
        metadata["cwe"] = cwe
    if owasp:
        metadata["owasp"] = owasp

    def _safe_ident(name: str) -> bool:
        return bool(name) and name.replace("_", "a").isalnum() and not name[0].isdigit()

    # Build sink call patterns from wrapper call metadata.
    sink_patterns: List[Dict[str, str]] = []
    seen_sink = set()
    for raw_call in calls or []:
        call = str(raw_call or "").strip().replace("()", "")
        if not call:
            continue
        exact = f"{call}(...)"
        if exact not in seen_sink:
            sink_patterns.append({"pattern": exact})
            seen_sink.add(exact)

        method = call.split(".")[-1]
        if _safe_ident(method):
            wildcard = f"$OBJ.{method}(...)"
            if wildcard not in seen_sink:
                sink_patterns.append({"pattern": wildcard})
                seen_sink.add(wildcard)
            direct = f"{method}(...)"
            if direct not in seen_sink:
                sink_patterns.append({"pattern": direct})
                seen_sink.add(direct)

    # ── Build language-specific patterns ──
    # Any non-python key (react, javascript, node, etc.) uses JS patterns.
    if lang_key == "python":
        if sink_patterns:
            rule = {
                "id": rule_id,
                "patterns": [
                    {"pattern-inside": f"def {func_name}(...):\n  ..."},
                    {"pattern-either": sink_patterns},
                ],
                "message": message,
                "severity": semgrep_severity,
                "languages": ["python"],
                "metadata": metadata,
            }
        else:
            rule = {
                "id": rule_id,
                "pattern": f"def {func_name}(...):\n  ...",
                "message": message,
                "severity": semgrep_severity,
                "languages": ["python"],
                "metadata": metadata,
            }
    else:
        # JavaScript / TypeScript — build patterns based on whether the name
        # is a plain identifier or a dotted path (e.g. module.exports.userSearch).
        #
        # IMPORTANT: patterns like `function module.exports.x(...)` are invalid
        # JavaScript syntax.  Semgrep silently drops the ENTIRE rules file when
        # it encounters even one syntactically invalid pattern, falling back to
        # built-in rules only.  So dotted names must only use assignment forms.
        #
        # Strip any accidental trailing () the Wrapper Hunter may have included.
        clean_name = func_name.replace("()", "").strip()
        is_dotted = "." in clean_name

        def_patterns = []
        if not is_dotted:
            # Simple identifier — all forms are valid JS
            def_patterns += [
                {"pattern": f"function {clean_name}(...) {{ ... }}"},
                {"pattern": f"const {clean_name} = (...) => {{ ... }}"},
                {"pattern": f"let {clean_name} = (...) => {{ ... }}"},
                {"pattern": f"var {clean_name} = (...) => {{ ... }}"},
                {"pattern": f"this.{clean_name} = (...) => {{ ... }}"},
                {"pattern": f"this.{clean_name} = function(...) {{ ... }}"},
                {"pattern": f"{clean_name}: (...) => {{ ... }}"},
                {"pattern": f"{clean_name}: function(...) {{ ... }}"},
                {"pattern": f"{clean_name}(...) {{ ... }}"},
            ]
        # Assignment patterns work for ANY name form, including dotted paths
        # like module.exports.userSearch = function(req, res) { ... }
        def_patterns += [
            {"pattern": f"{clean_name} = (...) => {{ ... }}"},
            {"pattern": f"{clean_name} = function(...) {{ ... }}"},
        ]

        if sink_patterns:
            rule = {
                "id": rule_id,
                "patterns": [
                    {"pattern-either": def_patterns},
                    {"pattern-either": sink_patterns},
                ],
                "message": message,
                "severity": semgrep_severity,
                "languages": ["javascript", "typescript"],
                "metadata": metadata,
            }
        else:
            rule = {
                "id": rule_id,
                "pattern-either": def_patterns,
                "message": message,
                "severity": semgrep_severity,
                "languages": ["javascript", "typescript"],
                "metadata": metadata,
            }

    return rule


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE
# ─────────────────────────────────────────────────────────────────────────────

def count_generated_rules(llm_result: Dict[str, Any]) -> int:
    """Quick count of how many rules would be generated (for logging/WS)."""
    results = llm_result.get("results", {})
    count = 0
    for section in results.values():
        if section and isinstance(section, dict):
            count += len(section.get("wrapper_functions", []))
    return count


def _semgrep_langs_for_key(lang_key: str) -> List[str]:
    """Map any LLM language key to the correct Semgrep language list."""
    if lang_key == "python":
        return ["python"]
    if lang_key.lower() in _JS_LANG_KEYS:
        return ["javascript", "typescript"]
    return [lang_key]


def _build_manual_review_rule(
    func_name: str,
    semgrep_langs: List[str],
    lang_key: str,
) -> Dict[str, Any] | None:
    """
    Build a broad Semgrep rule for a function that could not be AI-analysed
    (request too large, repeated 429s, etc.).

    The rule flags the function *definition* at WARNING severity and asks a
    human to review it — Semgrep may independently catch dangerous patterns
    inside the body even without LLM guidance.
    """
    func_name = (func_name or "").strip()
    if not func_name:
        return None

    safe_name = "".join(c if c.isalnum() else "-" for c in func_name).strip("-").lower()
    rule_id = f"fixora-manual-review-{safe_name}"

    message = (
        f"Function '{func_name}()' requires manual security review. "
        "AI analysis was inconclusive (request too large or repeated API errors). "
        "Inspect this function for unsanitised user input reaching dangerous sinks."
    )
    metadata: Dict[str, Any] = {
        "category": "security",
        "technology": list(semgrep_langs),
        "source": "fixora-manual-review",
        "confidence": "UNKNOWN",
        "review_reason": "AI analysis inconclusive — manual inspection required",
    }

    if lang_key == "python":
        return {
            "id": rule_id,
            "pattern": f"def {func_name}(...):\n  ...",
            "message": message,
            "severity": "WARNING",
            "languages": ["python"],
            "metadata": metadata,
        }
    else:
        clean_name = func_name.replace("()", "").strip()
        is_dotted  = "." in clean_name
        patterns   = []
        if not is_dotted:
            patterns += [
                {"pattern": f"function {clean_name}(...) {{ ... }}"},
                {"pattern": f"const {clean_name} = (...) => {{ ... }}"},
                {"pattern": f"let {clean_name} = (...) => {{ ... }}"},
                {"pattern": f"var {clean_name} = (...) => {{ ... }}"},
                {"pattern": f"this.{clean_name} = (...) => {{ ... }}"},
                {"pattern": f"this.{clean_name} = function(...) {{ ... }}"},
                {"pattern": f"{clean_name}: (...) => {{ ... }}"},
                {"pattern": f"{clean_name}: function(...) {{ ... }}"},
                {"pattern": f"{clean_name}(...) {{ ... }}"},
            ]
        patterns += [
            {"pattern": f"{clean_name} = (...) => {{ ... }}"},
            {"pattern": f"{clean_name} = function(...) {{ ... }}"},
        ]
        return {
            "id": rule_id,
            "pattern-either": patterns,
            "message": message,
            "severity": "WARNING",
            "languages": ["javascript", "typescript"],
            "metadata": metadata,
        }
