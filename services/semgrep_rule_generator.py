# Semgrep Rule Generator - Converts LLM sink_modules.json into custom Semgrep rules
# These rules supplement Semgrep's built-in rules to catch project-specific
# vulnerable wrapper functions that Semgrep wouldn't know about.

import logging
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

def generate_custom_rules(llm_result: Dict[str, Any]) -> str:
    """
    Generate custom Semgrep YAML rules from the LLM's sink_modules.json output.

    For each vulnerable wrapper function identified by the LLM, we create a
    Semgrep rule that flags the DEFINITION of the vulnerable function itself.
    Standard call-pattern rules (func(...)) fail for framework endpoints
    (e.g. FastAPI route handlers) that are never called directly in code.
    By matching `def func(...): ...` we catch the vulnerable code block.

    Semgrep's built-in rules already catch direct usage of dangerous APIs
    (e.g. subprocess.run(shell=True)), but they can't see through
    project-specific wrapper abstractions — that's our value-add.

    Returns:
        YAML string ready to write to .fixora-rules.yml, or "" if no rules.
    """
    rules: List[Dict[str, Any]] = []
    results = llm_result.get("results", {})

    for lang_key in ("python", "react"):
        section = results.get(lang_key)
        if not section:
            continue

        semgrep_langs = LANG_TO_SEMGREP.get(lang_key, [lang_key])
        wrapper_functions = section.get("wrapper_functions", [])

        for wrapper in wrapper_functions:
            rule = _build_wrapper_rule(wrapper, semgrep_langs, lang_key)
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
    message = (
        f"Vulnerable function '{func_name}()' wraps {wraps_text}. "
        f"Vulnerability: {vuln_type}. {reason}"
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
    }
    if cwe:
        metadata["cwe"] = cwe
    if owasp:
        metadata["owasp"] = owasp

    # ── Build language-specific patterns matching the DEFINITION, not calls ──
    if lang_key == "python":
        rule: Dict[str, Any] = {
            "id": rule_id,
            # Match the function definition itself so Semgrep flags
            # the vulnerable code block even for framework endpoints
            # (FastAPI routes, Django views, etc.) that are never
            # called explicitly in user code.
            "pattern": f"def {func_name}(...):\n  ...",
            "message": message,
            "severity": semgrep_severity,
            "languages": ["python"],
            "metadata": metadata,
        }
    else:
        # JavaScript / TypeScript — cover standard forms:
        #   function name(...) { ... }
        #   const name = (...) => { ... }
        #   name(...) { ... }  (class method / object shorthand)
        rule: Dict[str, Any] = {
            "id": rule_id,
            "pattern-either": [
                {"pattern": f"function {func_name}(...) {{ ... }}"},
                {"pattern": f"const {func_name} = (...) => {{ ... }}"},
                {"pattern": f"{func_name}(...) {{ ... }}"},
            ],
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
    for lang_key in ("python", "react"):
        section = results.get(lang_key)
        if section:
            count += len(section.get("wrapper_functions", []))
    return count
