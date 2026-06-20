# Pipeline Trace Service — transforms ai_debug + vulnerabilities into animation-ready JSON
# Pure read-only transform — no new storage, no pipeline changes.

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CAPS — keep trace JSON lightweight for Render (target < 50 KB)
# ─────────────────────────────────────────────────────────────────────────────
MAX_MODULES_PER_LANG = 50
MAX_SAMPLED_WRAPPERS = 8
MAX_SAMPLED_FINDINGS = 6
MAX_TRADITIONAL_FINDINGS = 10
MAX_DYNAMIC_FINDINGS = 10
YAML_PREVIEW_CHARS = 500


# ─────────────────────────────────────────────────────────────────────────────
# STAGE CAPTIONS (the "guided story" text)
# ─────────────────────────────────────────────────────────────────────────────
STAGE_CAPTIONS = {
    "discovery": (
        "Fixora reads your requirements.txt / package.json plus every "
        "import statement to map every library your code touches."
    ),
    "ast_walk": (
        "It walks your code's syntax tree function by function, looking "
        "for any function that calls something from that map."
    ),
    "llm_phase1": (
        "AI looks at just your library list and flags which ones are "
        "dangerous if misused."
    ),
    "llm_phase2": (
        "AI then reads only the functions touching those flagged libraries, "
        "in small batches, and explains exactly how an attacker would "
        "exploit each one."
    ),
    "rule_generation": (
        "Every confirmed vulnerable wrapper becomes a brand-new Semgrep "
        "rule recognizing that exact function."
    ),
    "scan_comparison": (
        "Vanilla Semgrep is structurally blind to your own wrapper "
        "functions. These rules didn't exist anywhere until this scan."
    ),
}

STAGE_TITLES = {
    "discovery": "Module Discovery",
    "ast_walk": "AST Walk & Wrapper Extraction",
    "llm_phase1": "AI Sink Identification",
    "llm_phase2": "AI Vulnerability Analysis",
    "rule_generation": "Custom Rule Generation",
    "scan_comparison": "Traditional vs. Dynamic Scan",
}


def build_trace(
    ai_debug_doc: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Transform an ai_debug document + its associated vulnerability list
    into the animation-friendly trace JSON.

    The output is designed for lightweight frontend rendering:
    - Arrays are capped for animation sanity
    - source_code is never included
    - Heavy fields (llm_prompt, raw wrapper data) are stripped
    """
    scan_id = ai_debug_doc.get("scan_id", "")
    repo_id = ai_debug_doc.get("repository_id", "")
    created_at = ai_debug_doc.get("created_at", "")

    wrapper_data = ai_debug_doc.get("wrapper_hunter_results") or {}
    llm_result = ai_debug_doc.get("llm_result") or {}
    custom_rules_yaml = ai_debug_doc.get("custom_rules_yaml") or ""
    chunk_stats_raw = ai_debug_doc.get("chunk_stats") or {}
    rules_count = ai_debug_doc.get("rules_count", 0)

    # If wrapper data was truncated (large repos), provide empty structure
    if isinstance(wrapper_data, dict) and wrapper_data.get("_truncated"):
        wrapper_data = {"results": {}, "_truncated": True}

    wd_results = wrapper_data.get("results", {}) or {}
    llm_results = llm_result.get("results", {}) or {}

    stages = [
        _build_discovery_stage(wd_results),
        _build_ast_walk_stage(wd_results),
        _build_llm_phase1_stage(llm_results),
        _build_llm_phase2_stage(llm_results, chunk_stats_raw),
        _build_rule_generation_stage(llm_results, custom_rules_yaml, rules_count),
        _build_scan_comparison_stage(vulnerabilities),
    ]

    return {
        "scan_id": scan_id,
        "repository_id": repo_id,
        "created_at": created_at,
        "stages": stages,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STAGE BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_discovery_stage(wd_results: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 1 — Module Discovery from manifests + imports."""
    languages = {}

    for lang_key, section in wd_results.items():
        if not isinstance(section, dict):
            continue
        modules = section.get("modules") or {}
        from_manifest = [str(m) for m in (modules.get("from_manifest") or []) if m is not None]
        from_imports = [str(m) for m in (modules.get("from_imports") or []) if m is not None]
        all_mods = [str(m) for m in (modules.get("all") or []) if m is not None]

        languages[lang_key] = {
            "from_manifest": from_manifest[:MAX_MODULES_PER_LANG],
            "from_imports": from_imports[:MAX_MODULES_PER_LANG],
            "all": all_mods[:MAX_MODULES_PER_LANG],
            "total_manifest": len(from_manifest),
            "total_imports": len(from_imports),
            "total_all": len(all_mods),
        }

    return {
        "id": "discovery",
        "title": STAGE_TITLES["discovery"],
        "caption": STAGE_CAPTIONS["discovery"],
        "languages": languages,
    }


def _build_ast_walk_stage(wd_results: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 2 — AST Walk showing extracted wrapper functions (sampled)."""
    files_map: Dict[str, List[Dict[str, Any]]] = {}
    total_wrappers = 0

    for lang_key, section in wd_results.items():
        if not isinstance(section, dict):
            continue
        wrappers = section.get("wrapper_functions") or []
        total_wrappers += len(wrappers)

        for w in wrappers:
            file_path = w.get("file", "unknown")
            if file_path not in files_map:
                files_map[file_path] = []
            files_map[file_path].append({
                "name": w.get("function_name", "<anonymous>"),
                "line_start": w.get("line_start"),
                "line_end": w.get("line_end"),
                "calls": [str(c) for c in (w.get("calls") or []) if c],
                "modules_used": [str(m) for m in (w.get("modules_used") or []) if m],
                "environment": w.get("environment", "BACKEND"),
                "has_auth_check": w.get("has_auth_check", False),
                # NOTE: No source_code — intentionally stripped for trace weight
            })

    # Sample representative files/functions for animation
    sampled_files = []
    sampled_count = 0
    for file_path in sorted(files_map.keys()):
        if sampled_count >= MAX_SAMPLED_WRAPPERS:
            break
        funcs = files_map[file_path]
        remaining_slots = MAX_SAMPLED_WRAPPERS - sampled_count
        sampled_funcs = funcs[:remaining_slots]
        sampled_files.append({
            "file": file_path,
            "functions": sampled_funcs,
            "total_functions": len(funcs),
        })
        sampled_count += len(sampled_funcs)

    return {
        "id": "ast_walk",
        "title": STAGE_TITLES["ast_walk"],
        "caption": STAGE_CAPTIONS["ast_walk"],
        "files": sampled_files,
        "total_wrappers": total_wrappers,
        "sampled_wrappers": sampled_count,
    }


def _build_llm_phase1_stage(llm_results: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 3 — AI identifies dangerous sink modules."""
    sink_modules = {}
    sink_reasons = {}

    for lang_key, section in llm_results.items():
        if not isinstance(section, dict):
            continue
        modules_info = section.get("modules") or {}
        sinks = modules_info.get("sink_modules") or []
        reason = modules_info.get("reason") or ""
        sink_modules[lang_key] = [str(s) for s in sinks if s]
        sink_reasons[lang_key] = str(reason)

    return {
        "id": "llm_phase1",
        "title": STAGE_TITLES["llm_phase1"],
        "caption": STAGE_CAPTIONS["llm_phase1"],
        "sink_modules": sink_modules,
        "sink_reasons": sink_reasons,
    }


def _build_llm_phase2_stage(
    llm_results: Dict[str, Any],
    chunk_stats_raw: Dict[str, Any],
) -> Dict[str, Any]:
    """Stage 4 — AI vulnerability analysis with chunk progress."""
    all_findings = []

    for lang_key, section in llm_results.items():
        if not isinstance(section, dict):
            continue
        wrappers = section.get("wrapper_functions") or []
        for w in wrappers:
            all_findings.append({
                "function_name": w.get("function_name", ""),
                "file": w.get("file", ""),
                "vulnerability_type": w.get("vulnerability_type", ""),
                "severity": w.get("severity", "MEDIUM"),
                "vulnerable_parameter": w.get("vulnerable_parameter", ""),
                "malicious_payload": str(w.get("malicious_payload", ""))[:200],
                "exploit_explanation": str(w.get("exploit_explanation", ""))[:300],
                "impact_summary": str(w.get("impact_summary", ""))[:300],
                "calls": [str(c) for c in (w.get("calls") or [])[:5] if c],
                "modules_used": [str(m) for m in (w.get("modules_used") or [])[:5] if m],
            })

    chunk_stats = {
        "total": chunk_stats_raw.get("total_chunks", 0),
        "succeeded": chunk_stats_raw.get("succeeded", 0),
        "failed": chunk_stats_raw.get("failed", 0),
        "manual_review": chunk_stats_raw.get("manual_review", 0),
    }

    return {
        "id": "llm_phase2",
        "title": STAGE_TITLES["llm_phase2"],
        "caption": STAGE_CAPTIONS["llm_phase2"],
        "chunk_stats": chunk_stats,
        "findings": all_findings[:MAX_SAMPLED_FINDINGS],
        "total_findings": len(all_findings),
        "sampled_findings": min(len(all_findings), MAX_SAMPLED_FINDINGS),
    }


def _build_rule_generation_stage(
    llm_results: Dict[str, Any],
    custom_rules_yaml: str,
    rules_count: int,
) -> Dict[str, Any]:
    """Stage 5 — Custom Semgrep rule generation."""
    return {
        "id": "rule_generation",
        "title": STAGE_TITLES["rule_generation"],
        "caption": STAGE_CAPTIONS["rule_generation"],
        "rules_generated": rules_count,
        "yaml_preview": custom_rules_yaml[:YAML_PREVIEW_CHARS] if custom_rules_yaml else "",
        "has_full_yaml": len(custom_rules_yaml) > YAML_PREVIEW_CHARS,
    }


def _build_scan_comparison_stage(
    vulnerabilities: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Stage 6 — Traditional vs. Dynamic scan comparison.

    Partitions vulnerabilities by rule_id prefix:
    - fixora-wrapper-* or fixora-manual-review-* → dynamic (AI-generated)
    - everything else → traditional (built-in Semgrep rules)

    This is the ENTIRE "traditional vs dynamic Semgrep" feature —
    no second scan needed.
    """
    traditional = []
    dynamic_only = []

    for v in vulnerabilities:
        rule_id = str(v.get("rule_id") or "").lower()
        is_dynamic = (
            rule_id.startswith("fixora-wrapper-")
            or rule_id.startswith("fixora-manual-review-")
        )

        entry = {
            "rule_id": v.get("rule_id", ""),
            "title": v.get("title", "Unknown"),
            "severity": v.get("severity", "medium"),
            "file_path": v.get("file_path", ""),
            "type": v.get("type", ""),
            "vulnerability_type": v.get("type", ""),
            "line_number": v.get("line_number"),
        }

        if is_dynamic:
            dynamic_only.append(entry)
        else:
            traditional.append(entry)

    # Severity distribution for chart
    def _severity_counts(items):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in items:
            sev = str(item.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    return {
        "id": "scan_comparison",
        "title": STAGE_TITLES["scan_comparison"],
        "caption": STAGE_CAPTIONS["scan_comparison"],
        "traditional_count": len(traditional),
        "dynamic_only_count": len(dynamic_only),
        "traditional_severity": _severity_counts(traditional),
        "dynamic_severity": _severity_counts(dynamic_only),
        "traditional_findings": traditional[:MAX_TRADITIONAL_FINDINGS],
        "dynamic_only_findings": dynamic_only[:MAX_DYNAMIC_FINDINGS],
        "total_traditional": len(traditional),
        "total_dynamic": len(dynamic_only),
    }
