# LLM Service - Wrapper Hunter Analysis
# Receives wrapper_hunter_results.json, returns sink_modules.json
import logging
import json
from typing import Dict, Any, Optional
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# ─────────────────────────────────────────────────────────────────────────────
# PROMPT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_wrapper_analysis_prompt(wrapper_data: Dict[str, Any]) -> str:
    """
    Build a prompt from wrapper_hunter_results.json.

    wrapper_data shape:
    {
      "language": "python" | "react" | "both",
      "results": {
          "python": {
              "modules": { "from_manifest": [...], "from_imports": [...], "all": [...] },
              "wrapper_functions": [ { function_name, file, line_start, line_end,
                                       calls, modules_used, source_code } ]
          },
          "react": { ... same ... }
      }
    }

    Expected LLM response (sink_modules.json):
    {
      "language": "python" | "react" | "both",
      "results": {
          "python": {
              "modules": {
                  "sink_modules": [...],   // subset of all[] that are actually dangerous
                  "reason": "..."
              },
              "wrapper_functions": [       // ONLY vulnerable functions
                  {
                      "function_name": "...",
                      "file": "...",
                      "vulnerability_type": "SQL Injection | RCE | SSRF | Path Traversal | ...",
                      "severity": "HIGH | MEDIUM | LOW",
                      "calls": [...],
                      "modules_used": [...],
                      "source_code": "...",
                      "reason": "One-line explanation of why this is vulnerable"
                  }
              ]
          },
          "react": { ... same ... }
      },
      "analysis_summary": "..."
    }
    """
    parts = []

    parts.append(
        "You are an expert application-security engineer performing static analysis.\n\n"
        "I will give you the output of a 'Wrapper Hunter' pre-scan tool. It contains:\n"
        "  1. modules.json  - Every module imported across the codebase, split by source\n"
        "     - from_manifest : packages explicitly in requirements.txt / package.json\n"
        "     - from_imports  : all modules found via import statements (incl. stdlib)\n"
        "     - all           : union of both lists\n"
        "  2. wrapper_functions - Custom functions that call at least one of these modules\n\n"
        "YOUR TASKS:\n"
        "  A. From the 'all' modules list, identify only the DANGEROUS SINK modules\n"
        "     (modules that can cause RCE, SQLi, SSRF, path traversal, command injection,\n"
        "      deserialization, XXE, or other critical vulnerabilities when misused).\n\n"
        "  B. For each wrapper_function, examine its source code and determine:\n"
        "     - Does it pass user-controlled data to a dangerous sink WITHOUT proper sanitization?\n"
        "     - If YES -> include it in the output with vulnerability_type, severity, and reason.\n"
        "     - If NO  -> skip it entirely.\n\n"
        "SEVERITY GUIDELINES:\n"
        "  HIGH   - Direct path from user input to sink, no sanitization (e.g. raw SQL concat)\n"
        "  MEDIUM - Partial sanitization or indirect path\n"
        "  LOW    - Theoretical risk, unlikely to be exploitable\n\n"
        "RESPOND WITH ONLY VALID JSON. No markdown, no explanation outside the JSON.\n"
        "Use this EXACT structure (sink_modules.json):\n\n"
        "{\n"
        '  "language": "<same as input>",\n'
        '  "results": {\n'
        '    "python": {\n'
        '      "modules": {\n'
        '        "sink_modules": ["os", "subprocess", ...],\n'
        '        "reason": "Brief explanation of why these are sinks"\n'
        '      },\n'
        '      "wrapper_functions": [\n'
        '        {\n'
        '          "function_name": "...",\n'
        '          "file": "...",\n'
        '          "vulnerability_type": "SQL Injection",\n'
        '          "severity": "HIGH",\n'
        '          "calls": ["sqlite3.execute"],\n'
        '          "modules_used": ["sqlite3"],\n'
        '          "source_code": "...",\n'
        '          "reason": "User input concatenated directly into SQL query"\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  },\n'
        '  "analysis_summary": "X vulnerable wrappers found across Y files."\n'
        "}\n\n"
        "If a language section has no vulnerable wrappers, still include the key but with "
        "wrapper_functions as an empty list and sink_modules as the dangerous subset.\n"
        "If NO vulnerabilities are found at all, return:\n"
        '{"language":"<lang>","results":{},"analysis_summary":"No vulnerable wrappers found."}\n\n'
        "=== WRAPPER HUNTER INPUT DATA ===\n\n"
    )

    language = wrapper_data.get("language", "unknown")
    parts.append(f"Language detected: {language}\n\n")

    results = wrapper_data.get("results", {})

    for lang_key, lang_label, code_fence in [
        ("python", "PYTHON PROJECT", "python"),
        ("react",  "REACT / NODE.JS PROJECT", "javascript"),
    ]:
        if lang_key not in results:
            continue

        section = results[lang_key]
        modules = section.get("modules", {})
        wrappers = section.get("wrapper_functions", [])

        parts.append(f"--- {lang_label} ---\n")
        parts.append(f"from_manifest ({len(modules.get('from_manifest', []))} packages): "
                     f"{', '.join(modules.get('from_manifest', [])) or 'none'}\n")
        parts.append(f"from_imports  ({len(modules.get('from_imports', []))} modules): "
                     f"{', '.join(modules.get('from_imports', [])) or 'none'}\n")
        # Cap 'all' list to 150 entries to avoid blowing input token budget
        all_mods = modules.get('all', [])
        shown = all_mods[:150]
        truncated = len(all_mods) - len(shown)
        all_display = ', '.join(shown) + (f" ... (+{truncated} more)" if truncated else "")
        parts.append(f"all modules   ({len(all_mods)} total): {all_display or 'none'}\n\n")

        if wrappers:
            parts.append(f"Wrapper functions ({len(wrappers)} found):\n\n")
            for i, w in enumerate(wrappers, 1):
                parts.append(f"[{i}] {w.get('function_name', '?')} "
                              f"({w.get('file', '?')} L{w.get('line_start', '?')}-{w.get('line_end', '?')})\n")
                parts.append(f"    calls       : {', '.join(w.get('calls', []))}\n")
                parts.append(f"    modules_used: {', '.join(w.get('modules_used', []))}\n")
                parts.append(f"    source:\n```{code_fence}\n{w.get('source_code', '')}\n```\n\n")
        else:
            parts.append("No wrapper functions found (no functions call any imported module).\n\n")

    return "".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# LLM CALLER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_wrappers_with_llm(wrapper_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send wrapper_hunter_results.json to Groq LLM.
    Returns sink_modules.json  (same structure, but only vulnerable items).
    Uses AsyncOpenAI so the event loop is never blocked.
    """
    from openai import AsyncOpenAI

    groq_token = settings.groq_api_key
    if not groq_token:
        logger.error("GROQ_API_KEY not configured.")
        return _empty_result(wrapper_data, error="GROQ_API_KEY not configured")

    prompt = build_wrapper_analysis_prompt(wrapper_data)

    logger.info("=" * 80)
    logger.info("WRAPPER HUNTER PROMPT → Groq LLM")
    logger.info("=" * 80)
    logger.info(prompt)
    logger.info("=" * 80)

    try:
        client = AsyncOpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=groq_token,
        )

        completion = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert application-security engineer. "
                        "You analyze code for vulnerabilities and respond ONLY with valid JSON. "
                        "Never include markdown code fences or any text outside the JSON object."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            max_tokens=4096,
            temperature=0.1,  # Low temperature for more deterministic/accurate output
        )

        raw_response = completion.choices[0].message.content

        logger.info("=" * 80)
        logger.info("Groq LLM RAW RESPONSE (sink_modules.json):")
        logger.info("=" * 80)
        logger.info(raw_response)
        logger.info("=" * 80)

        result = _extract_json_from_response(raw_response)

        if result is None:
            logger.warning("Could not parse LLM response as JSON")
            return _empty_result(
                wrapper_data,
                error="LLM response could not be parsed as JSON",
                raw_response=raw_response,
            )

        # Ensure top-level keys exist
        result.setdefault("language", wrapper_data.get("language", "unknown"))
        result.setdefault("results", {})
        result.setdefault("analysis_summary", "Analysis complete")

        logger.info("=" * 80)
        logger.info("PARSED sink_modules.json (final LLM output):")
        logger.info("=" * 80)
        logger.info(json.dumps(result, indent=2))
        logger.info("=" * 80)
        return result

    except Exception as exc:
        logger.error(f"Error calling Groq LLM: {exc}")
        return _empty_result(wrapper_data, error=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _empty_result(wrapper_data: Dict[str, Any], error: str = "", raw_response: str = "") -> Dict[str, Any]:
    """Return a safe empty sink_modules.json when LLM fails."""
    out: Dict[str, Any] = {
        "language": wrapper_data.get("language", "unknown"),
        "results": {},
        "analysis_summary": f"Analysis failed: {error}" if error else "No results",
    }
    if error:
        out["error"] = error
    if raw_response:
        out["raw_response"] = raw_response
    return out


def _extract_json_from_response(text: str) -> Optional[Dict]:
    """Bulletproof JSON extractor: handles raw JSON, markdown fences, and stray text."""
    import re

    # 0. Pre-strip: remove ALL markdown code-fence wrappers first so later steps
    #    never see backtick characters inside the candidate string.
    clean = re.sub(r'^```(?:json)?\s*', '', text.strip(), flags=re.MULTILINE)
    clean = re.sub(r'^```\s*$', '', clean, flags=re.MULTILINE)
    clean = clean.strip()

    # 1. Direct parse of cleaned text
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass

    # 2. Regex-captured markdown code fences on original text (handles multi-line fences)
    fence_patterns = [
        r'```json\s*\n([\s\S]*?)\n```',
        r'```\s*\n([\s\S]*?)\n```',
        r'```json([\s\S]*?)```',
        r'```([\s\S]*?)```',
    ]
    for pattern in fence_patterns:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except json.JSONDecodeError:
                continue

    # 3. Find the outermost balanced { ... } block in the cleaned text
    start = clean.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(clean)):
            if clean[i] == "{":
                depth += 1
            elif clean[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(clean[start:i + 1])
                    except json.JSONDecodeError:
                        break

    return None
