# LLM Service - Wrapper Hunter Analysis
# Receives wrapper_hunter_results.json, returns sink_modules.json
import logging
import json
import os
from typing import Dict, Any, Optional
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

ALLOWED_VULNERABILITY_TYPES = {
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "XSS",
    "SSRF",
    "Insecure Deserialization",
    "IDOR / Broken Access Control",
    "Cryptographic Failure",
    "Hardcoded Secret",
    "Business Logic Flaw",
    "Security Misconfiguration",
}

FRONTEND_IMPOSSIBLE_TYPES = {
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
}

# ─────────────────────────────────────────────────────────────────────────────
# PROMPT BUILDERS — 2-phase LLM analysis
# ─────────────────────────────────────────────────────────────────────────────

def _format_module_section(lang_key: str, modules: Dict[str, Any]) -> str:
    """Render module lists into a compact, readable string for prompts."""
    lang_label = "PYTHON PROJECT" if lang_key == "python" else "REACT / NODE.JS PROJECT"
    from_manifest = [str(m) for m in modules.get("from_manifest", []) if m is not None]
    from_imports  = [str(m) for m in modules.get("from_imports",  []) if m is not None]
    all_mods      = [str(m) for m in modules.get("all",           []) if m is not None]

    shown     = all_mods[:150]
    truncated = len(all_mods) - len(shown)
    all_display = ", ".join(shown) + (f" ... (+{truncated} more)" if truncated else "")

    return (
        f"--- {lang_label} ---\n"
        f"from_manifest ({len(from_manifest)} packages): {', '.join(from_manifest) or 'none'}\n"
        f"from_imports  ({len(from_imports)} modules): {', '.join(from_imports) or 'none'}\n"
        f"all modules   ({len(all_mods)} total): {all_display or 'none'}\n"
    )


def build_module_sink_prompt(lang_key: str, modules: Dict[str, Any]) -> str:
    """
    PHASE 1 prompt — sent ONCE per language before any function analysis.

    Asks the LLM to identify which modules in the project are dangerous
    security sinks (SQL, OS commands, network, serialization, etc.).

    Expected response::

        {
          "sink_modules": ["os", "subprocess", "sqlite3"],
          "reason": "Brief explanation"
        }
    """
    lang_label = "Python" if lang_key == "python" else "JavaScript/React/Node.js"
    return (
        "You are an expert application-security engineer.\n\n"
        f"I am scanning a {lang_label} project and need to know which imported modules "
        "are DANGEROUS SECURITY SINKS — modules that, when misused, can lead to:\n"
        "  • SQL / NoSQL / LDAP / XPath injection\n"
        "  • OS command injection / RCE\n"
        "  • SSRF / open redirect\n"
        "  • Path traversal / arbitrary file read-write\n"
        "  • Insecure deserialization\n"
        "  • XXE / template injection / prototype pollution\n"
        "  • Cryptographic failures (weak hashing, bad PRNG)\n"
        "  • Hardcoded secrets and broken authentication gates\n\n"
        "Respond ONLY with valid JSON (no markdown, no extra text):\n"
        '{"sink_modules": ["mod1", "mod2", ...], "reason": "One sentence explanation"}\n\n'
        "If NO modules are sinks, respond:\n"
        '{"sink_modules": [], "reason": "No dangerous sink modules detected."}\n\n'
        "=== MODULE LIST ===\n\n"
        + _format_module_section(lang_key, modules)
    )


def build_function_chunk_prompt(
    lang_key: str,
    modules: Dict[str, Any],
    sink_modules: list,
    sink_reason: str,
    wrappers: list,
) -> str:
    """
    PHASE 2 prompt — sent for EACH chunk of wrapper functions.

    Embeds the sink modules identified in Phase 1 as context so the LLM
    focuses on whether each function passes user input to those known sinks
    without proper sanitisation.

    Expected response::

        {
          "language": "<same as input>",
          "results": {
            "<lang_key>": {
              "wrapper_functions": [
                {
                  "function_name": "...",
                  "file": "...",
                  "vulnerability_type": "SQL Injection",
                  "severity": "HIGH",
                  "calls": [...],
                  "modules_used": [...],
                  "reason": "..."
                }
              ]
            }
          },
          "analysis_summary": "X vulnerable wrappers found."
        }
    """
    code_fence  = "python" if lang_key == "python" else "javascript"

    # ── Function list ─────────────────────────────────────────────────────
    func_parts = []
    for i, w in enumerate(wrappers, 1):
        calls        = [str(c) for c in (w.get("calls")        or []) if c is not None]
        modules_used = [str(m) for m in (w.get("modules_used") or []) if m is not None]
        env = w.get("environment", "BACKEND")
        auth = "Present" if w.get("has_auth_check", True) else "None detected"
        func_parts.append(
            f"[{i}] {w.get('function_name', '?')} ({w.get('file', '?')})\n"
            f"    Environment : {env}\n"
            f"    Auth Checks : {auth}\n"
            f"    calls       : {', '.join(calls)}\n"
            f"    modules_used: {', '.join(modules_used)}\n"
            f"    source:\n```{code_fence}\n{w.get('source_code', '')}\n```\n\n"
        )

    return (
        "You are an expert application-security engineer. Analyze these wrappers.\n\n"
        "TAXONOMY GUIDELINES (STRICT ENUMERATION):\n"
        "The 'vulnerability_type' MUST be exactly one of the following:\n"
        "['SQL Injection', 'Command Injection', 'Path Traversal', 'XSS', 'SSRF', 'Insecure Deserialization', 'IDOR / Broken Access Control', 'Cryptographic Failure', 'Hardcoded Secret', 'Business Logic Flaw', 'Security Misconfiguration']\n\n"
        "EXCLUSION RULES (CRITICAL):\n"
        "1. FRONTEND RULE: If 'Environment' is 'BROWSER (Frontend)', it is MATHEMATICALLY IMPOSSIBLE for it to have SQL Injection, Command Injection, or Path Traversal. Ignore generic fetch() or console.log() calls here.\n"
        "2. ORM RULE: Assume Supabase, Prisma, and TypeORM queries are perfectly parameterized by default. Do NOT flag them for SQLi.\n"
        "3. VULNERABILITY HIERARCHY: If 'Auth Checks' is 'None detected', do NOT blindly flag it as IDOR. You MUST check for Injection first. If you see SQL string concatenation (SQLi), subprocess execution (Command Injection), os.remove/open (Path Traversal), or resolve_entities=True (XXE/Deserialization), you MUST flag the Injection flaw. Injection is always a higher priority than IDOR.\n"
        "4. FORMAT STRINGS: In JavaScript/TypeScript, template literals (e.g., `console.log(`Error: ${err}`)`) are safe. Do NOT flag them as Unsafe Format Strings (this is a C/C++ concept).\n\n"
        "SINK CONTEXT:\n"
        f"Known sink modules: {', '.join(sink_modules) if sink_modules else 'none'}\n"
        f"Sink reason: {sink_reason or 'No pre-identified sink context.'}\n\n"
        "RESPOND WITH ONLY VALID JSON. No markdown, no text outside the JSON.\n"
        "IMPORTANT: Do NOT include \"source_code\" in your output.\n"
        "Use this EXACT structure:\n\n"
        "{\n"
        '  "language": "<same as input>",\n'
        '  "results": {\n'
        f'    "{lang_key}": {{\n'
        '      "wrapper_functions": [\n'
        '        {\n'
        '          "function_name": "...",\n'
        '          "file": "...",\n'
        '          "vulnerability_type": "SQL Injection",\n'
        '          "severity": "HIGH",\n'
        '          "calls": ["sqlite3.execute"],\n'
        '          "modules_used": ["sqlite3"],\n'
        '          "reason": "User input concatenated directly into SQL query"\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  },\n'
        '  "analysis_summary": "X vulnerable wrappers found."\n'
        "}\n\n"
        f"If NO vulnerabilities are found return:\n"
        f'{{"language":"<lang>","results":{{"{lang_key}":{{"wrapper_functions":[]}}}},"analysis_summary":"No vulnerable wrappers found."}}\n\n'
        f"=== WRAPPER FUNCTIONS ({len(wrappers)}) ===\n\n"
        + "".join(func_parts)
    )


def _normalize_vulnerability_type(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None

    aliases = {
        "sqli": "SQL Injection",
        "sql injection": "SQL Injection",
        "command injection": "Command Injection",
        "path traversal": "Path Traversal",
        "xss": "XSS",
        "cross site scripting": "XSS",
        "cross-site scripting": "XSS",
        "ssrf": "SSRF",
        "insecure deserialization": "Insecure Deserialization",
        "idor": "IDOR / Broken Access Control",
        "bola": "IDOR / Broken Access Control",
        "idor / broken access control": "IDOR / Broken Access Control",
        "broken access control": "IDOR / Broken Access Control",
        "cryptographic failure": "Cryptographic Failure",
        "hardcoded secret": "Hardcoded Secret",
        "hardcoded secrets": "Hardcoded Secret",
        "business logic flaw": "Business Logic Flaw",
        "security misconfiguration": "Security Misconfiguration",
    }

    key = raw.lower()
    normalized = aliases.get(key)
    if normalized in ALLOWED_VULNERABILITY_TYPES:
        return normalized
    if raw in ALLOWED_VULNERABILITY_TYPES:
        return raw
    return None


def _sanitize_llm_wrappers(chunk_wrappers: list, ai_wrappers: list) -> list:
    """Enforce strict taxonomy and frontend exclusion rules on AI output."""
    if not isinstance(ai_wrappers, list):
        return []

    context_by_key = {}
    for w in chunk_wrappers:
        fn = str(w.get("function_name") or "").strip()
        fp = str(w.get("file") or "").strip()
        context_by_key[(fn, fp)] = w

    cleaned = []
    for row in ai_wrappers:
        if not isinstance(row, dict):
            continue

        vuln_type = _normalize_vulnerability_type(row.get("vulnerability_type"))
        if not vuln_type:
            continue

        fn = str(row.get("function_name") or "").strip()
        fp = str(row.get("file") or "").strip()
        ctx = context_by_key.get((fn, fp), {})
        env = str(ctx.get("environment") or "BACKEND")

        if env == "BROWSER (Frontend)" and vuln_type in FRONTEND_IMPOSSIBLE_TYPES:
            continue

        item = dict(row)
        item["vulnerability_type"] = vuln_type
        cleaned.append(item)

    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# LLM CALLER (RATE-LIMITED SEQUENTIAL CHUNKING)
# ─────────────────────────────────────────────────────────────────────────────

MAX_RETRIES = 3                  # Retry attempts per chunk (helps transient 429s)
SOURCE_CODE_CHAR_LIMIT = 1500   # Max chars of source_code sent per function (~375 tokens)

# ── Rate limiting (Groq) ─────────────────────────────────────────────────────
# These defaults match the dashboard limits shown in your screenshots:
# ~30 RPM and ~12K TPM for the selected model.
GROQ_TPM_LIMIT = int(os.getenv("GROQ_TPM_LIMIT", "12000"))
GROQ_RPM_LIMIT = int(os.getenv("GROQ_RPM_LIMIT", "30"))
TOKEN_BUFFER = float(os.getenv("GROQ_TOKEN_BUFFER", "0.80"))
EFFECTIVE_TPM = int(GROQ_TPM_LIMIT * TOKEN_BUFFER)  # default: 9600

# Keep headroom under raw limits to reduce 429 risk during noisy periods.
MAX_RPM = min(int(os.getenv("GROQ_MAX_RPM", "20")), GROQ_RPM_LIMIT)
MIN_REQUEST_GAP_SECONDS = float(os.getenv("GROQ_MIN_REQUEST_GAP_SECONDS", "3"))

# 429 handling: wait at least this long, but also honor remaining window time.
RATE_LIMIT_BACKOFF = int(os.getenv("GROQ_RATE_LIMIT_BACKOFF", "20"))
RATE_LIMIT_JITTER_MAX = int(os.getenv("GROQ_RATE_LIMIT_JITTER_MAX", "10"))

# ── Dynamic chunking ──────────────────────────────────────────────────────────
# Estimated token cost of prompt overhead per chunk:
# system message + module list headers + formatting (~600 tokens)
PROMPT_OVERHEAD_TOKENS = 600
# Token budget available for function content inside a single Groq request.
# Keep this tied directly to effective TPM to preserve the original greedy
# chunking behavior.
FUNCTION_BUDGET_PER_CHUNK = EFFECTIVE_TPM - PROMPT_OVERHEAD_TOKENS


def _estimate_function_tokens(func: dict) -> int:
    """
    Estimate the token cost of a single wrapper function entry in the LLM
    prompt.  Uses the same truncation cap (SOURCE_CODE_CHAR_LIMIT) so the
    estimate reflects what will actually be sent.

    Adds a +30 token overhead per function for template formatting (brackets,
    labels, whitespace).
    """
    src = (func.get("source_code") or "")[:SOURCE_CODE_CHAR_LIMIT]
    calls = [str(c) for c in (func.get("calls") or []) if c is not None]
    mods  = [str(m) for m in (func.get("modules_used") or []) if m is not None]
    text  = " ".join([
        func.get("function_name", ""),
        func.get("file", ""),
        str(func.get("line_start", "")),
        str(func.get("line_end", "")),
        ", ".join(calls),
        ", ".join(mods),
        src,
    ])
    return max(1, len(text) // 4) + 30  # +30 for per-function prompt formatting


def _build_dynamic_chunks(all_wrappers: list) -> list:
    """
    Group wrapper functions into token-aware chunks.  No function is ever
    split across two chunks — each function always appears whole.

    Algorithm (greedy bin-packing):
    * Estimate each function's token cost with ``_estimate_function_tokens``.
    * Accumulate functions into the current chunk while the running total
      stays within FUNCTION_BUDGET_PER_CHUNK.
    * When adding the next function would exceed the budget, flush the current
      chunk and start a new one.
    * If a *single* function alone exceeds the budget (rare — source_code is
      already capped at SOURCE_CODE_CHAR_LIMIT), it gets its own chunk with
      ``oversized=True``.  The chunk is still sent to Groq; an HTTP 413 is
      the only condition that escalates it to manual review.

    Returns a list of dicts::

        {
          "funcs":       [wrapper_dict, ...],
          "func_tokens": int,   # sum of per-function token estimates
          "oversized":   bool,  # True → single fn fills the whole chunk
        }
    """
    chunks: list = []
    current_funcs: list = []
    current_tokens: int = 0

    for func in all_wrappers:
        func_tokens = _estimate_function_tokens(func)

        if not current_funcs:
            # Start a new chunk — always accept even if this one function
            # alone exceeds the budget (will be marked oversized on flush).
            current_funcs = [func]
            current_tokens = func_tokens
        elif current_tokens + func_tokens <= FUNCTION_BUDGET_PER_CHUNK:
            # Fits in the current chunk — append.
            current_funcs.append(func)
            current_tokens += func_tokens
        else:
            # Overflows — flush current chunk first, then start fresh.
            chunks.append({
                "funcs":       current_funcs,
                "func_tokens": current_tokens,
                "oversized":   (
                    len(current_funcs) == 1
                    and current_tokens > FUNCTION_BUDGET_PER_CHUNK
                ),
            })
            current_funcs  = [func]
            current_tokens = func_tokens

    # Flush the final chunk
    if current_funcs:
        chunks.append({
            "funcs":       current_funcs,
            "func_tokens": current_tokens,
            "oversized":   (
                len(current_funcs) == 1
                and current_tokens > FUNCTION_BUDGET_PER_CHUNK
            ),
        })

    return chunks


async def analyze_wrappers_with_llm(
    wrapper_data: Dict[str, Any],
    progress_callback=None,
) -> Dict[str, Any]:
    """
    Two-phase LLM analysis of wrapper functions.

    **Phase 1 — Sink identification (once per language)**
    Send the module list alone to Groq and ask which modules are dangerous
    security sinks.  This gives targeted context for Phase 2.

    **Phase 2 — Function vulnerability analysis (once per chunk)**
    Send each dynamic chunk of wrapper functions WITH the identified sinks
    embedded as context.  The model focuses on whether each function passes
    user input to the known sinks without sanitisation.

    Rate-limiting / error handling:
    * Token budget per minute = EFFECTIVE_TPM (GROQ_TPM_LIMIT * TOKEN_BUFFER).
    * Hard cap of MAX_RPM requests per 60-second window.
    * 429 → global back-off of RATE_LIMIT_BACKOFF + jitter, then retry (up to
      MAX_RETRIES).  Phase 1 failure → continue with empty sinks list.
    * 413 → chunk too large; record in ``manual_review_required``; no retry.

    Returns the merged result plus a ``_chunk_meta`` key that records per-chunk
    status (for AI-debug storage).

    *progress_callback* — optional ``async def(msg: dict)`` called after every
    Phase 2 chunk so the caller can forward WebSocket updates with ETA.
    """
    import asyncio
    import time
    import random

    language = wrapper_data.get("language", "unknown")
    final_merged_result: Dict[str, Any] = {
        "language": language,
        "results": {},
        "analysis_summary": "",
    }

    results = wrapper_data.get("results", {})
    total_vuln_wrappers = 0
    total_sinks: set = set()
    all_chunk_meta: list = []
    manual_review_required: list = []

    # ── Pre-compute dynamic chunks across ALL languages (for accurate ETA) ─
    chunks_by_lang: Dict[str, list] = {}
    total_phase2_chunks = 0  # total Phase 2 chunks across all languages

    for lang_key, env_data in results.items():
        all_wrappers = env_data.get("wrapper_functions", [])
        final_merged_result["results"][lang_key] = {
            "modules": {
                "sink_modules": [],
                "reason": "",
            },
            "wrapper_functions": [],
        }
        if all_wrappers:
            lang_chunks = _build_dynamic_chunks(all_wrappers)
            chunks_by_lang[lang_key] = lang_chunks
            total_phase2_chunks += len(lang_chunks)
            oversized_count = sum(1 for c in lang_chunks if c["oversized"])
            logger.info(
                f"[{lang_key}] {len(all_wrappers)} wrapper(s) → "
                f"{len(lang_chunks)} dynamic chunk(s) "
                f"(fn-budget {FUNCTION_BUDGET_PER_CHUNK} tokens/chunk"
                + (f", {oversized_count} oversized" if oversized_count else "")
                + ")."
            )
        else:
            logger.info(f"[{lang_key}] No wrappers found. Skipping LLM call.")

    # Total calls = 1 Phase 1 per language-with-wrappers + all Phase 2 chunks
    langs_with_wrappers = list(chunks_by_lang.keys())
    total_calls = len(langs_with_wrappers) + total_phase2_chunks

    if total_phase2_chunks == 0:
        final_merged_result["analysis_summary"] = "No wrapper functions to analyse."
        final_merged_result["_chunk_meta"] = {
            "total_chunks": 0, "succeeded": 0, "failed": 0,
            "manual_review": 0, "oversized_chunks": 0,
            "manual_review_required": [],
            "chunk_details": [],
        }
        return final_merged_result

    # ── Rate-limiter state (shared across all languages) ──────────────────
    rate_state = {
        "minute_start": time.monotonic(),
        "requests_this_minute": 0,
        "tokens_this_minute": 0,
        "last_request_ts": 0.0,
    }

    # ── ETA tracking ──────────────────────────────────────────────────────
    # NOTE: phase_start is set PER-LANGUAGE just before Phase 2 so that Phase 1
    # wait time does not inflate the per-chunk average.
    processed_total = 0  # counts Phase 2 chunks processed (for ETA)

    # ── Process language-by-language ──────────────────────────────────────
    for lang_key in langs_with_wrappers:
        modules = results[lang_key].get("modules", {})
        chunks  = chunks_by_lang[lang_key]

        # ── PHASE 1: identify dangerous sink modules ──────────────────────
        logger.info(f"[{lang_key}] === Phase 1: module sink identification ===")
        sink_modules, sink_reason = await _call_groq_module_phase(
            lang_key, modules, rate_state
        )
        # Store Phase 1 sinks in the merged result immediately
        final_merged_result["results"][lang_key]["modules"]["sink_modules"] = sink_modules
        final_merged_result["results"][lang_key]["modules"]["reason"] = sink_reason
        for s in sink_modules:
            total_sinks.add(s)

        # ── PHASE 2: analyse each function chunk with sink context ─────────
        logger.info(f"[{lang_key}] === Phase 2: {len(chunks)} function chunk(s) ===")
        phase_start = time.monotonic()  # reset timer here — excludes Phase 1 wait

        # Emit preliminary progress so frontend knows total chunk count immediately
        if progress_callback:
            try:
                await progress_callback({
                    "type":      "llm_chunk_progress",
                    "lang":      lang_key,
                    "chunk_idx": -1,
                    "processed": processed_total,
                    "total":     total_phase2_chunks,
                    "failed":    0,
                    "manual_review": 0,
                    "estimated_seconds_remaining": None,
                    "message": (
                        f"AI analysis: phase 1 complete — "
                        f"{len(sink_modules)} sink(s) identified. "
                        f"Analysing {total_phase2_chunks} chunk(s)..."
                    ),
                })
            except Exception as e:
                logger.warning(f"Failed to send Phase 1→2 progress: {e}")
        for chunk_idx, chunk_info in enumerate(chunks):
            chunk     = chunk_info["funcs"]
            oversized = chunk_info["oversized"]
            # Total estimated tokens = function content + prompt overhead
            estimated_tokens = chunk_info["func_tokens"] + PROMPT_OVERHEAD_TOKENS

            # Build phase-2 prompt with truncated source_code
            truncated_chunk = [
                {**w, "source_code": (w.get("source_code") or "")[:SOURCE_CODE_CHAR_LIMIT]}
                for w in chunk
            ]
            prompt = build_function_chunk_prompt(
                lang_key, modules, sink_modules, sink_reason, truncated_chunk
            )

            chunk_payload = {
                "language": language,
                "results": {
                    lang_key: {
                        "modules": modules,
                        "wrapper_functions": chunk,
                    }
                },
            }

            # ── Rate-limit gate ───────────────────────────────────────────
            await _rate_limit_wait(rate_state, estimated_tokens)

            logger.info(
                f"  Phase 2 chunk {chunk_idx+1}/{len(chunks)} [{lang_key}] "
                f"({len(chunk)} fn(s), ~{estimated_tokens} est. tokens)"
                + (" [OVERSIZED — single fn exceeds budget, may 413]" if oversized else "")
            )

            # ── Call Groq with retry / error handling ─────────────────────
            chunk_result, meta = await _call_groq_with_retry(
                chunk_payload, prompt, chunk_idx, len(chunks), lang_key,
                estimated_tokens, rate_state,
            )

            # Annotate meta with chunk-level details before storing
            meta["oversized"]  = oversized
            meta["func_count"] = len(chunk)

            # Record this request against the rate window
            _record_request(rate_state, estimated_tokens)

            all_chunk_meta.append(meta)
            processed_total += 1

            # ── Handle 413 → manual review ────────────────────────────────
            if meta["status"] == "manual_review":
                manual_review_required.append({
                    "chunk_index":    meta["chunk_index"],
                    "lang":           meta["lang"],
                    "function_names": meta["function_names"],
                    "reason": (
                        "Request too large for AI analysis (HTTP 413). "
                        "Review these functions manually."
                    ),
                    "wrapper_count": len(meta["function_names"]),
                    "was_oversized_estimate": oversized,
                })

            elif meta["status"] == "success" and chunk_result:
                # ── Merge successful results ──────────────────────────────
                chunk_results = chunk_result.get("results", {})
                # Accept the lang_key the model echoed (may differ)
                ai_output = chunk_results.get(lang_key) or next(iter(chunk_results.values()), None)
                if ai_output:
                    # Phase 2 may return sink_modules too; merge them in
                    new_sinks = ai_output.get("modules", {}).get("sink_modules", [])
                    current_sinks = final_merged_result["results"][lang_key]["modules"]["sink_modules"]
                    if isinstance(new_sinks, list):
                        for sink in new_sinks:
                            if sink and sink not in current_sinks:
                                current_sinks.append(sink)
                                total_sinks.add(sink)

                    # Merge vulnerable wrapper functions
                    new_wrappers = ai_output.get("wrapper_functions", [])
                    if isinstance(new_wrappers, list):
                        new_wrappers = _sanitize_llm_wrappers(chunk, new_wrappers)
                        final_merged_result["results"][lang_key]["wrapper_functions"].extend(
                            new_wrappers
                        )
                        total_vuln_wrappers += len(new_wrappers)

            # ── Progress + ETA callback ───────────────────────────────────
            if progress_callback:
                try:
                    elapsed = time.monotonic() - phase_start
                    avg_per_chunk = elapsed / processed_total
                    est_remaining = avg_per_chunk * (total_phase2_chunks - processed_total)
                    failed_so_far = sum(1 for m in all_chunk_meta if m["status"] == "failed")

                    await progress_callback({
                        "type":      "llm_chunk_progress",
                        "lang":      lang_key,
                        "chunk_idx": chunk_idx,
                        "processed": processed_total,
                        "total":     total_phase2_chunks,
                        "failed":    failed_so_far,
                        "manual_review": len(manual_review_required),
                        "estimated_seconds_remaining": round(est_remaining),
                        "message": (
                            f"AI analysis: processed {processed_total}/"
                            f"{total_phase2_chunks} chunks"
                            + (f" ({failed_so_far} failed)" if failed_so_far else "")
                            + (f" ({len(manual_review_required)} need manual review)"
                               if manual_review_required else "")
                        ),
                    })
                    logger.info(f"Sent chunk progress: {processed_total}/{total_phase2_chunks}")
                except Exception as e:
                    logger.warning(f"Failed to send chunk progress: {e}")

    # ── Summary ───────────────────────────────────────────────────────────
    failed_chunks = [m for m in all_chunk_meta if m["status"] == "failed"]
    summary_parts = [
        f"Analysis complete. Found {total_vuln_wrappers} vulnerable wrappers "
        f"and {len(total_sinks)} unique sinks.",
    ]
    if failed_chunks:
        summary_parts.append(f" {len(failed_chunks)} chunk(s) failed after retries.")
    if manual_review_required:
        summary_parts.append(
            f" {len(manual_review_required)} chunk(s) too large — flagged for manual review."
        )

    final_merged_result["analysis_summary"] = "".join(summary_parts)
    final_merged_result["_chunk_meta"] = {
        "total_chunks":    len(all_chunk_meta),
        "succeeded":       sum(1 for m in all_chunk_meta if m["status"] == "success"),
        "failed":          len(failed_chunks),
        "manual_review":   len(manual_review_required),
        "oversized_chunks": sum(1 for m in all_chunk_meta if m.get("oversized", False)),
        "manual_review_required": manual_review_required,
        "chunk_details":   all_chunk_meta,
    }

    logger.info("=" * 80)
    logger.info("MERGED CHUNK ANALYSIS COMPLETE (final LLM output):")
    logger.info("=" * 80)
    logger.info(json.dumps(final_merged_result, indent=2)[:5000])
    logger.info("=" * 80)

    return final_merged_result


# ── Rate-limiter helpers ──────────────────────────────────────────────────────

async def _rate_limit_wait(state: dict, estimated_tokens: int):
    """Block until there is room in the current 60-second window for one
    more request of *estimated_tokens* tokens."""
    import time
    import asyncio

    if estimated_tokens > EFFECTIVE_TPM:
        # Oversized estimates can happen for huge single-function chunks.
        # Let the call proceed and rely on HTTP 413 handling instead of deadlocking.
        logger.warning(
            f"Estimated request ({estimated_tokens} tokens) exceeds effective TPM "
            f"({EFFECTIVE_TPM}). Sending anyway and relying on 413/manual-review fallback."
        )
        return

    while True:
        now = time.monotonic()

        # Smooth pacing: avoid bursty back-to-back sends.
        last_ts = state.get("last_request_ts", 0.0)
        if last_ts > 0:
            delta = now - last_ts
            if delta < MIN_REQUEST_GAP_SECONDS:
                gap_wait = MIN_REQUEST_GAP_SECONDS - delta
                logger.info(f"Pacing gap: waiting {gap_wait:.1f}s before next request")
                await asyncio.sleep(gap_wait)
                continue

        elapsed = now - state["minute_start"]
        if elapsed >= 60:
            # Window expired — reset
            state["minute_start"] = now
            state["requests_this_minute"] = 0
            state["tokens_this_minute"] = 0
            return

        needs_wait = (
            state["requests_this_minute"] >= MAX_RPM
            or state["tokens_this_minute"] + estimated_tokens > EFFECTIVE_TPM
        )
        if not needs_wait:
            return

        wait_time = max(0, 60 - elapsed)
        logger.info(
            f"Rate gate: {state['requests_this_minute']} RPM / "
            f"{state['tokens_this_minute']} TPM used, next est={estimated_tokens} — "
            f"waiting {wait_time:.1f}s for next window"
        )
        await asyncio.sleep(wait_time)
        state["minute_start"] = time.monotonic()
        state["requests_this_minute"] = 0
        state["tokens_this_minute"] = 0


def _record_request(state: dict, estimated_tokens: int):
    """Update the rate-limiter counters after a successful send."""
    import time

    state["requests_this_minute"] += 1
    state["tokens_this_minute"] += estimated_tokens
    state["last_request_ts"] = time.monotonic()


async def _handle_429_backoff(state: dict):
    """Global back-off on HTTP 429: sleep RATE_LIMIT_BACKOFF + random jitter
    seconds, then reset the rate window.  The jitter prevents thundering-herd
    when multiple scans share the same API key."""
    import time
    import asyncio
    import random

    elapsed = time.monotonic() - state["minute_start"]
    window_wait = max(0, 60 - elapsed)
    jitter = random.randint(1, RATE_LIMIT_JITTER_MAX) if RATE_LIMIT_JITTER_MAX > 0 else 0
    wait = max(RATE_LIMIT_BACKOFF, int(window_wait)) + jitter
    logger.warning(
        f"Rate limited (429). Backoff: {wait}s "
        f"(base={RATE_LIMIT_BACKOFF}s, window={int(window_wait)}s, jitter={jitter}s)"
    )
    await asyncio.sleep(wait)
    state["minute_start"] = time.monotonic()
    state["requests_this_minute"] = 0
    state["tokens_this_minute"] = 0
    state["last_request_ts"] = 0.0


async def _call_groq_module_phase(
    lang_key: str,
    modules: Dict[str, Any],
    rate_state: dict,
) -> tuple:
    """
    PHASE 1 — identify dangerous sink modules for one language.

    Sends ONLY the module list (no function source code).
    Retries up to MAX_RETRIES times on 429 (with backoff) or generic errors.
    On failure returns ``([], "")`` so Phase 2 continues without sink context.

    Returns: ``(sink_modules: list[str], reason: str)``
    """
    import asyncio

    prompt = build_module_sink_prompt(lang_key, modules)
    # Module-only prompts are very small — rough estimate
    estimated_tokens = max(
        200,
        len(prompt) // 4 + 100,
    )
    context_payload = {"language": lang_key, "results": {lang_key: {"modules": modules}}}

    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(
            f"  Phase 1 [{lang_key}] — module sink detection, attempt {attempt}/{MAX_RETRIES}"
        )
        await _rate_limit_wait(rate_state, estimated_tokens)
        result = await _call_groq_api(prompt, context_payload)
        _record_request(rate_state, estimated_tokens)

        if not result or result.get("error"):
            error_type = result.get("error_type", "") if result else ""
            if error_type == "rate_limit":
                logger.warning(f"  Phase 1 [{lang_key}] — 429 on attempt {attempt}")
                if attempt < MAX_RETRIES:
                    await _handle_429_backoff(rate_state)
                    continue
            elif error_type == "too_large":
                # Module-only prompt too large — extremely unlikely; give up
                logger.warning(f"  Phase 1 [{lang_key}] — 413 (module list too large). Skipping sink detection.")
                break
            elif attempt < MAX_RETRIES:
                backoff = 5 * attempt
                logger.warning(
                    f"  Phase 1 [{lang_key}] — attempt {attempt} failed: "
                    f"{result.get('error', 'unknown') if result else 'no response'}. "
                    f"Retrying in {backoff}s..."
                )
                await asyncio.sleep(backoff)
                continue
            break

        # Success — extract sink_modules and reason
        sink_modules = result.get("sink_modules", [])
        reason       = result.get("reason", "")
        if not isinstance(sink_modules, list):
            sink_modules = []
        sink_modules = [str(s) for s in sink_modules if s is not None]
        logger.info(
            f"  Phase 1 [{lang_key}] — identified {len(sink_modules)} sink(s): {sink_modules}"
        )
        return sink_modules, reason

    logger.warning(
        f"  Phase 1 [{lang_key}] — FAILED after {MAX_RETRIES} attempts. "
        "Continuing Phase 2 without sink context."
    )
    return [], ""


async def _call_groq_with_retry(
    chunk_payload: Dict[str, Any],
    prompt: str,
    chunk_index: int,
    total_chunks: int,
    lang_key: str,
    estimated_tokens: int,
    rate_state: dict,
) -> tuple:
    """
    Call Groq for a single chunk with up to MAX_RETRIES attempts.

    * HTTP 429 → global 2-minute + jitter backoff, then retry.
    * HTTP 413 → skip immediately (manual review), no retry.
    * Other errors → small linear backoff, then retry.

    Returns ``(result_dict | None, meta_dict)``.
    """
    import asyncio

    func_names = [
        w.get("function_name", "?")
        for w in chunk_payload.get("results", {}).get(lang_key, {}).get("wrapper_functions", [])
    ]
    meta = {
        "chunk_index": chunk_index,
        "lang": lang_key,
        "function_names": func_names,
        "status": "failed",
        "attempts": 0,
        "error": None,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        meta["attempts"] = attempt
        logger.info(
            f"  Chunk {chunk_index+1}/{total_chunks} [{lang_key}] — "
            f"attempt {attempt}/{MAX_RETRIES}"
        )
        result = await _call_groq_api(prompt, chunk_payload)

        # ── Success ───────────────────────────────────────────────────────
        if result and not result.get("error"):
            meta["status"] = "success"
            meta["error"] = None
            return result, meta

        error_type = result.get("error_type", "") if result else ""
        error_msg = result.get("error", "Unknown error") if result else "No response"
        meta["error"] = error_msg

        # ── 413 Request Too Large → skip to manual review (no retry) ─────
        if error_type == "too_large":
            logger.warning(
                f"  Chunk {chunk_index+1}/{total_chunks} [{lang_key}] — "
                f"413 Too Large. Flagging for manual review."
            )
            meta["status"] = "manual_review"
            return result, meta

        # ── 429 Rate Limited → global backoff + jitter, then retry ────────
        if error_type == "rate_limit":
            logger.warning(
                f"  Chunk {chunk_index+1}/{total_chunks} [{lang_key}] — "
                f"429 Rate Limited on attempt {attempt}."
            )
            if attempt < MAX_RETRIES:
                await _handle_429_backoff(rate_state)
                continue
            # Final attempt also got 429 — give up
            break

        # ── Other error → small backoff, then retry ──────────────────────
        logger.warning(
            f"  Chunk {chunk_index+1}/{total_chunks} [{lang_key}] — "
            f"attempt {attempt} failed: {error_msg}"
        )
        if attempt < MAX_RETRIES:
            backoff = 5 * attempt
            logger.info(f"  Retrying in {backoff}s...")
            await asyncio.sleep(backoff)

    logger.error(
        f"  Chunk {chunk_index+1}/{total_chunks} [{lang_key}] — "
        f"FAILED after {MAX_RETRIES} attempts"
    )
    return None, meta


async def _call_groq_api(prompt: str, context_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Make a single Groq API call with the pre-built *prompt*.

    *context_payload* is only used for error fallback metadata (language key,
    etc.) — it is NOT read to construct the prompt.

    Returns the parsed JSON result on success, or an ``_empty_result`` dict
    with ``error`` (and optionally ``error_type``) on failure.

    Recognised ``error_type`` values:
    * ``"rate_limit"`` — HTTP 429 (caller should back off globally).
    * ``"too_large"``  — HTTP 413 (chunk should be skipped / manual review).
    """
    from openai import AsyncOpenAI, RateLimitError, APIStatusError

    groq_token = settings.groq_api_key
    if not groq_token:
        logger.error("GROQ_API_KEY not configured.")
        return _empty_result(context_payload, error="GROQ_API_KEY not configured")

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
                        "Never include markdown code fences or any text outside the JSON object. "
                        "Do NOT include a \"source_code\" field in your output."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            max_tokens=8192,
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        raw_response = completion.choices[0].message.content
        result = _extract_json_from_response(raw_response)

        if result is None:
            logger.warning("Chunk LLM response could not be parsed as JSON.")
            return _empty_result(context_payload, error="JSON parse failed", raw_response=raw_response)

        return result

    except RateLimitError as exc:
        logger.warning(f"Groq 429 Rate Limit: {exc}")
        return _empty_result(context_payload, error=str(exc), error_type="rate_limit")

    except APIStatusError as exc:
        if exc.status_code == 413:
            logger.warning(f"Groq 413 Request Too Large: {exc}")
            return _empty_result(context_payload, error=str(exc), error_type="too_large")
        logger.error(f"Groq API error ({exc.status_code}): {exc}")
        return _empty_result(context_payload, error=str(exc))

    except Exception as exc:
        logger.error(f"Error calling Groq LLM on chunk: {exc}")
        return _empty_result(context_payload, error=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _empty_result(
    wrapper_data: Dict[str, Any],
    error: str = "",
    raw_response: str = "",
    error_type: str = "",
) -> Dict[str, Any]:
    """Return a safe empty sink_modules.json when LLM fails."""
    out: Dict[str, Any] = {
        "language": wrapper_data.get("language", "unknown"),
        "results": {},
        "analysis_summary": f"Analysis failed: {error}" if error else "No results",
    }
    if error:
        out["error"] = error
    if error_type:
        out["error_type"] = error_type
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

    # 4. Truncated JSON repair: LLM hit max_tokens and the JSON was cut off.
    #    Try to close all open brackets/braces so we salvage whatever was parsed.
    if start is not None and start != -1:
        repaired = _repair_truncated_json(clean[start:])
        if repaired is not None:
            return repaired

    return None


def _repair_truncated_json(text: str) -> Optional[Dict]:
    """Attempt to repair truncated JSON by closing open strings, arrays, and objects."""
    # Strip any trailing incomplete key-value (e.g. '"reason": "some text that was cu')
    # by removing everything after the last complete comma or opening bracket.
    import re

    # Remove trailing whitespace
    t = text.rstrip()

    # If we're inside an unclosed string, close it
    # Count unescaped quotes
    in_string = False
    last_good = 0
    i = 0
    while i < len(t):
        ch = t[i]
        if ch == '\\' and in_string:
            i += 2  # skip escaped char
            continue
        if ch == '"':
            in_string = not in_string
        if not in_string:
            last_good = i
        i += 1

    if in_string:
        # Close the dangling string
        t = t[:last_good + 1]

    # Remove any trailing comma or colon (invalid before closing brackets)
    t = re.sub(r'[,:]+\s*$', '', t)

    # Remove any trailing incomplete key (e.g. '"some_key"' with no value)
    t = re.sub(r',?\s*"[^"]*"\s*$', '', t)

    # Now count open brackets and braces and close them
    opens = []
    in_str = False
    for i, ch in enumerate(t):
        if ch == '\\' and in_str:
            continue
        if ch == '"' and (i == 0 or t[i-1] != '\\'):
            in_str = not in_str
        if in_str:
            continue
        if ch in ('{', '['):
            opens.append(ch)
        elif ch == '}':
            if opens and opens[-1] == '{':
                opens.pop()
        elif ch == ']':
            if opens and opens[-1] == '[':
                opens.pop()

    # Close in reverse order
    closers = {'[': ']', '{': '}'}
    suffix = ''.join(closers[b] for b in reversed(opens))
    t = t + suffix

    try:
        result = json.loads(t)
        if isinstance(result, dict):
            logger.warning(f"Repaired truncated JSON (closed {len(opens)} bracket(s))")
            return result
    except json.JSONDecodeError:
        pass

    return None
