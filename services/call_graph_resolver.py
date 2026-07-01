"""
Call Graph Resolver — Cross-File Vulnerability Chain Detection (Python only)

Given:
  - call_graph: {"func_name|file_path": ["callee_func1", "callee_func2"]}
  - route_map:  {"func_name|file_path": {"method": "GET", "path": "/users/{id}", "params": ["user_id"]}}
  - vulnerable_wrappers: list of AI-flagged wrapper dicts with "function_name" and "file"

Produces:
  - promoted_wrappers: list of wrapper-like dicts that the Rule Generator can consume
  - verified_chains: list of full chain metadata for logging/UI
"""

import logging
from typing import Dict, Any, List, Tuple, Set
from collections import deque

logger = logging.getLogger(__name__)

MAX_CHAIN_DEPTH = 10


def resolve_vulnerable_chains(
    call_graph: Dict[str, List[str]],
    route_map: Dict[str, Dict[str, Any]],
    vulnerable_wrappers: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Walk BACKWARDS from each vulnerable wrapper through the call graph
    to find all API routes that transitively reach the sink.

    Returns:
        promoted_wrappers: wrapper-like dicts to inject into LLM results for rule generation
        verified_chains:   full chain metadata for logging/UI display
    """
    if not call_graph or not vulnerable_wrappers:
        return [], []

    # ── Step 1: Build the set of vulnerable function names ──
    vuln_func_names: Set[str] = set()
    vuln_metadata: Dict[str, Dict[str, Any]] = {}  # func_name -> first wrapper's metadata
    for w in vulnerable_wrappers:
        fname = w.get("function_name", "")
        if fname and fname != "<module_global>":
            vuln_func_names.add(fname)
            if fname not in vuln_metadata:
                vuln_metadata[fname] = w

    if not vuln_func_names:
        return [], []

    # ── Step 2: Build reverse index (callee → set of caller keys) ──
    # call_graph maps "caller_func|file" → ["callee_func_name", ...]
    # We need: "callee_func_name" → set of "caller_func|file" keys
    reverse_index: Dict[str, Set[str]] = {}
    for caller_key, callees in call_graph.items():
        for callee_name in callees:
            reverse_index.setdefault(callee_name, set()).add(caller_key)

    # ── Step 3: BFS upward from each vulnerable function ──
    verified_chains: List[Dict[str, Any]] = []
    promoted_wrappers: List[Dict[str, Any]] = []
    seen_promotions: Set[str] = set()  # prevent duplicate promotions

    for vuln_func_name in vuln_func_names:
        original_wrapper = vuln_metadata[vuln_func_name]

        # BFS: each entry is (current_func_name, chain_so_far)
        queue: deque = deque()
        queue.append((vuln_func_name, [vuln_func_name]))
        visited: Set[str] = {vuln_func_name}

        while queue:
            current_name, chain = queue.popleft()

            if len(chain) > MAX_CHAIN_DEPTH:
                continue

            # Find all callers of current_name
            callers = reverse_index.get(current_name, set())

            for caller_key in callers:
                caller_func = caller_key.split("|")[0]
                caller_file = caller_key.split("|")[1] if "|" in caller_key else ""

                if caller_func in visited:
                    continue
                visited.add(caller_func)

                new_chain = [caller_func] + chain

                # Check if this caller is a route entry point
                if caller_key in route_map:
                    route_info = route_map[caller_key]
                    chain_record = {
                        "route": {
                            "func": caller_func,
                            "file": caller_file,
                            "method": route_info.get("method", ""),
                            "path": route_info.get("path", ""),
                            "params": route_info.get("params", []),
                        },
                        "chain": new_chain,
                        "sink": {
                            "func": vuln_func_name,
                            "file": original_wrapper.get("file", ""),
                            "vuln_type": original_wrapper.get("vulnerability_type", ""),
                            "severity": original_wrapper.get("severity", "MEDIUM"),
                        },
                        "depth": len(new_chain),
                    }
                    verified_chains.append(chain_record)
                    logger.info(
                        f"[CallGraph] Chain found: {' → '.join(new_chain)} "
                        f"({route_info.get('method', '?')} {route_info.get('path', '?')} "
                        f"→ {vuln_func_name} [{original_wrapper.get('vulnerability_type', '?')}])"
                    )

                # Promote this caller as a new wrapper (so Rule Generator creates rules for it)
                promotion_key = f"{caller_func}|{caller_file}"
                if promotion_key not in seen_promotions:
                    seen_promotions.add(promotion_key)
                    promoted_wrappers.append({
                        "function_name": caller_func,
                        "file": caller_file,
                        "cross_file": True,
                        "promoted_from": vuln_func_name,
                        "vulnerability_type": original_wrapper.get("vulnerability_type", ""),
                        "severity": original_wrapper.get("severity", "MEDIUM"),
                        "reason": (
                            f"Cross-file chain: {caller_func} transitively calls "
                            f"vulnerable function {vuln_func_name} "
                            f"({original_wrapper.get('vulnerability_type', 'unknown')})"
                        ),
                        "source_patterns": original_wrapper.get("source_patterns", []),
                        "sink_patterns": [f"{caller_func}(...)"],
                        "sanitizer_patterns": original_wrapper.get("sanitizer_patterns", []),
                        "skip_sanitizer_patterns": [],
                        "vulnerable_parameter": "cross_file_taint",
                        "malicious_payload": original_wrapper.get("malicious_payload"),
                        "exploit_explanation": (
                            f"Untrusted input flows through {caller_func} in {caller_file}, "
                            f"which calls {vuln_func_name}, reaching a dangerous sink."
                        ),
                        "impact_summary": original_wrapper.get("impact_summary", ""),
                    })

                # Continue BFS upward
                queue.append((caller_func, new_chain))

    logger.info(
        f"[CallGraph] Resolution complete: "
        f"{len(verified_chains)} chain(s), {len(promoted_wrappers)} promotion(s)"
    )
    return promoted_wrappers, verified_chains
