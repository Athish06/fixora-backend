# Visualizer routes — serves the animated pipeline trace for a scan
from fastapi import APIRouter, Depends, HTTPException, status
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from services.pipeline_trace_service import build_trace

router = APIRouter(prefix='/visualizer', tags=['Visualizer'])


@router.get('/trace/{scan_id}')
async def get_pipeline_trace(
    scan_id: str,
    current_user: TokenData = Depends(get_current_user),
    db=Depends(get_database)
):
    """
    Return the animation-friendly pipeline trace for a specific scan.

    Reads from existing ai_debug + vulnerabilities collections —
    no new computation, no pipeline changes.  Pure read-only transform.
    """
    # Find the ai_debug doc for this scan
    ai_debug_doc = await db.ai_debug.find_one(
        {'scan_id': scan_id},
        {'_id': 0}
    )
    if not ai_debug_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='No AI debug data found for this scan. Run a scan first.'
        )

    # Verify ownership — user must own the repository
    repo_id = ai_debug_doc.get('repository_id')
    repo = await db.repositories.find_one(
        {'id': repo_id, 'user_id': current_user.user_id}
    )
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied'
        )

    # Fetch vulnerabilities for this scan (for comparison stage)
    vulnerabilities = await db.vulnerabilities.find(
        {'repository_id': repo_id, 'scan_id': scan_id},
        {
            '_id': 0,
            'rule_id': 1,
            'title': 1,
            'severity': 1,
            'file_path': 1,
            'type': 1,
            'line_number': 1,
        }
    ).to_list(5000)

    # Build the trace JSON
    trace = build_trace(ai_debug_doc, vulnerabilities)

    # Add repository name for display
    trace['repository'] = repo.get('full_name') or repo.get('name', repo_id)

    return trace


@router.get('/ast-tree/{scan_id}')
async def get_ast_tree(
    scan_id: str,
    file_path: str,
    function_name: str,
    current_user: TokenData = Depends(get_current_user),
    db=Depends(get_database)
):
    """
    On-demand AST parse of a specific wrapper function's source code.
    Returns the ordered Call nodes with sink classification.
    """
    ai_debug_doc = await db.ai_debug.find_one({'scan_id': scan_id}, {'_id': 0})
    if not ai_debug_doc:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Verify ownership
    repo = await db.repositories.find_one({'id': ai_debug_doc.get('repository_id'), 'user_id': current_user.user_id})
    if not repo:
        raise HTTPException(status_code=403, detail="Access denied")

    # Find the function source
    wd_results = ai_debug_doc.get("wrapper_hunter_results", {}).get("results", {})
    wrapper = None
    for lang_key, section in wd_results.items():
        if not isinstance(section, dict):
            continue
        for w in section.get("wrapper_functions", []):
            if w.get("file") == file_path and w.get("function_name") == function_name:
                wrapper = w
                break
        if wrapper:
            break

    if not wrapper or not wrapper.get("source_code"):
        raise HTTPException(status_code=404, detail="Source code not available for this function")

    # We only parse Python for now
    if not file_path.endswith(".py"):
        raise HTTPException(status_code=400, detail="AST Tree is currently only supported for Python files")

    import ast
    from services.github_scan_service import UNAMBIGUOUS_SINK_METHODS, AMBIGUOUS_SINK_METHODS
    ALL_SINKS = UNAMBIGUOUS_SINK_METHODS | AMBIGUOUS_SINK_METHODS

    try:
        tree = ast.parse(wrapper["source_code"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse AST: {str(e)}")

    def _get_call_name(call_node):
        func = call_node.func
        if isinstance(func, ast.Name): return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            node = func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name): parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    call_details = wrapper.get("call_details", {})
    children = []

    # Walk document order
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_str = _get_call_name(node)
            if not call_str: continue

            # See if this call was flagged in the main scan
            detail = call_details.get(call_str)
            
            method = call_str.rsplit(".", 1)[-1] if "." in call_str else call_str
            
            is_sink = False
            confidence = None
            category = None
            note = None

            if detail:
                is_sink = True
                confidence = detail.get("confidence")
                if confidence == "import_resolved":
                    note = f"Confirmed vulnerable: '{method}' traces back to imported '{detail.get('module')}' module."
                    category = "Import Resolved"
                elif confidence == "name_match_unambiguous":
                    note = f"Confirmed vulnerable: '{method}' is an unambiguous sink method name."
                    category = "Name Match"
                elif confidence == "builtin":
                    note = f"Confirmed vulnerable: '{method}' is a dangerous builtin function."
                    category = "Builtin"
            else:
                # Why wasn't it flagged?
                if method in AMBIGUOUS_SINK_METHODS:
                    note = f"Safe: '{method}' is an ambiguous method name with no dangerous import binding."
                elif call_str in ["<plaintext-password-comparison>"]:
                    pass
                else:
                    note = "Safe: Standard function call."

            children.append({
                "call": f"{call_str}()",
                "line": getattr(node, "lineno", None),
                "resolved_module": detail.get("module") if detail else None,
                "is_sink": is_sink,
                "confidence": confidence,
                "category": category,
                "note": note
            })

    # Sort children by line number to ensure document order
    children.sort(key=lambda x: x["line"] or 0)

    return {
        "function_name": function_name,
        "line_start": wrapper.get("line_start"),
        "line_end": wrapper.get("line_end"),
        "children": children
    }
