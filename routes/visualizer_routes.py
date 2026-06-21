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

    import ast
    import uuid
    import re

    AMBIGUOUS_SINK_METHODS = {
        "get", "post", "put", "patch", "delete", "request", "send",
        "find", "find_one", "insert", "update", "delete_one", "delete_many",
        "read", "write", "open", "save", "download", "exec", "eval", "dangerouslySetInnerHTML"
    }

    call_details = wrapper.get("call_details", {})
    is_python = file_path.endswith(".py")

    if is_python:
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

        def _build_ast_node(node):
            if not isinstance(node, ast.AST):
                return None
            node_type = type(node).__name__
            label = node_type
            
            if isinstance(node, ast.Name):
                label = f"Name: {node.id}"
            elif isinstance(node, ast.Constant):
                label = f"Constant: {repr(node.value)}"
            elif isinstance(node, ast.arg):
                label = f"arg: {node.arg}"
            elif isinstance(node, ast.Attribute):
                label = f"Attribute: {node.attr}"
                
            result = {
                "id": str(uuid.uuid4()),
                "type": node_type,
                "label": label,
                "line": getattr(node, "lineno", None),
                "children": [],
                "is_sink": False,
                "confidence": None,
                "category": None,
                "note": None,
                "call_str": None,
            }

            if isinstance(node, ast.Call):
                call_str = _get_call_name(node)
                if call_str:
                    result["call_str"] = call_str
                    result["label"] = f"Call: {call_str}()"
                    detail = call_details.get(call_str)
                    method = call_str.rsplit(".", 1)[-1] if "." in call_str else call_str
                    if detail:
                        result["is_sink"] = True
                        result["confidence"] = detail.get("confidence")
                        if result["confidence"] == "import_resolved":
                            result["note"] = f"Confirmed vulnerable: '{method}' traces back to imported '{detail.get('module')}' module."
                            result["category"] = "Import Resolved"
                        elif result["confidence"] == "name_match_unambiguous":
                            result["note"] = f"Confirmed vulnerable: '{method}' is an unambiguous sink method name."
                            result["category"] = "Name Match"
                        elif result["confidence"] == "builtin":
                            result["note"] = f"Confirmed vulnerable: '{method}' is a dangerous builtin function."
                            result["category"] = "Builtin"
                    else:
                        if method in AMBIGUOUS_SINK_METHODS:
                            result["note"] = f"Safe: '{method}' is an ambiguous method name with no dangerous import binding."
                        else:
                            result["note"] = "Safe: Standard function call."

            for field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    for item in value:
                        child_node = _build_ast_node(item)
                        if child_node:
                            result["children"].append(child_node)
                elif isinstance(value, ast.AST):
                    child_node = _build_ast_node(value)
                    if child_node:
                        result["children"].append(child_node)
                        
            return result

        full_tree = _build_ast_node(tree)
        if full_tree and full_tree["type"] == "Module" and len(full_tree["children"]) == 1:
            full_tree = full_tree["children"][0]
    else:
        # Pseudo Parser for JS/TS/JSX
        lines = wrapper["source_code"].split('\n')
        root_nodes = []
        stack = [(0, root_nodes)]
        
        for i, line in enumerate(lines):
            lineno = i + 1
            stripped = line.strip()
            if not stripped: continue
            
            indent = len(line) - len(line.lstrip())
            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()
                
            current_children = stack[-1][1]
            node_id = str(uuid.uuid4())
            
            call_match = re.search(r'([a-zA-Z0-9_\.]+)\s*\(', stripped)
            is_sink = False
            confidence = "none"
            category = ""
            note = ""
            label = stripped
            if len(label) > 40: label = label[:37] + "..."
            node_type = "Statement"
            
            if stripped.startswith("if") or stripped.startswith("for") or stripped.startswith("while"):
                node_type = "ControlFlow"
            elif stripped.startswith("return"):
                node_type = "Return"
            elif call_match:
                node_type = "Call"
                call_name = call_match.group(1)
                label = f"Call: {call_name}()"
                detail = call_details.get(call_name)
                method = call_name.split('.')[-1]
                
                if detail:
                    is_sink = True
                    confidence = detail.get("confidence")
                    if confidence == "import_resolved":
                        note = f"Confirmed vulnerable: '{method}' traces back to imported module."
                        category = "Import Resolved"
                    elif confidence == "name_match_unambiguous":
                        note = f"Confirmed vulnerable: '{method}' is an unambiguous sink method name."
                        category = "Name Match"
                    elif confidence == "builtin":
                        note = f"Confirmed vulnerable: '{method}' is a dangerous builtin function."
                        category = "Builtin"
                    else:
                        # Ambiguous or generic pattern match
                        category = detail.get("category", "Pattern Match")
                        note = f"Potential Sink: '{method}' was flagged by analysis pattern."
                elif method in AMBIGUOUS_SINK_METHODS:
                    is_sink = False
                    note = f"Safe: '{method}' is an ambiguous method name."
                else:
                    note = "Safe: Standard function call."
                    
            node = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "children": [],
                "is_sink": is_sink,
                "confidence": confidence,
                "category": category,
                "note": note,
                "line_start": lineno,
                "line_end": lineno,
            }
            current_children.append(node)
            if stripped.endswith("{") or stripped.endswith("("):
                stack.append((indent, node["children"]))
                
        full_tree = {
            "id": str(uuid.uuid4()),
            "label": function_name,
            "type": "FunctionDef",
            "children": root_nodes,
            "is_sink": False,
            "confidence": "none",
            "category": "",
            "note": "",
            "line_start": wrapper.get("line_start"),
            "line_end": wrapper.get("line_end"),
        }

    return {
        "function_name": function_name,
        "line_start": wrapper.get("line_start"),
        "line_end": wrapper.get("line_end"),
        "ast_tree": full_tree
    }
