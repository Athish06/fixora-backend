# Scan routes
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import jwt
import logging
import asyncio
import base64
import json
import hashlib
import re
from datetime import datetime
from config.database import get_database
from config.settings import get_settings
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.scan import ScanResult
from services.activity_service import log_activity
from services.websocket_manager import get_connection_manager
from services.github_scan_service import GitHubScanService
from services.llm_service import analyze_wrappers_with_llm
from services.semgrep_rule_generator import generate_custom_rules, count_generated_rules

router = APIRouter(prefix='/scan', tags=['Scans'])
logger = logging.getLogger(__name__)
settings = get_settings()

UNIFIED_VULN_CATEGORIES = [
    "Injection (SQL/NoSQL/LDAP/Command/Path Traversal)",
    "Broken Access Control (IDOR/BOLA)",
    "Cross-Site Scripting (XSS)",
    "Server-Side Request Forgery (SSRF)",
    "Insecure Deserialization",
    "Hardcoded Secrets / Credentials",
    "Cryptographic Failures",
    "Security Misconfiguration (CORS, Headers)",
    "Insecure Design / Architecture",
    "Business Logic Flaws",
]

_PLACEHOLDER_TEXT_RE = re.compile(
    r"requires\s+logn|requires\s+login|unknown\s+vulnerability|security\s+issue",
    flags=re.IGNORECASE,
)


def _normalize_unified_type_and_category(
    rule_id: str,
    metadata: Dict[str, Any],
    description: str,
):
    hay = " ".join([
        str(rule_id or ""),
        str(metadata.get("category") or ""),
        str(metadata.get("vulnerability_type") or ""),
        str(description or ""),
    ]).lower()

    if any(k in hay for k in ["sqli", "sql injection", "nosql", "ldap", "xpath", "command-injection", "command injection", "path-traversal", "path traversal"]):
        if "command" in hay:
            return "Command Injection", "Injection (SQL/NoSQL/LDAP/Command/Path Traversal)"
        if "path" in hay and "travers" in hay:
            return "Path Traversal", "Injection (SQL/NoSQL/LDAP/Command/Path Traversal)"
        return "SQL Injection", "Injection (SQL/NoSQL/LDAP/Command/Path Traversal)"
    if "xss" in hay or "cross-site scripting" in hay or "cross site scripting" in hay:
        return "XSS", "Cross-Site Scripting (XSS)"
    if "ssrf" in hay or "server-side request forgery" in hay:
        return "SSRF", "Server-Side Request Forgery (SSRF)"
    if "deserialize" in hay:
        return "Insecure Deserialization", "Insecure Deserialization"
    if "idor" in hay or "bola" in hay or "broken access" in hay:
        return "IDOR / Broken Access Control", "Broken Access Control (IDOR/BOLA)"
    if "secret" in hay or "credential" in hay or "hardcoded" in hay:
        return "Hardcoded Secret", "Hardcoded Secrets / Credentials"
    if "crypto" in hay or "weak hash" in hay or "weak cipher" in hay or "encryption" in hay:
        return "Cryptographic Failure", "Cryptographic Failures"
    if "cors" in hay or "header" in hay or "misconfig" in hay or "csrf" in hay:
        return "Security Misconfiguration", "Security Misconfiguration (CORS, Headers)"
    if "business" in hay or "logic" in hay or "workflow" in hay:
        return "Business Logic Flaw", "Business Logic Flaws"
    return "Security Misconfiguration", "Insecure Design / Architecture"


def _clean_placeholder_text(value: str, fallback: str) -> str:
    text = str(value or "").strip()
    if not text or _PLACEHOLDER_TEXT_RE.search(text):
        return fallback
    return text

@router.get('/{scan_id}', response_model=ScanResult)
async def get_scan_status(
    scan_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get the status of a scan"""
    scan = await db.scans.find_one({'id': scan_id}, {'_id': 0})
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Scan not found')
    
    return ScanResult(**scan)


# ============== WEBHOOK ENDPOINTS FOR GITHUB ACTIONS ==============

class SemgrepResult(BaseModel):
    check_id: str
    path: str
    start: Dict[str, int]
    end: Dict[str, int]
    extra: Dict[str, Any]


class SemgrepPayload(BaseModel):
    results: List[Dict[str, Any]]
    errors: Optional[List[Dict[str, Any]]] = []


class ScanWebhookPayload(BaseModel):
    scan_id: str
    repository: str
    branch: str
    scan_mode: str
    commit_sha: str
    results: SemgrepPayload


class WrapperHunterPayload(BaseModel):
    scan_id: str
    repository: str
    encoded_data: str  # Base64-encoded JSON to bypass Cloudflare WAF


@router.post('/webhook/wrapper-results')
async def receive_wrapper_hunter_results(
    payload: WrapperHunterPayload,
    background_tasks: BackgroundTasks,
    x_fixora_token: str = Header(..., alias="X-Fixora-Token"),
    db = Depends(get_database)
):
    """
    Webhook endpoint to receive Wrapper Hunter results from GitHub Actions.
    1. Validates the token
    2. Logs the wrapper data
    3. Sends to Groq LLM for analysis
    4. Triggers the Semgrep scan workflow
    5. Cleans up the wrapper hunter workflow file
    """
    logger.info(f"Received wrapper hunter results for scan {payload.scan_id}")

    # Decode the Base64-encoded payload (sent this way to avoid Cloudflare WAF blocking
    # requests containing raw exploit-like strings such as eval(), exec(), SELECT etc.)
    try:
        decoded_bytes = base64.b64decode(payload.encoded_data)
        wrapper_data = json.loads(decoded_bytes)
    except Exception as e:
        logger.error(f"Failed to decode base64 payload: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid encoded_data: must be a base64-encoded JSON string"
        )

    try:
        # Validate the token
        decoded = jwt.decode(
            x_fixora_token,
            settings.jwt_secret_key,
            algorithms=["HS256"]
        )
        
        if decoded.get("type") != "scan_webhook":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        repo_id = decoded.get("repo_id")
        user_id = decoded.get("user_id")
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    # Get the scan record
    scan = await db.scans.find_one({"id": payload.scan_id})
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    
    # ===== LOG WRAPPER HUNTER RESULTS =====
    logger.info("=" * 80)
    logger.info("WRAPPER HUNTER RESULTS RECEIVED:")
    logger.info("=" * 80)
    logger.info(str(wrapper_data)[:2000])  # truncated log
    logger.info("=" * 80)
    
    # Send WebSocket update: wrapper hunter results received
    ws_manager = get_connection_manager()
    await ws_manager.send_to_scan(payload.scan_id, {
        "type": "wrapper_hunter_complete",
        "scan_id": payload.scan_id,
        "message": "Wrapper analysis completed. Starting AI analysis..."
    })

    # Update scan status — wrapper results received, AI analysis starting
    await db.scans.update_one(
        {"id": payload.scan_id},
        {"$set": {
            "status": "running",
            "progress": 30,
            "phase": "llm_analysis",
            "wrapper_data": wrapper_data
        }}
    )

    # ===== OFFLOAD ALL HEAVY WORK TO BACKGROUND — return 200 immediately =====
    # The LLM call can take 60-120 seconds; the GitHub Actions curl has a
    # --max-time limit.  Returning here lets the workflow step succeed while
    # all processing (LLM analysis + Semgrep trigger) happens in the background.
    background_tasks.add_task(
        _process_wrapper_results_in_background,
        payload.scan_id, payload.repository, repo_id, user_id,
        wrapper_data, scan, db
    )

    return {
        "success": True,
        "scan_id": payload.scan_id,
        "message": "Wrapper hunter results received. AI analysis + Semgrep scan starting in background."
    }


async def _process_wrapper_results_in_background(
    scan_id: str,
    repository: str,
    repo_id: str,
    user_id: str,
    wrapper_data: dict,
    scan: dict,
    db
):
    """
    Background task – runs after the HTTP response is already sent.
    1. Send wrapper data to Groq LLM (can take 30-60s)
    2. Store LLM result (sink_modules.json)
    3. Generate custom Semgrep rules from LLM output
    4. Store LLM-identified wrappers as AI patterns
    5. Trigger Semgrep scan (with custom rules)
    """
    import json as json_module
    ws_manager = get_connection_manager()

    try:
        # ── LLM ANALYSIS ──────────────────────────────────────────────────────
        logger.info(f"[BG] Starting LLM analysis for scan {scan_id}")
        await ws_manager.send_to_scan(scan_id, {
            "type": "llm_analysis_started",
            "scan_id": scan_id,
            "message": "AI analyzing wrapper functions for security sinks..."
        })

        # Progress callback — forwards chunk progress to the WebSocket
        async def _chunk_progress(msg: dict):
            msg["scan_id"] = scan_id
            await ws_manager.send_to_scan(scan_id, msg)

        llm_result = await analyze_wrappers_with_llm(
            wrapper_data, progress_callback=_chunk_progress
        )

        # Extract chunk metadata before stripping it from the LLM result
        chunk_meta = llm_result.pop("_chunk_meta", None)

        logger.info("=" * 80)
        logger.info("LLM ANALYSIS RESULT (sink_modules.json):")
        logger.info("=" * 80)
        logger.info(json_module.dumps(llm_result, indent=2)[:5000])
        logger.info("=" * 80)

        # Count findings for WebSocket message
        sink_results = llm_result.get("results", {})
        vuln_wrapper_count = sum(
            len(section.get("wrapper_functions", []))
            for section in sink_results.values()
        )
        sink_module_count = sum(
            len(section.get("modules", {}).get("sink_modules", []))
            for section in sink_results.values()
        )

        # ── GENERATE CUSTOM SEMGREP RULES ─────────────────────────────────────
        custom_rules_yaml = ""
        rules_count = 0
        manual_review_list = chunk_meta.get("manual_review_required", []) if chunk_meta else []
        if vuln_wrapper_count > 0 or manual_review_list:
            logger.info(
                f"[BG] Generating custom Semgrep rules for "
                f"{vuln_wrapper_count} vulnerable wrapper(s) + "
                f"{len(manual_review_list)} manual-review function(s)"
            )
            custom_rules_yaml = generate_custom_rules(llm_result, manual_review_list)
            rules_count = count_generated_rules(llm_result)
            logger.info(f"[BG] Generated {rules_count} custom Semgrep rules")
        else:
            logger.info("[BG] No vulnerable wrappers found — skipping custom rule generation")

        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "progress": 45,
                "phase": "triggering_semgrep",
                "llm_result": llm_result,
                "custom_rules_yaml": custom_rules_yaml,
            }}
        )

        # Build chunk summary for WebSocket
        failed_count = chunk_meta["failed"] if chunk_meta else 0
        total_chunks = chunk_meta["total_chunks"] if chunk_meta else 0
        manual_review_count = chunk_meta.get("manual_review", 0) if chunk_meta else 0
        chunk_status_msg = ""
        if failed_count:
            chunk_status_msg = f" ({failed_count}/{total_chunks} chunks failed after retries)"
        if manual_review_count:
            chunk_status_msg += f" ({manual_review_count} chunk(s) flagged for manual review)"

        await ws_manager.send_to_scan(scan_id, {
            "type": "llm_analysis_complete",
            "scan_id": scan_id,
            "vulnerable_wrappers_count": vuln_wrapper_count,
            "sink_modules_count": sink_module_count,
            "custom_rules_count": count_generated_rules(llm_result),
            "chunk_stats": chunk_meta,
            "manual_review_count": manual_review_count,
            "message": (
                f"AI analysis complete. Found {vuln_wrapper_count} vulnerable wrapper(s) "
                f"across {sink_module_count} sink module(s). "
                f"Generated {count_generated_rules(llm_result)} custom Semgrep rule(s). "
                f"Starting Semgrep scan...{chunk_status_msg}"
            )
        })

        # ── STORE FULL AI PIPELINE DEBUG DATA ─────────────────────────────────
        await _store_ai_debug(
            scan_id, repo_id, wrapper_data, llm_result,
            custom_rules_yaml, vuln_wrapper_count, sink_module_count, rules_count, db,
            chunk_meta=chunk_meta
        )

        # ── TRIGGER SEMGREP ──────────────────────────────────────────────────
        await _trigger_semgrep_after_wrapper_analysis(
            scan_id, repository, repo_id, user_id, scan, db,
            custom_rules_yaml=custom_rules_yaml
        )

    except Exception as exc:
        logger.error(f"[BG] Error processing wrapper results for scan {scan_id}: {exc}")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "error": str(exc)}}
        )
        await ws_manager.send_to_scan(scan_id, {
            "type": "scan_failed",
            "scan_id": scan_id,
            "message": f"Error during AI analysis: {str(exc)}"
        })


async def _store_ai_debug(
    scan_id: str,
    repo_id: str,
    wrapper_data: Dict[str, Any],
    llm_result: Dict[str, Any],
    custom_rules_yaml: str,
    vuln_wrapper_count: int,
    sink_module_count: int,
    rules_count: int,
    db,
    chunk_meta: Dict[str, Any] = None
):
    """
    Store the full AI pipeline debug data (Wrapper Hunter → LLM → Semgrep rules)
    into the ai_debug collection.  One document per scan, upserted by scan_id.
    """
    try:
        import json as _json

        # Prompts are now built per-chunk in the 2-phase flow (build_module_sink_prompt /
        # build_function_chunk_prompt) — no single combined prompt to store here.
        llm_prompt = "(2-phase analysis: module-sink prompt + per-chunk function prompts)"

        # Extract failed chunk details and manual review items for dedicated storage
        failed_chunks = []
        manual_review_required = []
        chunk_stats = {}
        wrapper_targets_summary = []
        orchestrator_meta = {}

        if isinstance(wrapper_data, dict):
            orchestrator_meta = wrapper_data.get("orchestrator", {}) or {}
            raw_targets = wrapper_data.get("scan_targets", []) or []
            for t in raw_targets:
                modules = (t.get("modules", {}) or {}).get("all", []) or []
                wrapper_targets_summary.append({
                    "language": t.get("language"),
                    "root_path": t.get("root_path"),
                    "scan_path": t.get("scan_path"),
                    "wrapper_count": t.get("wrapper_count", 0),
                    "module_count": len(modules),
                })

        if chunk_meta:
            chunk_stats = {
                "total_chunks":    chunk_meta.get("total_chunks", 0),
                "succeeded":       chunk_meta.get("succeeded", 0),
                "failed":          chunk_meta.get("failed", 0),
                "manual_review":   chunk_meta.get("manual_review", 0),
                "oversized_chunks": chunk_meta.get("oversized_chunks", 0),
            }
            manual_review_required = chunk_meta.get("manual_review_required", [])
            for detail in chunk_meta.get("chunk_details", []):
                if detail.get("status") == "failed":
                    failed_chunks.append({
                        "chunk_index": detail.get("chunk_index"),
                        "lang": detail.get("lang"),
                        "function_names": detail.get("function_names", []),
                        "attempts": detail.get("attempts", 0),
                        "error": detail.get("error", "Unknown"),
                    })

        doc = {
            "id": str(uuid.uuid4()),
            "repository_id": repo_id,
            "scan_id": scan_id,
            "created_at": datetime.now().isoformat(),
            # Full pipeline data
            "wrapper_hunter_results": wrapper_data,
            "llm_prompt": llm_prompt,
            "llm_result": llm_result,
            "custom_rules_yaml": custom_rules_yaml,
            # Summary counts for quick list views
            "vuln_wrapper_count": vuln_wrapper_count,
            "sink_module_count": sink_module_count,
            "rules_count": rules_count,
            "wrapper_targets_summary": wrapper_targets_summary,
            "orchestrator": orchestrator_meta,
            # Chunk processing stats
            "chunk_stats": chunk_stats,
            "failed_chunks": failed_chunks,
            # Functions too large for AI — user must inspect manually
            "manual_review_required": manual_review_required,
        }

        # MongoDB hard limit is 16 MB per document.  For large repos (e.g. Apache
        # Spark) the raw wrapper hunter data alone can exceed this.  Progressively
        # strip the heaviest fields until the document fits.
        MONGO_LIMIT_BYTES = 12 * 1024 * 1024  # 12 MB — leave headroom

        def _doc_size(d):
            return len(_json.dumps(d, default=str).encode("utf-8"))

        if _doc_size(doc) > MONGO_LIMIT_BYTES:
            size_mb = _doc_size(doc) / (1024 * 1024)
            logger.warning(
                f"AI debug document for scan {scan_id} is {size_mb:.1f} MB — "
                f"truncating wrapper_hunter_results to fit MongoDB 16 MB limit"
            )
            doc["wrapper_hunter_results"] = {
                "_truncated": True,
                "_original_size_mb": round(size_mb, 1),
                "_reason": "Raw wrapper hunter data exceeded MongoDB document size limit",
            }

        if _doc_size(doc) > MONGO_LIMIT_BYTES:
            size_mb = _doc_size(doc) / (1024 * 1024)
            logger.warning(
                f"AI debug document still {size_mb:.1f} MB after truncating wrapper data — "
                f"also truncating llm_prompt"
            )
            doc["llm_prompt"] = f"(Truncated — document was {size_mb:.1f} MB, exceeding MongoDB limit)"

        # Upsert: one record per scan_id (replace if reprocessed)
        await db.ai_debug.replace_one(
            {"scan_id": scan_id},
            doc,
            upsert=True
        )
        final_mb = _doc_size(doc) / (1024 * 1024)
        logger.info(f"Stored AI debug data for scan {scan_id} in ai_debug collection ({final_mb:.1f} MB)")

    except Exception as e:
        logger.error(f"Error storing AI debug data for scan {scan_id}: {e}")
        # Non-fatal — don't fail the scan over this


async def _trigger_semgrep_after_wrapper_analysis(
    scan_id: str,
    repository: str,
    repo_id: str, 
    user_id: str,
    scan: dict,
    db,
    custom_rules_yaml: str = ""
):
    """Background task: trigger the Semgrep scan after wrapper analysis is done.
    
    If custom_rules_yaml is provided, pushes .fixora-rules.yml to the repo
    so Semgrep picks up AI-generated rules alongside --config auto.
    """
    try:
        # Get GitHub connection
        github_connection = await db.github_connections.find_one({"user_id": user_id})
        if not github_connection:
            logger.error(f"No GitHub connection for user {user_id}")
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"status": "failed", "error": "No GitHub connection"}}
            )
            return
        
        installation_id = github_connection.get("installation_id")
        if not installation_id:
            logger.error("No installation ID found")
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"status": "failed", "error": "No GitHub App installation"}}
            )
            return
        
        # Import here to avoid circular imports
        from routes.github_routes import get_installation_access_token
        access_token = await get_installation_access_token(installation_id)
        if not access_token:
            logger.error("Failed to get installation access token")
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"status": "failed", "error": "Failed to get access token"}}
            )
            return
        
        owner, repo_name = repository.split("/", 1)
        service = GitHubScanService(access_token)
        
        # Get default branch
        repo_info = await service.get_repository_info(owner, repo_name)
        default_branch = repo_info.get("default_branch", "main")
        
        # Delete wrapper hunter workflow file (cleanup)
        logger.info(f"Cleaning up wrapper hunter workflow from {repository}")
        await service.delete_wrapper_hunter_workflow(owner, repo_name, default_branch)
        
        # ── PUSH CUSTOM RULES (AI-GENERATED) ────────────────────────────────
        if custom_rules_yaml:
            logger.info(f"Pushing AI-generated custom Semgrep rules to {repository}")
            rules_pushed = await service.push_custom_rules_file(
                owner, repo_name, default_branch, custom_rules_yaml
            )
            if rules_pushed:
                logger.info(f"Custom rules pushed successfully to {repository}")
            else:
                logger.warning(f"Failed to push custom rules to {repository} — Semgrep will run with built-in rules only")
        
        # Ensure Semgrep workflow is in place
        await service.push_workflow_file(owner, repo_name, default_branch)
        
        # Wait for GitHub to index the workflow file
        await asyncio.sleep(5)
        
        # Trigger the Semgrep scan
        scan_branch = scan.get("branch", default_branch)
        scan_mode = scan.get("scan_mode", "full")
        base_commit = scan.get("base_commit", "")
        
        triggered = await service.trigger_workflow(
            owner=owner,
            repo=repo_name,
            scan_id=scan_id,
            target_branch=scan_branch,
            scan_mode=scan_mode,
            base_commit=base_commit or ""
        )
        
        if triggered:
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {
                    "progress": 55,
                    "phase": "semgrep_running",
                    "status": "running"
                }}
            )
            
            ws_manager = get_connection_manager()
            rules_msg = " (with AI-enhanced rules)" if custom_rules_yaml else ""
            await ws_manager.send_to_scan(scan_id, {
                "type": "semgrep_started",
                "scan_id": scan_id,
                "has_custom_rules": bool(custom_rules_yaml),
                "message": f"Semgrep security scan running{rules_msg}..."
            })
            
            logger.info(f"Semgrep scan triggered for {repository} (scan_id: {scan_id})")
        else:
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"status": "failed", "error": "Failed to trigger Semgrep workflow"}}
            )
            logger.error(f"Failed to trigger Semgrep scan for {repository}")
    
    except Exception as e:
        logger.error(f"Error in _trigger_semgrep_after_wrapper_analysis: {e}")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "error": str(e)}}
        )


@router.post('/webhook/results')
async def receive_scan_results(
    payload: ScanWebhookPayload,
    x_fixora_token: str = Header(..., alias="X-Fixora-Token"),
    db = Depends(get_database)
):
    """
    Webhook endpoint to receive scan results from GitHub Actions.
    Validates the token and processes Semgrep results.
    """
    logger.info(f"Received webhook for scan {payload.scan_id}")
    logger.info(f"Received token: {x_fixora_token}")
    logger.info(f"Using JWT secret key for verification (first 10 chars): {settings.jwt_secret_key[:10]}...")
    
    try:
        # Validate the token
        decoded = jwt.decode(
            x_fixora_token,
            settings.jwt_secret_key,
            algorithms=["HS256"]
        )
        
        logger.info(f"Token decoded successfully: type={decoded.get('type')}, repo_id={decoded.get('repo_id')}")
        
        if decoded.get("type") != "scan_webhook":
            logger.error(f"Invalid token type: {decoded.get('type')}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        repo_id = decoded.get("repo_id")
        user_id = decoded.get("user_id")
        
    except jwt.ExpiredSignatureError:
        logger.error("Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    # Get the scan record
    scan = await db.scans.find_one({"id": payload.scan_id})
    
    if not scan:
        logger.warning(f"Scan not found: {payload.scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    logger.info(f"Processing scan results for {payload.scan_id} - Repository: {payload.repository}, Branch: {payload.branch}")
    
    # Process Semgrep results
    semgrep_results = payload.results.results
    new_vulnerabilities = []
    current_scan_vulnerabilities = []
    now_iso = datetime.now().isoformat()
    
    logger.info(f"Processing {len(semgrep_results)} Semgrep results")

    # Build lookup maps for existing vulnerabilities in this repository so
    # rescans update existing findings instead of creating duplicates.
    existing_docs = await db.vulnerabilities.find(
        {"repository_id": repo_id},
        {
            "_id": 0,
            "id": 1,
            "fingerprint": 1,
            "rule_id": 1,
            "file_path": 1,
            "line_number": 1,
            "end_line": 1,
            "description": 1,
        },
    ).sort("created_at", 1).to_list(50000)

    existing_by_fingerprint = {}
    existing_by_legacy = {}
    duplicate_doc_ids = []
    canonical_by_key = {}
    for doc in existing_docs:
        legacy_key = (
            f"{doc.get('rule_id', '')}|{doc.get('file_path', '')}|"
            f"{doc.get('line_number', 0)}|{doc.get('end_line', 0)}|"
            f"{(doc.get('description') or '').strip()}"
        )
        canonical_key = doc.get("fingerprint") or f"legacy::{legacy_key}"
        if canonical_key in canonical_by_key:
            duplicate_doc_ids.append(doc["id"])
            continue

        canonical_by_key[canonical_key] = doc
        fp = doc.get("fingerprint")
        if fp:
            existing_by_fingerprint[fp] = doc
        existing_by_legacy[legacy_key] = doc

    if duplicate_doc_ids:
        await db.vulnerabilities.delete_many({"id": {"$in": duplicate_doc_ids}})
        logger.info(
            f"Removed {len(duplicate_doc_ids)} pre-existing duplicate vulnerability record(s) "
            f"for repository {repo_id} before processing scan {payload.scan_id}"
        )

    # De-duplicate repeated Semgrep entries inside the same webhook payload.
    seen_in_this_scan = set()
    updated_existing_count = 0
    
    for result in semgrep_results:
        # Extract severity from Semgrep metadata
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = metadata.get("severity", "medium").lower()
        
        # Map Semgrep severity to our format
        severity_map = {
            "error": "high",
            "warning": "medium", 
            "info": "low",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        severity = severity_map.get(severity, "medium")
        
        # Extract vulnerability type/category in unified taxonomy
        rule_id = result.get("check_id", "")
        description = extra.get("message", "No description available")
        vuln_type, category = _normalize_unified_type_and_category(
            rule_id=rule_id,
            metadata=metadata,
            description=description,
        )
        description = _clean_placeholder_text(
            description,
            f"Potential {vuln_type} detected. Review data flow and controls.",
        )
        file_path = result.get("path", "")
        line_number = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", 0)

        # Stable fingerprint to identify the same finding across multiple scans.
        legacy_key = (
            f"{rule_id}|{file_path}|{line_number}|{end_line}|{description.strip()}"
        )
        fingerprint = hashlib.sha256(legacy_key.encode("utf-8")).hexdigest()

        if fingerprint in seen_in_this_scan:
            continue
        seen_in_this_scan.add(fingerprint)

        existing = existing_by_fingerprint.get(fingerprint) or existing_by_legacy.get(legacy_key)

        raw_title = result.get("check_id", "Unknown vulnerability").split(".")[-1].replace("-", " ").title()
        title = _clean_placeholder_text(raw_title, vuln_type)
        normalized_vuln = {
            "severity": severity,
            "type": vuln_type,
            "category": category,
            "title": title,
        }

        if existing:
            await db.vulnerabilities.update_one(
                {"id": existing["id"]},
                {
                    "$set": {
                        "scan_id": payload.scan_id,
                        "type": vuln_type,
                        "category": category,
                        "title": title,
                        "description": description,
                        "severity": severity,
                        "file_path": file_path,
                        "line_number": line_number,
                        "end_line": end_line,
                        "code_snippet": extra.get("lines", ""),
                        "rule_id": rule_id,
                        "cwe": metadata.get("cwe", []),
                        "owasp": metadata.get("owasp", []),
                        "fix_regex": extra.get("fix_regex", None),
                        "status": "open",
                        "branch": payload.branch,
                        "commit_sha": payload.commit_sha,
                        "fingerprint": fingerprint,
                        "last_seen_at": now_iso,
                        "last_scan_id": payload.scan_id,
                    },
                    "$addToSet": {
                        "scan_ids": payload.scan_id,
                    },
                },
            )
            updated_existing_count += 1
            current_scan_vulnerabilities.append(normalized_vuln)
            # Backfill the fingerprint map for legacy records that lacked it.
            existing_by_fingerprint[fingerprint] = {"id": existing["id"], "fingerprint": fingerprint}
            continue
        
        vulnerability = {
            "id": str(uuid.uuid4()),
            "repository_id": repo_id,
            "scan_id": payload.scan_id,
            "user_id": user_id,
            "type": vuln_type,
            "category": category,
            "title": title,
            "description": description,
            "severity": severity,
            "file_path": file_path,
            "line_number": line_number,
            "end_line": end_line,
            "code_snippet": extra.get("lines", ""),
            "rule_id": rule_id,
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "fix_regex": extra.get("fix_regex", None),
            "status": "open",
            "ai_verified": False,
            "ai_confidence": None,
            "ai_reasoning": None,
            "created_at": now_iso,
            "branch": payload.branch,
            "commit_sha": payload.commit_sha,
            "fingerprint": fingerprint,
            "scan_ids": [payload.scan_id],
            "first_seen_at": now_iso,
            "last_seen_at": now_iso,
            "last_scan_id": payload.scan_id,
        }
        
        new_vulnerabilities.append(vulnerability)
        current_scan_vulnerabilities.append(normalized_vuln)
        existing_by_fingerprint[fingerprint] = {"id": vulnerability["id"], "fingerprint": fingerprint}
        existing_by_legacy[legacy_key] = {"id": vulnerability["id"], "fingerprint": fingerprint}
    
    # Insert only genuinely new vulnerabilities; existing ones were updated in-place.
    if new_vulnerabilities:
        result = await db.vulnerabilities.insert_many(new_vulnerabilities)
        logger.info(f"Inserted {len(result.inserted_ids)} new vulnerabilities into database")
    if updated_existing_count:
        logger.info(f"Updated {updated_existing_count} existing vulnerabilities from previous scans")
    if not new_vulnerabilities and not updated_existing_count:
        logger.info("No vulnerabilities found in scan results")
    
    # Update scan record using unique findings seen in THIS scan.
    vuln_count = len(current_scan_vulnerabilities)
    severity_counts = {
        "critical": len([v for v in current_scan_vulnerabilities if v["severity"] == "critical"]),
        "high": len([v for v in current_scan_vulnerabilities if v["severity"] == "high"]),
        "medium": len([v for v in current_scan_vulnerabilities if v["severity"] == "medium"]),
        "low": len([v for v in current_scan_vulnerabilities if v["severity"] == "low"])
    }
    
    await db.scans.update_one(
        {"id": payload.scan_id},
        {"$set": {
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.now().isoformat(),
            "vulnerability_count": vuln_count,
            "severity_counts": severity_counts,
            "commit_sha": payload.commit_sha,
            "errors": payload.results.errors
        }}
    )
    
    logger.info(f"Updated scan record: {payload.scan_id} - Status: completed, Vulnerabilities: {vuln_count}")
    
    # Update repository stats
    await db.repositories.update_one(
        {"id": repo_id},
        {"$set": {
            "last_scan": datetime.now().isoformat(),
            "vulnerability_count": vuln_count,
            "last_scan_branch": payload.branch,
            "last_commit_sha": payload.commit_sha
        }}
    )
    
    logger.info(f"Updated repository {repo_id} stats - Total vulnerabilities: {vuln_count}")
    
    # Log activity
    await log_activity(
        db, user_id, 'scan_completed', 'repository', repo_id,
        details={"message": f"Found {vuln_count} vulnerabilities", "vulnerability_count": vuln_count, "severity_counts": severity_counts}
    )
    
    # Store notification for real-time delivery
    notification = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "type": "scan_complete",
        "title": "Scan Completed",
        "message": f"Security scan for {payload.repository} found {vuln_count} vulnerabilities",
        "data": {
            "scan_id": payload.scan_id,
            "repository_id": repo_id,
            "repository": payload.repository,
            "vulnerability_count": vuln_count,
            "severity_counts": severity_counts
        },
        "read": False,
        "created_at": datetime.now().isoformat()
    }
    
    # Insert into DB (this adds _id field to the dict)
    await db.notifications.insert_one(notification)
    
    # Send real-time WebSocket notification (remove _id to avoid serialization error)
    notification_copy = {k: v for k, v in notification.items() if k != '_id'}
    ws_manager = get_connection_manager()
    
    # First, try to send to scan-specific socket
    scan_socket_sent = await ws_manager.send_to_scan(payload.scan_id, {
        "type": "scan_complete",
        "notification": notification_copy
    })
    
    # Also send to general user connections
    await ws_manager.send_to_user(user_id, {
        "type": "scan_complete",
        "notification": notification_copy
    })
    
    logger.info(f"Scan {payload.scan_id} completed with {vuln_count} vulnerabilities")
    
    # Clean up: Delete ALL Fixora files from the repository after scan completes.
    # Each deletion is independent — a failure on one does NOT stop the others.
    try:
        # Get GitHub connection for this user
        github_connection = await db.github_connections.find_one({"user_id": user_id})
        
        if not github_connection:
            logger.warning(f"No GitHub connection found for user {user_id}, skipping cleanup")
        else:
            installation_id = github_connection.get("installation_id")
            if installation_id:
                from routes.github_routes import get_installation_access_token
                access_token = await get_installation_access_token(installation_id)
                if not access_token:
                    access_token = github_connection.get("access_token", "")
            else:
                access_token = github_connection.get("access_token", "")

            if not access_token:
                logger.error("No access token available for cleanup, skipping")
            else:
                service = GitHubScanService(access_token)
                owner, repo_name = payload.repository.split("/", 1)
                repo_info = await service.get_repository_info(owner, repo_name)
                default_branch = repo_info.get("default_branch", "main")

                # 1. Delete Semgrep workflow (.github/workflows/fixora-scan.yml)
                try:
                    ok = await service.delete_workflow_file(owner, repo_name, default_branch)
                    if ok:
                        logger.info(f"✅ Deleted Semgrep workflow from {payload.repository}")
                    else:
                        logger.warning(f"⚠️  Semgrep workflow not deleted from {payload.repository}")
                except Exception as e:
                    logger.error(f"Error deleting Semgrep workflow: {e}")

                # 2. Delete Wrapper Hunter workflow (.github/workflows/fixora-wrapper-hunter.yml)
                try:
                    ok = await service.delete_wrapper_hunter_workflow(owner, repo_name, default_branch)
                    if ok:
                        logger.info(f"✅ Deleted Wrapper Hunter workflow from {payload.repository}")
                    else:
                        logger.warning(f"⚠️  Wrapper Hunter workflow not deleted from {payload.repository}")
                except Exception as e:
                    logger.error(f"Error deleting Wrapper Hunter workflow: {e}")

                # 3. Delete AI-generated custom rules (.fixora-rules.yml)
                try:
                    ok = await service.delete_custom_rules_file(owner, repo_name, default_branch)
                    if ok:
                        logger.info(f"✅ Deleted custom rules file from {payload.repository}")
                    else:
                        logger.warning(f"⚠️  Custom rules file not deleted from {payload.repository}")
                except Exception as e:
                    logger.error(f"Error deleting custom rules file: {e}")

    except Exception as e:
        logger.error(f"Unexpected error during post-scan cleanup: {e}")
    
    # Close the scan-specific WebSocket connection
    if scan_socket_sent:
        await ws_manager.disconnect_scan(payload.scan_id)
        logger.info(f"Closed WebSocket for scan {payload.scan_id}")
    
    return {
        "success": True,
        "processed": vuln_count,
        "scan_id": payload.scan_id
    }
