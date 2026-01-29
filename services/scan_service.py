# Scan service - handles vulnerability scanning
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from schemas.ai_pattern import AIPattern, AIPatternCreate
from schemas.vulnerability import Vulnerability, VulnerabilityCreate, VulnerabilitySeverity

logger = logging.getLogger(__name__)

async def run_scan(scan_id: str, repository_id: str, db):
    """Background task to simulate scanning process"""
    try:
        # Phase 1: Discovery (mock)
        await db.scans.update_one(
            {'scan_id': scan_id},
            {'$set': {'status': 'running', 'phase': 'discovery', 'progress': 10}}
        )
        await asyncio.sleep(2)
        
        # Create mock AI patterns
        patterns = [
            AIPatternCreate(
                repository_id=repository_id,
                pattern_type='sink',
                pattern_name='db.execute()',
                description='Database execution sink detected',
                confidence=0.92
            ),
            AIPatternCreate(
                repository_id=repository_id,
                pattern_type='wrapper',
                pattern_name='safe_query()',
                description='Safe query wrapper function',
                confidence=0.88
            )
        ]
        
        for pattern_data in patterns:
            pattern = AIPattern(**pattern_data.model_dump())
            doc = pattern.model_dump()
            doc['created_at'] = doc['created_at'].isoformat()
            await db.ai_patterns.insert_one(doc)
        
        # Phase 2: Scanning
        await db.scans.update_one(
            {'scan_id': scan_id},
            {'$set': {'phase': 'scanning', 'progress': 40, 'patterns_discovered': len(patterns)}}
        )
        await asyncio.sleep(3)
        
        # Phase 3: Classification (mock vulnerabilities)
        await db.scans.update_one(
            {'scan_id': scan_id},
            {'$set': {'phase': 'classification', 'progress': 70}}
        )
        
        mock_vulns = [
            VulnerabilityCreate(
                repository_id=repository_id,
                type='SQL Injection',
                severity=VulnerabilitySeverity.HIGH,
                title='Potential SQL Injection in user query',
                description='User input directly concatenated to SQL query',
                cwe_id='CWE-89',
                file_path='src/api/users.py',
                line_number=45,
                code_snippet='query = "SELECT * FROM users WHERE id = " + user_id',
                ai_confidence=0.94,
                ai_reasoning='Detected unsanitized user input flowing into database sink'
            ),
            VulnerabilityCreate(
                repository_id=repository_id,
                type='Command Injection',
                severity=VulnerabilitySeverity.CRITICAL,
                title='Command injection vulnerability',
                description='Shell command execution with user input',
                cwe_id='CWE-78',
                file_path='src/utils/process.py',
                line_number=23,
                code_snippet='os.system("ping " + user_input)',
                ai_confidence=0.98,
                ai_reasoning='Direct os.system call with unsanitized input'
            )
        ]
        
        for vuln_data in mock_vulns:
            vuln = Vulnerability(**vuln_data.model_dump())
            doc = vuln.model_dump()
            doc['created_at'] = doc['created_at'].isoformat()
            await db.vulnerabilities.insert_one(doc)
        
        await asyncio.sleep(2)
        
        # Phase 4: Complete
        await db.scans.update_one(
            {'scan_id': scan_id},
            {'$set': {
                'status': 'completed',
                'phase': 'completed',
                'progress': 100,
                'vulnerabilities_found': len(mock_vulns),
                'completed_at': datetime.now(timezone.utc).isoformat()
            }}
        )
        
        # Update repository
        await db.repositories.update_one(
            {'id': repository_id},
            {'$set': {
                'last_scan': datetime.now(timezone.utc).isoformat(),
                'total_vulnerabilities': len(mock_vulns),
                'status': 'connected'
            }}
        )
        
    except Exception as e:
        logger.error(f'Scan failed: {e}')
        await db.scans.update_one(
            {'scan_id': scan_id},
            {'$set': {'status': 'failed', 'message': str(e)}}
        )
