# HuggingFace LLM Service for analyzing wrapper functions
import logging
import json
from typing import Dict, Any, List, Optional
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def build_wrapper_analysis_prompt(wrapper_data: Dict[str, Any]) -> str:
    """
    Build a structured prompt for the LLM to analyze wrapper functions
    and generate custom Semgrep rules for vulnerable wrappers.
    """
    prompt_parts = []
    prompt_parts.append(
        "You are an expert SAST security engineer. I am providing you with the dependency analysis "
        "and custom wrapper functions from a codebase. Your task is to:\n\n"
        "1. Analyze each wrapper function that calls known dangerous sinks "
        "(e.g., os.system, subprocess.run, eval, exec, child_process.exec, SQL query builders, etc.)\n"
        "2. Determine if the wrapper adequately sanitizes inputs before passing them to the sink.\n"
        "3. If a wrapper does NOT sanitize inputs, generate a valid Semgrep YAML rule using taint mode "
        "where the pattern-sink is a call to that specific wrapper function.\n"
        "4. If a wrapper adequately sanitizes inputs, skip it.\n\n"
        "Return ONLY a valid JSON object with this structure:\n"
        '{\n'
        '  "custom_rules": [\n'
        '    {\n'
        '      "id": "fixora-custom-<function_name>",\n'
        '      "message": "Description of the vulnerability",\n'
        '      "severity": "ERROR|WARNING|INFO",\n'
        '      "languages": ["python"|"javascript"|"typescript"],\n'
        '      "rule_yaml": "<complete semgrep rule in YAML format>"\n'
        '    }\n'
        '  ],\n'
        '  "analysis_summary": "Brief summary of findings"\n'
        '}\n\n'
        "If no vulnerable wrappers are found, return: {\"custom_rules\": [], \"analysis_summary\": \"No vulnerable wrappers found\"}\n\n"
        "Here is the codebase analysis:\n\n"
    )

    # Add Python section
    if "python" in wrapper_data:
        py = wrapper_data["python"]
        prompt_parts.append("=== PYTHON PROJECT ===\n")
        prompt_parts.append(f"User-installed packages: {', '.join(py['packages'].get('user_installed', []))}\n")
        prompt_parts.append(f"Stdlib modules are also available.\n\n")

        wrappers = py.get("wrapper_functions", [])
        if wrappers:
            prompt_parts.append(f"Found {len(wrappers)} wrapper function(s) calling external libraries:\n\n")
            for i, w in enumerate(wrappers, 1):
                prompt_parts.append(f"--- Wrapper {i}: {w['function_name']} ---\n")
                prompt_parts.append(f"File: {w['file']}\n")
                prompt_parts.append(f"Lines: {w['line_start']}-{w['line_end']}\n")
                prompt_parts.append(f"Calls: {', '.join(w['calls'])}\n")
                prompt_parts.append(f"Source code:\n```python\n{w['source_code']}\n```\n\n")
        else:
            prompt_parts.append("No wrapper functions found in Python code.\n\n")

    # Add React/JS section
    if "react" in wrapper_data:
        js = wrapper_data["react"]
        prompt_parts.append("=== REACT/JAVASCRIPT PROJECT ===\n")
        prompt_parts.append(f"User-installed packages: {', '.join(js['packages'].get('user_installed', []))}\n")
        prompt_parts.append(f"Node.js built-in modules are also available.\n\n")

        wrappers = js.get("wrapper_functions", [])
        if wrappers:
            prompt_parts.append(f"Found {len(wrappers)} wrapper function(s) calling external libraries:\n\n")
            for i, w in enumerate(wrappers, 1):
                prompt_parts.append(f"--- Wrapper {i}: {w['function_name']} ---\n")
                prompt_parts.append(f"File: {w['file']}\n")
                prompt_parts.append(f"Lines: {w['line_start']}-{w['line_end']}\n")
                prompt_parts.append(f"Calls: {', '.join(w['calls'])}\n")
                prompt_parts.append(f"Source code:\n```javascript\n{w['source_code']}\n```\n\n")
        else:
            prompt_parts.append("No wrapper functions found in React/JS code.\n\n")

    return "".join(prompt_parts)


async def analyze_wrappers_with_llm(wrapper_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send wrapper analysis data to HuggingFace LLM and get custom Semgrep rules back.
    Uses Qwen/Qwen3-Coder-Next:novita model via OpenAI-compatible API.
    """
    from openai import OpenAI

    hf_token = settings.hf_token
    if not hf_token:
        logger.error("HF_TOKEN not configured. Cannot analyze wrappers with LLM.")
        return {"custom_rules": [], "analysis_summary": "HF_TOKEN not configured", "error": True}

    # Build the prompt
    prompt = build_wrapper_analysis_prompt(wrapper_data)
    
    logger.info("=" * 80)
    logger.info("WRAPPER HUNTER PROMPT SENT TO HUGGING FACE LLM:")
    logger.info("=" * 80)
    logger.info(prompt)
    logger.info("=" * 80)

    try:
        client = OpenAI(
            base_url="https://router.huggingface.co/v1",
            api_key=hf_token,
        )

        completion = client.chat.completions.create(
            model="Qwen/Qwen3-Coder-Next:novita",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert SAST security engineer. Analyze wrapper functions for security vulnerabilities "
                        "and generate custom Semgrep rules. Always respond with valid JSON only, no markdown formatting."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
        )

        raw_response = completion.choices[0].message.content
        
        logger.info("=" * 80)
        logger.info("HUGGING FACE LLM RESPONSE:")
        logger.info("=" * 80)
        logger.info(raw_response)
        logger.info("=" * 80)

        # Parse the response - try to extract JSON from it
        result = _extract_json_from_response(raw_response)
        
        if result is None:
            logger.warning("Could not parse LLM response as JSON, returning empty rules")
            return {
                "custom_rules": [],
                "analysis_summary": "LLM response could not be parsed",
                "raw_response": raw_response
            }

        # Ensure expected structure
        if "custom_rules" not in result:
            result["custom_rules"] = []
        if "analysis_summary" not in result:
            result["analysis_summary"] = "Analysis complete"

        return result

    except Exception as e:
        logger.error(f"Error calling HuggingFace LLM: {e}")
        return {
            "custom_rules": [],
            "analysis_summary": f"LLM error: {str(e)}",
            "error": True
        }


def _extract_json_from_response(text: str) -> Optional[Dict]:
    """Try to extract valid JSON from LLM response text"""
    # First, try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON block in markdown code fences
    import re
    json_patterns = [
        r'```json\s*\n(.*?)\n```',
        r'```\s*\n(.*?)\n```',
        r'\{[\s\S]*"custom_rules"[\s\S]*\}'
    ]
    
    for pattern in json_patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                json_str = match.group(1) if match.lastindex else match.group(0)
                return json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                continue

    return None
