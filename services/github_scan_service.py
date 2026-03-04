# GitHub Scanning Service - Implements the "Infection" mechanism
# Pushes workflows, injects secrets, and triggers scans via GitHub Actions

import httpx
import logging
import uuid
import base64
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

GITHUB_API_URL = "https://api.github.com"
WORKFLOW_FILE_PATH = ".github/workflows/fixora-scan.yml"
WRAPPER_WORKFLOW_FILE_PATH = ".github/workflows/fixora-wrapper-hunter.yml"
CUSTOM_RULES_FILE_PATH = ".fixora-rules.yml"

# ============== WRAPPER HUNTER WORKFLOW TEMPLATE ==============
WRAPPER_HUNTER_TEMPLATE = '''name: Fixora Wrapper Hunter

on:
  repository_dispatch:
    types: [fixora-wrapper-hunt]
  workflow_dispatch:
    inputs:
      scan_id:
        description: 'Fixora scan ID for tracking'
        required: true
      target_branch:
        description: 'Branch to analyze'
        required: true
        default: 'main'

jobs:
  wrapper-hunt:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.client_payload.target_branch || github.event.inputs.target_branch }}
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run Wrapper Hunter
        run: |
          cat > /tmp/wrapper_hunter.py << 'HUNTER_SCRIPT'
          #!/usr/bin/env python3
          import ast
          import os
          import re
          import json

          IGNORE_DIRS = {
              "node_modules", "venv", ".venv", "env", ".env", ".git",
              "__pycache__", "build", "dist", ".next", ".cache",
              "coverage", ".tox", "egg-info", ".eggs", "site-packages",
              ".github", ".vscode",
          }

          # ─── LANGUAGE DETECTION ───────────────────────────────────────────────────────
          def detect_language(repo_root):
              has_py = (
                  os.path.isfile(os.path.join(repo_root, "requirements.txt"))
                  or os.path.isfile(os.path.join(repo_root, "setup.py"))
                  or os.path.isfile(os.path.join(repo_root, "pyproject.toml"))
                  or os.path.isfile(os.path.join(repo_root, "Pipfile"))
                  or os.path.isfile(os.path.join(repo_root, "setup.cfg"))
              )
              has_js = os.path.isfile(os.path.join(repo_root, "package.json"))
              if has_py and has_js:
                  return "both"
              if has_py:
                  return "python"
              if has_js:
                  return "react"
              for dirpath, dirnames, filenames in os.walk(repo_root):
                  dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                  for fn in filenames:
                      if fn.endswith(".py"):
                          return "python"
                      if fn.endswith((".js", ".jsx", ".ts", ".tsx")):
                          return "react"
              return "unknown"

          # ─── MANIFEST PARSERS ─────────────────────────────────────────────────────────
          def _parse_single_requirements_file(path):
              # Parse a single requirements file -> clean package names
              pkgs = []
              if not os.path.isfile(path):
                  return pkgs
              with open(path, "r", errors="ignore") as f:
                  for line in f:
                      line = line.strip()
                      if not line or line.startswith(("#", "-", "git+", "http")):
                          continue
                      name = re.split(r"[><=!~;@\[#\s]", line)[0].strip()
                      if name:
                          pkgs.append(name.lower().replace("-", "_"))
              return pkgs

          def parse_requirements_txt(repo_root):
              # Parse requirements.txt AND any requirements-*.txt / requirements/*.txt
              pkgs = set()
              # Main file
              main = os.path.join(repo_root, "requirements.txt")
              pkgs.update(_parse_single_requirements_file(main))
              # Extra files at root: requirements-dev.txt, requirements_test.txt, etc.
              for fn in os.listdir(repo_root):
                  if re.match(r"requirements[_-].+\.txt$", fn, re.IGNORECASE):
                      pkgs.update(_parse_single_requirements_file(os.path.join(repo_root, fn)))
              # Subdirectory: requirements/*.txt
              req_dir = os.path.join(repo_root, "requirements")
              if os.path.isdir(req_dir):
                  for fn in os.listdir(req_dir):
                      if fn.endswith(".txt"):
                          pkgs.update(_parse_single_requirements_file(os.path.join(req_dir, fn)))
              return sorted(pkgs)

          def parse_setup_py(repo_root):
              # Extract install_requires from setup.py using regex
              pkgs = []
              sp = os.path.join(repo_root, "setup.py")
              if not os.path.isfile(sp):
                  return pkgs
              try:
                  with open(sp, "r", errors="ignore") as f:
                      content = f.read()
                  m = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
                  if m:
                      for pkg in re.findall(r"""["']([^"']+)["']""", m.group(1)):
                          name = re.split(r"[><=!~;\[#\s]", pkg)[0].strip()
                          if name:
                              pkgs.append(name.lower().replace("-", "_"))
              except Exception:
                  pass
              return sorted(set(pkgs))

          def parse_pyproject_toml(repo_root):
              # Extract dependencies from pyproject.toml using regex (no toml lib needed)
              pkgs = []
              pp = os.path.join(repo_root, "pyproject.toml")
              if not os.path.isfile(pp):
                  return pkgs
              try:
                  with open(pp, "r", errors="ignore") as f:
                      content = f.read()
                  # [project] dependencies = [...]
                  m = re.search(r"\[project\].*?dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
                  if m:
                      for pkg in re.findall(r"""["']([^"']+)["']""", m.group(1)):
                          name = re.split(r"[><=!~;\[#\s]", pkg)[0].strip()
                          if name:
                              pkgs.append(name.lower().replace("-", "_"))
                  # [tool.poetry.dependencies]
                  m2 = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?:\[|\Z)", content, re.DOTALL)
                  if m2:
                      for line in m2.group(1).strip().splitlines():
                          line = line.strip()
                          if line and not line.startswith(("#", "[")) and "=" in line:
                              name = line.split("=")[0].strip().strip('"').strip("'")
                              if name and name != "python":
                                  pkgs.append(name.lower().replace("-", "_"))
              except Exception:
                  pass
              return sorted(set(pkgs))

          def parse_pipfile(repo_root):
              # Extract packages from Pipfile [packages] section
              pkgs = []
              pf = os.path.join(repo_root, "Pipfile")
              if not os.path.isfile(pf):
                  return pkgs
              try:
                  with open(pf, "r", errors="ignore") as f:
                      content = f.read()
                  for section_name in ("packages", "dev-packages"):
                      pat = rf"\[{re.escape(section_name)}\](.*?)(?:\[|\Z)"
                      m = re.search(pat, content, re.DOTALL)
                      if m:
                          for line in m.group(1).strip().splitlines():
                              line = line.strip()
                              if line and not line.startswith("#") and "=" in line:
                                  name = line.split("=")[0].strip().strip('"').strip("'")
                                  if name:
                                      pkgs.append(name.lower().replace("-", "_"))
              except Exception:
                  pass
              return sorted(set(pkgs))

          def parse_package_json(repo_root):
              # Parse package.json -> all dependency names
              pkgs = []
              pj = os.path.join(repo_root, "package.json")
              if not os.path.isfile(pj):
                  return pkgs
              try:
                  with open(pj, "r", errors="ignore") as f:
                      data = json.load(f)
                  for key in ("dependencies", "devDependencies", "peerDependencies"):
                      if key in data and isinstance(data[key], dict):
                          pkgs.extend(data[key].keys())
              except Exception:
                  pass
              return sorted(set(pkgs))

          # ─── IMPORT COLLECTORS ────────────────────────────────────────────────────────
          def collect_python_imports(repo_root):
              # Walk all .py files; collect every top-level module name imported
              found = set()
              for dirpath, dirnames, filenames in os.walk(repo_root):
                  dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                  for fn in filenames:
                      if not fn.endswith(".py"):
                          continue
                      fp = os.path.join(dirpath, fn)
                      try:
                          with open(fp, "r", errors="ignore") as f:
                              source = f.read()
                          tree = ast.parse(source, filename=fp)
                      except Exception:
                          continue
                      for node in ast.walk(tree):
                          if isinstance(node, ast.Import):
                              for alias in node.names:
                                  found.add(alias.name.split(".")[0])
                          elif isinstance(node, ast.ImportFrom):
                              if node.module:
                                  found.add(node.module.split(".")[0])
              return sorted(found)

          def collect_js_imports(repo_root):
              # Walk all JS/TS files; collect every imported module name via import/require
              found = set()
              JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
              for dirpath, dirnames, filenames in os.walk(repo_root):
                  dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                  for fn in filenames:
                      if not any(fn.endswith(ext) for ext in JS_EXTS):
                          continue
                      fp = os.path.join(dirpath, fn)
                      try:
                          with open(fp, "r", errors="ignore") as f:
                              source = f.read()
                      except Exception:
                          continue
                      for m in re.finditer(r'import\s+(?:[^\\x22\\x27]*\s+from\s+)?[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]', source):
                          mod = m.group(1)
                          if not mod.startswith("."):
                              found.add(mod.split("/")[0] if not mod.startswith("@") else "/".join(mod.split("/")[:2]))
                      for m in re.finditer(r'require\s*\(\s*[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]\s*\)', source):
                          mod = m.group(1)
                          if not mod.startswith("."):
                              found.add(mod.split("/")[0] if not mod.startswith("@") else "/".join(mod.split("/")[:2]))
              return sorted(found)

          # ─── PYTHON WRAPPER EXTRACTION (AST) ─────────────────────────────────────────
          def _get_call_name(call_node):
              func = call_node.func
              if isinstance(func, ast.Name):
                  return func.id
              elif isinstance(func, ast.Attribute):
                  parts = []
                  node = func
                  while isinstance(node, ast.Attribute):
                      parts.append(node.attr)
                      node = node.value
                  if isinstance(node, ast.Name):
                      parts.append(node.id)
                  return ".".join(reversed(parts))
              return None

          # Known dangerous method names — indicate security-relevant operations
          # even when called on LOCAL objects (e.g. cursor.execute, proc.communicate).
          # These catch cases where the AST can't trace variable origin back to a module.
          DANGEROUS_SINK_METHODS = {
              # Database / SQL
              "execute", "executemany", "executescript", "mogrify", "callproc",
              "raw", "extra",
              # OS / Command execution
              "system", "popen",
              # Request / SSRF
              "urlopen", "urlretrieve",
              # Deserialization (when on unknown objects)
              "loads", "load",
          }

          def extract_python_wrappers(repo_root, all_modules):
              # Find every function that:
              #   1. Calls any module from all_modules (existing), OR
              #   2. Calls a method on a variable derived from an imported module
              #      (e.g. cursor.execute where cursor = conn.cursor()), OR
              #   3. Calls a known dangerous method on ANY object (fallback)
              wrappers = []
              target = set(all_modules)
              dangerous_builtins = {"eval", "exec", "__import__", "compile", "open", "globals", "locals"}
              for dirpath, dirnames, filenames in os.walk(repo_root):
                  dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                  for fn in filenames:
                      if not fn.endswith(".py"):
                          continue
                      fp = os.path.join(dirpath, fn)
                      try:
                          with open(fp, "r", errors="ignore") as f:
                              source = f.read()
                          tree = ast.parse(source, filename=fp)
                      except Exception:
                          continue
                      # Per-file: alias -> root module name
                      imported_names = {}
                      for node in ast.walk(tree):
                          if isinstance(node, ast.Import):
                              for alias in node.names:
                                  root = alias.name.split(".")[0]
                                  if root in target:
                                      imported_names[alias.asname or alias.name.split(".")[0]] = root
                          elif isinstance(node, ast.ImportFrom):
                              module = (node.module or "").split(".")[0]
                              if module in target:
                                  for alias in node.names:
                                      imported_names[alias.asname or alias.name] = module
                      rel = os.path.relpath(fp, repo_root)
                      for node in ast.walk(tree):
                          if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                              # ── Pass 1: Track variables derived from imports ──
                              # Handles chains like:
                              #   conn = sqlite3.connect(...)   → conn linked to sqlite3
                              #   cursor = conn.cursor()        → cursor linked to sqlite3
                              # Two iterations catch A→B→C chains.
                              import_derived = {}
                              for _pass in range(2):
                                  for child in ast.walk(node):
                                      # Simple assignments: x = something.method()
                                      if isinstance(child, ast.Assign):
                                          if isinstance(child.value, ast.Call):
                                              cn = _get_call_name(child.value)
                                              if cn:
                                                  cr = cn.split(".")[0]
                                                  linked = imported_names.get(cr) or import_derived.get(cr)
                                                  if linked:
                                                      for tgt in child.targets:
                                                          if isinstance(tgt, ast.Name):
                                                              import_derived[tgt.id] = linked
                                          # x = something (non-call assignment from import alias)
                                          elif isinstance(child.value, ast.Attribute):
                                              cn = _get_call_name(ast.Call(func=child.value, args=[], keywords=[]))  # reuse helper
                                              if cn:
                                                  cr = cn.split(".")[0]
                                                  linked = imported_names.get(cr) or import_derived.get(cr)
                                                  if linked:
                                                      for tgt in child.targets:
                                                          if isinstance(tgt, ast.Name):
                                                              import_derived[tgt.id] = linked
                                          elif isinstance(child.value, ast.Name):
                                              if child.value.id in imported_names:
                                                  for tgt in child.targets:
                                                      if isinstance(tgt, ast.Name):
                                                          import_derived[tgt.id] = imported_names[child.value.id]
                                              elif child.value.id in import_derived:
                                                  for tgt in child.targets:
                                                      if isinstance(tgt, ast.Name):
                                                          import_derived[tgt.id] = import_derived[child.value.id]
                                      # with-statement context managers:
                                      #   with sqlite3.connect("db") as conn:
                                      #   async with aiohttp.ClientSession() as session:
                                      if isinstance(child, (ast.With, ast.AsyncWith)):
                                          for item in child.items:
                                              ctx = item.context_expr
                                              if isinstance(ctx, ast.Call) and item.optional_vars:
                                                  cn = _get_call_name(ctx)
                                                  if cn:
                                                      cr = cn.split(".")[0]
                                                      linked = imported_names.get(cr) or import_derived.get(cr)
                                                      if linked and isinstance(item.optional_vars, ast.Name):
                                                          import_derived[item.optional_vars.id] = linked

                              # ── Pass 2: Collect calls ──────────────────────────
                              calls_found = {}
                              for child in ast.walk(node):
                                  if isinstance(child, ast.Call):
                                      call_str = _get_call_name(child)
                                      if not call_str:
                                          continue
                                      root = call_str.split(".")[0]
                                      # Direct import call (existing)
                                      if root in imported_names:
                                          calls_found[call_str] = imported_names[root]
                                      # Dangerous builtins (existing)
                                      elif root in dangerous_builtins:
                                          calls_found[call_str] = "builtins"
                                      # NEW: Variable derived from an import (cursor.execute, conn.commit)
                                      elif root in import_derived:
                                          calls_found[call_str] = import_derived[root]
                                      # NEW: Known dangerous method on any object (fallback)
                                      elif "." in call_str:
                                          method = call_str.rsplit(".", 1)[-1]
                                          if method in DANGEROUS_SINK_METHODS:
                                              calls_found[call_str] = f"<object>.{method}"
                              if calls_found:
                                  func_src = ast.get_source_segment(source, node) or ""
                                  wrappers.append({
                                      "function_name": node.name,
                                      "file": rel,
                                      "line_start": node.lineno,
                                      "line_end": node.end_lineno,
                                      "calls": list(calls_found.keys()),
                                      "modules_used": list(set(calls_found.values())),
                                      "source_code": func_src,
                                  })
              return wrappers

          # ─── JS/REACT WRAPPER EXTRACTION (regex) ─────────────────────────────────────
          def extract_js_wrappers(repo_root, all_modules):
              # Find functions in JS/TS files that call any module from all_modules
              wrappers = []
              JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
              target = set(all_modules)
              SKIP_NAMES = {"if", "for", "while", "switch", "catch", "constructor", "else", "try"}
              for dirpath, dirnames, filenames in os.walk(repo_root):
                  dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                  for fn in filenames:
                      if not any(fn.endswith(ext) for ext in JS_EXTS):
                          continue
                      fp = os.path.join(dirpath, fn)
                      try:
                          with open(fp, "r", errors="ignore") as f:
                              source = f.read()
                      except Exception:
                          continue
                      # Build alias -> module map for modules in target
                      alias_map = {}
                      for m in re.finditer(r'import\s+(\w+)\s+from\s+[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]', source):
                          raw_mod = m.group(2)
                          mod = raw_mod.split("/")[0] if not raw_mod.startswith("@") else "/".join(raw_mod.split("/")[:2])
                          if mod in target:
                              alias_map[m.group(1)] = mod
                      for m in re.finditer(r'import\s+\{([^}]+)\}\s+from\s+[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]', source):
                          raw_mod = m.group(2)
                          mod = raw_mod.split("/")[0] if not raw_mod.startswith("@") else "/".join(raw_mod.split("/")[:2])
                          if mod in target:
                              for part in m.group(1).split(","):
                                  part = part.strip()
                                  if " as " in part:
                                      _, alias = part.split(" as ", 1)
                                      alias_map[alias.strip()] = mod
                                  else:
                                      alias_map[part] = mod
                      for m in re.finditer(r'(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]\s*\)', source):
                          raw_mod = m.group(2)
                          mod = raw_mod.split("/")[0] if not raw_mod.startswith("@") else "/".join(raw_mod.split("/")[:2])
                          if mod in target:
                              alias_map[m.group(1)] = mod
                      for m in re.finditer(r'(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(\s*[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]\s*\)', source):
                          raw_mod = m.group(2)
                          mod = raw_mod.split("/")[0] if not raw_mod.startswith("@") else "/".join(raw_mod.split("/")[:2])
                          if mod in target:
                              for part in m.group(1).split(","):
                                  alias_map[part.strip()] = mod
                      if not alias_map:
                          continue
                      rel = os.path.relpath(fp, repo_root)
                      FUNC_RE = re.compile(
                          r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{'
                          r'|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{'
                          r'|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\([^)]*\)\s*\{'
                      )
                      for m in FUNC_RE.finditer(source):
                          func_name = next((g for g in m.groups() if g), None)
                          if not func_name or func_name in SKIP_NAMES:
                              continue
                          try:
                              brace_pos = source.index("{", m.start())
                          except ValueError:
                              continue
                          depth = 0
                          end_pos = brace_pos
                          for i in range(brace_pos, len(source)):
                              if source[i] == "{":
                                  depth += 1
                              elif source[i] == "}":
                                  depth -= 1
                                  if depth == 0:
                                      end_pos = i
                                      break
                          func_body = source[m.start():end_pos + 1]
                          calls_found = {}
                          for alias, mod in alias_map.items():
                              for cm in re.finditer(r'\\b' + re.escape(alias) + r'\.(\w+)\s*\(', func_body):
                                  calls_found[alias + "." + cm.group(1)] = mod
                              if re.search(r'\\b' + re.escape(alias) + r'\s*\(', func_body):
                                  if alias not in calls_found:
                                      calls_found[alias] = mod
                          if calls_found:
                              line_start = source[:m.start()].count("\\n") + 1
                              line_end = line_start + func_body.count("\\n")
                              wrappers.append({
                                  "function_name": func_name,
                                  "file": rel,
                                  "line_start": line_start,
                                  "line_end": line_end,
                                  "calls": list(calls_found.keys()),
                                  "modules_used": list(set(calls_found.values())),
                                  "source_code": func_body,
                              })
              return wrappers

          # ─── ORCHESTRATOR ─────────────────────────────────────────────────────────────
          def run_wrapper_hunter(repo_root="."):
              lang = detect_language(repo_root)
              results = {}
              if lang in ("python", "both"):
                  # Collect from ALL manifest sources
                  manifest_pkgs = sorted(set(
                      parse_requirements_txt(repo_root)
                      + parse_setup_py(repo_root)
                      + parse_pyproject_toml(repo_root)
                      + parse_pipfile(repo_root)
                  ))
                  import_mods = collect_python_imports(repo_root)
                  all_modules = sorted(set(manifest_pkgs) | set(import_mods))
                  results["python"] = {
                      "modules": {
                          "from_manifest": manifest_pkgs,
                          "from_imports": import_mods,
                          "all": all_modules,
                      },
                      "wrapper_functions": extract_python_wrappers(repo_root, all_modules),
                  }
              if lang in ("react", "both"):
                  manifest_pkgs = parse_package_json(repo_root)
                  import_mods = collect_js_imports(repo_root)
                  all_modules = sorted(set(manifest_pkgs) | set(import_mods))
                  results["react"] = {
                      "modules": {
                          "from_manifest": manifest_pkgs,
                          "from_imports": import_mods,
                          "all": all_modules,
                      },
                      "wrapper_functions": extract_js_wrappers(repo_root, all_modules),
                  }
              return {"language": lang, "results": results}

          if __name__ == "__main__":
              output = run_wrapper_hunter(".")
              with open("wrapper-hunter-results.json", "w") as f:
                  json.dump(output, f, indent=2)
              print(json.dumps(output, indent=2))
          HUNTER_SCRIPT
          python3 /tmp/wrapper_hunter.py

      - name: Send Wrapper Hunter Results to Fixora
        run: |
          SCAN_ID="${{ github.event.client_payload.scan_id || github.event.inputs.scan_id }}"
          
          if [ -f wrapper-hunter-results.json ]; then
            echo "Sending wrapper hunter results to Fixora backend..."
            
            # Build payload
            jq -n --arg scan_id "$SCAN_ID" --arg repo "${{ github.repository }}" \\
              --slurpfile results wrapper-hunter-results.json \\
              '{scan_id: $scan_id, repository: $repo, wrapper_data: $results[0]}' > wh-payload.json
            
            MAX_RETRIES=3
            RETRY_COUNT=0
            
            while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
              echo "Attempt $((RETRY_COUNT + 1))/$MAX_RETRIES..."
              HTTP_STATUS=$(curl -s -o /tmp/wh-response.txt -w "%{http_code}" \\
                -X POST "${{ secrets.FIXORA_API_URL }}/api/scan/webhook/wrapper-results" \\
                -H "Content-Type: application/json" \\
                -H "X-Fixora-Token: ${{ secrets.FIXORA_API_TOKEN }}" \\
                -d @wh-payload.json \\
                --max-time 60)
              echo "HTTP status: $HTTP_STATUS"
              cat /tmp/wh-response.txt || true
              if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
                echo "✅ Wrapper hunter results sent successfully (HTTP $HTTP_STATUS)"
                exit 0
              else
                RETRY_COUNT=$((RETRY_COUNT + 1))
                echo "⚠️  Attempt $RETRY_COUNT failed (HTTP $HTTP_STATUS). Retrying in 10s..."
                sleep 10
              fi
            done
            
            echo "❌ Failed to send wrapper hunter results after $MAX_RETRIES attempts"
            exit 1
          else
            echo "⚠️  No wrapper hunter results file found"
          fi

      - name: Upload Wrapper Hunter Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: wrapper-hunter-results
          path: wrapper-hunter-results.json
          retention-days: 7
'''

# Semgrep workflow template
WORKFLOW_TEMPLATE = '''name: Fixora Security Scan

on:
  repository_dispatch:
    types: [fixora-scan]
  workflow_dispatch:
    inputs:
      scan_mode:
        description: 'Scan mode: full or diff'
        required: true
        default: 'full'
        type: choice
        options:
          - full
          - diff
      target_branch:
        description: 'Branch to scan'
        required: true
        default: 'main'
      base_commit:
        description: 'Base commit for diff scan (optional)'
        required: false
        default: ''
      scan_id:
        description: 'Fixora scan ID for tracking'
        required: true

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout target branch
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.client_payload.target_branch || github.event.inputs.target_branch }}
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Semgrep
        run: pip install semgrep

      - name: Run Semgrep Scan (Full)
        if: ${{ (github.event.client_payload.scan_mode || github.event.inputs.scan_mode) == 'full' }}
        run: |
          EXTRA_CONFIG=""
          if [ -f .fixora-rules.yml ]; then
            echo "Found Fixora custom rules from AI analysis, including in scan..."
            EXTRA_CONFIG="--config .fixora-rules.yml"
          fi
          FIXORA_EXCLUDE="--exclude '.github/workflows/fixora-scan.yml' --exclude '.github/workflows/fixora-wrapper-hunter.yml'"
          semgrep scan --config auto $EXTRA_CONFIG $FIXORA_EXCLUDE --json --output semgrep-results.json . || true

      - name: Run Semgrep Scan (Diff)
        if: ${{ (github.event.client_payload.scan_mode || github.event.inputs.scan_mode) == 'diff' && (github.event.client_payload.base_commit || github.event.inputs.base_commit) != '' }}
        run: |
          EXTRA_CONFIG=""
          if [ -f .fixora-rules.yml ]; then
            echo "Found Fixora custom rules from AI analysis, including in scan..."
            EXTRA_CONFIG="--config .fixora-rules.yml"
          fi
          BASE_COMMIT="${{ github.event.client_payload.base_commit || github.event.inputs.base_commit }}"
          git diff --name-only $BASE_COMMIT HEAD > all_changed_files.txt
          # Exclude Fixora's own workflow files so Semgrep doesn't flag them
          grep -v -E 'fixora-scan\.yml|fixora-wrapper-hunter\.yml' all_changed_files.txt > changed_files.txt || true
          FIXORA_EXCLUDE="--exclude '.github/workflows/fixora-scan.yml' --exclude '.github/workflows/fixora-wrapper-hunter.yml'"
          if [ -s changed_files.txt ]; then
            semgrep scan --config auto $EXTRA_CONFIG $FIXORA_EXCLUDE --json --output semgrep-results.json $(cat changed_files.txt | tr '\\n' ' ') || true
          else
            echo '{"results": [], "errors": []}' > semgrep-results.json
          fi

      - name: Send Results to Fixora
        run: |
          SCAN_ID="${{ github.event.client_payload.scan_id || github.event.inputs.scan_id }}"
          TARGET_BRANCH="${{ github.event.client_payload.target_branch || github.event.inputs.target_branch }}"
          SCAN_MODE="${{ github.event.client_payload.scan_mode || github.event.inputs.scan_mode }}"
          
          if [ -f semgrep-results.json ]; then
            echo "Sending results to Fixora backend: ${{ secrets.FIXORA_API_URL }}"
            echo "Using API token: ${FIXORA_API_TOKEN:0:10}... (masked for security)"
            
            # Create payload
            cat > payload.json << EOF
          {
            "scan_id": "$SCAN_ID",
            "repository": "${{ github.repository }}",
            "branch": "$TARGET_BRANCH",
            "scan_mode": "$SCAN_MODE",
            "commit_sha": "${{ github.sha }}",
            "results": $(cat semgrep-results.json)
          }
          EOF
            
            # Send to Fixora with retry logic
            MAX_RETRIES=3
            RETRY_COUNT=0
            
            while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
              echo "Attempting to send results (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)..."
              if curl -X POST "${{ secrets.FIXORA_API_URL }}/api/scan/webhook/results" \
                -H "Content-Type: application/json" \
                -H "X-Fixora-Token: ${{ secrets.FIXORA_API_TOKEN }}" \
                -d @payload.json \
                --max-time 30 \
                --retry 2 \
                --retry-delay 5; then
                echo "✅ Results sent successfully"
                exit 0
              else
                RETRY_COUNT=$((RETRY_COUNT + 1))
                echo "⚠️  Attempt $RETRY_COUNT failed. Retrying..."
                sleep 5
              fi
            done
            
            echo "❌ Failed to send results after $MAX_RETRIES attempts"
            echo "This usually means your Fixora backend is not publicly accessible."
            echo "For local development, use ngrok or similar to expose your backend."
            echo "Backend URL configured: ${{ secrets.FIXORA_API_URL }}"
            exit 1
          else
            echo "⚠️  No results file found"
          fi

      - name: Upload Scan Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: semgrep-results
          path: semgrep-results.json
          retention-days: 7
'''


class GitHubScanService:
    """Service for managing GitHub repository scanning infrastructure"""
    
    def __init__(self, access_token: str):
        self.access_token = access_token
        # Check if this is an installation token (starts with ghs_)
        self.is_installation_token = access_token.startswith("ghs_")
        # Use 'token' prefix for OAuth user access tokens (not 'Bearer')
        self.headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.is_installation_token:
            logger.info("GitHubScanService initialized with installation token")
    
    async def get_repository_info(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get repository information including default branch"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}",
                headers=self.headers
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get repository info: {response.text}")
            
            return response.json()
    
    async def get_branches(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Get all branches in a repository"""
        branches = []
        page = 1
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches",
                    params={"per_page": 100, "page": page},
                    headers=self.headers
                )
                
                if response.status_code != 200:
                    raise Exception(f"Failed to get branches: {response.text}")
                
                page_branches = response.json()
                if not page_branches:
                    break
                
                branches.extend([{
                    "name": b["name"],
                    "sha": b["commit"]["sha"],
                    "protected": b.get("protected", False)
                } for b in page_branches])
                
                page += 1
                if page > 10:  # Safety limit
                    break
        
        return branches
    
    async def get_file_tree(self, owner: str, repo: str, branch: str, path: str = "") -> List[Dict[str, Any]]:
        """Get file tree structure for a branch (files and folders only, no content)"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get the tree recursively
            response = await client.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/{branch}",
                params={"recursive": "1"},
                headers=self.headers
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get file tree: {response.text}")
            
            data = response.json()
            tree = data.get("tree", [])
            
            # Format tree structure
            file_tree = []
            for item in tree:
                file_tree.append({
                    "path": item["path"],
                    "type": "folder" if item["type"] == "tree" else "file",
                    "sha": item["sha"],
                    "size": item.get("size", 0) if item["type"] == "blob" else None
                })
            
            return file_tree
    
    async def get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        """Get the SHA of the latest commit on a branch"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Use branches API - more reliable than refs API
            response = await client.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches/{branch}",
                headers=self.headers
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get branch SHA: {response.text}")
            
            return response.json()["commit"]["sha"]
    
    async def check_branch_exists(self, owner: str, repo: str, branch: str) -> bool:
        """Check if a branch exists"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches/{branch}",
                headers=self.headers
            )
            return response.status_code == 200
    
    async def check_token_permissions(self, owner: str, repo: str) -> dict:
        """Check if the token has the required permissions for scanning
        
        Note: For GitHub App installation tokens, the permissions object in API responses
        may show all False values even though the app has full write access.
        We need to verify actual write capability differently.
        """
        result = {
            "can_read": False,
            "can_write": False,
            "scopes": [],
            "error": None
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Make a request and check response headers for scopes
                response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}",
                    headers=self.headers
                )
                
                logger.info(f"Permission check for {owner}/{repo}: status={response.status_code}, is_installation_token={self.is_installation_token}")
                
                if response.status_code == 200:
                    result["can_read"] = True
                    
                    # For installation tokens, the app permissions determine access
                    # Since we configured the app with Contents: write, we have write access
                    if self.is_installation_token:
                        result["can_write"] = True
                        logger.info(f"Installation token - write access granted for {owner}/{repo}")
                        return result
                    
                    # For OAuth tokens, check scopes and permissions
                    scopes = response.headers.get("X-OAuth-Scopes", "")
                    result["scopes"] = [s.strip() for s in scopes.split(",") if s.strip()]
                    
                    # Check repository permissions from response
                    repo_data = response.json()
                    permissions = repo_data.get("permissions", {})
                    result["permissions"] = permissions
                    
                    logger.info(f"OAuth permissions for {owner}/{repo}: {permissions}, scopes: {result['scopes']}")
                    
                    # Check if OAuth token has repo scope or push permission
                    if "repo" in result["scopes"] or "public_repo" in result["scopes"]:
                        result["can_write"] = True
                    elif permissions.get("push", False) or permissions.get("admin", False):
                        result["can_write"] = True
                    else:
                        result["can_write"] = False
                        logger.warning(f"OAuth token lacks write access for {owner}/{repo}")
                        
                elif response.status_code == 403:
                    result["error"] = "Access forbidden - check GitHub App permissions"
                    logger.error(f"403 Forbidden for {owner}/{repo}: {response.text}")
                elif response.status_code == 404:
                    result["error"] = "Repository not found or no access"
                    logger.error(f"404 Not Found for {owner}/{repo}")
                    
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Exception checking permissions for {owner}/{repo}: {e}")
            
        return result
    
    async def inject_repository_secret(self, owner: str, repo: str, secret_name: str, secret_value: str) -> bool:
        """Inject a secret into the repository for GitHub Actions"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # First, get the repository's public key for encrypting secrets
                key_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/actions/secrets/public-key",
                    headers=self.headers
                )
                
                if key_response.status_code != 200:
                    logger.error(f"Failed to get public key: {key_response.status_code} - {key_response.text}")
                    # Secrets might not be accessible, but we can continue
                    return False
                
                key_data = key_response.json()
                public_key = key_data["key"]
                key_id = key_data["key_id"]
                
                # Encrypt the secret using libsodium (PyNaCl)
                from nacl import encoding, public
                
                public_key_bytes = public.PublicKey(public_key.encode(), encoding.Base64Encoder())
                sealed_box = public.SealedBox(public_key_bytes)
                encrypted = sealed_box.encrypt(secret_value.encode())
                encrypted_value = base64.b64encode(encrypted).decode()
                
                # Create or update the secret
                secret_response = await client.put(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/actions/secrets/{secret_name}",
                    headers=self.headers,
                    json={
                        "encrypted_value": encrypted_value,
                        "key_id": key_id
                    }
                )
                
                if secret_response.status_code in [201, 204]:
                    logger.info(f"Injected secret {secret_name} into {owner}/{repo}")
                    return True
                else:
                    logger.error(f"Failed to inject secret: {secret_response.status_code} - {secret_response.text}")
                    return False
                    
        except ImportError:
            logger.error("PyNaCl not installed. Cannot encrypt secrets.")
            return False
        except Exception as e:
            logger.error(f"Error injecting secret: {e}")
            return False
    
    async def push_workflow_file(self, owner: str, repo: str, default_branch: str = "main") -> bool:
        """Push the Semgrep workflow file to the DEFAULT branch (required for repository_dispatch)"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Check if file already exists on default branch
                check_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WORKFLOW_FILE_PATH}",
                    params={"ref": default_branch},
                    headers=self.headers
                )
                
                sha = None
                if check_response.status_code == 200:
                    sha = check_response.json().get("sha")
                
                # Encode workflow content
                content = base64.b64encode(WORKFLOW_TEMPLATE.encode()).decode()
                
                # Create or update the file on DEFAULT branch
                payload = {
                    "message": "chore: Add Fixora security scanning workflow",
                    "content": content,
                    "branch": default_branch
                }
                
                if sha:
                    payload["sha"] = sha
                
                response = await client.put(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WORKFLOW_FILE_PATH}",
                    headers=self.headers,
                    json=payload
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"Pushed workflow file to {owner}/{repo} on branch {default_branch}")
                    return True
                else:
                    logger.error(f"Failed to push workflow: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error pushing workflow file: {e}")
            return False
    
    async def delete_workflow_file(self, owner: str, repo: str, default_branch: str = "main") -> bool:
        """Delete the Fixora workflow file after scan completion to clean up user's repository"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # First, get the file's SHA (required for deletion)
                check_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WORKFLOW_FILE_PATH}",
                    params={"ref": default_branch},
                    headers=self.headers
                )
                
                if check_response.status_code != 200:
                    logger.info(f"Workflow file not found in {owner}/{repo}, nothing to delete")
                    return True  # File doesn't exist, consider it success
                
                sha = check_response.json().get("sha")
                if not sha:
                    logger.error(f"Could not get SHA for workflow file in {owner}/{repo}")
                    return False
                
                # Use client.request("DELETE", ...) because httpx.delete() doesn't support json body
                response = await client.request(
                    "DELETE",
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WORKFLOW_FILE_PATH}",
                    headers=self.headers,
                    json={
                        "message": "chore: Remove Fixora scanning workflow (scan completed)",
                        "sha": sha,
                        "branch": default_branch
                    }
                )
                
                if response.status_code in [200, 204]:
                    logger.info(f"Deleted workflow file from {owner}/{repo} on branch {default_branch}")
                    return True
                else:
                    logger.error(f"Failed to delete workflow: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error deleting workflow file: {e}")
            return False
    
    async def push_wrapper_hunter_workflow(self, owner: str, repo: str, default_branch: str = "main") -> bool:
        """Push the Wrapper Hunter workflow file to the DEFAULT branch"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Check if file already exists
                check_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WRAPPER_WORKFLOW_FILE_PATH}",
                    params={"ref": default_branch},
                    headers=self.headers
                )
                
                sha = None
                if check_response.status_code == 200:
                    sha = check_response.json().get("sha")
                
                content = base64.b64encode(WRAPPER_HUNTER_TEMPLATE.encode()).decode()
                
                payload = {
                    "message": "chore: Add Fixora wrapper hunter workflow",
                    "content": content,
                    "branch": default_branch
                }
                
                if sha:
                    payload["sha"] = sha
                
                response = await client.put(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WRAPPER_WORKFLOW_FILE_PATH}",
                    headers=self.headers,
                    json=payload
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"Pushed wrapper hunter workflow to {owner}/{repo} on branch {default_branch}")
                    return True
                else:
                    logger.error(f"Failed to push wrapper hunter workflow: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error pushing wrapper hunter workflow: {e}")
            return False
    
    async def delete_wrapper_hunter_workflow(self, owner: str, repo: str, default_branch: str = "main") -> bool:
        """Delete the Wrapper Hunter workflow file after completion"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                check_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WRAPPER_WORKFLOW_FILE_PATH}",
                    params={"ref": default_branch},
                    headers=self.headers
                )
                
                if check_response.status_code != 200:
                    logger.info(f"Wrapper hunter workflow not found in {owner}/{repo}, nothing to delete")
                    return True
                
                sha = check_response.json().get("sha")
                if not sha:
                    return False
                
                response = await client.request(
                    "DELETE",
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{WRAPPER_WORKFLOW_FILE_PATH}",
                    headers=self.headers,
                    json={
                        "message": "chore: Remove Fixora wrapper hunter workflow (completed)",
                        "sha": sha,
                        "branch": default_branch
                    }
                )
                
                if response.status_code in [200, 204]:
                    logger.info(f"Deleted wrapper hunter workflow from {owner}/{repo}")
                    return True
                else:
                    logger.error(f"Failed to delete wrapper hunter workflow: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error deleting wrapper hunter workflow: {e}")
            return False
    
    async def push_custom_rules_file(self, owner: str, repo: str, default_branch: str, rules_yaml: str) -> bool:
        """Push .fixora-rules.yml (AI-generated Semgrep rules) to the repository.
        
        This file is picked up by the Semgrep workflow alongside --config auto,
        letting Semgrep catch calls to project-specific dangerous wrappers that
        built-in rules wouldn't know about.
        """
        if not rules_yaml or not rules_yaml.strip():
            logger.info("No custom rules to push (empty YAML)")
            return True  # Not an error — just nothing to push
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Check if file already exists
                check_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{CUSTOM_RULES_FILE_PATH}",
                    params={"ref": default_branch},
                    headers=self.headers
                )
                
                sha = None
                if check_response.status_code == 200:
                    sha = check_response.json().get("sha")
                
                content = base64.b64encode(rules_yaml.encode()).decode()
                
                payload = {
                    "message": "chore: Add Fixora AI-generated Semgrep rules for scan",
                    "content": content,
                    "branch": default_branch
                }
                
                if sha:
                    payload["sha"] = sha
                
                response = await client.put(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{CUSTOM_RULES_FILE_PATH}",
                    headers=self.headers,
                    json=payload
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"Pushed custom Semgrep rules to {owner}/{repo} ({CUSTOM_RULES_FILE_PATH})")
                    return True
                else:
                    logger.error(f"Failed to push custom rules: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error pushing custom rules file: {e}")
            return False
    
    async def delete_custom_rules_file(self, owner: str, repo: str, default_branch: str = "main") -> bool:
        """Delete .fixora-rules.yml after scan completion to keep the repo clean."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                check_response = await client.get(
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{CUSTOM_RULES_FILE_PATH}",
                    params={"ref": default_branch},
                    headers=self.headers
                )
                
                if check_response.status_code != 200:
                    logger.info(f"Custom rules file not found in {owner}/{repo}, nothing to delete")
                    return True
                
                sha = check_response.json().get("sha")
                if not sha:
                    return False
                
                response = await client.request(
                    "DELETE",
                    f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{CUSTOM_RULES_FILE_PATH}",
                    headers=self.headers,
                    json={
                        "message": "chore: Remove Fixora AI-generated rules (scan completed)",
                        "sha": sha,
                        "branch": default_branch
                    }
                )
                
                if response.status_code in [200, 204]:
                    logger.info(f"Deleted custom rules file from {owner}/{repo}")
                    return True
                else:
                    logger.error(f"Failed to delete custom rules: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error deleting custom rules file: {e}")
            return False
    
    async def trigger_wrapper_hunter(
        self,
        owner: str,
        repo: str,
        scan_id: str,
        target_branch: str = "main",
        max_retries: int = 3
    ) -> bool:
        """Trigger the Wrapper Hunter workflow via repository_dispatch"""
        import asyncio
        
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        f"{GITHUB_API_URL}/repos/{owner}/{repo}/dispatches",
                        headers=self.headers,
                        json={
                            "event_type": "fixora-wrapper-hunt",
                            "client_payload": {
                                "scan_id": scan_id,
                                "target_branch": target_branch
                            }
                        }
                    )
                    
                    if response.status_code == 204:
                        logger.info(f"Triggered wrapper hunter for {owner}/{repo} (scan_id: {scan_id})")
                        return True
                    elif response.status_code == 404:
                        logger.warning(f"Wrapper hunter dispatch failed (attempt {attempt + 1}/{max_retries}): {response.text}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(3)
                            continue
                    else:
                        logger.error(f"Failed to trigger wrapper hunter: {response.status_code} - {response.text}")
                        return False
                        
            except Exception as e:
                logger.error(f"Error triggering wrapper hunter (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                return False
        
        logger.error(f"Failed to trigger wrapper hunter after {max_retries} attempts")
        return False
    
    async def trigger_workflow(
        self, 
        owner: str, 
        repo: str, 
        scan_id: str,
        target_branch: str = "main",
        scan_mode: str = "full",
        base_commit: str = "",
        max_retries: int = 3
    ) -> bool:
        """Trigger the Fixora scan workflow via repository_dispatch"""
        import asyncio
        
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    # Use repository_dispatch which works from any branch
                    response = await client.post(
                        f"{GITHUB_API_URL}/repos/{owner}/{repo}/dispatches",
                        headers=self.headers,
                        json={
                            "event_type": "fixora-scan",
                            "client_payload": {
                                "scan_mode": scan_mode,
                                "target_branch": target_branch,
                                "base_commit": base_commit or "",
                                "scan_id": scan_id
                            }
                        }
                    )
                    
                    if response.status_code == 204:
                        logger.info(f"Triggered scan workflow for {owner}/{repo} (scan_id: {scan_id})")
                        return True
                    elif response.status_code == 404:
                        # Repository not found or no access
                        logger.warning(f"Repository dispatch failed (attempt {attempt + 1}/{max_retries}): {response.text}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(3)  # Wait 3 seconds before retry
                            continue
                    else:
                        logger.error(f"Failed to trigger workflow: {response.status_code} - {response.text}")
                        return False
                        
            except Exception as e:
                logger.error(f"Error triggering workflow (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                return False
        
        logger.error(f"Failed to trigger workflow after {max_retries} attempts")
        return False
    
    async def get_commits(
        self, 
        owner: str, 
        repo: str, 
        branch: str,
        since: Optional[datetime] = None,
        per_page: int = 30
    ) -> List[Dict[str, Any]]:
        """Get recent commits for a branch"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {"sha": branch, "per_page": per_page}
            if since:
                params["since"] = since.isoformat()
            
            response = await client.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits",
                params=params,
                headers=self.headers
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get commits: {response.text}")
            
            commits = response.json()
            return [{
                "sha": c["sha"],
                "message": c["commit"]["message"],
                "author": c["commit"]["author"]["name"],
                "date": c["commit"]["author"]["date"],
                "url": c["html_url"]
            } for c in commits]
    
    async def setup_repository_for_scanning(
        self, 
        owner: str, 
        repo: str,
        api_token: str,
        api_url: str
    ) -> Dict[str, Any]:
        """
        Complete setup process for a repository:
        1. Get repo info
        2. Inject secrets
        3. Push workflow file to main branch
        """
        result = {
            "success": False,
            "steps": {
                "api_token_secret": False,
                "api_url_secret": False,
                "workflow_file": False
            },
            "error": None,
            "details": None
        }
        
        try:
            # Get repository info
            repo_info = await self.get_repository_info(owner, repo)
            default_branch = repo_info.get("default_branch", "main")
            
            # Step 1: Inject API token secret
            result["steps"]["api_token_secret"] = await self.inject_repository_secret(
                owner, repo, "FIXORA_API_TOKEN", api_token
            )
            
            # Step 2: Inject API URL secret
            result["steps"]["api_url_secret"] = await self.inject_repository_secret(
                owner, repo, "FIXORA_API_URL", api_url
            )
            
            # Step 3: Push workflow file to main branch (required for repository_dispatch)
            result["steps"]["workflow_file"] = await self.push_workflow_file(owner, repo, default_branch)
            
            if not result["steps"]["workflow_file"]:
                result["error"] = "Failed to push workflow file"
                return result
            
            result["success"] = all(result["steps"].values())
            
            if not result["success"]:
                failed_steps = [k for k, v in result["steps"].items() if not v]
                result["error"] = f"Some steps failed: {', '.join(failed_steps)}"
            
            return result
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Error setting up repository: {e}")
            return result


def generate_repo_api_token(repo_id: str, user_id: str) -> str:
    """Generate a unique API token for a repository to use in GitHub Actions"""
    import jwt
    from config.settings import get_settings
    
    settings = get_settings()
    
    payload = {
        "repo_id": repo_id,
        "user_id": user_id,
        "type": "scan_webhook",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=365)  # Long-lived token for Actions
    }
    
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
    logger.info(f"Generated API token for repo {repo_id}: {token}")
    logger.info(f"Using JWT secret key (first 10 chars): {settings.jwt_secret_key[:10]}...")
    return token
