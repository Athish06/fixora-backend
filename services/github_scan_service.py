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
          """
          Fixora Wrapper Hunter - Dependency Mapping & Custom Wrapper Detection
          Analyzes a project to find all dependencies, default modules,
          and custom wrapper functions that call external libraries.
          """
          import ast
          import os
          import re
          import json
          import sys

          # ============ PHASE 0: KNOWN DEFAULT / STDLIB MODULES ============

          PYTHON_STDLIB = {
              "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
              "asyncore", "atexit", "audioop", "base64", "bdb", "binascii",
              "binhex", "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb",
              "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections",
              "colorsys", "compileall", "concurrent", "configparser", "contextlib",
              "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
              "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
              "difflib", "dis", "distutils", "doctest", "email", "encodings",
              "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
              "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
              "getpass", "gettext", "glob", "grp", "gzip", "hashlib", "heapq",
              "hmac", "html", "http", "idlelib", "imaplib", "imghdr", "imp",
              "importlib", "inspect", "io", "ipaddress", "itertools", "json",
              "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
              "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
              "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
              "numbers", "operator", "optparse", "os", "ossaudiodev",
              "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
              "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
              "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
              "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
              "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
              "selectors", "shelve", "shlex", "shutil", "signal", "site",
              "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
              "ssl", "stat", "statistics", "string", "stringprep", "struct",
              "subprocess", "sunau", "symtable", "sys", "sysconfig", "syslog",
              "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
              "textwrap", "threading", "time", "timeit", "tkinter", "token",
              "tokenize", "trace", "traceback", "tracemalloc", "tty", "turtle",
              "turtledemo", "types", "typing", "unicodedata", "unittest",
              "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
              "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml",
              "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
              "_thread", "__future__",
          }

          NODE_BUILTINS = {
              "assert", "buffer", "child_process", "cluster", "console",
              "constants", "crypto", "dgram", "dns", "domain", "events",
              "fs", "http", "https", "module", "net", "os", "path",
              "perf_hooks", "process", "punycode", "querystring", "readline",
              "repl", "stream", "string_decoder", "timers", "tls", "tty",
              "url", "util", "v8", "vm", "worker_threads", "zlib",
              "react", "react-dom", "react/jsx-runtime",
          }

          IGNORE_DIRS = {
              "node_modules", "venv", ".venv", "env", ".env", ".git",
              "__pycache__", "build", "dist", ".next", ".cache",
              "coverage", ".tox", "egg-info", ".eggs", "site-packages",
              ".github", ".vscode",
          }

          # ============ PHASE 1: DEPENDENCY MAPPING ============

          def parse_requirements_txt(repo_root):
              """Parse requirements.txt and return set of package names"""
              deps = set()
              req_path = os.path.join(repo_root, "requirements.txt")
              if not os.path.isfile(req_path):
                  return deps
              with open(req_path, "r", errors="ignore") as f:
                  for line in f:
                      line = line.strip()
                      if not line or line.startswith("#") or line.startswith("-"):
                          continue
                      # Strip version specifiers
                      pkg = re.split(r"[><=!~;@\[]", line)[0].strip()
                      if pkg:
                          deps.add(pkg.lower().replace("-", "_"))
              return deps

          def parse_package_json(repo_root):
              """Parse package.json and return set of dependency names"""
              deps = set()
              pj_path = os.path.join(repo_root, "package.json")
              if not os.path.isfile(pj_path):
                  return deps
              try:
                  with open(pj_path, "r", errors="ignore") as f:
                      data = json.load(f)
                  for key in ("dependencies", "devDependencies", "peerDependencies"):
                      if key in data and isinstance(data[key], dict):
                          deps.update(data[key].keys())
              except Exception:
                  pass
              return deps

          # ============ PHASE 2: IMPORT EXTRACTION ============

          def extract_python_imports(filepath):
              """Use AST to extract all imports from a Python file"""
              imports = []
              try:
                  with open(filepath, "r", errors="ignore") as f:
                      source = f.read()
                  tree = ast.parse(source, filename=filepath)
              except (SyntaxError, UnicodeDecodeError, ValueError):
                  return imports

              for node in ast.walk(tree):
                  if isinstance(node, ast.Import):
                      for alias in node.names:
                          imports.append({
                              "module": alias.name,
                              "names": [alias.asname or alias.name],
                              "type": "import"
                          })
                  elif isinstance(node, ast.ImportFrom):
                      module = node.module or ""
                      names = [a.name for a in node.names]
                      imports.append({
                          "module": module,
                          "names": names,
                          "type": "from_import"
                      })
              return imports

          # Regex patterns for JS/TS imports
          RE_ES6_IMPORT = re.compile(
              r"""import\\s+(?:"""
              r"""(?P<default>[\\w$]+)"""              # default import
              r"""|\\{\\s*(?P<named>[^}]+)\\s*\\}"""   # named imports
              r"""|(?P<def2>[\\w$]+)\\s*,\\s*\\{\\s*(?P<named2>[^}]+)\\s*\\}"""  # default + named
              r"""|\\*\\s+as\\s+(?P<star>[\\w$]+)"""   # namespace import
              r""")\\s+from\\s+['\"](?P<source>[^'\"]+)['\"]""",
              re.MULTILINE,
          )
          RE_REQUIRE = re.compile(
              r"""(?:const|let|var)\\s+(?:"""
              r"""(?P<name>[\\w$]+)"""
              r"""|\\{\\s*(?P<destructured>[^}]+)\\s*\\}"""
              r""")\\s*=\\s*require\\(['\"](?P<source>[^'\"]+)['\"]\\)""",
              re.MULTILINE,
          )

          def extract_js_imports(filepath):
              """Use regex to extract imports from JS/TS files"""
              imports = []
              try:
                  with open(filepath, "r", errors="ignore") as f:
                      source = f.read()
              except Exception:
                  return imports

              for m in RE_ES6_IMPORT.finditer(source):
                  src = m.group("source")
                  names = []
                  if m.group("default"):
                      names.append(m.group("default"))
                  if m.group("named"):
                      names.extend([n.strip().split(" as ")[0].strip() for n in m.group("named").split(",")])
                  if m.group("def2"):
                      names.append(m.group("def2"))
                  if m.group("named2"):
                      names.extend([n.strip().split(" as ")[0].strip() for n in m.group("named2").split(",")])
                  if m.group("star"):
                      names.append(m.group("star"))
                  imports.append({"module": src, "names": names, "type": "es6_import"})

              for m in RE_REQUIRE.finditer(source):
                  src = m.group("source")
                  names = []
                  if m.group("name"):
                      names.append(m.group("name"))
                  if m.group("destructured"):
                      names.extend([n.strip().split(":")[0].strip() for n in m.group("destructured").split(",")])
                  imports.append({"module": src, "names": names, "type": "require"})

              return imports

          # ============ PHASE 3: WRAPPER FUNCTION DETECTION (Python) ============

          def classify_import(module_name, user_deps, stdlib_set):
              """Classify a module as user-installed, stdlib, or local"""
              top = module_name.split(".")[0].lower().replace("-", "_")
              if top in {d.lower().replace("-", "_") for d in user_deps}:
                  return "user_installed"
              if top in stdlib_set:
                  return "stdlib"
              return "local"

          def classify_js_import(module_name, user_deps, builtins):
              """Classify a JS module"""
              # Relative imports are local
              if module_name.startswith(".") or module_name.startswith("/"):
                  return "local"
              # Scoped packages: @scope/pkg -> check @scope/pkg
              top = module_name.split("/")[0] if not module_name.startswith("@") else "/".join(module_name.split("/")[:2])
              if top in user_deps:
                  return "user_installed"
              if top in builtins:
                  return "stdlib"
              return "user_installed"  # assume npm package if not builtin

          def extract_python_wrappers(filepath, user_deps):
              """
              Use AST to find functions that call any module listed in user_deps.
              Returns list of wrapper function dicts with source code.
              """
              wrappers = []
              try:
                  with open(filepath, "r", errors="ignore") as f:
                      source = f.read()
                  tree = ast.parse(source, filename=filepath)
                  lines = source.splitlines()
              except (SyntaxError, UnicodeDecodeError, ValueError):
                  return wrappers

              # Collect imported names that map to user-installed deps
              imported_names = set()
              for node in ast.walk(tree):
                  if isinstance(node, ast.Import):
                      for alias in node.names:
                          top = alias.name.split(".")[0].lower().replace("-", "_")
                          if top in {d.lower().replace("-", "_") for d in user_deps}:
                              imported_names.add(alias.asname or alias.name)
                  elif isinstance(node, ast.ImportFrom):
                      module = (node.module or "").split(".")[0].lower().replace("-", "_")
                      if module in {d.lower().replace("-", "_") for d in user_deps}:
                          for alias in node.names:
                              imported_names.add(alias.name)

              if not imported_names:
                  return wrappers

              # Find function definitions that call any imported name
              for node in ast.walk(tree):
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                      calls_dep = set()
                      for child in ast.walk(node):
                          if isinstance(child, ast.Call):
                              call_name = _get_call_name(child)
                              if call_name:
                                  # Check if the call references an imported dep name
                                  root_name = call_name.split(".")[0]
                                  if root_name in imported_names:
                                      calls_dep.add(call_name)
                      if calls_dep:
                          # Extract full function source
                          start = node.lineno - 1
                          end = node.end_lineno if hasattr(node, "end_lineno") and node.end_lineno else start + 1
                          func_source = "\\n".join(lines[start:end])
                          wrappers.append({
                              "function_name": node.name,
                              "calls": list(calls_dep),
                              "line_start": node.lineno,
                              "line_end": end,
                              "source_code": func_source,
                              "file": filepath
                          })
              return wrappers

          def _get_call_name(call_node):
              """Extract the full dotted name from a Call node"""
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

          def extract_js_wrappers(filepath, user_deps):
              """
              Simple heuristic: find exported functions that use imported dep names.
              Uses regex since full JS AST is heavy.
              """
              wrappers = []
              try:
                  with open(filepath, "r", errors="ignore") as f:
                      source = f.read()
                      lines = source.splitlines()
              except Exception:
                  return wrappers

              # Gather imported names tied to user_deps
              imported_names = set()
              for m in RE_ES6_IMPORT.finditer(source):
                  src = m.group("source")
                  if src.startswith(".") or src.startswith("/"):
                      continue
                  top = src.split("/")[0] if not src.startswith("@") else "/".join(src.split("/")[:2])
                  if top in user_deps:
                      if m.group("default"):
                          imported_names.add(m.group("default"))
                      if m.group("named"):
                          for n in m.group("named").split(","):
                              imported_names.add(n.strip().split(" as ")[-1].strip())
                      if m.group("def2"):
                          imported_names.add(m.group("def2"))
                      if m.group("named2"):
                          for n in m.group("named2").split(","):
                              imported_names.add(n.strip().split(" as ")[-1].strip())

              for m in RE_REQUIRE.finditer(source):
                  src = m.group("source")
                  if src.startswith(".") or src.startswith("/"):
                      continue
                  top = src.split("/")[0] if not src.startswith("@") else "/".join(src.split("/")[:2])
                  if top in user_deps:
                      if m.group("name"):
                          imported_names.add(m.group("name"))
                      if m.group("destructured"):
                          for n in m.group("destructured").split(","):
                              imported_names.add(n.strip().split(":")[0].strip())

              if not imported_names:
                  return wrappers

              # Find function declarations that reference those names
              func_pattern = re.compile(
                  r"(?:^|\\n)"
                  r"(?:export\\s+)?(?:async\\s+)?function\\s+(\\w+)\\s*\\([^)]*\\)\\s*\\{",
                  re.MULTILINE,
              )
              arrow_pattern = re.compile(
                  r"(?:^|\\n)"
                  r"(?:export\\s+)?(?:const|let|var)\\s+(\\w+)\\s*=\\s*(?:async\\s+)?(?:\\([^)]*\\)|\\w+)\\s*=>",
                  re.MULTILINE,
              )

              for pattern in [func_pattern, arrow_pattern]:
                  for m in pattern.finditer(source):
                      func_name = m.group(1)
                      start_pos = m.start()
                      start_line = source[:start_pos].count("\\n")

                      # Find matching closing brace (simple brace counting)
                      brace_pos = source.find("{", m.end() - 1)
                      if brace_pos == -1:
                          # Arrow function without braces - take single line
                          end_line = start_line
                          func_body = lines[start_line] if start_line < len(lines) else ""
                      else:
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
                          end_line = source[:end_pos + 1].count("\\n")
                          func_body = "\\n".join(lines[start_line:end_line + 1])

                      # Check if function body references any imported dep names
                      found_calls = set()
                      for name in imported_names:
                          if name in func_body:
                              found_calls.add(name)

                      if found_calls:
                          wrappers.append({
                              "function_name": func_name,
                              "calls": list(found_calls),
                              "line_start": start_line + 1,
                              "line_end": end_line + 1,
                              "source_code": func_body,
                              "file": filepath
                          })

              return wrappers

          # ============ MAIN RUNNER ============

          def run_wrapper_hunter(repo_root="."):
              result = {
                  "python": None,
                  "react": None,
              }

              # Check what exists
              has_python = os.path.isfile(os.path.join(repo_root, "requirements.txt"))
              has_react = os.path.isfile(os.path.join(repo_root, "package.json"))

              # --- PYTHON ---
              if has_python:
                  py_user_deps = parse_requirements_txt(repo_root)
                  py_section = {
                      "packages": {
                          "user_installed": sorted(py_user_deps),
                          "stdlib": sorted(PYTHON_STDLIB),
                      },
                      "file_analysis": [],
                      "wrapper_functions": [],
                  }

                  for dirpath, dirnames, filenames in os.walk(repo_root):
                      dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                      for fn in filenames:
                          if not fn.endswith(".py"):
                              continue
                          fp = os.path.join(dirpath, fn)
                          rel = os.path.relpath(fp, repo_root)
                          imports = extract_python_imports(fp)
                          if not imports:
                              continue

                          classified = []
                          for imp in imports:
                              cat = classify_import(imp["module"], py_user_deps, PYTHON_STDLIB)
                              classified.append({**imp, "classification": cat})

                          py_section["file_analysis"].append({
                              "file": rel,
                              "imports": classified,
                          })

                          wrappers = extract_python_wrappers(fp, py_user_deps)
                          for w in wrappers:
                              w["file"] = rel
                              py_section["wrapper_functions"].append(w)

                  result["python"] = py_section

              # --- REACT / JS ---
              if has_react:
                  js_user_deps = parse_package_json(repo_root)
                  js_section = {
                      "packages": {
                          "user_installed": sorted(js_user_deps),
                          "builtin": sorted(NODE_BUILTINS),
                      },
                      "file_analysis": [],
                      "wrapper_functions": [],
                  }

                  for dirpath, dirnames, filenames in os.walk(repo_root):
                      dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                      for fn in filenames:
                          if not any(fn.endswith(ext) for ext in (".js", ".jsx", ".ts", ".tsx")):
                              continue
                          fp = os.path.join(dirpath, fn)
                          rel = os.path.relpath(fp, repo_root)
                          imports = extract_js_imports(fp)
                          if not imports:
                              continue

                          classified = []
                          for imp in imports:
                              cat = classify_js_import(imp["module"], js_user_deps, NODE_BUILTINS)
                              classified.append({**imp, "classification": cat})

                          js_section["file_analysis"].append({
                              "file": rel,
                              "imports": classified,
                          })

                          wrappers = extract_js_wrappers(fp, js_user_deps)
                          for w in wrappers:
                              w["file"] = rel
                              js_section["wrapper_functions"].append(w)

                  result["react"] = js_section

              # Remove null sections
              result = {k: v for k, v in result.items() if v is not None}
              return result

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
              if curl -X POST "${{ secrets.FIXORA_API_URL }}/api/scan/webhook/wrapper-results" \\
                -H "Content-Type: application/json" \\
                -H "X-Fixora-Token: ${{ secrets.FIXORA_API_TOKEN }}" \\
                -d @wh-payload.json \\
                --max-time 30 \\
                --retry 2 \\
                --retry-delay 5; then
                echo "\\n✅ Wrapper hunter results sent successfully"
                exit 0
              else
                RETRY_COUNT=$((RETRY_COUNT + 1))
                echo "⚠️  Attempt $RETRY_COUNT failed. Retrying..."
                sleep 5
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
          semgrep scan --config auto --json --output semgrep-results.json . || true

      - name: Run Semgrep Scan (Diff)
        if: ${{ (github.event.client_payload.scan_mode || github.event.inputs.scan_mode) == 'diff' && (github.event.client_payload.base_commit || github.event.inputs.base_commit) != '' }}
        run: |
          BASE_COMMIT="${{ github.event.client_payload.base_commit || github.event.inputs.base_commit }}"
          git diff --name-only $BASE_COMMIT HEAD > changed_files.txt
          if [ -s changed_files.txt ]; then
            semgrep scan --config auto --json --output semgrep-results.json $(cat changed_files.txt | tr '\\n' ' ') || true
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
