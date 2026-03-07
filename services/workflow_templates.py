# Workflow templates for GitHub Actions (Wrapper Hunter + Semgrep Scan)
# Extracted from github_scan_service.py to keep the service file focused.

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

      - name: Prepare JS Extractor
        run: |
          npm install --prefix /tmp/js-parser @babel/parser > /dev/null 2>&1
          cat > /tmp/js_extractor.js << 'JS_EXTRACTOR_SCRIPT'
          'use strict';
          const fs = require('fs');
          const path = require('path');
          const { parse } = require('/tmp/js-parser/node_modules/@babel/parser');

          const IGNORE_DIRS = new Set([
              'node_modules','venv','.venv','env','.env','.git',
              '__pycache__','build','dist','.next','.cache',
              'coverage','.tox','egg-info','.eggs','site-packages',
              '.github','.vscode','vendor','bower_components',
          ]);
          const JS_EXTS = new Set(['.js','.jsx','.ts','.tsx','.mjs','.cjs']);

          const DANGEROUS_GLOBALS = new Set([
              'eval','Function','setTimeout','setInterval','setImmediate',
          ]);
          const DANGEROUS_SINK_METHODS = new Set([
              'query','execute','exec','aggregate','raw',
              'find','findOne','findById','findOneAndUpdate','findOneAndDelete',
              'deleteOne','deleteMany','updateOne','updateMany','insertOne','insertMany',
              'replaceOne','bulkWrite','distinct','countDocuments',
              'execSync','spawn','spawnSync','execFile','execFileSync','fork',
              'write','writeln','insertAdjacentHTML',
              'deserialize','unserialize',
          ]);

          function walkDir(dir, cb) {
              let entries;
              try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
              catch(e) { return; }
              for (const ent of entries) {
                  if (ent.isDirectory() && !IGNORE_DIRS.has(ent.name))
                      walkDir(path.join(dir, ent.name), cb);
                  else if (ent.isFile() && JS_EXTS.has(path.extname(ent.name)))
                      cb(path.join(dir, ent.name));
              }
          }

          function parseFile(fp, src) {
              const ext = path.extname(fp);
              const plugins = [
                  'dynamicImport','optionalChaining','nullishCoalescingOperator',
                  'classProperties','classPrivateProperties','classPrivateMethods',
                  'exportDefaultFrom','exportNamespaceFrom','decorators-legacy',
                  'topLevelAwait','importMeta','objectRestSpread',
              ];
              if (ext === '.ts' || ext === '.tsx') plugins.push('typescript');
              if (ext === '.jsx' || ext === '.tsx' || ext === '.js' || ext === '.mjs')
                  plugins.push('jsx');
              try {
                  return parse(src, {
                      sourceType: 'unambiguous',
                      allowImportExportEverywhere: true,
                      allowReturnOutsideFunction: true,
                      allowSuperOutsideMethod: true,
                      plugins,
                      errorRecovery: true,
                  });
              } catch(e) { return null; }
          }

          function callName(node) {
              if (!node) return null;
              if (node.type === 'Identifier') return node.name;
              if (node.type === 'MemberExpression' && !node.computed) {
                  const o = callName(node.object);
                  const p = node.property.name || node.property.value;
                  return o && p ? o + '.' + p : (p || o);
              }
              return null;
          }

          function collectImports(body) {
              const imports = new Set();
              const alias = {};
              function normMod(raw) {
                  if (!raw || raw.startsWith('.')) return null;
                  return raw.startsWith('@')
                      ? raw.split('/').slice(0, 2).join('/')
                      : raw.split('/')[0];
              }
              function visit(node) {
                  if (!node || typeof node !== 'object') return;
                  if (node.type === 'ImportDeclaration' && node.source) {
                      const mod = normMod(node.source.value);
                      if (mod) {
                          imports.add(mod);
                          for (const s of (node.specifiers || []))
                              alias[s.local.name] = mod;
                      }
                  }
                  if (node.type === 'VariableDeclaration') {
                      for (const d of node.declarations) {
                          if (d.init && d.init.type === 'CallExpression' &&
                              d.init.callee && d.init.callee.name === 'require' &&
                              d.init.arguments[0] && d.init.arguments[0].value) {
                              const mod = normMod(d.init.arguments[0].value);
                              if (mod) {
                                  imports.add(mod);
                                  if (d.id.type === 'Identifier') {
                                      alias[d.id.name] = mod;
                                  } else if (d.id.type === 'ObjectPattern') {
                                      for (const p of d.id.properties) {
                                          const nm = (p.value || p.key);
                                          if (nm && nm.name) alias[nm.name] = mod;
                                      }
                                  }
                              }
                          }
                      }
                  }
                  for (const k of Object.keys(node)) {
                      if (k === 'type'||k === 'start'||k === 'end'||k === 'loc') continue;
                      const v = node[k];
                      if (Array.isArray(v)) v.forEach(c => { if (c && c.type) visit(c); });
                      else if (v && typeof v === 'object' && v.type) visit(v);
                  }
              }
              (body || []).forEach(visit);
              return { imports: [...imports].sort(), alias };
          }

          function isFn(n) {
              return n && (
                  n.type==='FunctionDeclaration'||n.type==='FunctionExpression'||
                  n.type==='ArrowFunctionExpression'||n.type==='ClassMethod'||
                  n.type==='ClassPrivateMethod'||n.type==='ObjectMethod');
          }

          function fnName(node, parent) {
              if (node.id && node.id.name) return node.id.name;
              if (node.key) return node.key.name || node.key.value || '<method>';
              if (parent) {
                  if (parent.type === 'VariableDeclarator' && parent.id)
                      return parent.id.name;
                  if (parent.type === 'AssignmentExpression' && parent.left)
                      return callName(parent.left) || '<assigned>';
                  if (parent.type === 'ObjectProperty' && parent.key)
                      return parent.key.name || parent.key.value || '<prop>';
                  if (parent.type === 'CallExpression') {
                      const cn = callName(parent.callee) || '?';
                      const a0 = parent.arguments[0];
                      const hint = a0 && a0.value != null ? String(a0.value) : '';
                      return '<callback:' + cn + (hint ? '(' + hint + ')' : '') + '>';
                  }
              }
              return '<anonymous>';
          }

          function findCalls(fnNode, aliasMap) {
              const calls = {};
              function visit(node) {
                  if (!node || typeof node !== 'object') return;
                  if (node !== fnNode && isFn(node)) return;
                  if (node.type === 'CallExpression') {
                      const cn = callName(node.callee);
                      if (cn) {
                          const root = cn.split('.')[0];
                          const method = cn.includes('.') ? cn.split('.').pop() : null;
                          if (DANGEROUS_GLOBALS.has(cn) || DANGEROUS_GLOBALS.has(root))
                              calls[cn] = 'builtins';
                          else if (aliasMap[root])
                              calls[cn] = aliasMap[root];
                          else if (method && DANGEROUS_SINK_METHODS.has(method))
                              calls[cn] = '<object>.' + method;
                      }
                  }
                  if (node.type === 'NewExpression') {
                      const cn = callName(node.callee);
                      if (cn === 'Function') calls['new Function'] = 'builtins';
                  }
                  if (node.type === 'AssignmentExpression' &&
                      node.left && node.left.type === 'MemberExpression') {
                      const prop = node.left.property &&
                          (node.left.property.name || node.left.property.value);
                      if (prop === 'innerHTML' || prop === 'outerHTML') {
                          const obj = callName(node.left.object) || '<element>';
                          calls[obj + '.' + prop] = 'DOM';
                      }
                  }
                  if (node.type === 'JSXAttribute' && node.name &&
                      node.name.name === 'dangerouslySetInnerHTML')
                      calls['dangerouslySetInnerHTML'] = 'React/DOM';
                  for (const k of Object.keys(node)) {
                      if (k==='type'||k==='start'||k==='end'||k==='loc') continue;
                      const v = node[k];
                      if (Array.isArray(v)) v.forEach(c => { if (c&&c.type) visit(c); });
                      else if (v && typeof v==='object' && v.type) visit(v);
                  }
              }
              visit(fnNode);
              return calls;
          }

          function extractFile(ast, src, relPath, aliasMap) {
              const wrappers = [];
              function visit(node, parent) {
                  if (!node || typeof node !== 'object') return;
                  if (isFn(node)) {
                      const name = fnName(node, parent);
                      const calls = findCalls(node, aliasMap);
                      if (Object.keys(calls).length > 0) {
                          const funcSrc = (node.start != null && node.end != null)
                              ? src.substring(node.start, node.end) : '';
                          const ls = node.loc ? node.loc.start.line : 1;
                          const le = node.loc ? node.loc.end.line : ls;
                          wrappers.push({
                              function_name: name, file: relPath,
                              line_start: ls, line_end: le,
                              calls: Object.keys(calls),
                              modules_used: [...new Set(Object.values(calls))],
                              source_code: funcSrc,
                          });
                      }
                  }
                  for (const k of Object.keys(node)) {
                      if (k==='type'||k==='start'||k==='end'||k==='loc') continue;
                      const v = node[k];
                      if (Array.isArray(v)) v.forEach(c => { if (c&&c.type) visit(c, node); });
                      else if (v && typeof v==='object' && v.type) visit(v, node);
                  }
              }
              visit(ast.program || ast, null);
              return wrappers;
          }

          const repoRoot = process.argv[2] || '.';
          const manifestPkgs = JSON.parse(process.argv[3] || '[]');
          const allImports = new Set();
          const allWrappers = [];
          walkDir(repoRoot, (fp) => {
              let src;
              try { src = fs.readFileSync(fp, 'utf8'); } catch(e) { return; }
              const ast = parseFile(fp, src);
              if (!ast || !ast.program) return;
              const rel = path.relative(repoRoot, fp);
              const { imports, alias } = collectImports(ast.program.body);
              imports.forEach(i => allImports.add(i));
              const wrappers = extractFile(ast, src, rel, alias);
              allWrappers.push(...wrappers);
          });
          process.stdout.write(JSON.stringify({
              from_imports: [...allImports].sort(),
              wrappers: allWrappers,
          }));
          JS_EXTRACTOR_SCRIPT

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

          # â”€â”€â”€ LANGUAGE DETECTION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

          # â”€â”€â”€ MANIFEST PARSERS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

          # â”€â”€â”€ IMPORT COLLECTORS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

          # â”€â”€â”€ JS/REACT EXTRACTION (AST via Node.js) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
          def run_js_extractor(repo_root, manifest_pkgs):
              import subprocess, sys
              try:
                  result = subprocess.run(
                      ["node", "/tmp/js_extractor.js", repo_root, json.dumps(manifest_pkgs)],
                      capture_output=True, text=True, timeout=120
                  )
                  if result.returncode != 0:
                      print(f"JS extractor error: {result.stderr[:500]}", file=sys.stderr)
                      return {"from_imports": [], "wrappers": []}
                  return json.loads(result.stdout)
              except Exception as e:
                  print(f"JS extractor failed: {e}", file=sys.stderr)
                  return {"from_imports": [], "wrappers": []}

          # â”€â”€â”€ PYTHON WRAPPER EXTRACTION (AST) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

          # Known dangerous method names â€” indicate security-relevant operations
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
                              # â”€â”€ Pass 1: Track variables derived from imports â”€â”€
                              # Handles chains like:
                              #   conn = sqlite3.connect(...)   â†’ conn linked to sqlite3
                              #   cursor = conn.cursor()        â†’ cursor linked to sqlite3
                              # Two iterations catch Aâ†’Bâ†’C chains.
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

                              # â”€â”€ Pass 2: Collect calls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

          # â”€â”€â”€ ORCHESTRATOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                  js_result = run_js_extractor(repo_root, manifest_pkgs)
                  import_mods = js_result.get("from_imports", [])
                  all_modules = sorted(set(manifest_pkgs) | set(import_mods))
                  results["react"] = {
                      "modules": {
                          "from_manifest": manifest_pkgs,
                          "from_imports": import_mods,
                          "all": all_modules,
                      },
                      "wrapper_functions": js_result.get("wrappers", []),
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
                echo "[OK] Wrapper hunter results sent successfully (HTTP $HTTP_STATUS)"
                exit 0
              else
                RETRY_COUNT=$((RETRY_COUNT + 1))
                echo "[WARNING] Attempt $RETRY_COUNT failed (HTTP $HTTP_STATUS). Retrying in 10s..."
                sleep 10
              fi
            done
            
            echo "[FAIL] Failed to send wrapper hunter results after $MAX_RETRIES attempts"
            exit 1
          else
            echo "[WARNING] No wrapper hunter results file found"
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
                echo "[OK] Results sent successfully"
                exit 0
              else
                RETRY_COUNT=$((RETRY_COUNT + 1))
                echo "[WARNING] Attempt $RETRY_COUNT failed. Retrying..."
                sleep 5
              fi
            done
            
            echo "[FAIL] Failed to send results after $MAX_RETRIES attempts"
            echo "This usually means your Fixora backend is not publicly accessible."
            echo "For local development, use ngrok or similar to expose your backend."
            echo "Backend URL configured: ${{ secrets.FIXORA_API_URL }}"
            exit 1
          else
            echo "[WARNING] No results file found"
          fi

      - name: Upload Scan Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: semgrep-results
          path: semgrep-results.json
          retention-days: 7
'''
