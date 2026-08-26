// Underlay starter - frontend hydration helper for `dev` tab setup.
//
// Invoked by `tasks.dev` concurrent entries as a `setup = [{ rhai = ... }]`
// step. Runs before the app's dev server starts and ensures bun dependencies
// are installed on a fingerprint-controlled basis.
//
// This is starter-owned helper glue, not Effigy runtime. It supports the
// generic `app-*` layout and the Underlay reference `acme-*` layout by
// default, and repos can override the package directories through
// `[bundle.dirs]`.
//
// When the repo declares one root Bun workspace (root `package.json` with a
// non-empty `workspaces` array plus a root `bun.lock`), hydration collapses to
// exactly one `bun install --frozen-lockfile` at the repo root. Per-package
// installs are drift under that contract, so they are skipped entirely.
//
// The shell program is assembled one line per statement on purpose. Rhai caps
// expression complexity, and a single long `+` chain over ~200 fragments is
// rejected at compile time with `Expression exceeds maximum complexity`, which
// makes the whole helper unreachable through any Effigy entry point.
//
// The program stays shell rather than a typed Rhai host surface because it
// needs shell-native locking, traps, grouped subshells, and package-manager
// probes across a small directory matrix.
//
// The Effigy runtime already supplies `process::stream`, `path::join`,
// `task_name`, and `repo_root` as script bindings.
//
// Contract expected by the managed `dev` task:
//   - `task_name` is the `name` field of the concurrent entry (e.g. "front").
//   - On failure, throw; the runtime will surface that as a setup error.

let runtime_root = path::join(repo_root, ".effigy/runtime");

fn optional_config_string(path, fallback) {
    let value = config::get(path);
    if value.type_of() == "()" {
        return fallback;
    }
    if value.type_of() != "string" {
        throw `expected Effigy config string at ${path}, got ${value.type_of()}`;
    }
    return str::trim(value);
}

fn optional_repo_dir(configured) {
    if configured == "" {
        return "";
    }
    return path::join(repo_root, configured);
}

let front_dir = optional_config_string("bundle.dirs.front", "");
let admin_dir = optional_config_string("bundle.dirs.admin", "");
let client_dir = optional_config_string("bundle.dirs.client", "");
let ui_dir = optional_config_string("bundle.dirs.ui", "");
let underlay_source = optional_config_string("bundle.sources.underlay", "../underlay");
let poodle_source = optional_config_string("bundle.sources.poodle", "../poodle");
let underlay_dir = path::join(repo_root, underlay_source);
let poodle_dir = path::join(repo_root, poodle_source);
let app_client_dir = path::join(repo_root, "app-client");
let acme_client_dir = path::join(repo_root, "acme-client");
let legacy_client_dir = path::join(repo_root, "client");
let app_ui_dir = path::join(repo_root, "app-ui");
let acme_ui_dir = path::join(repo_root, "acme-ui");
let legacy_ui_dir = path::join(repo_root, "ui");
let app_front_dir = path::join(repo_root, "app-front");
let acme_front_dir = path::join(repo_root, "acme-front");
let legacy_front_dir = path::join(repo_root, "front");
let app_admin_dir = path::join(repo_root, "app-admin");
let acme_admin_dir = path::join(repo_root, "acme-admin");
let legacy_admin_dir = path::join(repo_root, "admin");
let client_abs_dir = optional_repo_dir(client_dir);
let ui_abs_dir = optional_repo_dir(ui_dir);
let front_abs_dir = optional_repo_dir(front_dir);
let admin_abs_dir = optional_repo_dir(admin_dir);

let shell = "";
shell += "set -eu\n";
shell += "\n";
shell += "runtime_root='" + runtime_root + "'\n";
shell += "setup_task_name='" + task_name + "'\n";
shell += "repo_root='" + repo_root + "'\n";
shell += "\n";
shell += "lock_dir=\"$runtime_root/ui-setup.lock\"\n";
shell += "mkdir -p \"$runtime_root\"\n";
shell += "stamp_root=\"$runtime_root/ui-hydration\"\n";
shell += "mkdir -p \"$stamp_root\"\n";
shell += "\n";
shell += "reclaim_stale_lock_if_needed() {\n";
shell += "  if [ -f \"$lock_dir/pid\" ]; then\n";
shell += "    lock_pid=$(cat \"$lock_dir/pid\" 2>/dev/null || true)\n";
shell += "    if [ -n \"$lock_pid\" ] && ! kill -0 \"$lock_pid\" 2>/dev/null; then\n";
shell += "      rm -rf \"$lock_dir\"\n";
shell += "      return 0\n";
shell += "    fi\n";
shell += "  fi\n";
shell += "  if [ -n \"$(find \"$lock_dir\" -maxdepth 0 -mmin +2 -print -quit 2>/dev/null)\" ]; then\n";
shell += "    rm -rf \"$lock_dir\"\n";
shell += "  fi\n";
shell += "}\n";
shell += "\n";
shell += "while ! mkdir \"$lock_dir\" 2>/dev/null; do\n";
shell += "  reclaim_stale_lock_if_needed\n";
shell += "  sleep 0.2\n";
shell += "done\n";
shell += "printf '%s\\n' \"$$\" > \"$lock_dir/pid\"\n";
shell += "\n";
shell += "cleanup() {\n";
shell += "  rm -rf \"$lock_dir\" 2>/dev/null || true\n";
shell += "}\n";
shell += "trap cleanup EXIT INT TERM\n";
shell += "\n";
shell += "package_fingerprint() {\n";
shell += "  dir=\"$1\"\n";
shell += "  (\n";
shell += "    cd \"$dir\"\n";
shell += "    printf 'platform %s %s\\n' \"$(uname -s)\" \"$(uname -m)\"\n";
shell += "    if [ -f bun.lock ]; then\n";
shell += "      cksum package.json bun.lock\n";
shell += "    else\n";
shell += "      cksum package.json\n";
shell += "    fi\n";
shell += "  ) | cksum | awk '{print $1\":\"$2}'\n";
shell += "}\n";
shell += "\n";
shell += "node_modules_satisfies_package_json() {\n";
shell += "  dir=\"$1\"\n";
shell += "  if [ ! -d \"$dir/node_modules\" ]; then\n";
shell += "    return 1\n";
shell += "  fi\n";
shell += "  bun -e '\n";
shell += "const fs = require(\"node:fs\");\n";
shell += "const path = require(\"node:path\");\n";
shell += "const dir = process.argv[1];\n";
shell += "const pkg = JSON.parse(fs.readFileSync(path.join(dir, \"package.json\"), \"utf8\"));\n";
shell += "const names = Object.keys({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) });\n";
shell += "for (const name of names) {\n";
shell += "  if (!fs.existsSync(path.join(dir, \"node_modules\", ...name.split(\"/\")))) process.exit(1);\n";
shell += "}\n";
shell += "' \"$dir\"\n";
shell += "}\n";
shell += "\n";
shell += "ensure_bun_install() {\n";
shell += "  dir=\"$1\"\n";
shell += "  label=\"$2\"\n";
shell += "\n";
shell += "  if [ ! -f \"$dir/package.json\" ]; then\n";
shell += "    printf '[warn] skipping %s; no package.json at %s\\n' \"$label\" \"$dir\"\n";
shell += "    return 0\n";
shell += "  fi\n";
shell += "\n";
shell += "  fingerprint=$(package_fingerprint \"$dir\")\n";
shell += "  stamp_path=\"$stamp_root/$label.stamp\"\n";
shell += "\n";
shell += "  if [ -f \"$stamp_path\" ] \\\n";
shell += "    && [ \"$(cat \"$stamp_path\")\" = \"$fingerprint\" ] \\\n";
shell += "    && node_modules_satisfies_package_json \"$dir\"; then\n";
shell += "    printf '[info] %s already hydrated\\n' \"$label\"\n";
shell += "    return 0\n";
shell += "  fi\n";
shell += "\n";
shell += "  printf '[info] bun install -> %s\\n' \"$label\"\n";
shell += "  rm -f \"$stamp_path\"\n";
shell += "  (\n";
shell += "    cd \"$dir\"\n";
shell += "    bun install\n";
shell += "  )\n";
shell += "  printf '%s\\n' \"$fingerprint\" > \"$stamp_path\"\n";
shell += "}\n";
shell += "\n";
shell += "# --- root workspace support -------------------------------------------------\n";
shell += "#\n";
shell += "# A root workspace owns one `package.json` with a non-empty `workspaces` array\n";
shell += "# and one root `bun.lock`. Hydration is then a single frozen root install; any\n";
shell += "# per-package install is drift.\n";
shell += "\n";
shell += "root_workspace_members() {\n";
shell += "  bun -e '\n";
shell += "const fs = require(\"node:fs\");\n";
shell += "const path = require(\"node:path\");\n";
shell += "const root = process.argv[1];\n";
shell += "const pkg = JSON.parse(fs.readFileSync(path.join(root, \"package.json\"), \"utf8\"));\n";
shell += "const patterns = Array.isArray(pkg.workspaces) ? pkg.workspaces : (pkg.workspaces && pkg.workspaces.packages) || [];\n";
shell += "const out = [];\n";
shell += "for (const pattern of patterns) {\n";
shell += "  if (pattern.endsWith(\"/*\")) {\n";
shell += "    const base = path.join(root, pattern.slice(0, -2));\n";
shell += "    if (!fs.existsSync(base)) continue;\n";
shell += "    for (const entry of fs.readdirSync(base, { withFileTypes: true })) {\n";
shell += "      if (entry.isDirectory() && fs.existsSync(path.join(base, entry.name, \"package.json\"))) {\n";
shell += "        out.push(path.join(pattern.slice(0, -2), entry.name));\n";
shell += "      }\n";
shell += "    }\n";
shell += "  } else {\n";
shell += "    out.push(pattern);\n";
shell += "  }\n";
shell += "}\n";
shell += "process.stdout.write(out.join(\"\\n\"));\n";
shell += "' \"$repo_root\"\n";
shell += "}\n";
shell += "\n";
shell += "root_workspace_detected() {\n";
shell += "  if [ ! -f \"$repo_root/package.json\" ] || [ ! -f \"$repo_root/bun.lock\" ]; then\n";
shell += "    return 1\n";
shell += "  fi\n";
shell += "  bun -e '\n";
shell += "const fs = require(\"node:fs\");\n";
shell += "const path = require(\"node:path\");\n";
shell += "const pkg = JSON.parse(fs.readFileSync(path.join(process.argv[1], \"package.json\"), \"utf8\"));\n";
shell += "const ws = Array.isArray(pkg.workspaces) ? pkg.workspaces : (pkg.workspaces && pkg.workspaces.packages) || [];\n";
shell += "if (!Array.isArray(ws) || ws.length === 0) process.exit(1);\n";
shell += "' \"$repo_root\"\n";
shell += "}\n";
shell += "\n";
shell += "# Fingerprint every manifest the lock is meant to satisfy, not just the root\n";
shell += "# pair. A child manifest edit without a lock update must invalidate the stamp so\n";
shell += "# the frozen install runs and reports the mismatch.\n";
shell += "root_workspace_fingerprint() {\n";
shell += "  (\n";
shell += "    cd \"$repo_root\"\n";
shell += "    printf 'platform %s %s\\n' \"$(uname -s)\" \"$(uname -m)\"\n";
shell += "    cksum package.json bun.lock\n";
shell += "    root_workspace_members | while IFS= read -r member; do\n";
shell += "      [ -n \"$member\" ] || continue\n";
shell += "      if [ -f \"$member/package.json\" ]; then\n";
shell += "        cksum \"$member/package.json\"\n";
shell += "      else\n";
shell += "        printf 'missing %s/package.json\\n' \"$member\"\n";
shell += "      fi\n";
shell += "    done\n";
shell += "  ) | cksum | awk '{print $1\":\"$2}'\n";
shell += "}\n";
shell += "\n";
shell += "# A matching stamp is not enough: the installed tree can be wiped independently\n";
shell += "# of `.effigy/runtime` (for example by resetting the isolated container volume).\n";
shell += "root_workspace_install_satisfied() {\n";
shell += "  if [ ! -d \"$repo_root/node_modules\" ]; then\n";
shell += "    return 1\n";
shell += "  fi\n";
shell += "  members=$(root_workspace_members)\n";
shell += "  bun -e '\n";
shell += "const fs = require(\"node:fs\");\n";
shell += "const path = require(\"node:path\");\n";
shell += "const root = process.argv[1];\n";
shell += "const members = (process.argv[2] || \"\").split(\"\\n\").filter(Boolean);\n";
shell += "if (members.length === 0) process.exit(1);\n";
shell += "const resolves = (dir, name) =>\n";
shell += "  fs.existsSync(path.join(dir, \"node_modules\", ...name.split(\"/\"))) ||\n";
shell += "  fs.existsSync(path.join(root, \"node_modules\", ...name.split(\"/\")));\n";
shell += "for (const member of members) {\n";
shell += "  const dir = path.join(root, member);\n";
shell += "  const manifest = path.join(dir, \"package.json\");\n";
shell += "  if (!fs.existsSync(manifest)) process.exit(1);\n";
shell += "  const pkg = JSON.parse(fs.readFileSync(manifest, \"utf8\"));\n";
shell += "  const names = Object.keys({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) });\n";
shell += "  for (const name of names) {\n";
shell += "    if (!resolves(dir, name)) process.exit(1);\n";
shell += "  }\n";
shell += "}\n";
shell += "' \"$repo_root\" \"$members\"\n";
shell += "}\n";
shell += "\n";
shell += "ensure_root_workspace_install() {\n";
shell += "  fingerprint=$(root_workspace_fingerprint)\n";
shell += "  stamp_path=\"$stamp_root/workspace-root.stamp\"\n";
shell += "\n";
shell += "  if [ -f \"$stamp_path\" ] \\\n";
shell += "    && [ \"$(cat \"$stamp_path\")\" = \"$fingerprint\" ] \\\n";
shell += "    && root_workspace_install_satisfied; then\n";
shell += "    printf '[info] root workspace already hydrated\\n'\n";
shell += "    return 0\n";
shell += "  fi\n";
shell += "\n";
shell += "  printf '[info] bun install --frozen-lockfile -> workspace root\\n'\n";
shell += "  rm -f \"$stamp_path\"\n";
shell += "  (\n";
shell += "    cd \"$repo_root\"\n";
shell += "    bun install --frozen-lockfile\n";
shell += "  )\n";
shell += "  printf '%s\\n' \"$fingerprint\" > \"$stamp_path\"\n";
shell += "}\n";
shell += "\n";
shell += "# --- flat layout helpers ----------------------------------------------------\n";
shell += "\n";
shell += "ensure_bun_install_if_present() {\n";
shell += "  dir=\"$1\"\n";
shell += "  label=\"$2\"\n";
shell += "  if [ -f \"$dir/package.json\" ]; then\n";
shell += "    ensure_bun_install \"$dir\" \"$label\"\n";
shell += "  fi\n";
shell += "}\n";
shell += "\n";
shell += "resolve_first_package_dir() {\n";
shell += "  for dir in \"$@\"; do\n";
shell += "    if [ -f \"$dir/package.json\" ]; then\n";
shell += "      printf '%s\\n' \"$dir\"\n";
shell += "      return 0\n";
shell += "    fi\n";
shell += "  done\n";
shell += "  return 1\n";
shell += "}\n";
shell += "\n";
shell += "ensure_svelte_sync_if_present() {\n";
shell += "  dir=\"$1\"\n";
shell += "  label=\"$2\"\n";
shell += "  if [ ! -f \"$dir/package.json\" ]; then\n";
shell += "    return 0\n";
shell += "  fi\n";
shell += "  if [ ! -f \"$dir/svelte.config.js\" ] && [ ! -f \"$dir/svelte.config.ts\" ]; then\n";
shell += "    return 0\n";
shell += "  fi\n";
shell += "  printf '[info] svelte-kit sync -> %s\\n' \"$label\"\n";
shell += "  (\n";
shell += "    cd \"$dir\"\n";
shell += "    kit_cli=\"\"\n";
shell += "    for candidate in node_modules/@sveltejs/kit/svelte-kit.js \"$repo_root/node_modules/@sveltejs/kit/svelte-kit.js\"; do\n";
shell += "      if [ -f \"$candidate\" ]; then kit_cli=\"$candidate\"; break; fi\n";
shell += "    done\n";
shell += "    if [ -z \"$kit_cli\" ]; then\n";
shell += "      printf '[error] missing @sveltejs/kit CLI in %s\\n' \"$dir\" >&2\n";
shell += "      exit 1\n";
shell += "    fi\n";
shell += "    bun \"$kit_cli\" sync\n";
shell += "  )\n";
shell += "}\n";

// --- hydration targets ------------------------------------------------------
//
// Sibling framework checkouts are separate repos, not workspace members, so
// they hydrate the same way in both layouts.
shell += "ensure_bun_install_if_present \"" + underlay_dir + "\" \"underlay\"\n";
shell += "ensure_bun_install_if_present \"" + poodle_dir + "\" \"poodle\"\n";
shell += "\n";
shell += "if root_workspace_detected; then\n";
shell += "  ensure_root_workspace_install\n";
shell += "else\n";

if client_dir != "" {
    shell += "  ensure_bun_install_if_present \"" + client_abs_dir + "\" \"" + client_dir + "\"\n";
} else {
    shell += "  ensure_bun_install_if_present \"" + app_client_dir + "\" \"app-client\"\n";
    shell += "  ensure_bun_install_if_present \"" + acme_client_dir + "\" \"acme-client\"\n";
    shell += "  ensure_bun_install_if_present \"" + legacy_client_dir + "\" \"client\"\n";
}

if ui_dir != "" {
    shell += "  ensure_bun_install_if_present \"" + ui_abs_dir + "\" \"" + ui_dir + "\"\n";
} else {
    shell += "  ensure_bun_install_if_present \"" + app_ui_dir + "\" \"app-ui\"\n";
    shell += "  ensure_bun_install_if_present \"" + acme_ui_dir + "\" \"acme-ui\"\n";
    shell += "  ensure_bun_install_if_present \"" + legacy_ui_dir + "\" \"ui\"\n";
}

shell += "fi\n";
shell += "\n";
shell += "case \"$setup_task_name\" in\n";

shell += "  front) selected_dir=$(resolve_first_package_dir";
if front_dir != "" {
    shell += " \"" + front_abs_dir + "\"";
} else {
    shell += " \"" + app_front_dir + "\" \"" + acme_front_dir + "\" \"" + legacy_front_dir + "\"";
}
shell += ")\n";
shell += "    if [ -z \"$selected_dir\" ]; then\n";
shell += "      printf '[warn] skipping front; none of these package dirs exist\\n'\n";
shell += "    else\n";
shell += "      root_workspace_detected || ensure_bun_install \"$selected_dir\" \"front\"\n";
shell += "      ensure_svelte_sync_if_present \"$selected_dir\" \"front\"\n";
shell += "    fi ;;\n";

shell += "  admin) selected_dir=$(resolve_first_package_dir";
if admin_dir != "" {
    shell += " \"" + admin_abs_dir + "\"";
} else {
    shell += " \"" + app_admin_dir + "\" \"" + acme_admin_dir + "\" \"" + legacy_admin_dir + "\"";
}
shell += ")\n";
shell += "    if [ -z \"$selected_dir\" ]; then\n";
shell += "      printf '[warn] skipping admin; none of these package dirs exist\\n'\n";
shell += "    else\n";
shell += "      root_workspace_detected || ensure_bun_install \"$selected_dir\" \"admin\"\n";
shell += "      ensure_svelte_sync_if_present \"$selected_dir\" \"admin\"\n";
shell += "    fi ;;\n";

shell += "  *) printf '[error] unsupported ui setup target %s\\n' \"$setup_task_name\"; exit 1 ;;\n";
shell += "esac\n";

let result = process::stream("sh", ["-lc", shell]);
if !result["success"] {
    throw result["stderr"].to_string();
}
