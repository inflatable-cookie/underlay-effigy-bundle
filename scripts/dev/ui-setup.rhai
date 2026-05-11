// Underlay starter - frontend hydration helper for `dev` tab setup.
//
// Invoked by `tasks.dev` concurrent entries as a `setup = [{ rhai = ... }]`
// step. Runs before the app's dev server starts and ensures bun
// dependencies are installed on a fingerprint-controlled basis.
//
// This is starter-owned helper glue, not Effigy runtime. It supports the
// generic `app-*` layout and the Underlay reference `acme-*` layout by
// default, and repos can override the package directories through
// `[bundle.dirs]`.
// The Effigy runtime already supplies
// `process::stream`, `path::join`, `task_name`, and `repo_root` as
// script bindings.
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

let shell_header = "set -eu\n"
    + "\n"
    + "runtime_root='" + runtime_root + "'\n"
    + "lock_dir=\"$runtime_root/ui-setup.lock\"\n"
    + "mkdir -p \"$runtime_root\"\n"
    + "stamp_root=\"$runtime_root/ui-hydration\"\n"
    + "mkdir -p \"$stamp_root\"\n"
    + "setup_task_name='" + task_name + "'\n"
    + "\n"
    + "reclaim_stale_lock_if_needed() {\n"
    + "  if [ -f \"$lock_dir/pid\" ]; then\n"
    + "    lock_pid=$(cat \"$lock_dir/pid\" 2>/dev/null || true)\n"
    + "    if [ -n \"$lock_pid\" ] && ! kill -0 \"$lock_pid\" 2>/dev/null; then\n"
    + "      rm -rf \"$lock_dir\"\n"
    + "      return 0\n"
    + "    fi\n"
    + "  fi\n"
    + "  if [ -n \"$(find \"$lock_dir\" -maxdepth 0 -mmin +2 -print -quit 2>/dev/null)\" ]; then\n"
    + "    rm -rf \"$lock_dir\"\n"
    + "  fi\n"
    + "}\n"
    + "\n"
    + "while ! mkdir \"$lock_dir\" 2>/dev/null; do\n"
    + "  reclaim_stale_lock_if_needed\n"
    + "  sleep 0.2\n"
    + "done\n"
    + "printf '%s\\n' \"$$\" > \"$lock_dir/pid\"\n"
    + "\n"
    + "cleanup() {\n"
    + "  rm -rf \"$lock_dir\" 2>/dev/null || true\n"
    + "}\n"
    + "trap cleanup EXIT INT TERM\n"
    + "\n";

let shell_functions = "package_fingerprint() {\n"
    + "  dir=\"$1\"\n"
    + "  (\n"
    + "    cd \"$dir\"\n"
    + "    printf 'platform %s %s\\n' \"$(uname -s)\" \"$(uname -m)\"\n"
    + "    if [ -f bun.lock ]; then\n"
    + "      cksum package.json bun.lock\n"
    + "    else\n"
    + "      cksum package.json\n"
    + "    fi\n"
    + "  ) | cksum | awk '{print $1\":\"$2}'\n"
    + "}\n"
    + "\n"
    + "node_modules_satisfies_package_json() {\n"
    + "  dir=\"$1\"\n"
    + "  if [ ! -d \"$dir/node_modules\" ]; then\n"
    + "    return 1\n"
    + "  fi\n"
    + "  bun -e '\n"
    + "const fs = require(\"node:fs\");\n"
    + "const path = require(\"node:path\");\n"
    + "const dir = process.argv[1];\n"
    + "const pkg = JSON.parse(fs.readFileSync(path.join(dir, \"package.json\"), \"utf8\"));\n"
    + "const names = Object.keys({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) });\n"
    + "for (const name of names) {\n"
    + "  if (!fs.existsSync(path.join(dir, \"node_modules\", ...name.split(\"/\")))) process.exit(1);\n"
    + "}\n"
    + "' \"$dir\"\n"
    + "}\n"
    + "\n"
    + "ensure_bun_install() {\n"
    + "  dir=\"$1\"\n"
    + "  label=\"$2\"\n"
    + "\n"
    + "  if [ ! -f \"$dir/package.json\" ]; then\n"
    + "    printf '[warn] skipping %s; no package.json at %s\\n' \"$label\" \"$dir\"\n"
    + "    return 0\n"
    + "  fi\n"
    + "\n"
    + "  fingerprint=$(package_fingerprint \"$dir\")\n"
    + "  stamp_path=\"$stamp_root/$label.stamp\"\n"
    + "\n"
    + "  if [ -f \"$stamp_path\" ] \\\n"
    + "    && [ \"$(cat \"$stamp_path\")\" = \"$fingerprint\" ] \\\n"
    + "    && node_modules_satisfies_package_json \"$dir\"; then\n"
    + "    printf '[info] %s already hydrated\\n' \"$label\"\n"
    + "    return 0\n"
    + "  fi\n"
    + "\n"
    + "  printf '[info] bun install -> %s\\n' \"$label\"\n"
    + "  rm -f \"$stamp_path\"\n"
    + "  (\n"
    + "    cd \"$dir\"\n"
    + "    bun install\n"
    + "  )\n"
    + "  printf '%s\\n' \"$fingerprint\" > \"$stamp_path\"\n"
    + "}\n"
    + "\n";

let shell_layout_helpers = "ensure_bun_install_if_present() {\n"
    + "  dir=\"$1\"\n"
    + "  label=\"$2\"\n"
    + "  if [ -f \"$dir/package.json\" ]; then\n"
    + "    ensure_bun_install \"$dir\" \"$label\"\n"
    + "  fi\n"
    + "}\n"
    + "\n"
    + "resolve_first_package_dir() {\n"
    + "  for dir in \"$@\"; do\n"
    + "    if [ -f \"$dir/package.json\" ]; then\n"
    + "      printf '%s\\n' \"$dir\"\n"
    + "      return 0\n"
    + "    fi\n"
    + "  done\n"
    + "  return 1\n"
    + "}\n"
    + "\n"
    + "ensure_svelte_sync_if_present() {\n"
    + "  dir=\"$1\"\n"
    + "  label=\"$2\"\n"
    + "  if [ ! -f \"$dir/package.json\" ]; then\n"
    + "    return 0\n"
    + "  fi\n"
    + "  if [ ! -f \"$dir/svelte.config.js\" ] && [ ! -f \"$dir/svelte.config.ts\" ]; then\n"
    + "    return 0\n"
    + "  fi\n"
    + "  printf '[info] svelte-kit sync -> %s\\n' \"$label\"\n"
    + "  (\n"
    + "    cd \"$dir\"\n"
    + "    if [ ! -f node_modules/@sveltejs/kit/svelte-kit.js ]; then\n"
    + "      printf '[error] missing @sveltejs/kit CLI in %s\\n' \"$dir\" >&2\n"
    + "      exit 1\n"
    + "    fi\n"
    + "    bun ./node_modules/@sveltejs/kit/svelte-kit.js sync\n"
    + "  )\n"
    + "}\n"
    + "\n"
    + "ensure_first_bun_install() {\n"
    + "  label=\"$1\"\n"
    + "  shift\n"
    + "  for dir in \"$@\"; do\n"
    + "    if [ -f \"$dir/package.json\" ]; then\n"
    + "      ensure_bun_install \"$dir\" \"$label\"\n"
    + "      return 0\n"
    + "    fi\n"
    + "  done\n"
    + "  printf '[warn] skipping %s; none of these package dirs exist: %s\\n' \"$label\" \"$*\"\n"
    + "}\n"
    + "\n";

let shell_targets = "ensure_bun_install_if_present \"" + underlay_dir + "\" \"underlay\"\n"
    + "ensure_bun_install_if_present \"" + poodle_dir + "\" \"poodle\"\n";

if client_dir != "" {
    shell_targets += "ensure_bun_install_if_present \"" + client_abs_dir + "\" \"" + client_dir + "\"\n";
} else {
    shell_targets += "ensure_bun_install_if_present \"" + app_client_dir + "\" \"app-client\"\n";
    shell_targets += "ensure_bun_install_if_present \"" + acme_client_dir + "\" \"acme-client\"\n";
    shell_targets += "ensure_bun_install_if_present \"" + legacy_client_dir + "\" \"client\"\n";
}

if ui_dir != "" {
    shell_targets += "ensure_bun_install_if_present \"" + ui_abs_dir + "\" \"" + ui_dir + "\"\n";
} else {
    shell_targets += "ensure_bun_install_if_present \"" + app_ui_dir + "\" \"app-ui\"\n";
    shell_targets += "ensure_bun_install_if_present \"" + acme_ui_dir + "\" \"acme-ui\"\n";
    shell_targets += "ensure_bun_install_if_present \"" + legacy_ui_dir + "\" \"ui\"\n";
}

shell_targets += "\ncase \"$setup_task_name\" in\n";
shell_targets += "  front) selected_dir=$(resolve_first_package_dir";
if front_dir != "" {
    shell_targets += ` "${front_abs_dir}"`;
} else {
    shell_targets += ` "${app_front_dir}" "${acme_front_dir}" "${legacy_front_dir}"`;
}
shell_targets += ")\n";
shell_targets += "    if [ -z \"$selected_dir\" ]; then\n";
shell_targets += "      printf '[warn] skipping front; none of these package dirs exist\\n'\n";
shell_targets += "    else\n";
shell_targets += "      ensure_bun_install \"$selected_dir\" \"front\"\n";
shell_targets += "      ensure_svelte_sync_if_present \"$selected_dir\" \"front\"\n";
shell_targets += "    fi ;;\n";
shell_targets += "  admin) selected_dir=$(resolve_first_package_dir";
if admin_dir != "" {
    shell_targets += ` "${admin_abs_dir}"`;
} else {
    shell_targets += ` "${app_admin_dir}" "${acme_admin_dir}" "${legacy_admin_dir}"`;
}
shell_targets += ")\n";
shell_targets += "    if [ -z \"$selected_dir\" ]; then\n";
shell_targets += "      printf '[warn] skipping admin; none of these package dirs exist\\n'\n";
shell_targets += "    else\n";
shell_targets += "      ensure_bun_install \"$selected_dir\" \"admin\"\n";
shell_targets += "      ensure_svelte_sync_if_present \"$selected_dir\" \"admin\"\n";
shell_targets += "    fi ;;\n";
shell_targets += "  *) printf '[error] unsupported ui setup target %s\\n' \"$setup_task_name\"; exit 1 ;;\n";
shell_targets += "esac\n";

let shell = shell_header + shell_functions + shell_layout_helpers + shell_targets;

// This stays as a shell program on purpose. The helper needs shell-native
// locking, traps, grouped subshells, and package-manager probes across a small
// directory matrix; a typed Rhai host surface would be more complex than the
// script it replaces.
let result = process::stream("sh", ["-lc", shell]);
if !result["success"] {
    throw result["stderr"].to_string();
}
