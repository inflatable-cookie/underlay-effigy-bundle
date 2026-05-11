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

fn bundle_host() {
    let host = optional_config_string("bundle.host", "");
    if host == "" {
        throw "underlay minio bootstrap helper requires `[bundle].host`";
    }
    return host;
}

fn project_name() {
    let name = optional_config_string("bundle.project_name", "");
    if name == "" {
        throw "underlay minio bootstrap helper requires `[bundle].project_name`";
    }
    return name;
}

fn route_domain(host, path, fallback_label) {
    let label = optional_config_string(path, fallback_label);
    if label == "" {
        return host;
    }
    return label + "." + host;
}

fn blob_bucket_name() {
    let project = project_name();
    let base = if str::ends_with(project, "-dev") {
        str::replace(project, "-dev", "")
    } else {
        project
    };
    return base + "-media";
}

fn required_config_string(path) {
    let value = config::get(path);
    if value.type_of() == "()" {
        throw `missing required Effigy config value: ${path}`;
    }
    return value.to_string();
}

fn require_success(result, message) {
    if !result["success"] {
        throw `${message}\n${result["stderr"]}`;
    }
}

let host = bundle_host();
let front_domain = route_domain(host, "bundle.routes.front", "");
let admin_domain = route_domain(host, "bundle.routes.admin", "admin");
let bucket = blob_bucket_name();
let system_name = required_config_string("systems.default");
let container_name = required_config_string(`systems.${system_name}.container`);

let cors_json = "[{\"AllowedOrigins\":[\"https://"
    + front_domain
    + "\",\"https://"
    + admin_domain
    + "\"],\"AllowedMethods\":[\"GET\",\"HEAD\",\"PUT\"],\"AllowedHeaders\":[\"*\"],\"ExposeHeaders\":[\"ETag\",\"x-amz-request-id\",\"x-amz-id-2\"],\"MaxAgeSeconds\":3000}]";

let shell_script = "set -eu\n"
    + "mc alias set local http://127.0.0.1:9000 minioadmin minioadmin >/dev/null 2>&1\n"
    + "until mc ready local >/dev/null 2>&1; do sleep 1; done\n"
    + "mc mb local/" + bucket + " --ignore-existing >/dev/null\n"
    + "mc anonymous set download local/" + bucket + " >/dev/null\n"
    + "cat > /tmp/effigy-minio-cors.json <<'EOF'\n"
    + cors_json
    + "\nEOF\n"
    + "mc cors set local/" + bucket + " /tmp/effigy-minio-cors.json >/dev/null\n";

let result = exec::run(
    ["sh", "-lc", shell_script],
    #{ run_in: "container", container: container_name, service: "minio" },
);

require_success(result, "failed to configure minio bucket and cors");
log(`[ok] configured minio bucket ${bucket} with public-read and browser upload cors`);
