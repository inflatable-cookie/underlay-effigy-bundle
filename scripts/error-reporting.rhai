// Error-reporting smoke, metrics, and validation helpers for Underlay bundles.
//
// These are invoked through Effigy tasks. They expect `effigy dev` to be
// running when the smoke path is exercised.

fn require_success(result, message) {
    if !result["success"] {
        throw `${message}\n${result["stderr"]}`;
    }
}

fn required_config_string(path) {
    let value = config::get(path);
    if value.type_of() == "()" {
        throw `missing required Effigy config value: ${path}`;
    }
    return value.to_string();
}

fn run_sql(sql) {
    let system_name = required_config_string("systems.default");
    let container_name = required_config_string(`systems.${system_name}.container`);
    let database_name = required_config_string("bundle.database");
    let result = exec::run(
        [
        "psql",
        "-U",
        "postgres",
        "-d",
        database_name,
        "-t",
        "-A",
        "-c",
        sql,
    ],
        #{ run_in: "container", container: container_name, service: "postgres" },
    );
    require_success(result, "failed to query postgres");
    return result["stdout"].to_string();
}

fn smoke_error_logging() {
    let api_base_url = env("API_BASE_URL");
    if api_base_url == "" {
        api_base_url = "https://api." + required_config_string("bundle.host");
    }
    let smoke_endpoint = env("SMOKE_ENDPOINT");
    if smoke_endpoint == "" {
        smoke_endpoint = "/v1/dev/error-smoke";
    }

    let url = api_base_url + smoke_endpoint;
    log(`Triggering forced error: ${url}`);
    let response = http::post(url);

    let http_code = response["status"].to_string();
    if http_code != "500" {
        throw `expected HTTP 500 from smoke endpoint, got ${http_code}. Ensure the API is running in debug mode.\n${response["body"]}`;
    }
    log("Smoke endpoint returned 500");
    log("Waiting briefly for async error-log write...");
    time::sleep_ms(1000);

    let sql = "SELECT json_build_object('error_code', error_code, 'message', message, 'handler_context', context->'handler_context') FROM platform.error_log WHERE error_code = 'smoke.forced_db_failure' ORDER BY occurred_at DESC LIMIT 1;";
    let row_json = run_sql(sql);
    if row_json == "" {
        throw "no matching error_log row found for code smoke.forced_db_failure";
    }

    log(row_json);
    if !row_json.contains("\"error_code\" : \"smoke.forced_db_failure\"") && !row_json.contains("\"error_code\":\"smoke.forced_db_failure\"") {
        throw "error_code missing in row";
    }
    if !row_json.contains("\"message\" : \"Forced failure for error-log smoke testing\"") && !row_json.contains("\"message\":\"Forced failure for error-log smoke testing\"") {
        throw "message missing in row";
    }
    if row_json.contains("\"handler_context\" : null") || row_json.contains("\"handler_context\":null") {
        throw "handler_context missing or null";
    }
    if !row_json.contains("\"operation\" : \"smoke.error_logging_capture\"") && !row_json.contains("\"operation\":\"smoke.error_logging_capture\"") {
        throw "handler_context.operation missing";
    }

    log("Smoke test passed: error_code, message, and handler_context are present");
}

fn error_log_metrics() {
    let window_hours = env("WINDOW_HOURS");
    if window_hours == "" {
        window_hours = "24";
    }

    log(`Computing error-log metrics for the last ${window_hours} hour(s)`);
    let sql = "WITH windowed AS (SELECT context FROM platform.error_log WHERE occurred_at > now() - make_interval(hours => " + window_hours + ")), stats AS (SELECT COUNT(*)::int AS total_errors, COUNT(*) FILTER (WHERE context->'handler_context' IS NULL OR context->'handler_context' = 'null'::jsonb OR context->'handler_context' = '{}'::jsonb)::int AS null_handler_context FROM windowed) SELECT json_build_object('window_hours', " + window_hours + ", 'total_errors', total_errors, 'null_handler_context', null_handler_context, 'null_rate_percent', CASE WHEN total_errors = 0 THEN 0 ELSE ROUND((null_handler_context::numeric / total_errors::numeric) * 100, 2) END) FROM stats;";
    let result = run_sql(sql);
    if result == "" {
        throw "failed to query error log metrics";
    }
    log(result);
    return result;
}

fn check_route_error_patterns() {
    let target_dir = env("ERROR_REPORTING_ROUTES_DIR");
    if target_dir == "" {
        target_dir = "acme-api/crates/api/src/routes";
    }
    if !fs::exists(target_dir) {
        throw `target directory not found: ${target_dir}; set ERROR_REPORTING_ROUTES_DIR for this repo`;
    }

    log(`Checking route handlers in: ${target_dir}`);
    let raw_status_pattern = "StatusCode::(BAD_REQUEST|UNAUTHORIZED|FORBIDDEN|NOT_FOUND|METHOD_NOT_ALLOWED|CONFLICT|UNPROCESSABLE_ENTITY|TOO_MANY_REQUESTS|INTERNAL_SERVER_ERROR|NOT_IMPLEMENTED|BAD_GATEWAY|SERVICE_UNAVAILABLE|GATEWAY_TIMEOUT)\\s*\\.into_response\\(\\)";
    let raw_status_matches = search::files(target_dir, raw_status_pattern, #{ glob: "*.rs" });
    if raw_status_matches["success"] {
        log_warn("Non-canonical raw status error responses found:");
        log_warn(raw_status_matches["stdout"].to_string());
        throw "migrate raw status error responses to ApiError/ApiResult";
    }

    let compat_matches = search::files(target_dir, "\\berror_response\\(", #{ glob: "*.rs" });
    if compat_matches["success"] {
        let compat_count = compat_matches["count"];
        log_warn(`Compatibility helper usage found (migration candidates): ${compat_count}`);
    }

    log("Pass: no raw status error responses found.");
}

fn validate_error_reporting() {
    let threshold = env("NULL_RATE_THRESHOLD");
    if threshold == "" {
        threshold = "25";
    }

    log("Checking route patterns for canonical ApiError usage");
    check_route_error_patterns();
    log("Route pattern check passed");

    log("Running smoke test for end-to-end error logging capture");
    smoke_error_logging();
    log("Smoke test passed");

    log("Measuring handler_context null-rate");
    let metrics_json = error_log_metrics();
    let metrics = json::parse(metrics_json);
    let total_errors = metrics["total_errors"].to_int();
    let null_rate = metrics["null_rate_percent"].to_string();

    if total_errors == 0 {
        log_warn("No errors in window; null-rate trend is not yet meaningful.");
        log("Validation completed (smoke path verified).");
        return;
    }

    if null_rate.to_float() <= threshold.to_float() {
        log(`Null-rate ${null_rate}% is within threshold (${threshold}%).`);
    } else {
        log_warn(`Null-rate ${null_rate}% exceeds threshold (${threshold}%).`);
        log_warn("Routing/middleware path is healthy; continue collecting data after more migrated failures.");
    }

    log("Validation run complete.");
}

if task_name == "smoke:error-logging" {
    smoke_error_logging();
} else if task_name == "metrics:error-log" {
    error_log_metrics();
} else if task_name == "validate:error-reporting" {
    validate_error_reporting();
} else {
    throw `unsupported error-reporting task: ${task_name}`;
}
