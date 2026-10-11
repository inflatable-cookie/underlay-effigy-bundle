// Fixed diagnostic vocabulary; captured subprocess payloads never cross this boundary.
const phases = new Set(["admission", "configuration", "service-status", "compose-bindings", "host-inventory", "gateway-status", "gateway-port", "route-validation", "service-port"]);
const operations = new Set(["verify", "private-root", "compose", "default.hosts", "gateway.status", "gateway.https", "routes", "postgres", "smtp", "mailpit_http", "silo", "silo_console", "dbgate", "hybrid_services.status", "disposable_test.status", "hybrid_services.hosts", "disposable_test.hosts"]);
const classes = new Set(["ProfileError", "OSError", "FileNotFoundError", "PermissionError", "TimeoutExpired", "JSONDecodeError", "ValueError", "TypeError", "other"]);
const messages = new Set(["operation_failed", "command_timeout", "invalid_json", "source_or_binary_refused", "private_gateway_unavailable", "loopback_binding_unavailable", "binding_conflict", "effective_route_unavailable", "file_unavailable", "permission_denied"]);

export function safeContextRecord(value) {
  if (!value || value.schema !== "underlay.profile-context-error.v1" ||
      !phases.has(value.phase) || !operations.has(value.operation) ||
      !classes.has(value.error_class) || !messages.has(value.message)) return null;
  return { schema: value.schema, phase: value.phase, operation: value.operation,
    error_class: value.error_class, message: value.message,
    exit_status: Number.isInteger(value.exit_status) && Math.abs(value.exit_status) <= 255 ? value.exit_status : null };
}

export function decodeContext(result) {
  if (result.error || result.status !== 0) {
    for (const line of String(result.stderr || "").slice(-16384).split("\n")) {
      if (!line.startsWith("UNDERLAY_CONTEXT_ERROR ") || line.length > 1024) continue;
      try {
        const record = safeContextRecord(JSON.parse(line.slice("UNDERLAY_CONTEXT_ERROR ".length)));
        if (record) { record.exit_status = Number.isInteger(result.status) ? result.status : null; throw Object.assign(new Error(`UNDERLAY_CONTEXT_ERROR ${JSON.stringify(record)}`), { contextDiagnostic: true }); }
      } catch (error) {
        if (error.contextDiagnostic) throw error;
      }
    }
    const timeout = result.error?.code === "ETIMEDOUT";
    throw new Error(`UNDERLAY_CONTEXT_ERROR ${JSON.stringify({ schema: "underlay.profile-context-error.v1",
      phase: "configuration", operation: "verify", error_class: timeout ? "TimeoutExpired" : "OSError",
      exit_status: Number.isInteger(result.status) ? result.status : null, message: timeout ? "command_timeout" : "operation_failed" })}`);
  }
  try { return JSON.parse(result.stdout); }
  catch {
    throw new Error(`UNDERLAY_CONTEXT_ERROR ${JSON.stringify({ schema: "underlay.profile-context-error.v1",
      phase: "configuration", operation: "verify", error_class: "JSONDecodeError", exit_status: 0, message: "invalid_json" })}`);
  }
}
