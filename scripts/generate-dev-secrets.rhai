let force = args.contains("--force");
let generated = #{};

let jwt = random::jwt_env_keys();

fn should_generate(name, force) {
    if force || !secrets::has(name) {
        log("[ok] queued generated secret `" + name + "`");
        true
    } else {
        log("[info] secret `" + name + "` already exists");
        false
    }
}

if should_generate("auth_jwt_private_key", force) {
    generated["auth_jwt_private_key"] = jwt["private_key"];
}
if should_generate("auth_jwt_public_key", force) {
    generated["auth_jwt_public_key"] = jwt["public_key"];
}
if should_generate("auth_oauth_secret_key", force) {
    generated["auth_oauth_secret_key"] = random::base64(32);
}
if should_generate("encryption_key", force) {
    generated["encryption_key"] = random::base64(32);
}
if should_generate("aws_access_key_id", force) {
    generated["aws_access_key_id"] = "minioadmin";
}
if should_generate("aws_secret_access_key", force) {
    generated["aws_secret_access_key"] = "minioadmin";
}
if should_generate("ai_router_api_key", force) {
    generated["ai_router_api_key"] = "local-dev-key";
}

if generated.len() > 0 {
    secrets::set_many(generated);
    log("[ok] stored " + generated.len().to_string() + " generated secret(s)");
}

log("[ok] local dev secret generation complete");
