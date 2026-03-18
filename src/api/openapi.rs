//! OpenAPI specification generation
//!
//! This module provides the ApiDoc struct for generating OpenAPI/Swagger specifications.
//! Only compiled when the "swagger-gen" feature is enabled.

use utoipa::OpenApi;

use crate::api::types::*;
use crate::models::CustomRule;
use crate::server::router::CreateTokenApiRequest;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "registry-firewall API",
        description = "A unified registry proxy that protects development environments from software supply chain attacks",
    ),
    paths(
        crate::server::router::api_dashboard_handler,
        crate::server::router::api_blocks_handler,
        crate::server::router::api_security_sources_handler,
        crate::server::router::api_trigger_sync_handler,
        crate::server::router::api_cache_stats_handler,
        crate::server::router::api_cache_clear_handler,
        crate::server::router::api_list_rules_handler,
        crate::server::router::api_create_rule_handler,
        crate::server::router::api_get_rule_handler,
        crate::server::router::api_update_rule_handler,
        crate::server::router::api_delete_rule_handler,
        crate::server::router::api_list_tokens_handler,
        crate::server::router::api_create_token_handler,
        crate::server::router::api_delete_token_handler,
    ),
    components(
        schemas(
            DashboardStats, SecuritySourceSummary, BlockLogsQuery, BlockLogsResponse,
            BlockLogEntry, SecuritySourcesResponse, SecuritySourceInfo, SyncTriggerResponse,
            CacheStatsResponse, CacheClearResponse, RulesResponse, TokensResponse,
            TokenInfo, CreateTokenRequest, CreateTokenResponse, MessageResponse, ErrorResponse,
            CustomRule, CreateTokenApiRequest,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "dashboard", description = "Dashboard statistics"),
        (name = "blocks", description = "Block log management"),
        (name = "security-sources", description = "Security source management"),
        (name = "cache", description = "Cache management"),
        (name = "rules", description = "Custom block rule management"),
        (name = "tokens", description = "API token management"),
    )
)]
pub struct ApiDoc;

/// Security schemes modifier for OpenAPI spec
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // Set version from Cargo.toml
        openapi.info.version = env!("CARGO_PKG_VERSION").to_string();

        // Add server definition with placeholder
        openapi.servers = Some(vec![utoipa::openapi::ServerBuilder::new()
            .url("{scheme}://{host}:{port}")
            .description(Some("registry-firewall instance"))
            .parameter(
                "scheme",
                utoipa::openapi::ServerVariableBuilder::new()
                    .default_value("http")
                    .enum_values(Some(["http", "https"])),
            )
            .parameter(
                "host",
                utoipa::openapi::ServerVariableBuilder::new().default_value("localhost"),
            )
            .parameter(
                "port",
                utoipa::openapi::ServerVariableBuilder::new().default_value("8080"),
            )
            .build()]);

        // Add security schemes
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_token",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("token")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "basic_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Basic)
                    .build(),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apidoc_generates_openapi() {
        let openapi = ApiDoc::openapi();
        let json = openapi.to_pretty_json().unwrap();
        assert!(!json.is_empty());
    }

    #[test]
    fn test_apidoc_version_matches_cargo() {
        let openapi = ApiDoc::openapi();
        assert_eq!(openapi.info.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_apidoc_security_schemes() {
        let openapi = ApiDoc::openapi();
        let components = openapi.components.unwrap();
        assert!(components.security_schemes.contains_key("bearer_token"));
        assert!(components.security_schemes.contains_key("basic_auth"));
    }

    #[test]
    fn test_apidoc_has_paths() {
        let openapi = ApiDoc::openapi();
        assert!(!openapi.paths.paths.is_empty());
    }
}
