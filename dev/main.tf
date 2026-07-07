module "lb" {
  source = "../../../modules/ebt/load-balancer"

  project                    = var.project
  cloud_run_service_name_ui  = data.google_cloud_run_service.management_ui_service.name
  cloud_run_service_name_api = data.google_cloud_run_service.management_api_service.name
  domains                    = var.domains
  region                     = var.region
  sonarqube_mig              = local.sonarqube_mig
  iap                        = true

  iap_accessors = concat(
    [
      var.groups["developers"]
    ],
    var.additional_iap_accessors
  )

  ssl_policy_profile         = "MODERN"
  ssl_policy_min_tls_version = "TLS_1_2"

  cloud_armor_policy_name = "${var.project}-security-policy"

  # US-only traffic.
  cloud_armor_enable_geo_restriction = true
  cloud_armor_allowed_country_codes  = ["US"]

  # Keep geo restriction enforced.
  cloud_armor_geo_restriction_preview = false

  # Rate limiting.
  cloud_armor_enable_rate_limit                 = true
  cloud_armor_rate_limit_preview                = false
  cloud_armor_rate_limit_threshold_count        = 300
  cloud_armor_rate_limit_threshold_interval_sec = 60
  cloud_armor_rate_limit_exceed_action          = "deny(429)"
  cloud_armor_rate_limit_enforce_on_key         = "IP"

  # OWASP WAF.
  # Start in preview mode to avoid blocking valid traffic during first rollout.
  cloud_armor_enable_owasp_rules = true
  cloud_armor_owasp_preview      = true
  cloud_armor_owasp_sensitivity  = 1
  cloud_armor_owasp_action       = "deny(403)"

  # Optional explicit denylist.
  cloud_armor_denied_ip_ranges = []

  # You currently have adaptive protection enabled.
  # Keep true if your org/project supports it.
  cloud_armor_enable_adaptive_protection = true
}