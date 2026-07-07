locals {
  cloud_armor_denied_ip_rule = length(var.cloud_armor_denied_ip_ranges) > 0 ? [
    {
      priority      = 500
      description   = "Deny explicitly blocked IP ranges"
      action        = "deny(403)"
      preview       = false
      expression    = null
      src_ip_ranges = var.cloud_armor_denied_ip_ranges
      rate_limit    = false
    }
  ] : []

  /*
    IMPORTANT:
    This denies traffic outside the approved country list.

    We are NOT doing an early "allow US" rule because that would stop
    rule evaluation and bypass rate limiting / OWASP rules.

    Flow:
      Non-US traffic -> denied here
      US traffic     -> continues to rate limit + OWASP WAF + default allow
  */
  cloud_armor_geo_allowlist_rule = var.cloud_armor_enable_geo_restriction ? [
    {
      priority      = 700
      description   = "Deny traffic outside approved countries: ${join(",", var.cloud_armor_allowed_country_codes)}"
      action        = "deny(403)"
      preview       = var.cloud_armor_geo_restriction_preview
      expression    = join(" && ", [for country in var.cloud_armor_allowed_country_codes : "origin.region_code != '${country}'"])
      src_ip_ranges = null
      rate_limit    = false
    }
  ] : []

  cloud_armor_rate_limit_rule = var.cloud_armor_enable_rate_limit ? [
    {
      priority      = 900
      description   = "Global request throttling by client IP"
      action        = "throttle"
      preview       = var.cloud_armor_rate_limit_preview
      expression    = "true"
      src_ip_ranges = null
      rate_limit    = true
    }
  ] : []

  cloud_armor_owasp_rules = var.cloud_armor_enable_owasp_rules ? [
    {
      priority      = 1000
      description   = "OWASP SQL injection protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1010
      description   = "OWASP cross-site scripting protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1020
      description   = "OWASP local file inclusion protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1030
      description   = "OWASP remote file inclusion protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1040
      description   = "OWASP remote code execution protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1050
      description   = "OWASP scanner detection protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1060
      description   = "OWASP protocol attack protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1070
      description   = "OWASP PHP injection protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('php-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    },
    {
      priority      = 1080
      description   = "OWASP Java attack protection"
      action        = var.cloud_armor_owasp_action
      preview       = var.cloud_armor_owasp_preview
      expression    = "evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': ${var.cloud_armor_owasp_sensitivity}})"
      src_ip_ranges = null
      rate_limit    = false
    }
  ] : []

  cloud_armor_security_rules = concat(
    local.cloud_armor_denied_ip_rule,
    local.cloud_armor_geo_allowlist_rule,
    local.cloud_armor_rate_limit_rule,
    local.cloud_armor_owasp_rules
  )
}

resource "google_compute_security_policy" "policy" {
  name        = var.cloud_armor_policy_name != null ? var.cloud_armor_policy_name : "${var.project}-security-policy"
  project     = var.project
  description = "Cloud Armor policy for ${var.project} edge load balancer"

  dynamic "adaptive_protection_config" {
    for_each = var.cloud_armor_enable_adaptive_protection ? [1] : []

    content {
      layer_7_ddos_defense_config {
        enable = true
      }
    }
  }

  dynamic "rule" {
    for_each = {
      for rule in local.cloud_armor_security_rules : rule.priority => rule
    }

    content {
      priority    = rule.value.priority
      description = rule.value.description
      action      = rule.value.action
      preview     = rule.value.preview

      match {
        versioned_expr = rule.value.src_ip_ranges != null ? "SRC_IPS_V1" : null

        dynamic "config" {
          for_each = rule.value.src_ip_ranges != null ? [rule.value.src_ip_ranges] : []

          content {
            src_ip_ranges = config.value
          }
        }

        dynamic "expr" {
          for_each = rule.value.expression != null ? [rule.value.expression] : []

          content {
            expression = expr.value
          }
        }
      }

      dynamic "rate_limit_options" {
        for_each = rule.value.rate_limit ? [1] : []

        content {
          conform_action = "allow"
          exceed_action  = var.cloud_armor_rate_limit_exceed_action
          enforce_on_key = var.cloud_armor_rate_limit_enforce_on_key

          rate_limit_threshold {
            count        = var.cloud_armor_rate_limit_threshold_count
            interval_sec = var.cloud_armor_rate_limit_threshold_interval_sec
          }
        }
      }
    }
  }

  rule {
    priority    = 2147483647
    description = "Default allow after geo, rate-limit, and OWASP checks"
    action      = "allow"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}