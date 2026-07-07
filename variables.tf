variable "cloud_armor_policy_name" {
  description = "Optional Cloud Armor policy name. If null, a default policy name is generated."
  type        = string
  default     = null
}

variable "cloud_armor_enable_geo_restriction" {
  description = "Enable country-based restriction."
  type        = bool
  default     = true
}

variable "cloud_armor_allowed_country_codes" {
  description = "Country codes allowed to access the load balancer. Default allows only US."
  type        = list(string)
  default     = ["US"]

  validation {
    condition     = length(var.cloud_armor_allowed_country_codes) > 0
    error_message = "cloud_armor_allowed_country_codes must contain at least one country code."
  }
}

variable "cloud_armor_geo_restriction_preview" {
  description = "Run geo restriction in Cloud Armor preview mode."
  type        = bool
  default     = false
}

variable "cloud_armor_denied_ip_ranges" {
  description = "Optional IP CIDR ranges to deny before geo, rate-limit, and OWASP checks."
  type        = list(string)
  default     = []
}

variable "cloud_armor_enable_rate_limit" {
  description = "Enable Cloud Armor rate limiting."
  type        = bool
  default     = true
}

variable "cloud_armor_rate_limit_preview" {
  description = "Run rate limiting in Cloud Armor preview mode."
  type        = bool
  default     = false
}

variable "cloud_armor_rate_limit_threshold_count" {
  description = "Allowed request count per interval."
  type        = number
  default     = 300

  validation {
    condition     = var.cloud_armor_rate_limit_threshold_count > 0
    error_message = "cloud_armor_rate_limit_threshold_count must be greater than 0."
  }
}

variable "cloud_armor_rate_limit_threshold_interval_sec" {
  description = "Rate limit interval in seconds."
  type        = number
  default     = 60

  validation {
    condition = contains([
      10,
      30,
      60,
      120,
      180,
      240,
      300,
      600,
      900,
      1200,
      1800,
      3600
    ], var.cloud_armor_rate_limit_threshold_interval_sec)

    error_message = "cloud_armor_rate_limit_threshold_interval_sec must be a supported Cloud Armor interval."
  }
}

variable "cloud_armor_rate_limit_exceed_action" {
  description = "Action when rate limit is exceeded."
  type        = string
  default     = "deny(429)"

  validation {
    condition = contains([
      "deny(403)",
      "deny(404)",
      "deny(429)",
      "deny(502)"
    ], var.cloud_armor_rate_limit_exceed_action)

    error_message = "cloud_armor_rate_limit_exceed_action must be deny(403), deny(404), deny(429), or deny(502)."
  }
}

variable "cloud_armor_rate_limit_enforce_on_key" {
  description = "Rate limit key. IP is safest default."
  type        = string
  default     = "IP"
}

variable "cloud_armor_enable_owasp_rules" {
  description = "Enable Cloud Armor OWASP preconfigured WAF rules."
  type        = bool
  default     = true
}

variable "cloud_armor_owasp_preview" {
  description = "Run OWASP WAF rules in preview mode. Recommended true during first rollout."
  type        = bool
  default     = true
}

variable "cloud_armor_owasp_sensitivity" {
  description = "OWASP WAF sensitivity. Start with 1, then tune upward after reviewing logs."
  type        = number
  default     = 1

  validation {
    condition     = var.cloud_armor_owasp_sensitivity >= 0 && var.cloud_armor_owasp_sensitivity <= 4
    error_message = "cloud_armor_owasp_sensitivity must be between 0 and 4."
  }
}

variable "cloud_armor_owasp_action" {
  description = "Action for OWASP WAF rule matches."
  type        = string
  default     = "deny(403)"

  validation {
    condition = contains([
      "deny(403)",
      "deny(404)",
      "deny(502)"
    ], var.cloud_armor_owasp_action)

    error_message = "cloud_armor_owasp_action must be deny(403), deny(404), or deny(502)."
  }
}

variable "cloud_armor_enable_adaptive_protection" {
  description = "Enable Cloud Armor Adaptive Protection L7 DDoS defense."
  type        = bool
  default     = true
}