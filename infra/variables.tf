variable "nombre" {
  description = "Prefijo de los recursos. Distinto del servicio creado a mano para no pisarlo."
  type        = string
  default     = "sast-studio-iac"
}

variable "region_render" {
  description = "Región de Render. virginia queda cerca de Neon aws-us-east-1."
  type        = string
  default     = "virginia"
}

variable "region_neon" {
  description = "Región de Neon."
  type        = string
  default     = "aws-us-east-1"
}

variable "neon_org_id" {
  description = "Organización de Neon (org-...)."
  type        = string
  default     = null
}

variable "plan_web" {
  description = "Plan del servicio web en Render (free, starter, standard...)."
  type        = string
  default     = "free"
}

variable "plan_keyvalue" {
  description = "Plan del Key Value (límite de peticiones)."
  type        = string
  default     = "free"
}

variable "repo_url" {
  description = "Repositorio que Render construye con el Dockerfile."
  type        = string
  default     = "https://github.com/NestorSnIbz/sast-studio"
}

variable "rama" {
  description = "Rama que se despliega."
  type        = string
  default     = "main"
}

variable "database_url" {
  description = "Cadena de conexión DIRECTA de Neon (con ?sslmode=require). Neon no la expone en Terraform."
  type        = string
  sensitive   = true
  default     = ""
}

variable "google_client_id" {
  type      = string
  sensitive = true
  default   = ""
}

variable "google_client_secret" {
  type      = string
  sensitive = true
  default   = ""
}

variable "admin_emails" {
  description = "Emails que ven el dashboard de uso, separados por comas."
  type        = string
  default     = ""
}
