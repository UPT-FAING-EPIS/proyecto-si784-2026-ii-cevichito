output "url" {
  description = "URL pública de la aplicación."
  value       = render_web_service.app.url
}

output "neon_project_id" {
  value = neon_project.db.id
}

output "neon_host" {
  description = "Host de la base de datos; la contraseña está en la consola de Neon."
  value       = neon_project.db.primary_compute.host
}
