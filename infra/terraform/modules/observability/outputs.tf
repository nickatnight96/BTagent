output "prometheus_namespace" {
  description = "Kubernetes namespace where Prometheus is deployed"
  value       = kubernetes_namespace.monitoring.metadata[0].name
}

output "grafana_url" {
  description = "Grafana dashboard URL"
  value       = "https://grafana.btagent.example.com"
}
