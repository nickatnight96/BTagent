# ── Monitoring Namespace ─────────────────────────────────────
resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
    labels = {
      name        = "monitoring"
      environment = var.environment
    }
  }
}

# ── Prometheus Stack (kube-prometheus-stack) ─────────────────
resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "56.6.2"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name

  values = [
    yamlencode({
      prometheus = {
        prometheusSpec = {
          retention         = "15d"
          retentionSize     = "40GB"
          replicas          = 1
          scrapeInterval    = "30s"
          evaluationInterval = "30s"
          resources = {
            requests = {
              cpu    = "500m"
              memory = "2Gi"
            }
            limits = {
              cpu    = "2000m"
              memory = "4Gi"
            }
          }
          storageSpec = {
            volumeClaimTemplate = {
              spec = {
                storageClassName = "gp3"
                accessModes      = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "50Gi"
                  }
                }
              }
            }
          }
          # Scrape BTagent backend pods
          additionalScrapeConfigs = [
            {
              job_name        = "btagent-backend"
              scrape_interval = "15s"
              kubernetes_sd_configs = [
                {
                  role = "pod"
                  namespaces = {
                    names = ["btagent-staging", "btagent-production"]
                  }
                }
              ]
              relabel_configs = [
                {
                  source_labels = ["__meta_kubernetes_pod_label_app_kubernetes_io_component"]
                  action        = "keep"
                  regex         = "backend"
                }
                ,{
                  source_labels = ["__meta_kubernetes_pod_annotation_prometheus_io_port"]
                  action        = "replace"
                  target_label  = "__address__"
                  regex         = "(\\d+)"
                  replacement   = "$${1}:$$1"
                }
              ]
            }
          ]
        }
      }

      alertmanager = {
        alertmanagerSpec = {
          replicas = 1
          resources = {
            requests = {
              cpu    = "50m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "256Mi"
            }
          }
        }
      }

      grafana = {
        enabled = false # Deployed separately below for version control
      }

      # Node exporter for host metrics
      nodeExporter = {
        enabled = true
      }

      # Kube state metrics
      kubeStateMetrics = {
        enabled = true
      }
    })
  ]

  timeout = 600

  depends_on = [kubernetes_namespace.monitoring]
}

# ── Loki (Log Aggregation) ──────────────────────────────────
resource "helm_release" "loki" {
  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki-stack"
  version    = "2.10.2"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name

  values = [
    yamlencode({
      loki = {
        auth_enabled = false
        storage = {
          type = "filesystem"
        }
        limits_config = {
          retention_period    = "168h" # 7 days
          max_entries_limit_per_query = 5000
          ingestion_rate_mb          = 10
          ingestion_burst_size_mb    = 20
        }
        schema_config = {
          configs = [
            {
              from   = "2024-01-01"
              store  = "tsdb"
              object_store = "filesystem"
              schema = "v13"
              index = {
                prefix = "index_"
                period = "24h"
              }
            }
          ]
        }
        persistence = {
          enabled      = true
          storageClassName = "gp3"
          size         = "20Gi"
        }
        resources = {
          requests = {
            cpu    = "200m"
            memory = "512Mi"
          }
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
        }
      }

      promtail = {
        enabled = true
        config = {
          clients = [
            {
              url = "http://loki:3100/loki/api/v1/push"
            }
          ]
          snippets = {
            pipelineStages = [
              {
                docker = {}
              }
              ,{
                match = {
                  selector = "{app=\"btagent-backend\"}"
                  stages = [
                    {
                      json = {
                        expressions = {
                          level      = "level"
                          message    = "msg"
                          trace_id   = "trace_id"
                          request_id = "request_id"
                        }
                      }
                    }
                    ,{
                      labels = {
                        level = ""
                      }
                    }
                  ]
                }
              }
            ]
          }
        }
        resources = {
          requests = {
            cpu    = "50m"
            memory = "64Mi"
          }
          limits = {
            cpu    = "200m"
            memory = "128Mi"
          }
        }
      }
    })
  ]

  timeout = 600

  depends_on = [kubernetes_namespace.monitoring]
}

# ── Grafana ──────────────────────────────────────────────────
resource "helm_release" "grafana" {
  name       = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "grafana"
  version    = "7.3.3"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name

  values = [
    yamlencode({
      replicas = 1

      adminUser     = "admin"
      adminPassword = "" # Set via secret in production

      persistence = {
        enabled          = true
        storageClassName = "gp3"
        size             = "10Gi"
      }

      resources = {
        requests = {
          cpu    = "100m"
          memory = "256Mi"
        }
        limits = {
          cpu    = "500m"
          memory = "512Mi"
        }
      }

      datasources = {
        "datasources.yaml" = {
          apiVersion = 1
          datasources = [
            {
              name      = "Prometheus"
              type      = "prometheus"
              access    = "proxy"
              url       = "http://prometheus-kube-prometheus-prometheus:9090"
              isDefault = true
            }
            ,{
              name   = "Loki"
              type   = "loki"
              access = "proxy"
              url    = "http://loki:3100"
            }
          ]
        }
      }

      dashboardProviders = {
        "dashboardproviders.yaml" = {
          apiVersion = 1
          providers = [
            {
              name            = "default"
              orgId           = 1
              folder          = ""
              type            = "file"
              disableDeletion = false
              editable        = true
              options = {
                path = "/var/lib/grafana/dashboards/default"
              }
            }
          ]
        }
      }

      dashboards = {
        default = {
          kubernetes-cluster = {
            gnetId     = 6417
            revision   = 1
            datasource = "Prometheus"
          }
          node-exporter = {
            gnetId     = 1860
            revision   = 33
            datasource = "Prometheus"
          }
        }
      }

      ingress = {
        enabled          = true
        ingressClassName = "nginx"
        annotations = {
          "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
        }
        hosts = ["grafana.btagent.example.com"]
        tls = [
          {
            secretName = "grafana-tls"
            hosts      = ["grafana.btagent.example.com"]
          }
        ]
      }

      sidecar = {
        dashboards = {
          enabled = true
          label   = "grafana_dashboard"
        }
      }
    })
  ]

  timeout = 300

  depends_on = [
    kubernetes_namespace.monitoring,
    helm_release.prometheus,
    helm_release.loki,
  ]
}
