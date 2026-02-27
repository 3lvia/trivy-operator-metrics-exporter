{{- define "trivy-operator-metrics-exporter.name" -}}
trivy-operator-metrics-exporter
{{- end }}

{{- define "trivy-operator-metrics-exporter.labels" -}}
app.kubernetes.io/component: controller
app.kubernetes.io/name: trivy-operator-metrics-exporter
app.kubernetes.io/part-of: trivy-operator-metrics-exporter
{{- end }}
