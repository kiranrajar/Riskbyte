{{/*
Expand the name of the chart.
*/}}
{{- define "riskbyte.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "riskbyte.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "riskbyte.labels" -}}
helm.sh/chart: {{ include "riskbyte.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "riskbyte.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
riskbyte.io/tier: enterprise-soc
{{- end }}

{{/*
Selector labels
*/}}
{{- define "riskbyte.selectorLabels" -}}
app.kubernetes.io/name: {{ include "riskbyte.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
