{{/*
Expand the name of the chart.
*/}}
{{- define "merbridge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "merbridge.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "merbridge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "merbridge.labels" -}}
app: {{ .Values.merbridge.fullname }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "merbridge.nodeSelector" -}}
kubernetes.io/os: linux
{{- end }}

{{/*
Merbridge clean command
*/}}
{{- define "merbridge.cmd.clean" -}}
- make
- -k
- clean
{{- end }}

{{/*
Merbridge args command
*/}}
{{- define "merbridge.cmd.args" -}}
- /app/mbctl
- -m
- {{ .Values.merbridge.mode }}
- --ips-file
- {{ .Values.merbridge.ipsFilePath }}
{{ if eq .Values.merbridge.mode "linkerd" }}- --use-reconnect=false {{ end }}
{{- end }}

{{/*
Merbridge init args command
*/}}
{{- define "merbridge.cmd.init.args" -}}
- sh
- -c
- nsenter --net=/host/proc/1/ns/net ip -o addr | awk '{print $4}' | tee {{ .Values.merbridge.ipsFilePath }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "merbridge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "merbridge.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
