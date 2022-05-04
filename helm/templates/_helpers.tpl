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
app: {{ .Values.fullname }}
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
- {{ .Values.mode }}
- --ips-file
- {{ .Values.ipsFilePath }}
- --use-reconnect={{ if eq .Values.mode "istio" }}true{{ else }}false{{ end }}
- --cni-mode={{ .Values.cniMode }}
{{- if ne .Values.mountPath.proc "/host/proc" }}
- --host-proc={{ .Values.mountPath.proc }}
{{- end }}
{{- if ne .Values.mountPath.cniBin "/host/opt/cni/bin" }}
- --cni-bin-dir={{ .Values.mountPath.cniBin }}
{{- end }}
{{- if ne .Values.mountPath.cniConfig "/host/etc/cni/net.d" }}
- --cni-config-dir={{ .Values.mountPath.cniConfig }}
{{- end }}
{{- if ne .Values.mountPath.varRun "/host/var/run" }}
- --host-var-run={{ .Values.mountPath.varRun }}
{{- end }}
{{- end }}

{{/*
Merbridge init args command
*/}}
{{- define "merbridge.cmd.init.args" -}}
- sh
- -c
- nsenter --net=/host/proc/1/ns/net ip -o addr | awk '{print $4}' | tee {{ .Values.ipsFilePath }}
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
