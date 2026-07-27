{{- define "usg-est-issuer.name" -}}
usg-est-issuer
{{- end }}

{{- define "usg-est-issuer.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "usg-est-issuer.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "usg-est-issuer.labels" -}}
app.kubernetes.io/name: {{ include "usg-est-issuer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
