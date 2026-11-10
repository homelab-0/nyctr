{{/* Stable names keep Service targets and deployment selectors consistent. */}}
{{- define "nyctr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nyctr.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "nyctr.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "nyctr.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "nyctr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nyctr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "nyctr.labels" -}}
{{ include "nyctr.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}

{{- define "nyctr.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}

{{- define "nyctr.hostname" -}}
{{- (urlParse .Values.publicUrl).host | splitList ":" | first -}}
{{- end -}}

{{/* Fail before creating any resources when settings weaken release boundaries. */}}
{{- define "nyctr.validate" -}}
{{- if not (regexMatch "^[a-z]([-a-z0-9]*[a-z0-9])?$" (include "nyctr.fullname" .)) -}}
{{- fail "The generated resource name must be a DNS label beginning with a letter; set fullnameOverride if needed." -}}
{{- end -}}
{{- if ne (int .Values.replicaCount) 1 -}}
{{- fail "The Nyctr alpha supports exactly one application replica." -}}
{{- end -}}
{{- if eq (empty .Values.image.tag) (empty .Values.image.digest) -}}
{{- fail "Set exactly one explicit image.tag or image.digest; no image is assumed to exist." -}}
{{- end -}}
{{- if eq .Values.image.tag "latest" -}}
{{- fail "image.tag must be an explicit version or build tag, not latest." -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.httpRoute.enabled -}}
{{- fail "ingress.enabled and httpRoute.enabled are mutually exclusive." -}}
{{- end -}}
{{- $origin := urlParse .Values.publicUrl -}}
{{- if or (not $origin.host) $origin.path $origin.query $origin.fragment $origin.userinfo -}}
{{- fail "publicUrl must be an origin without a path, query, fragment or user information." -}}
{{- end -}}
{{- $hostParts := splitList ":" $origin.host -}}
{{- if eq (len $hostParts) 2 -}}
{{- $port := last $hostParts | atoi -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail "publicUrl has an invalid port." -}}
{{- end -}}
{{- end -}}
{{- range .Values.forwardedAllowIps -}}
{{- if or (contains "*" .) (contains "," .) -}}
{{- fail "forwardedAllowIps must contain only trusted proxy IP addresses or bounded ranges." -}}
{{- end -}}
{{- if and (contains "/" .) (not $.Values.networkPolicy.enabled) -}}
{{- fail "A forwardedAllowIps range requires networkPolicy.enabled=true: only the policy guarantees that every peer in the range is a trusted proxy. Use exact addresses otherwise." -}}
{{- end -}}
{{- end -}}
{{- $names := dict -}}
{{- range .Values.connectors.secrets -}}
{{- if hasKey $names .envName -}}
{{- fail "connectors.secrets contains duplicate environment names." -}}
{{- end -}}
{{- $_ := set $names .envName true -}}
{{- end -}}
{{- if ne (empty .Values.assistant.baseUrl) (empty .Values.assistant.model) -}}
{{- fail "assistant.baseUrl and assistant.model must be set together." -}}
{{- end -}}
{{- if and .Values.assistant.existingSecret (empty .Values.assistant.baseUrl) -}}
{{- fail "assistant.existingSecret is set but no assistant endpoint is configured." -}}
{{- end -}}
{{- if .Values.ingress.enabled -}}
{{- $_ := required "ingress.className is required." .Values.ingress.className -}}
{{- $_ := required "ingress.tlsSecretName must reference an existing certificate Secret." .Values.ingress.tlsSecretName -}}
{{- end -}}
{{- if and .Values.httpRoute.enabled (empty .Values.httpRoute.parentRefs) -}}
{{- fail "httpRoute.parentRefs must name an existing Gateway HTTPS listener." -}}
{{- end -}}
{{- if or .Values.ingress.enabled .Values.httpRoute.enabled -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" (include "nyctr.hostname" .) -}}
{{- fail "Ingress and HTTPRoute require a DNS hostname in publicUrl, not an IP address." -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.mode "live" -}}
{{- if ne $origin.scheme "https" -}}
{{- fail "Live mode requires an HTTPS publicUrl." -}}
{{- end -}}
{{- if empty .Values.forwardedAllowIps -}}
{{- fail "Live mode requires explicit forwardedAllowIps for the trusted TLS proxy." -}}
{{- end -}}
{{- $_ := required "Live mode requires database.existingSecret containing a PostgreSQL URL." .Values.database.existingSecret -}}
{{- if or .Values.demo.allowKnownCredentials .Values.demo.ephemeralDatabase -}}
{{- fail "Demo acknowledgements and ephemeral databases cannot be enabled in live mode." -}}
{{- end -}}
{{- if and .Values.networkPolicy.enabled (empty .Values.networkPolicy.ingressFrom) -}}
{{- fail "Live networkPolicy.ingressFrom must explicitly permit the trusted proxy peers." -}}
{{- end -}}
{{- if and (not .Values.auth.local.enabled) (not .Values.auth.oidc.enabled) -}}
{{- fail "Live mode requires at least one enabled authentication method." -}}
{{- end -}}
{{- if and (not .Values.auth.local.enabled) .Values.auth.local.bootstrap.existingSecret -}}
{{- fail "Local bootstrap credentials require auth.local.enabled=true." -}}
{{- end -}}
{{- $localAdmin := and .Values.auth.local.enabled (or .Values.auth.local.bootstrap.existingSecret .Values.auth.local.existingAccount) -}}
{{- $oidcAdmin := and .Values.auth.oidc.enabled (not (empty .Values.auth.oidc.adminGroups)) -}}
{{- if not (or $localAdmin $oidcAdmin) -}}
{{- fail "Configure a local bootstrap/existing administrator or explicit OIDC adminGroups." -}}
{{- end -}}
{{- if .Values.auth.oidc.enabled -}}
{{- $_ := required "auth.oidc.issuer is required when OIDC is enabled." .Values.auth.oidc.issuer -}}
{{- $_ := required "auth.oidc.clientId is required when OIDC is enabled." .Values.auth.oidc.clientId -}}
{{- $_ := required "auth.oidc.existingSecret is required when OIDC is enabled." .Values.auth.oidc.existingSecret -}}
{{- else if or .Values.auth.oidc.issuer .Values.auth.oidc.clientId .Values.auth.oidc.existingSecret -}}
{{- fail "OIDC settings are present but auth.oidc.enabled is false." -}}
{{- end -}}
{{- else if eq .Values.mode "demo" -}}
{{- if not .Values.demo.allowKnownCredentials -}}
{{- fail "Demo mode requires demo.allowKnownCredentials=true to acknowledge synthetic accounts." -}}
{{- end -}}
{{- if not (regexMatch "^http://(localhost|127\\.0\\.0\\.1):[0-9]+$" .Values.publicUrl) -}}
{{- fail "Demo publicUrl must be an HTTP loopback origin with an explicit port." -}}
{{- end -}}
{{- if or .Values.ingress.enabled .Values.httpRoute.enabled (not (empty .Values.forwardedAllowIps)) -}}
{{- fail "Demo mode allows only ClusterIP/loopback port forwarding, with no public route or proxy trust." -}}
{{- end -}}
{{- if or .Values.auth.oidc.enabled .Values.auth.oidc.existingSecret .Values.auth.oidc.issuer .Values.auth.oidc.clientId .Values.auth.local.bootstrap.existingSecret (not (empty .Values.connectors.secrets)) (not (empty .Values.connectors.hosts)) .Values.connectors.caBundle.existingSecret -}}
{{- fail "Demo mode cannot receive real identity-provider, bootstrap or connector configuration." -}}
{{- end -}}
{{- if or (not (empty .Values.providerWrites)) (ne (int .Values.collection.intervalSeconds) 0) .Values.collection.nudge.existingSecret .Values.assistant.baseUrl .Values.assistant.existingSecret -}}
{{- fail "Demo mode simulates every change and answers from samples; it cannot receive provider write permission, scheduled collection, a nudge token or a model endpoint." -}}
{{- end -}}
{{- if eq (empty .Values.database.existingSecret) (not .Values.demo.ephemeralDatabase) -}}
{{- fail "Demo requires exactly one external database Secret or demo.ephemeralDatabase=true." -}}
{{- end -}}
{{- else -}}
{{- fail "mode must be live or demo." -}}
{{- end -}}
{{- end -}}
