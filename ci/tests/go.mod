module dagger/tests

go 1.26.1

require (
	github.com/Khan/genqlient v0.8.1
	github.com/dagger/otel-go v1.43.0
	github.com/vektah/gqlparser/v2 v2.5.64
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/trace v1.46.0
)

require (
	github.com/99designs/gqlgen v0.17.90 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dagger/querybuilder v0.0.0-20260402040506-574a5e81cb59
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/sosodev/duration v1.4.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.17.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.17.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.46.0 // indirect
	go.opentelemetry.io/otel/log v0.17.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/sdk v1.46.0
	go.opentelemetry.io/otel/sdk/log v0.17.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// The Dagger code generator writes the replace directives of the
// OpenTelemetry log modules each time it generates the code of this
// module, so a change to them does not last. A package rule in
// .github/renovate.json5 stops Renovate from proposing versions for
// them. v0.16.0 of otlploggrpc, of otlploghttp, and of otel/sdk/log has
// advisories of MODERATE severity.
replace go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc => go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.16.0

replace go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp => go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.16.0

replace go.opentelemetry.io/otel/log => go.opentelemetry.io/otel/log v0.16.0

replace go.opentelemetry.io/otel/sdk/log => go.opentelemetry.io/otel/sdk/log v0.16.0

// The replace directives of otel/sdk, otel/sdk/metric, and grpc select
// versions that pass the vulnerability scan of the source tree. The scan
// reads this go.mod and fails on an advisory of HIGH or CRITICAL
// severity. github.com/dagger/otel-go requires otel/sdk v1.43.0,
// otel/sdk/metric v1.43.0, and grpc v1.79.3, and grpc v1.79.3 has
// advisories of HIGH severity. grpc v1.85.0 has no advisory. otel/sdk
// v1.46.0 and otel/trace v1.46.0 have one advisory of MODERATE severity,
// GHSA-q7gw-24fr-5p69, and v1.47.0 fixes it.
//
// Keep every go.opentelemetry.io/otel module at a version before v1.47.0
// while otel/log is at v0.16.0. otel/internal/global v1.47.0 imports
// otel/log, and otel/log v0.16.0 imports otel/internal/global, so the
// module does not compile. A package rule in .github/renovate.json5
// holds Renovate to the versions before v1.47.0.
//
// Check the selected versions for advisories after each `dagger develop`
// that changes this file.
replace go.opentelemetry.io/otel/sdk => go.opentelemetry.io/otel/sdk v1.46.0

replace go.opentelemetry.io/otel/sdk/metric => go.opentelemetry.io/otel/sdk/metric v1.46.0

replace google.golang.org/grpc => google.golang.org/grpc v1.85.0
