module go.jacobcolvin.com/terrarium/cmd/envoymanifest

go 1.26.0

require (
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/stretchr/testify v1.12.1
	github.com/ulikunitz/xz v0.5.17
	go.jacobcolvin.com/terrarium v0.7.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace go.jacobcolvin.com/terrarium => ../..
