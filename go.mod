module github.com/lbodlev888/ownvpn

go 1.26.2

require (
	github.com/jackpal/gateway v1.2.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	golang.org/x/crypto v0.53.0
)

require (
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/songgao/water => github.com/lbodlev888/water v0.0.2-0.20260712213340-e18a986cac0b
