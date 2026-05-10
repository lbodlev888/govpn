GOOS=linux GOARCH=amd64 go build -o vpn_amd64 .
GOOS=linux GOARCH=arm GOARM=7 go build -o vpn_armv7 .
