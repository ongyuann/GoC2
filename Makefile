linux_server:
	echo "Building Server"
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/server cmd/server/server.go
linux_cli:
	echo "Building Operator CLI"
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/operator cmd/operator/operator.go
macos_server:
	echo "Building Server"
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/server cmd/server/server.go
macos_cli:
	echo "Building Operator CLI"
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/operator cmd/operator/operator.go

windows_server:
	echo "Building Server"
	GOOS=windows GOARCH=amd64 go build  -ldflags "-s -w " -o bin/server.exe cmd/server/server.go

windows_cli:
	echo "Building Operator CLI"
	GOOS=windows GOARCH=amd64 go build  -ldflags "-s -w" -o bin/operator.exe cmd/operator/operator.go


client_windows_garble:
	@echo  - README -
	@echo "For some reason on windows the ldflags -X command doesnt work" 
	@echo "so you need to manually edit the internal/client/client.go file"
	@echo "and modify ServerSecret and ServerHostName Before Building"
	@echo "press enter once you made that change to start building..."
	@read NULL
	GOOS=windows garble build -ldflags "-s -w -H=windowsgui" -tags windows -o bin/client.exe cmd/client/client.go

client_windows_debug:
	@echo  - README -
	@echo "For some reason on windows the ldflags -X command doesnt work" 
	@echo "so you need to manually edit the internal/client/client.go file"
	@echo "and modify ServerSecret and ServerHostName Before Building"
	@echo "press enter once you made that change to start building..."
	@read NULL
	GOOS=windows go build -ldflags "-s -w" -tags windows -o bin/client.exe cmd/client/client.go

client_windows:
	@echo  - README -
	@echo "For some reason on windows the ldflags -X command doesnt work" 
	@echo "so you need to manually edit the internal/client/client.go file"
	@echo "and modify ServerSecret and ServerHostName Before Building"
	@echo "press enter once you made that change to start building..."
	@read NULL
	GOOS=windows go build -ldflags "-s -w -H=windowsgui" -tags windows -o bin/client.exe cmd/client/client.go

client_windows_old:
	echo "Start Server To Create Certificates Then Continue..."
	cp certs/* internal/client/
	sed -i 's/\/\/ServerHostName = "0.0.0.0"/ServerHostName = "0.0.0.0"/g' internal/client/client.go
	sed -i 's/\/\/ServerSecret = "SECRET"/ServerSecret = "turtleshells"/g' internal/client/client.go
	GOOS=windows go build -ldflags "-s -w" -tags windows -o bin/client.exe cmd/client/client.go
	echo "Removing Client Certificates"
	rm internal/client/*.key
	rm internal/client/*.cert

client_macos:
	@echo  - README -
	@echo "For some reason on windows the ldflags -X command doesnt work" 
	@echo "so you need to manually edit the internal/client/client.go file"
	@echo "and modify ServerSecret and ServerHostName Before Building"
	@echo "press enter once you made that change to start building..."
	@read NULL
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X client.ServerSecret=TEST;client.ServerHostName=0.0.0.0" -o bin/client cmd/client/client.go


client_linux:
	@echo  - README -
	@echo "For some reason on windows the ldflags -X command doesnt work" 
	@echo "so you need to manually edit the internal/client/client.go file"
	@echo "and modify ServerSecret and ServerHostName Before Building"
	@echo "press enter once you made that change to start building..."
	@read NULL
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X client.ServerSecret=($$SECRET);client.ServerHostName=($$SERVER)" -o bin/client cmd/client/client.go

macos: macos_server macos_cli

linux: linux_server linux_cli

windows: windows_server windows_cli
