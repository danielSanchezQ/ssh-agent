.PHONY: all ssh-agent clean
all: ssh-agent

clean:
	@echo "Deleting SSH-Agent..."
	@rm -f ./bin/ssh-agent

ssh-agent:
	@echo "Building SSH-Agent..."
	@go build \
	-ldflags " \
	-X main.Version=`cat .git/refs/heads/master` \
	" \
	-o bin/bssh-agent github.com/off-the-grid-inc/ssh-agent/cmd
