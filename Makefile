install:
	mkdir -p "$(HOME)/.local/bin"
	ln -sfn "$(PWD)/strongbox" "$(HOME)/.local/bin/strongbox"
