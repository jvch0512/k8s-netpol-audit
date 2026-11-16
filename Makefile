.PHONY: build test sample

build:
	mkdir -p build && nim c -d:release --hints:off --warnings:off -p:src -o:build/k8s-netpol-audit src/main.nim

test: build
	mkdir -p build && nim c -r --hints:off --warnings:off -p:src -o:build/tests tests/tests.nim && bash tests/cli.sh

sample: build
	mkdir -p docs site
	bin/k8s-netpol-audit examples > docs/sample-output.txt; true
	bin/k8s-netpol-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "k8s-netpol-audit" "Audits Kubernetes NetworkPolicy coverage from kubectl JSON: namespaces with workloads and no policy, missing default deny, allow-all ingress and egress rules. Nim." "Synthetic data."
