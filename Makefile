# Convenience targets. Every target only runs commands shown here.
.PHONY: samples summary test lint

samples:   ## re-create the synthetic firewall log and capture (identical every time)
	python3 tools/generate_sample_filterlog.py --out samples/filterlog_sample.log
	python3 tools/generate_synthetic_pcap.py --out samples/synthetic_scan_and_ssh.pcap

summary:   ## summarise the sample firewall log
	./scripts/filterlog_summary.sh --input samples/filterlog_sample.log

test:      ## run the whole test suite
	python3 -m pytest -v

lint:      ## ShellCheck and shfmt
	shellcheck -x scripts/*.sh
	shfmt -d -i 4 -ci scripts/*.sh
