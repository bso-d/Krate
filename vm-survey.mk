# vm-survey.mk — interim tool, not part of the repo build.
# Surveys a target VM (read-only) to decide which Krate bundle to build.
#
#   make -f vm-survey.mk HOST=user@vm1     survey a remote VM over ssh
#   make -f vm-survey.mk                   survey this machine
#   make -f vm-survey.mk push HOST=user@vm1   copy the script to the VM instead
#
# Plain tabs, no .RECIPEPREFIX, so system make (3.81) works as well as gmake.

HOST ?=
SCRIPT := vm-survey.sh

.PHONY: survey push
.DEFAULT_GOAL := survey

survey: $(SCRIPT)
	@if [ -n "$(HOST)" ]; then \
		echo "==> Surveying $(HOST) over ssh — read-only: installs nothing, changes nothing"; \
		ssh -o BatchMode=yes -o ConnectTimeout=10 "$(HOST)" 'bash -s' < $(SCRIPT); \
	else \
		echo "==> Surveying this machine (pass HOST=user@vm to survey a remote VM)"; \
		bash $(SCRIPT); \
	fi

push: $(SCRIPT)
	@[ -n "$(HOST)" ] || { echo "HOST is required, e.g. make -f vm-survey.mk push HOST=user@vm1" >&2; exit 1; }
	scp $(SCRIPT) "$(HOST)":~/
	@echo "==> Copied. Run it there with: ssh $(HOST) './$(SCRIPT)'"

$(SCRIPT):
	@echo "$(SCRIPT) not found in $$(pwd)" >&2; exit 1
