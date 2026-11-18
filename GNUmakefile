_mfetch:
	@echo " INFER"
	unic infer -r . -x _build -x vendors -x bin -x test \
		--prefer digestif.c --prefer mnet.ethernet \
		-o _mfetch

vendors: _mfetch
	@echo " FETCH"
	mfetch -q

wgd.hvt.target: | vendors
	@echo " BUILD unikernel/wgd.exe"
	@dune build --root . --profile=release --workspace=dune-workspace.wg ./unikernel/wgd.exe
	@echo " DESCR unikernel/wgd.exe"
	@$(shell dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
    --workspace=dune-workspace.wg \
		./unikernel/wgd.exe 1> $@ 2>&1)

wg.hvt.target: | vendors
	@echo " BUILD unikernel/wg.exe"
	@dune build --root . --profile=release --workspace=dune-workspace.wg ./unikernel/wg.exe
	@echo " DESCR unikernel/wg.exe"
	@$(shell dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
    --workspace=dune-workspace.wg \
		./unikernel/wg.exe 1> $@ 2>&1)

wgd.hvt: wgd.hvt.target
	@echo " COPY wgd.hvt"
	@cp $(file < wgd.hvt.target) $@
	@chmod +w $@
	@echo " STRIP wgd.hvt"
	@strip $@

wg.hvt: wg.hvt.target
	@echo " COPY wg.hvt"
	@cp $(file < wg.hvt.target) $@
	@chmod +w $@
	@echo " STRIP wg.hvt"
	@strip $@

wg.install: wgd.hvt wg.hvt
	@echo " GEN wg.install"
	@ocaml install.ml > $@

all: wg.install | vendors

.PHONY: clean
clean:
	if [ -d vendors ] ; then rm -fr vendors ; fi
	rm -f wgd.hvt.target
	rm -f wgd.hvt
	rm -f wg.hvt.target
	rm -f wg.hvt
	rm -f wg.install

install: wg.install
	@echo " INSTALL wg"
	opam-installer wg.install
