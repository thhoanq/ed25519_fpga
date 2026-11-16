.PHONY: sim core sign vectors clean

sim: core

core:
	./sim/run_xsim.sh core

sign:
	./sim/run_xsim.sh sign

vectors:
	cd src/model && python gensigs.py

clean:
	rm -rf xsim.dir .Xil *.pb *.jou *.wdb *.log webtalk*
