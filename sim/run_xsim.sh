#!/usr/bin/env bash
# Mô phỏng bằng Vivado xsim:  sim/run_xsim.sh {core|sign}
# Cần: xvlog/xelab/xsim trong PATH, và test vector (make vectors).
set -euo pipefail

# Testbench và RTL dùng đường dẫn .dat tương đối so với repo root.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TB="${1:-core}"
case "$TB" in
core) TOP=tb_core;         RTL_TOP=src/rtl/ed25519_sign_core.v ;;
sign) TOP=tb_ed25519_sign; RTL_TOP=src/rtl/ed25519_sign.v ;;
*)    echo "Usage: $0 {core|sign}"; exit 1 ;;
esac

if [ -d src/rtl/scalar_mult ]; then
  # Bản FPGA (phân cấp): file top tự `include các module con,
  # MULT_MACRO lấy từ thư viện Xilinx.
  INC=$(find src/rtl -type d -printf '-i %p ')
  RTL="$RTL_TOP $(dirname "$(command -v xvlog)")/../data/verilog/src/glbl.v"
  ELAB="-L unimacro_ver -L unisims_ver -L secureip work.glbl"
else
  # Bản ASIC (phẳng): không có `include, MULT_MACRO là model hành vi
  # trong mult_units_512.v.
  INC=""
  RTL="src/rtl/bram_253.v src/rtl/bram_255.v src/rtl/bram_256.v src/rtl/bram_512.v \
       src/rtl/precomp_rom.v src/rtl/mult_units_512.v src/rtl/ed25519_sign_core.v"
  [ "$TB" = sign ] && RTL="$RTL src/rtl/ed25519_sign.v"
  ELAB=""
fi

xvlog --nolog $INC $RTL "src/tb/$TOP.v"
xelab --nolog --timescale 1ns/1ps "work.$TOP" $ELAB -s "${TOP}_sim"
xsim "${TOP}_sim" --nolog -R
