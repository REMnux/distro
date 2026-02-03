#! /usr/bin/env bash
## vim:set ts=4 sw=4 et:
set -e; set -o pipefail
argv0=$0; argv0abs=$(readlink -fn "$argv0"); argv0dir=$(dirname "$argv0abs")

#
# Copyright (C) Markus Franz Xaver Johannes Oberhumer
#
# mimic running "ctest", i.e. the "test" section of CMakeLists.txt
#   - does not redirect stdout
#   - allows freely setting $upx_exe_runner, while CMake is restricted to configure-time settings
#
# requires:
#   $upx_exe                (required, but with convenience fallback "./upx")
# optional settings:
#   $upx_exe_runner         (e.g. "qemu-x86_64 -cpu Nehalem" or "valgrind")
#

cat >catch-sigsegv.gdb <<'EOF'
catch signal SIGSEGV
commands
    x/i $pc
    info reg
    x/32i $pc-0x20
    quit 77
end
EOF

catcher=$(readlink -fn catch-sigsegv.gdb)

function emu_gdb() {
    gdb -q -x "$catcher" <<EOF --args "$@"
    run
EOF
}

if [[ -n $upx_exe_runner ]]; then
    true
elif [[ -n $CMAKE_CROSSCOMPILING_EMULATOR ]]; then
    true
else
    upx_exe_runner=emu_gdb
    : ${upx_run_packed_test_count:=20}
fi

source "$argv0dir/mimic_ctest.sh"
