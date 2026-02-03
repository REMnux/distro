#! /usr/bin/env bash
## vim:set ts=4 sw=4 et:
set -e; set -o pipefail
argv0=$0; argv0abs=$(readlink -fn "$argv0"); argv0dir=$(dirname "$argv0abs")

#
# Copyright (C) Markus Franz Xaver Johannes Oberhumer
#
# test file system behaviour with symlinks; requires:
#   $upx_exe                (required, but with convenience fallback "./upx")
# optional settings:
#   $upx_exe_runner         (e.g. "qemu-x86_64 -cpu Nehalem" or "valgrind")
#   $upx_test_file
#

# IMPORTANT NOTE: this script only works on Unix
# IMPORTANT NOTE: do NOT run as user root!
umask 0022

# disable on macOS for now, see https://github.com/upx/upx/issues/612
if [[ "$(uname)" == Darwin ]]; then
    case "$UPX_DEBUG_FORCE_PACK_MACOS" in
        "" | "0") echo "$0: SKIPPED"; exit 0 ;;
    esac
fi

id || true
echo "PWD='$PWD'"
if [[ $UID == 0 || $EUID == 0 ]]; then
    echo "ERROR: do not run as root: UID=$UID EUID=$EUID"
    exit 91
fi

#***********************************************************************
# init & checks
#***********************************************************************

# upx_exe
[[ -z $upx_exe && -f ./upx && -x ./upx ]] && upx_exe=./upx # convenience fallback
if [[ -z $upx_exe ]]; then echo "UPX-ERROR: please set \$upx_exe"; exit 1; fi
if [[ ! -f $upx_exe ]]; then echo "UPX-ERROR: file '$upx_exe' does not exist"; exit 1; fi
upx_exe=$(readlink -fn "$upx_exe") # make absolute
[[ -f $upx_exe ]] || exit 1

# set emu and run_upx
emu=()
if [[ -n $upx_exe_runner ]]; then
    # usage examples:
    #   export upx_exe_runner="qemu-x86_64 -cpu Nehalem"
    #   export upx_exe_runner="valgrind --leak-check=no --error-exitcode=1 --quiet"
    #   export upx_exe_runner="wine"
    IFS=' ' read -r -a emu <<< "$upx_exe_runner" # split at spaces into array
elif [[ -n $CMAKE_CROSSCOMPILING_EMULATOR ]]; then
    IFS=';' read -r -a emu <<< "$CMAKE_CROSSCOMPILING_EMULATOR" # split at semicolons into array
fi
run_upx=( "${emu[@]}" "$upx_exe" )
echo "run_upx='${run_upx[*]}'"

# run_upx sanity check
if ! "${run_upx[@]}" --version-short >/dev/null; then echo "UPX-ERROR: FATAL: upx --version-short FAILED"; exit 1; fi
if ! "${run_upx[@]}" -L >/dev/null 2>&1; then echo "UPX-ERROR: FATAL: upx -L FAILED"; exit 1; fi
if ! "${run_upx[@]}" --help >/dev/null;  then echo "UPX-ERROR: FATAL: upx --help FAILED"; exit 1; fi

#***********************************************************************
# util functions
#***********************************************************************

exit_code=0
num_errors=0
all_errors=

failed() {
    ####exit $1
    # log error and keep going
    exit_code=1
    local a="$(basename "$(dirname "$PWD")")"
    local b="$(basename "$PWD")"
    let num_errors+=1 || true
    all_errors="${all_errors} $a/$b/$1"
    echo "    FAILED $b/$1"
}

assert_file() {
    local f
    for f in "$@"; do
        [[ ! -L "$f" && -f "$f" ]] && continue
        echo "failed '$f': not a regular file"
        failed 21
    done
}

assert_symlink_to_file() {
    local f
    for f in "$@"; do
        [[ -L "$f" && -f "$f" ]] && continue
        echo "failed '$f': not a symlink to file"
        failed 22
    done
}

assert_symlink_to_dir() {
    local f
    for f in "$@"; do
        [[ -L "$f" && -d "$f" ]] && continue
        echo "failed '$f': not a symlink to dir"
        failed 23
    done
}

assert_symlink_dangling() {
    local f
    for f in "$@"; do
        [[ -L "$f" && ! -e "$f" ]] && continue
        echo "failed '$f': not a dangling symlink"
        failed 24
    done
}

copy_directory() {
    if command -v rsync >/dev/null; then
        rsync -aH "$1/" "$2"
    else
        cp -ai "$1" "$2"
    fi
}

create_files() {
    # clean
    local d
    for d in z_dir_1 z_dir_2 z_dir_3 z_dir_4; do
        if [[ -d $d ]]; then
            chmod -R +rwx "./$d"
            rm -rf "./$d"
        fi
    done

    mkdir z_dir_1
    cd z_dir_1
    : > z_file
    ln -s z_file z_symlink_file
    : > z_file_link_1
    ln z_file_link_1 z_file_link_2
    ln -s z_file_link_1 z_symlink_file_link
    mkdir z_dir
    ln -s z_dir z_symlink_dir
    ln -s z_file_missing z_symlink_dangling
    assert_file             z_file*
    assert_symlink_to_file  z_symlink_file
    assert_symlink_to_dir   z_symlink_dir
    assert_symlink_dangling z_symlink_dangling
    cd ..

    # write-protect z_dir_2/z_file*
    copy_directory z_dir_1 z_dir_2
    chmod a-w z_dir_2/z_file*

    # write-protect z_dir_3 itself
    copy_directory z_dir_1 z_dir_3
    chmod a-w z_dir_3

    # write-protect everything in z_dir_4
    copy_directory z_dir_1 z_dir_4
    chmod -R a-w z_dir_4
}

print_header() {
    local x='==========='; x="$x$x$x$x$x$x$x"
    echo -e "\n${x}\n${1}\n${x}\n"
}

enter_dir() {
    cd "$1" || exit 1
    echo "===== $(basename "$PWD")"
}
leave_dir() {
    echo "===== $(basename "$PWD") files"
    ls -lA
    cd ..
}

#***********************************************************************
# setup
#***********************************************************************

#set -x # debug

export UPX="--prefer-ucl --no-color --no-progress"
export UPX_DEBUG_DISABLE_GITREV_WARNING=1
export UPX_DEBUG_DOCTEST_DISABLE=1 # already checked above

# get $test_file
if [[ -f $upx_test_file ]]; then
    test_file="$(readlink -fn "$upx_test_file")"
else
    for test_file in /usr/bin/gmake /usr/bin/make /usr/bin/env /bin/ls; do
        if [[ -f $test_file ]]; then
            test_file="$(readlink -fn "$test_file")"
            break
        fi
    done
fi
ls -l "$test_file"
file "$test_file" || true

# create and enter a tmpdir in the current directory
tmpdir="$(mktemp -d tmp-upx-test-XXXXXX)"
cd "./$tmpdir" || exit 1

#***********************************************************************
# default
#***********************************************************************

print_header "default"
flags="-qq -2 --no-filter"
mkdir default
cd default
create_files
enter_dir z_dir_1
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          || failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              && failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       && failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      && failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link && failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
enter_dir z_dir_2
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          || failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              && failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       && failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      && failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link && failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
enter_dir z_dir_3
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          && failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              && failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       && failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      && failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link && failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
enter_dir z_dir_4
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          && failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              && failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       && failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      && failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link && failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
cd ..

#***********************************************************************
# force-overwrite
#***********************************************************************

print_header "force-overwrite"
flags="-qq -2 --no-filter --force-overwrite"
mkdir force-overwrite
cd force-overwrite
create_files
enter_dir z_dir_1
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          || failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              || failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       || failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       || failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  || failed 18
assert_file z_symlink_file z_symlink_file_link
assert_file z_symlink_dir
assert_file z_symlink_dangling
leave_dir
enter_dir z_dir_2
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          || failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              || failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       || failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       || failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  || failed 18
assert_file z_symlink_file z_symlink_file_link
assert_file z_symlink_dir
assert_file z_symlink_dangling
leave_dir
enter_dir z_dir_3
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          && failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              || failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       || failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
enter_dir z_dir_4
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          && failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              || failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       || failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
cd ..

#***********************************************************************
# link
#***********************************************************************

print_header "link"
flags="-qq -2 --no-filter --link"
mkdir link
cd link
create_files
enter_dir z_dir_1
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          || failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              || failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       || failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       || failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  || failed 18
assert_file z_symlink_file z_symlink_file_link
assert_file z_symlink_dir
assert_file z_symlink_dangling
leave_dir
enter_dir z_dir_2
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          || failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              && failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       && failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       || failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  || failed 18
assert_file z_symlink_file z_symlink_file_link
assert_file z_symlink_dir
assert_file z_symlink_dangling
leave_dir
enter_dir z_dir_3
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          && failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              || failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       || failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
enter_dir z_dir_4
"${run_upx[@]}" $flags                 z_symlink_file      && failed 10
"${run_upx[@]}" $flags "$test_file" -o z_file_new          && failed 11
"${run_upx[@]}" $flags "$test_file" -o z_dir               && failed 12
"${run_upx[@]}" $flags "$test_file" -o z_file              && failed 13
"${run_upx[@]}" $flags "$test_file" -o z_file_link_1       && failed 14
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file      || failed 15
"${run_upx[@]}" $flags "$test_file" -o z_symlink_file_link || failed 16
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dir       && failed 17
"${run_upx[@]}" $flags "$test_file" -o z_symlink_dangling  && failed 18
assert_symlink_to_file  z_symlink_file z_symlink_file_link
assert_symlink_to_dir   z_symlink_dir
assert_symlink_dangling z_symlink_dangling
leave_dir
cd ..

#***********************************************************************
# done
#***********************************************************************

# clean up
cd ..
chmod -R +rwx "./$tmpdir"
rm -rf "./$tmpdir"

if [[ $exit_code == 0 ]]; then
    echo "UPX testsuite passed. All done."
else
    echo "UPX-ERROR: UPX testsuite FAILED:${all_errors}"
    echo "UPX-ERROR: UPX testsuite FAILED with $num_errors error(s). See log file."
fi
exit $exit_code
