#!/bin/sh

# $1 = key specification as multiline string
# $2 = dump file to store process memory

GEN_SCRIPT="debian/tests/helpers/gen_aes_key.py"

# Spawns subshell running the key generation script
(echo "$1" | python3 "${GEN_SCRIPT}") &

# Sleep to retrieve the PID of the child process reliably
sleep .3

PID=$(pgrep -f "python3 ${GEN_SCRIPT}")

#gcore -o"$3" ${PID} > /dev/null 2>&1
# Dumps memory
grep rw-p /proc/${PID}/maps | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1\t\2/p' \
| while read start stop;
    do gdb --batch --pid ${PID} -ex "append memory $2 0x$start 0x$stop" > /dev/null 2>&1;
done

# Terminates key generation script
kill -9 ${PID}
