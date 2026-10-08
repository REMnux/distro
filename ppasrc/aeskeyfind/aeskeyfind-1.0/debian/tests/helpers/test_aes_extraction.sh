#!/bin/sh

################################################################
# Usage:                                                       #
#     test_aes_extraction <KEY> <IV>                       #
#                                                              #
# Example:                                                     #
#     test_aes_extraction "DebianDebianDebi" "aaaabbbbccccdddd"#
#                                                              #
#                                                              #
# Note: Use either 16, 24 or 32 byte long keys and IVs.        #
################################################################

# Exit on first failure
set -e

# Converts a ASCII string to its hex representation
str2hex() {
    echo "$1" | sed 's/\(.\)/\1\n/g' | \
	xargs -I {} printf "%x" "'{}"
}

# Path of the script, which is used to create AES keys
# and dump the memory of the process performing AES construction
GEN_DUMP="debian/tests/helpers/gen_aes_dump.sh"


# Defines the AES key-material, used to generate the dump
# and to serve as target value for the extraction
if [ -z "$1" ]
then
    echo "No key provided!"
    exit 1
fi

KEY="$1"

# Combination of the parameters to feed into the script
if [ -z "$2" ]
then
    KEYSPEC="KEY=$1"
else
    KEYSPEC="KEY=$1\nIV=$2"
fi

# Memory dump to process
DMP="${AUTOPKGTEST_TMP}/aes.dmp"

# Dump memory of process, which generates key material
sh ${GEN_DUMP} "$KEYSPEC" "$DMP"

# Previous bug fixed in the past which might trigger again:
# https://bugs.debian.org/989179
ACTUAL=$(aeskeyfind "${DMP}")

# Checks, compare actual result with target values
echo "${ACTUAL}" | grep -q $(str2hex "${KEY}")

# Clean up
rm ${DMP}

exit 0
