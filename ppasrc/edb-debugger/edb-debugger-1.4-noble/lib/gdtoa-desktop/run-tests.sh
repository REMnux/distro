#!/bin/sh

inffix()
{
    sed 's/[Ii][Nn][Ff][intyINTY]*/Infinity/g'
}
checkXFailOrPass()
{
    local testOutFile="$1"
    if [ -f "$testsDir/obad/$testOutFile" ]; then
        if cmp -s "$bads/$testOutFile" "$testsDir/obad/$testOutFile"; then
            rm "$bads/$testOutFile"
            echo "XFAIL" >&2
        else
            echo "FAIL" >&2
        fi
    else
        echo "FAIL" >&2
    fi
}
compareWithReference()
{
    local testOutFile="$1.out"
    local testOutPath="$testsDir/$testOutFile"
    if [ "$1" = Q ] || [ "$1" = x ] || [ "$1" = xL ]; then
        testOutPath="$buildDir/$1.out"
    fi
    cmp -s "$testOutPath" zap || mv zap "$bads/$testOutFile"
    if ! [ -f "$bads/$testOutFile" ]; then
        echo "PASS" >&2
    else
        checkXFailOrPass "$testOutFile"
    fi
}

if [ -z "$2" ]; then
    echo "Usage: $0 testsSrcDir/ buildDir/" >&2
    exit 1
fi

testsDir="$1"
buildDir="$2"

cd "$buildDir" || exit
bads=tests-bad
rm -fr "$bads"
mkdir -p "$bads" || exit

echo -n "Testing dt..." >&2
cat "$testsDir"/testnos "$testsDir"/testnos1 | ./dt | inffix >zap 2>&1
compareWithReference dtst

echo -n "Testing dItest..." >&2
./dItest <"$testsDir"/testnos | inffix >zap 2>&1
compareWithReference dI

echo -n "Testing dItestsi..." >&2
./dItestsi <"$testsDir"/testnos | inffix >zap 2>&1
compareWithReference dIsi

echo -n "Testing ddtestsi..." >&2
./ddtestsi <"$testsDir"/testnos | inffix >zap 2>&1
compareWithReference ddsi

for i in dd d f x xL Q; do
    echo -n "Testing ${i}test..." >&2
    cat "$testsDir"/testnos "$testsDir"/rtestnos | ./"$i"test | inffix >zap 2>&1
    compareWithReference $i
done

echo -n "Testing strtodt..." >&2
cd "$testsDir" || exit
"$buildDir"/strtodt testnos3 >"$buildDir/$bads"/strtodt.out && rm "$buildDir/$bads"/strtodt.out
cd "$OLDPWD" || exit
if [ -f "$buildDir/$bads"/strtodt.out ]; then
    checkXFailOrPass strtodt.out
else
    echo "PASS" >&2
fi

echo -n "Testing strtodtnrp..." >&2
cd "$testsDir" || exit
"$buildDir"/strtodtnrp testnos3 >"$buildDir/$bads"/strtodtnrp.out && rm "$buildDir/$bads"/strtodtnrp.out
cd "$OLDPWD" || exit
if [ -f "$buildDir/$bads"/strtodtnrp.out ]; then
    checkXFailOrPass strtodtnrp.out
else
    echo "PASS" >&2
fi

if ! rmdir "$bads" 2>/dev/null; then
    cd "$bads"
    for i in *; do
        cmp -s $i "$testsDir/test/obad/$i" && rm $i
    done
    cd ..
    if ! rmdir "$bads" 2>/dev/null; then
        echo >&2
        echo " ** $(ls "$bads" | wc -l) tests FAILED" >&2
        echo " Details for failed tests are in $PWD/$bads" >&2
        echo " Reference test results are in   $testsDir" >&2
        echo >&2
        exit 1
    fi
fi
exit 0
