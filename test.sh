#! /bin/bash -e

if (( $# == 0 )); then
    >&2 echo "Please supply an argument: sha1, sha256, or sha512"
    >&2 echo "These are case-sensitive and must be lower-case!"
    exit 1
fi

if ! command -v "openssl" >/dev/null; then
    >&2 echo "This script uses openssl to compare correct hash values."
    >&2 echo "Please install it to continue."
    exit 1
fi

if [[ "$CC" == "" ]]; then
    >&2 echo "No environment variable \$CC found!"
    >&2 echo "Please set \$CC to your C compiler of choice and then run this script."
    exit 1
fi

echo "Compiling $1.c -> $1.out..."
$CC "$1.c" -o "$1.out" -O3 -Wall -W -pedantic

str=""

echo "Testing 512 hashes..."
for x in {1..512}; do
    str="a$str"
    out1="$("./$1.out" "$str")"
    out2="$(echo -n "$str" | openssl dgst -$1 -hex | cut -d' ' -f2)"
    if [[ "$out1" != "$out2" ]]; then
        >&2 echo "Failed with length $x!"
        >&2 echo "output: $out1"
        >&2 echo "real:   $out2"
        exit 1
    fi
done

echo "All test passed up to length 512!"
