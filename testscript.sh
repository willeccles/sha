#! /bin/bash -e

str=""

for x in {1..512}; do
    str="a$str"
    out1="$(./a.out "$str")"
    out2="$(echo -n "$str" | openssl dgst -sha1 -hex | cut -d' ' -f2)"
    if [[ "$out1" != "$out2" ]]; then
        >&2 echo "Failed with length $x!"
        >&2 echo "output: $out1"
        >&2 echo "real:   $out2"
        exit 1
    fi
done

echo "All test passed up to length 512!"
