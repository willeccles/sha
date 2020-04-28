# SHA Programs

This repository is a collection of basic SHA programs in C written for a cryptography paper.

## Usage

```
$ ./shaXXX.out "mymessage"
```

## Bugs

SHA-512 uses a 64-bit size integer instead of 128 as is specified in the standard. This is fine for these purposes.
