# HOL-4 Script for Mac-in-the-box (MITB)

Some words of how this is organized:

## MITB itself


The specification is in `mitbScript.sml`, in `MITB_STEP_def`. 
`PROTO_def` in `mitbScript.sml` defines the behaviour for a single
communication step, more or less what a library using the MITB would use.

The communication model for the security propert is in `uccomScript.sml` and
follows the Universal Composability framework by Canetti.

The sponge construction used is defined in `spongeScript.sml`.

## What about Keccak's permutation?

The proof of security for the MITB is independent of the permutation used, how
ever, I once planned to translate this to CakeML. Hence an implementation of
the permutation is defined in 
`keccak_funScript.sml`, in `permutation_def`.

Weirdly, the specification was once done in terms of SML code, in
`keccak.sml`, in `permutation1600`. The goal was once to
rewrite this in HOL in the file `keccakpermutationScript.sml`, but this is incomplete.
The types don't match the current
model. The type of the permutation in the spec will be:
```
( ('r+'c) word -> ('r+'c) word)
```
with r = 1151 and c = 448.
The type of the implementation will be whatver represents 1600 bits well enough.

When in doubt, the SML-Code of the specification is correct, because I've validated
it with the official test vectors.
