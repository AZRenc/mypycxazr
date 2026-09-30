mypycxazr: Mypy to Python C Extension Compiler, with MyPyC-Protect
===================================================================

`mypycxazr` is the compiler package of this repository: the `mypyc` code
generator forked from mypy 1.18.2 and extended with the optional
**MyPyC-Protect** release-protection layer.

    $ python -m mypycxazr --protect=strong mymodule.py

It is the same code base as upstream mypyc; see the
[mypyc repository](https://github.com/mypyc/mypyc) for the original project
and its issue tracker. User documentation for the compiler itself lives in
this directory, while this fork's protection documentation lives in
[`../docs`](../docs).

Start with:

  * [`../docs/protection.md`](../docs/protection.md) — levels and features
  * [`../docs/security-model.md`](../docs/security-model.md) — what is and is
    not protected
  * [`../docs/benchmarks.md`](../docs/benchmarks.md) — how the measurements
    are taken
  * [`doc/dev-intro.md`](./doc/dev-intro.md) — compiler internals

Mypyc welcomes new contributors!
