# Contributing

I welcome your pull requests.  However, I'm a stickler for detail.

1.  Never use a compiler-specific feature when the C++ Standard Library can do the job.
2.  Use Boost and the Standard Library rather than rolling your own solutions.
3.  Run your code through `clang-format`.  (See `src/format.sh` for how.)
4.  Minimize OS-specific code.
5.  Simplify, simplify, simplify!
6.  On Windows, ensure everything can be statically linked.
7.  If it doesn't compile cleanly on GCC, Clang++, and MSVC++, it won't be accepted.
8.  Thou shalt not use naked pointers or unchecked buffer access.
9.  Thou shalt not manage thine own memory.