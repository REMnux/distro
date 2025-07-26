#!/bin/sh

for x in *.cc *.hpp ; do clang-format -i --style=WebKit $x ; done
