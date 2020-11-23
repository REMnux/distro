#!/usr/bin/python3
#coding=UTF-8

from os import unlink, sep, listdir
from os.path import join, isdir, exists
from shutil import rmtree
from re import search

dirs = [X for X in
    ["CMakeFiles",
    "Debug",
    "Release",
    "x64",
    "x86",
    join("src", "CMakeFiles"),
    join("src", "Debug"),
    join("src", "Release"),
    join("src", "x64"),
    join("src", "x86"),
    join("src", "nsrllookup.dir"),
    join("man1", "CMakeFiles"),
    ".vs"] if exists(X) and isdir(X)]

all_files = listdir() + \
    [join("src", X) for X in listdir("src")] + \
    [join("man1", X) for X in listdir("man1")]

files = [X for X in all_files if search("vcxproj", X)] +\
    [X for X in all_files if search("CMakeCache.txt", X)] +\
    [X for X in all_files if search(r"CPack.*Config\.cmake$", X)] +\
    [X for X in all_files if search(r"cmake_install.cmake$", X)] +\
    [X for X in all_files if search(r"\.sln$", X)] +\
    [X for X in all_files if search(r"\.o$", X)] +\
    [X for X in all_files if search(r"\.obj$", X)] +\
    [X for X in all_files if search(r"\.VC.db", X)]

[rmtree(X) for X in dirs]
[unlink(X) for X in files]
