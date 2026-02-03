#! /usr/bin/env python3
## vim:set ts=4 sw=4 et: -*- coding: utf-8 -*-

# simulate "readlink -fn FILE" for systems that lack it (e.g. macOS-11)
# - result may differ from actual readlink(1) for edge cases
# - works with Python2 and Python3
#
# Copyright (C) Markus Franz Xaver Johannes Oberhumer

import os, sys
if len(sys.argv) != 2:
    sys.exit(1)
real_path = os.path.realpath(sys.argv[1])
sys.stdout.write(real_path)
sys.stdout.flush()
