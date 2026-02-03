from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.disassemble
import java.lang # type: ignore


class ArmDisassemblyInject(ghidra.app.plugin.core.debug.disassemble.DisassemblyInject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ArmDisassemblyInject"]
