from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.mem
import java.lang # type: ignore


class EntropyCalculate(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, b: ghidra.program.model.mem.MemoryBlock, csize: typing.Union[jpype.JInt, int]):
        ...

    def getValue(self, offset: typing.Union[jpype.JInt, int]) -> int:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...



__all__ = ["EntropyCalculate"]
