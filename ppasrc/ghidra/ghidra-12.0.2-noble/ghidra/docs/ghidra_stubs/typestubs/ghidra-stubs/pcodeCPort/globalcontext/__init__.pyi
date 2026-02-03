from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcodeCPort.pcoderaw
import java.lang # type: ignore


class TrackedContext(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    loc: ghidra.pcodeCPort.pcoderaw.VarnodeData
    val: jpype.JLong

    def __init__(self):
        ...


class ContextBitRange(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sbit: typing.Union[jpype.JInt, int], ebit: typing.Union[jpype.JInt, int]):
        ...

    def getValue(self, vec: jpype.JArray[jpype.JInt]) -> int:
        ...

    def setValue(self, vec: jpype.JArray[jpype.JInt], val: typing.Union[jpype.JInt, int]):
        ...

    @property
    def value(self) -> jpype.JInt:
        ...



__all__ = ["TrackedContext", "ContextBitRange"]
