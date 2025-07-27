from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcodeCPort.address
import ghidra.pcodeCPort.space
import java.lang # type: ignore


class VarnodeData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    space: ghidra.pcodeCPort.space.AddrSpace
    offset: jpype.JLong
    size: jpype.JInt

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, base: ghidra.pcodeCPort.space.AddrSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        ...

    def compareTo(self, other: VarnodeData) -> int:
        ...

    def getAddress(self) -> ghidra.pcodeCPort.address.Address:
        ...

    @property
    def address(self) -> ghidra.pcodeCPort.address.Address:
        ...



__all__ = ["VarnodeData"]
