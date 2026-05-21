from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.util
import java.lang # type: ignore


class FieldSearcher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getMatch(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getNextSignificantAddress(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def hasMatch(self, address: ghidra.program.model.address.Address) -> bool:
        ...

    @property
    def match(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def nextSignificantAddress(self) -> ghidra.program.model.address.Address:
        ...



__all__ = ["FieldSearcher"]
