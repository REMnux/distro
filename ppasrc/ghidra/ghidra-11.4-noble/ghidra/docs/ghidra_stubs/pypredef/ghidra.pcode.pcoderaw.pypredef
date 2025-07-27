from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.opbehavior
import ghidra.program.model.address
import ghidra.program.model.pcode


class PcodeOpRaw(ghidra.program.model.pcode.PcodeOp):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getBehavior(self) -> ghidra.pcode.opbehavior.OpBehavior:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def behavior(self) -> ghidra.pcode.opbehavior.OpBehavior:
        ...



__all__ = ["PcodeOpRaw"]
