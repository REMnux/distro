from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.trace.model
import javax.swing # type: ignore


class GAddressRangeField(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def setAddressFactory(self, factory: ghidra.program.model.address.AddressFactory):
        ...

    def setRange(self, range: ghidra.program.model.address.AddressRange):
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @range.setter
    def range(self, value: ghidra.program.model.address.AddressRange):
        ...


class GSpanField(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def setLifespan(self, lifespan: ghidra.trace.model.Lifespan):
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @lifespan.setter
    def lifespan(self, value: ghidra.trace.model.Lifespan):
        ...



__all__ = ["GAddressRangeField", "GSpanField"]
