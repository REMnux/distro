from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.slghsymbol
import ghidra.pcodeCPort.translate
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore


class SleighBase(ghidra.pcodeCPort.translate.Translate, NamedSymbolProvider):

    class_: typing.ClassVar[java.lang.Class]
    MAX_UNIQUE_SIZE: typing.Final = 128
    """
    Note: The value of :obj:`.MAX_UNIQUE_SIZE`  must match the corresponding value
    defined by sleighbase.cc
    """


    def __init__(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def findSymbol(self, id: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.slghsymbol.SleighSymbol:
        ...

    def isInitialized(self) -> bool:
        ...

    @property
    def initialized(self) -> jpype.JBoolean:
        ...


class address_set(generic.stl.SetSTL[ghidra.pcodeCPort.slghsymbol.VarnodeSymbol]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class NamedSymbolProvider(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def findSymbol(self, nm: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SleighSymbol:
        ...


@typing.type_check_only
class VarnodeSymbolCompare(java.util.Comparator[ghidra.pcodeCPort.slghsymbol.VarnodeSymbol]):

    class_: typing.ClassVar[java.lang.Class]

    def compare(self, op1: ghidra.pcodeCPort.slghsymbol.VarnodeSymbol, op2: ghidra.pcodeCPort.slghsymbol.VarnodeSymbol) -> int:
        ...



__all__ = ["SleighBase", "address_set", "NamedSymbolProvider", "VarnodeSymbolCompare"]
