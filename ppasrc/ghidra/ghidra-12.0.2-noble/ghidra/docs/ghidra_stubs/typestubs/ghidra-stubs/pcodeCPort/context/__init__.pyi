from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.error
import ghidra.pcodeCPort.slghsymbol
import ghidra.pcodeCPort.space
import ghidra.sleigh.grammar
import java.lang # type: ignore


class FixedHandle(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    space: ghidra.pcodeCPort.space.AddrSpace
    size: jpype.JInt
    offset_space: ghidra.pcodeCPort.space.AddrSpace
    offset_offset: jpype.JLong
    offset_size: jpype.JInt
    temp_space: ghidra.pcodeCPort.space.AddrSpace
    temp_offset: jpype.JLong

    def __init__(self):
        ...


class ContextSet(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    sym: ghidra.pcodeCPort.slghsymbol.TripleSymbol
    point: ConstructState
    num: jpype.JInt
    mask: jpype.JInt
    value: jpype.JInt
    flow: jpype.JBoolean

    def __init__(self):
        ...


class ConstructState(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    ct: ghidra.pcodeCPort.slghsymbol.Constructor
    hand: FixedHandle
    resolve: generic.stl.VectorSTL[ConstructState]
    parent: ConstructState
    length: jpype.JInt
    offset: jpype.JInt
    oper: jpype.JInt

    def __init__(self):
        ...


class Token(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, nm: typing.Union[java.lang.String, str], sz: typing.Union[jpype.JInt, int], be: typing.Union[jpype.JBoolean, bool], ind: typing.Union[jpype.JInt, int]):
        ...

    def getIndex(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getSize(self) -> int:
        ...

    def isBigEndian(self) -> bool:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class SleighError(ghidra.pcodeCPort.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, string: typing.Union[java.lang.String, str], location: ghidra.sleigh.grammar.Location):
        ...



__all__ = ["FixedHandle", "ContextSet", "ConstructState", "Token", "SleighError"]
