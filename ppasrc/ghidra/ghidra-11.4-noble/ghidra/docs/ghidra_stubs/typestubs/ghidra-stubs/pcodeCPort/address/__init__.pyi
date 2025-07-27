from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.space
import ghidra.pcodeCPort.translate
import java.io # type: ignore
import java.lang # type: ignore


class AddressUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def unsignedAdd(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def unsignedCompare(v1: typing.Union[jpype.JLong, int], v2: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def unsignedSubtract(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...


class Address(java.lang.Comparable[Address]):

    class mach_extreme(java.lang.Enum[Address.mach_extreme]):

        class_: typing.ClassVar[java.lang.Class]
        m_minimal: typing.Final[Address.mach_extreme]
        m_maximal: typing.Final[Address.mach_extreme]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Address.mach_extreme:
            ...

        @staticmethod
        def values() -> jpype.JArray[Address.mach_extreme]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, id: ghidra.pcodeCPort.space.AddrSpace, off: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, addr: Address):
        ...

    @typing.overload
    def __init__(self, ex: Address.mach_extreme):
        ...

    def add(self, off: typing.Union[jpype.JLong, int]) -> Address:
        ...

    def endianContain(self, sz: typing.Union[jpype.JInt, int], op2: Address, sz2: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def getAddrSize(self) -> int:
        ...

    def getOffset(self) -> int:
        ...

    def getShortcut(self) -> str:
        ...

    def getSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @staticmethod
    def getSpaceFromConst(addr: Address) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def isBigEndian(self) -> bool:
        ...

    def isConstant(self) -> bool:
        ...

    def isInvalid(self) -> bool:
        ...

    def overlap(self, skip: typing.Union[jpype.JInt, int], op: Address, size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def printRaw(self, s: java.io.PrintStream) -> int:
        ...

    def sub(self, off: typing.Union[jpype.JLong, int]) -> Address:
        ...

    def subtract(self, off: typing.Union[jpype.JLong, int]) -> Address:
        ...

    def toPhysical(self):
        ...

    def toString(self, showAddressSpace: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def addrSize(self) -> jpype.JInt:
        ...

    @property
    def constant(self) -> jpype.JBoolean:
        ...

    @property
    def shortcut(self) -> jpype.JChar:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def space(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...


class RangeList(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, rangeList: RangeList):
        ...

    @typing.overload
    def __init__(self):
        ...

    def begin(self) -> generic.stl.IteratorSTL[Range]:
        ...

    def clear(self):
        ...

    def empty(self) -> bool:
        ...

    def end(self) -> generic.stl.IteratorSTL[Range]:
        ...

    @typing.overload
    def getFirstRange(self) -> Range:
        ...

    @typing.overload
    def getFirstRange(self, spaceid: ghidra.pcodeCPort.space.AddrSpace) -> Range:
        ...

    @typing.overload
    def getLastRange(self) -> Range:
        ...

    @typing.overload
    def getLastRange(self, spaceid: ghidra.pcodeCPort.space.AddrSpace) -> Range:
        ...

    def inRange(self, addr: Address, size: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def insertRange(self, spc: ghidra.pcodeCPort.space.AddrSpace, first: typing.Union[jpype.JLong, int], last: typing.Union[jpype.JLong, int]):
        ...

    def longestFit(self, addr: Address, maxsize: typing.Union[jpype.JLong, int]) -> int:
        ...

    def printBounds(self, s: java.io.PrintStream):
        ...

    def removeRange(self, spc: ghidra.pcodeCPort.space.AddrSpace, first: typing.Union[jpype.JLong, int], last: typing.Union[jpype.JLong, int]):
        ...

    @property
    def lastRange(self) -> Range:
        ...

    @property
    def firstRange(self) -> Range:
        ...


class Range(java.lang.Comparable[Range]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, s: ghidra.pcodeCPort.space.AddrSpace, f: typing.Union[jpype.JLong, int], l: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self):
        ...

    def getFirst(self) -> int:
        ...

    def getFirstAddr(self) -> Address:
        ...

    def getLast(self) -> int:
        ...

    def getLastAddr(self) -> Address:
        ...

    def getLastAddrOpen(self, trans: ghidra.pcodeCPort.translate.Translate) -> Address:
        ...

    def getSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def lastAddrOpen(self) -> Address:
        ...

    @property
    def last(self) -> jpype.JLong:
        ...

    @property
    def firstAddr(self) -> Address:
        ...

    @property
    def lastAddr(self) -> Address:
        ...

    @property
    def space(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def first(self) -> jpype.JLong:
        ...



__all__ = ["AddressUtils", "Address", "RangeList", "Range"]
