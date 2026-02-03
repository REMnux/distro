from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcodeCPort.translate
import ghidra.program.model.pcode
import java.io # type: ignore
import java.lang # type: ignore


class spacetype(java.lang.Enum[spacetype]):

    class_: typing.ClassVar[java.lang.Class]
    IPTR_CONSTANT: typing.Final[spacetype]
    IPTR_PROCESSOR: typing.Final[spacetype]
    IPTR_SPACEBASE: typing.Final[spacetype]
    IPTR_INTERNAL: typing.Final[spacetype]
    IPTR_FSPEC: typing.Final[spacetype]
    IPTR_IOP: typing.Final[spacetype]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> spacetype:
        ...

    @staticmethod
    def values() -> jpype.JArray[spacetype]:
        ...


class AddrSpace(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MIN_SPACE: typing.Final[AddrSpace]
    MAX_SPACE: typing.Final[AddrSpace]
    hasphysical: typing.Final = 256

    @typing.overload
    def __init__(self, t: ghidra.pcodeCPort.translate.Translate, tp: spacetype, nm: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], ws: typing.Union[jpype.JInt, int], ind: typing.Union[jpype.JInt, int], fl: typing.Union[jpype.JInt, int], dl: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, t: ghidra.pcodeCPort.translate.Translate, tp: spacetype):
        ...

    def compareTo(self, base: AddrSpace) -> int:
        ...

    def contain(self, id2: AddrSpace) -> bool:
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getAddrSize(self) -> int:
        ...

    def getContain(self) -> AddrSpace:
        ...

    def getDelay(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getMask(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getScale(self) -> int:
        ...

    def getShortCut(self) -> str:
        ...

    def getTrans(self) -> ghidra.pcodeCPort.translate.Translate:
        ...

    def getType(self) -> spacetype:
        ...

    def getWordSize(self) -> int:
        ...

    def hasPhysical(self) -> bool:
        ...

    def isBigEndian(self) -> bool:
        ...

    def isHeritaged(self) -> bool:
        ...

    def isOtherSpace(self) -> bool:
        ...

    def printOffset(self, s: java.io.PrintStream, offset: typing.Union[jpype.JLong, int]):
        ...

    def printRaw(self, s: java.io.PrintStream, offset: typing.Union[jpype.JLong, int]) -> int:
        ...

    def toString(self, offset: typing.Union[jpype.JLong, int]) -> str:
        ...

    def wrapOffset(self, off: typing.Union[jpype.JLong, int]) -> int:
        ...

    @property
    def addrSize(self) -> jpype.JInt:
        ...

    @property
    def heritaged(self) -> jpype.JBoolean:
        ...

    @property
    def scale(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> spacetype:
        ...

    @property
    def otherSpace(self) -> jpype.JBoolean:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def shortCut(self) -> jpype.JChar:
        ...

    @property
    def delay(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def wordSize(self) -> jpype.JInt:
        ...

    @property
    def trans(self) -> ghidra.pcodeCPort.translate.Translate:
        ...

    @property
    def mask(self) -> jpype.JLong:
        ...


class OtherSpace(AddrSpace):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, t: ghidra.pcodeCPort.translate.Translate, nm: typing.Union[java.lang.String, str], ind: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, t: ghidra.pcodeCPort.translate.Translate):
        ...


class UniqueSpace(AddrSpace):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, t: ghidra.pcodeCPort.translate.Translate, ind: typing.Union[jpype.JInt, int], fl: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, t: ghidra.pcodeCPort.translate.Translate):
        ...


class ConstantSpace(AddrSpace):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, t: ghidra.pcodeCPort.translate.Translate):
        ...



__all__ = ["spacetype", "AddrSpace", "OtherSpace", "UniqueSpace", "ConstantSpace"]
