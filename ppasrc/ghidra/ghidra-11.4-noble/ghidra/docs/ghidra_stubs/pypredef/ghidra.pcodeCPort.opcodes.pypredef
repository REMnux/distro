from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


class OpCode(java.lang.Enum[OpCode]):

    class_: typing.ClassVar[java.lang.Class]
    DO_NOT_USE_ME_I_AM_ENUM_ELEMENT_ZERO: typing.Final[OpCode]
    CPUI_COPY: typing.Final[OpCode]
    CPUI_LOAD: typing.Final[OpCode]
    CPUI_STORE: typing.Final[OpCode]
    CPUI_BRANCH: typing.Final[OpCode]
    CPUI_CBRANCH: typing.Final[OpCode]
    CPUI_BRANCHIND: typing.Final[OpCode]
    CPUI_CALL: typing.Final[OpCode]
    CPUI_CALLIND: typing.Final[OpCode]
    CPUI_CALLOTHER: typing.Final[OpCode]
    CPUI_RETURN: typing.Final[OpCode]
    CPUI_INT_EQUAL: typing.Final[OpCode]
    CPUI_INT_NOTEQUAL: typing.Final[OpCode]
    CPUI_INT_SLESS: typing.Final[OpCode]
    CPUI_INT_SLESSEQUAL: typing.Final[OpCode]
    CPUI_INT_LESS: typing.Final[OpCode]
    CPUI_INT_LESSEQUAL: typing.Final[OpCode]
    CPUI_INT_ZEXT: typing.Final[OpCode]
    CPUI_INT_SEXT: typing.Final[OpCode]
    CPUI_INT_ADD: typing.Final[OpCode]
    CPUI_INT_SUB: typing.Final[OpCode]
    CPUI_INT_CARRY: typing.Final[OpCode]
    CPUI_INT_SCARRY: typing.Final[OpCode]
    CPUI_INT_SBORROW: typing.Final[OpCode]
    CPUI_INT_2COMP: typing.Final[OpCode]
    CPUI_INT_NEGATE: typing.Final[OpCode]
    CPUI_INT_XOR: typing.Final[OpCode]
    CPUI_INT_AND: typing.Final[OpCode]
    CPUI_INT_OR: typing.Final[OpCode]
    CPUI_INT_LEFT: typing.Final[OpCode]
    CPUI_INT_RIGHT: typing.Final[OpCode]
    CPUI_INT_SRIGHT: typing.Final[OpCode]
    CPUI_INT_MULT: typing.Final[OpCode]
    CPUI_INT_DIV: typing.Final[OpCode]
    CPUI_INT_SDIV: typing.Final[OpCode]
    CPUI_INT_REM: typing.Final[OpCode]
    CPUI_INT_SREM: typing.Final[OpCode]
    CPUI_BOOL_NEGATE: typing.Final[OpCode]
    CPUI_BOOL_XOR: typing.Final[OpCode]
    CPUI_BOOL_AND: typing.Final[OpCode]
    CPUI_BOOL_OR: typing.Final[OpCode]
    CPUI_FLOAT_EQUAL: typing.Final[OpCode]
    CPUI_FLOAT_NOTEQUAL: typing.Final[OpCode]
    CPUI_FLOAT_LESS: typing.Final[OpCode]
    CPUI_FLOAT_LESSEQUAL: typing.Final[OpCode]
    CPUI_UNUSED1: typing.Final[OpCode]
    CPUI_FLOAT_NAN: typing.Final[OpCode]
    CPUI_FLOAT_ADD: typing.Final[OpCode]
    CPUI_FLOAT_DIV: typing.Final[OpCode]
    CPUI_FLOAT_MULT: typing.Final[OpCode]
    CPUI_FLOAT_SUB: typing.Final[OpCode]
    CPUI_FLOAT_NEG: typing.Final[OpCode]
    CPUI_FLOAT_ABS: typing.Final[OpCode]
    CPUI_FLOAT_SQRT: typing.Final[OpCode]
    CPUI_FLOAT_INT2FLOAT: typing.Final[OpCode]
    CPUI_FLOAT_FLOAT2FLOAT: typing.Final[OpCode]
    CPUI_FLOAT_TRUNC: typing.Final[OpCode]
    CPUI_FLOAT_CEIL: typing.Final[OpCode]
    CPUI_FLOAT_FLOOR: typing.Final[OpCode]
    CPUI_FLOAT_ROUND: typing.Final[OpCode]
    CPUI_MULTIEQUAL: typing.Final[OpCode]
    CPUI_INDIRECT: typing.Final[OpCode]
    CPUI_PIECE: typing.Final[OpCode]
    CPUI_SUBPIECE: typing.Final[OpCode]
    CPUI_CAST: typing.Final[OpCode]
    CPUI_PTRADD: typing.Final[OpCode]
    CPUI_PTRSUB: typing.Final[OpCode]
    CPUI_SEGMENTOP: typing.Final[OpCode]
    CPUI_CPOOLREF: typing.Final[OpCode]
    CPUI_NEW: typing.Final[OpCode]
    CPUI_INSERT: typing.Final[OpCode]
    CPUI_EXTRACT: typing.Final[OpCode]
    CPUI_POPCOUNT: typing.Final[OpCode]
    CPUI_LZCOUNT: typing.Final[OpCode]
    CPUI_MAX: typing.Final[OpCode]

    def getBooleanFlip(self) -> bool:
        ...

    def getName(self) -> str:
        ...

    def getOpCodeFlip(self) -> OpCode:
        ...

    @staticmethod
    def get_opcode(nm: typing.Union[java.lang.String, str]) -> OpCode:
        ...

    @staticmethod
    def get_opname(op: OpCode) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> OpCode:
        ...

    @staticmethod
    def values() -> jpype.JArray[OpCode]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def opCodeFlip(self) -> OpCode:
        ...

    @property
    def booleanFlip(self) -> jpype.JBoolean:
        ...



__all__ = ["OpCode"]
