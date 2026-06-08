from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.program.model.pcode
import java.lang # type: ignore


class PatternBlock(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, off: typing.Union[jpype.JInt, int], msk: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def __init__(self, tf: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @typing.overload
    def __init__(self, a: PatternBlock, b: PatternBlock) -> None:
        ...

    @typing.overload
    def __init__(self, list: generic.stl.VectorSTL[PatternBlock]) -> None:
        ...

    def alwaysFalse(self) -> bool:
        ...

    def alwaysTrue(self) -> bool:
        ...

    def commonSubPattern(self, b: PatternBlock) -> PatternBlock:
        ...

    def dispose(self) -> None:
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        ...

    def getLength(self) -> int:
        ...

    def getMask(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getValue(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def identical(self, op2: PatternBlock) -> bool:
        ...

    def intersect(self, b: PatternBlock) -> PatternBlock:
        ...

    def shift(self, sa: typing.Union[jpype.JInt, int]) -> None:
        ...

    def specializes(self, op2: PatternBlock) -> bool:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class OrPattern(Pattern):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, a: DisjointPattern, b: DisjointPattern) -> None:
        ...

    @typing.overload
    def __init__(self, list: generic.stl.VectorSTL[DisjointPattern]) -> None:
        ...


class CombinePattern(DisjointPattern):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, con: ContextPattern, in_: InstructionPattern) -> None:
        ...


class ContextPattern(DisjointPattern):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, mv: PatternBlock) -> None:
        ...

    def getBlock(self) -> PatternBlock:
        ...

    @property
    def block(self) -> PatternBlock:
        ...


class Pattern(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def alwaysFalse(self) -> bool:
        ...

    def alwaysInstructionTrue(self) -> bool:
        ...

    def alwaysTrue(self) -> bool:
        ...

    def commonSubPattern(self, b: Pattern, sa: typing.Union[jpype.JInt, int]) -> Pattern:
        ...

    def dispose(self) -> None:
        ...

    def doAnd(self, b: Pattern, sa: typing.Union[jpype.JInt, int]) -> Pattern:
        ...

    def doOr(self, b: Pattern, sa: typing.Union[jpype.JInt, int]) -> Pattern:
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        ...

    def getDisjoint(self, i: typing.Union[jpype.JInt, int]) -> DisjointPattern:
        ...

    def numDisjoint(self) -> int:
        ...

    def shiftInstruction(self, sa: typing.Union[jpype.JInt, int]) -> None:
        ...

    def simplifyClone(self) -> Pattern:
        ...

    @property
    def disjoint(self) -> DisjointPattern:
        ...


class DisjointPattern(Pattern):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def getLength(self, context: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getMask(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], context: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getValue(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], context: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def identical(self, op2: DisjointPattern) -> bool:
        ...

    @staticmethod
    def resolveIntersectBlock(bl1: PatternBlock, bl2: PatternBlock, thisblock: PatternBlock) -> bool:
        ...

    def resolvesIntersect(self, op1: DisjointPattern, op2: DisjointPattern) -> bool:
        ...

    def specializes(self, op2: DisjointPattern) -> bool:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class InstructionPattern(DisjointPattern):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, mv: PatternBlock) -> None:
        ...

    @typing.overload
    def __init__(self, tf: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def getBlock(self) -> PatternBlock:
        ...

    @property
    def block(self) -> PatternBlock:
        ...



__all__ = ["PatternBlock", "OrPattern", "CombinePattern", "ContextPattern", "Pattern", "DisjointPattern", "InstructionPattern"]
