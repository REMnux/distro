from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore


class PatternBlock(java.lang.Object):
    """
    A mask/value pair viewed as two bitstreams
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, off: typing.Union[jpype.JInt, int], msk: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, tf: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, a: PatternBlock, b: PatternBlock):
        ...

    @typing.overload
    def __init__(self, list: java.util.ArrayList[typing.Any]):
        ...

    def alwaysFalse(self) -> bool:
        ...

    def alwaysTrue(self) -> bool:
        ...

    def andBlock(self, b: PatternBlock) -> PatternBlock:
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def getLength(self) -> int:
        ...

    def getMask(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getMaskVector(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getNonZeroLength(self) -> int:
        ...

    def getOffset(self) -> int:
        ...

    def getValue(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getValueVector(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getWholeBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Extract those portions of the pattern which constitute fully-specified bytes
        
        :return: an array of bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def identical(self, op2: PatternBlock) -> bool:
        ...

    def isContextMatch(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> bool:
        ...

    def isInstructionMatch(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> bool:
        ...

    def shift(self, sa: typing.Union[jpype.JInt, int]):
        ...

    def specializes(self, op2: PatternBlock) -> bool:
        ...

    @property
    def instructionMatch(self) -> jpype.JBoolean:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def contextMatch(self) -> jpype.JBoolean:
        ...

    @property
    def wholeBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def maskVector(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def nonZeroLength(self) -> jpype.JInt:
        ...

    @property
    def valueVector(self) -> jpype.JArray[jpype.JInt]:
        ...


class OrPattern(Pattern):
    """
    A pattern that can be matched by matching any of a list of subpatterns
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, a: DisjointPattern, b: DisjointPattern):
        ...

    @typing.overload
    def __init__(self, list: java.util.ArrayList[typing.Any]):
        ...


class CombinePattern(DisjointPattern):
    """
    A pattern that has both an instruction part and non-instruction part
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, con: ContextPattern, in_: InstructionPattern):
        ...


class ContextPattern(DisjointPattern):
    """
    Pattern which depends only on the non-instruction stream bits
    of the context
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, mv: PatternBlock):
        ...

    def getBlock(self) -> PatternBlock:
        ...

    @property
    def block(self) -> PatternBlock:
        ...


class Pattern(java.lang.Object):
    """
    A pattern which either matches or doesnt match a particular
    InstructionContext.  In particular, the bits comprising the
    current instruction in the executable, and possible other
    context bits
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def alwaysFalse(self) -> bool:
        ...

    def alwaysInstructionTrue(self) -> bool:
        ...

    def alwaysTrue(self) -> bool:
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def doAnd(self, b: Pattern, sa: typing.Union[jpype.JInt, int]) -> Pattern:
        ...

    def doOr(self, b: Pattern, sa: typing.Union[jpype.JInt, int]) -> Pattern:
        ...

    def getDisjoint(self, i: typing.Union[jpype.JInt, int]) -> DisjointPattern:
        ...

    def isMatch(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker, debug: ghidra.app.plugin.processors.sleigh.SleighDebugLogger) -> bool:
        ...

    def numDisjoint(self) -> int:
        ...

    def shiftInstruction(self, sa: typing.Union[jpype.JInt, int]):
        ...

    def simplifyClone(self) -> Pattern:
        ...

    @property
    def disjoint(self) -> DisjointPattern:
        ...


class DisjointPattern(Pattern):
    """
    A pattern with no ORs in it
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def decodeDisjoint(decoder: ghidra.program.model.pcode.Decoder) -> DisjointPattern:
        ...

    def getBlock(self, context: typing.Union[jpype.JBoolean, bool]) -> PatternBlock:
        ...

    def getContextBlock(self) -> PatternBlock:
        ...

    def getInstructionBlock(self) -> PatternBlock:
        ...

    def getLength(self, context: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getMask(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], context: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getValue(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], context: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getWholeInstructionBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def identical(self, op2: DisjointPattern) -> bool:
        ...

    def specializes(self, op2: DisjointPattern) -> bool:
        ...

    @property
    def instructionBlock(self) -> PatternBlock:
        ...

    @property
    def wholeInstructionBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def contextBlock(self) -> PatternBlock:
        ...

    @property
    def block(self) -> PatternBlock:
        ...


class InstructionPattern(DisjointPattern):
    """
    Matches against the actual instruction bit stream
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, mv: PatternBlock):
        ...

    @typing.overload
    def __init__(self, tf: typing.Union[jpype.JBoolean, bool]):
        ...

    def getBlock(self) -> PatternBlock:
        ...

    @property
    def block(self) -> PatternBlock:
        ...



__all__ = ["PatternBlock", "OrPattern", "CombinePattern", "ContextPattern", "Pattern", "DisjointPattern", "InstructionPattern"]
