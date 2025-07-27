from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.opcodes
import ghidra.pcodeCPort.space
import ghidra.program.model.pcode
import ghidra.sleigh.grammar
import java.lang # type: ignore


class ConstTpl(java.lang.Object):

    class const_type(java.lang.Enum[ConstTpl.const_type]):

        class_: typing.ClassVar[java.lang.Class]
        real: typing.Final[ConstTpl.const_type]
        handle: typing.Final[ConstTpl.const_type]
        j_start: typing.Final[ConstTpl.const_type]
        j_next: typing.Final[ConstTpl.const_type]
        j_next2: typing.Final[ConstTpl.const_type]
        j_curspace: typing.Final[ConstTpl.const_type]
        j_curspace_size: typing.Final[ConstTpl.const_type]
        spaceid: typing.Final[ConstTpl.const_type]
        j_relative: typing.Final[ConstTpl.const_type]
        j_flowref: typing.Final[ConstTpl.const_type]
        j_flowref_size: typing.Final[ConstTpl.const_type]
        j_flowdest: typing.Final[ConstTpl.const_type]
        j_flowdest_size: typing.Final[ConstTpl.const_type]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ConstTpl.const_type:
            ...

        @staticmethod
        def values() -> jpype.JArray[ConstTpl.const_type]:
            ...


    class v_field(java.lang.Enum[ConstTpl.v_field]):

        class_: typing.ClassVar[java.lang.Class]
        v_space: typing.Final[ConstTpl.v_field]
        v_offset: typing.Final[ConstTpl.v_field]
        v_size: typing.Final[ConstTpl.v_field]
        v_offset_plus: typing.Final[ConstTpl.v_field]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ConstTpl.v_field:
            ...

        @staticmethod
        def values() -> jpype.JArray[ConstTpl.v_field]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, op2: ConstTpl):
        ...

    @typing.overload
    def __init__(self, tp: ConstTpl.const_type):
        ...

    @typing.overload
    def __init__(self, tp: ConstTpl.const_type, val: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, tp: ConstTpl.const_type, ht: typing.Union[jpype.JInt, int], vf: ConstTpl.v_field):
        ...

    @typing.overload
    def __init__(self, tp: ConstTpl.const_type, ht: typing.Union[jpype.JInt, int], vf: ConstTpl.v_field, plus: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, sid: ghidra.pcodeCPort.space.AddrSpace):
        ...

    def changeHandleIndex(self, handmap: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def compareTo(self, op2: ConstTpl) -> int:
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getHandleIndex(self) -> int:
        ...

    def getReal(self) -> int:
        ...

    def getSelect(self) -> ConstTpl.v_field:
        ...

    def getSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getType(self) -> ConstTpl.const_type:
        ...

    def isConstSpace(self) -> bool:
        ...

    def isUniqueSpace(self) -> bool:
        ...

    def isZero(self) -> bool:
        ...

    def transfer(self, params: generic.stl.VectorSTL[HandleTpl]):
        ...

    @property
    def zero(self) -> jpype.JBoolean:
        ...

    @property
    def select(self) -> ConstTpl.v_field:
        ...

    @property
    def uniqueSpace(self) -> jpype.JBoolean:
        ...

    @property
    def handleIndex(self) -> jpype.JInt:
        ...

    @property
    def constSpace(self) -> jpype.JBoolean:
        ...

    @property
    def real(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> ConstTpl.const_type:
        ...

    @property
    def space(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...


class VarnodeTpl(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, hand: typing.Union[jpype.JInt, int], zerosize: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, sp: ConstTpl, off: ConstTpl, sz: ConstTpl):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, vn: VarnodeTpl):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    def adjustTruncation(self, sz: typing.Union[jpype.JInt, int], isbigendian: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def changeHandleIndex(self, handmap: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def compareTo(self, op2: VarnodeTpl) -> int:
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getOffset(self) -> ConstTpl:
        ...

    def getSize(self) -> ConstTpl:
        ...

    def getSpace(self) -> ConstTpl:
        ...

    def isLocalTemp(self) -> bool:
        ...

    def isRelative(self) -> bool:
        ...

    def isUnnamed(self) -> bool:
        ...

    def isZeroSize(self) -> bool:
        ...

    def setOffset(self, constVal: typing.Union[jpype.JLong, int]):
        ...

    def setRelative(self, constVal: typing.Union[jpype.JLong, int]):
        ...

    def setSize(self, sz: ConstTpl):
        ...

    def setUnnamed(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def transfer(self, params: generic.stl.VectorSTL[HandleTpl]) -> int:
        ...

    @property
    def size(self) -> ConstTpl:
        ...

    @size.setter
    def size(self, value: ConstTpl):
        ...

    @property
    def offset(self) -> ConstTpl:
        ...

    @property
    def localTemp(self) -> jpype.JBoolean:
        ...

    @property
    def zeroSize(self) -> jpype.JBoolean:
        ...

    @property
    def unnamed(self) -> jpype.JBoolean:
        ...

    @unnamed.setter
    def unnamed(self, value: jpype.JBoolean):
        ...

    @property
    def space(self) -> ConstTpl:
        ...

    @property
    def relative(self) -> jpype.JBoolean:
        ...


class PcodeBuilder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lbcnt: typing.Union[jpype.JInt, int]):
        ...

    def appendBuild(self, bld: OpTpl, secnum: typing.Union[jpype.JInt, int]):
        ...

    def appendCrossBuild(self, bld: OpTpl, secnum: typing.Union[jpype.JInt, int]):
        ...

    def build(self, construct: ConstructTpl, secnum: typing.Union[jpype.JInt, int]):
        ...

    def delaySlot(self, op: OpTpl):
        ...

    def dispose(self):
        ...

    def getLabelBase(self) -> int:
        ...

    def setLabel(self, op: OpTpl):
        ...

    @property
    def labelBase(self) -> jpype.JInt:
        ...


class HandleTpl(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, vn: VarnodeTpl):
        ...

    @typing.overload
    def __init__(self, spc: ConstTpl, sz: ConstTpl, vn: VarnodeTpl, t_space: ghidra.pcodeCPort.space.AddrSpace, t_offset: typing.Union[jpype.JLong, int]):
        ...

    def changeHandleIndex(self, handmap: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getPtrOffset(self) -> ConstTpl:
        ...

    def getPtrSize(self) -> ConstTpl:
        ...

    def getPtrSpace(self) -> ConstTpl:
        ...

    def getSize(self) -> ConstTpl:
        ...

    def getSpace(self) -> ConstTpl:
        ...

    def getTempOffset(self) -> ConstTpl:
        ...

    def getTempSpace(self) -> ConstTpl:
        ...

    def setPtrOffset(self, val: typing.Union[jpype.JLong, int]):
        ...

    def setPtrSize(self, sz: ConstTpl):
        ...

    def setSize(self, sz: ConstTpl):
        ...

    def setTempOffset(self, val: typing.Union[jpype.JLong, int]):
        ...

    @property
    def size(self) -> ConstTpl:
        ...

    @size.setter
    def size(self, value: ConstTpl):
        ...

    @property
    def ptrSize(self) -> ConstTpl:
        ...

    @ptrSize.setter
    def ptrSize(self, value: ConstTpl):
        ...

    @property
    def tempSpace(self) -> ConstTpl:
        ...

    @property
    def tempOffset(self) -> ConstTpl:
        ...

    @property
    def ptrOffset(self) -> ConstTpl:
        ...

    @property
    def ptrSpace(self) -> ConstTpl:
        ...

    @property
    def space(self) -> ConstTpl:
        ...


class ConstructTpl(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    loc: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, loc: ghidra.sleigh.grammar.Location):
        ...

    def addOp(self, ot: OpTpl) -> bool:
        ...

    def addOpList(self, oplist: generic.stl.VectorSTL[OpTpl]) -> bool:
        ...

    def buildOnly(self) -> bool:
        ...

    def changeHandleIndex(self, handmap: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def delaySlot(self) -> int:
        ...

    def deleteOps(self, indices: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder, sectionid: typing.Union[jpype.JInt, int]):
        ...

    def fillinBuild(self, check: generic.stl.VectorSTL[java.lang.Integer], const_space: ghidra.pcodeCPort.space.AddrSpace) -> generic.stl.Pair[java.lang.Integer, ghidra.sleigh.grammar.Location]:
        ...

    def getOpvec(self) -> generic.stl.VectorSTL[OpTpl]:
        ...

    def getResult(self) -> HandleTpl:
        ...

    def numLabels(self) -> int:
        ...

    def setInput(self, vn: VarnodeTpl, index: typing.Union[jpype.JInt, int], slot: typing.Union[jpype.JInt, int]):
        ...

    def setNumLabels(self, val: typing.Union[jpype.JInt, int]):
        ...

    def setOpvec(self, opvec: generic.stl.VectorSTL[OpTpl]):
        ...

    def setOutput(self, vn: VarnodeTpl, index: typing.Union[jpype.JInt, int]):
        ...

    def setResult(self, t: HandleTpl):
        ...

    @property
    def result(self) -> HandleTpl:
        ...

    @result.setter
    def result(self, value: HandleTpl):
        ...

    @property
    def opvec(self) -> generic.stl.VectorSTL[OpTpl]:
        ...

    @opvec.setter
    def opvec(self, value: generic.stl.VectorSTL[OpTpl]):
        ...


class OpTpl(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, oc: ghidra.pcodeCPort.opcodes.OpCode):
        ...

    def addInput(self, vt: VarnodeTpl):
        ...

    def changeHandleIndex(self, handmap: generic.stl.VectorSTL[java.lang.Integer]):
        ...

    def clearOutput(self):
        ...

    def dispose(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getIn(self, i: typing.Union[jpype.JInt, int]) -> VarnodeTpl:
        ...

    def getOpcode(self) -> ghidra.pcodeCPort.opcodes.OpCode:
        ...

    def getOut(self) -> VarnodeTpl:
        ...

    def isZeroSize(self) -> bool:
        ...

    def numInput(self) -> int:
        ...

    def removeInput(self, index: typing.Union[jpype.JInt, int]):
        ...

    def setInput(self, vt: VarnodeTpl, slot: typing.Union[jpype.JInt, int]):
        ...

    def setOpcode(self, o: ghidra.pcodeCPort.opcodes.OpCode):
        ...

    def setOutput(self, vt: VarnodeTpl):
        ...

    @property
    def zeroSize(self) -> jpype.JBoolean:
        ...

    @property
    def in_(self) -> VarnodeTpl:
        ...

    @property
    def opcode(self) -> ghidra.pcodeCPort.opcodes.OpCode:
        ...

    @opcode.setter
    def opcode(self, value: ghidra.pcodeCPort.opcodes.OpCode):
        ...

    @property
    def out(self) -> VarnodeTpl:
        ...



__all__ = ["ConstTpl", "VarnodeTpl", "PcodeBuilder", "HandleTpl", "ConstructTpl", "OpTpl"]
