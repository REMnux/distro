from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.format
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class PcodeFieldFactory(ghidra.app.util.viewer.field.FieldFactory):
    """
    Pcode field factory.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "PCode"
    MAX_DISPLAY_LINES_MSG: typing.Final = "Pcode Field.Maximum Lines To Display"
    DISPLAY_RAW_PCODE: typing.Final = "Pcode Field.Display Raw Pcode"
    MAX_DISPLAY_LINES: typing.Final = 30

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], model: ghidra.app.util.viewer.format.FieldFormatModel, highlightProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.Options):
        ...


class Offset(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, off: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, off: typing.Union[jpype.JInt, int], rel: Operand):
        ...

    def getOffset(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        """
        Method getOffset.
        
        :param ghidra.program.model.mem.MemBuffer buf: - a MemBuffer of bytes to parse
        :param jpype.JInt or int off: - offset into the MemBuffer at which to start
        :return: int - offset into the MemBuffer to which this Offset object points
                                given the bytes in the MemBuffer.
        :rtype: int
        """

    def setRelativeOffset(self, opHash: java.util.Hashtable[java.lang.String, Operand]):
        """
        Method setRelativeOffset.
        
        :param java.util.Hashtable[java.lang.String, Operand] opHash:
        """


class Constant(ExpressionValue):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, v: typing.Union[jpype.JLong, int]):
        ...

    def length(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...

    def longValue(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...


class Label(ExpressionValue):
    """
    To change this generated comment edit the template variable "typecomment":
    Window>Preferences>Java>Templates.
    To enable and disable the creation of type comments go to
    Window>Preferences>Java>Code Generation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def length(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...

    def longValue(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...


class Operand(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, n: typing.Union[java.lang.String, str], o: OperandValue, off: Offset):
        ...

    def dynamic(self) -> bool:
        ...

    def getAllHandles(self, handles: java.util.ArrayList[Handle], position: Position, off: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def getHandle(self, pcode: java.util.ArrayList[ghidra.program.model.pcode.PcodeOp], position: Position, off: typing.Union[jpype.JInt, int]) -> Handle:
        """
        Method getHandle.
        
        :param java.util.ArrayList[ghidra.program.model.pcode.PcodeOp] pcode: 
        :param Position position: 
        :param jpype.JInt or int off: 
        :return: Handle
        :rtype: Handle
        """

    @typing.overload
    def getHandle(self) -> Handle:
        """
        Returns previously computed handle for this operand.  Should not
        be called before the full version of getHandle, where Position and an
        offset are specified.
        
        :return: Handle
        :rtype: Handle
        """

    @typing.overload
    def getHandle(self, position: Position, off: typing.Union[jpype.JInt, int]) -> Handle:
        """
        Returns a handle for this operand *without* generating any pcode
        
        :param Position position: 
        :param jpype.JInt or int off: 
        :return: 
        :rtype: Handle
        :raises java.lang.Exception:
        """

    def getInfo(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> ConstructorInfo:
        ...

    def getPcode(self, position: Position) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Method getPcode
        
        :param Position position: 
        :return: array of pcode ops for this operand
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        :raises java.lang.Exception:
        """

    def getSize(self) -> int:
        """
        
        
        :return: 
        :rtype: int
        """

    def length(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...

    def linkRelativeOffsets(self, opHash: java.util.Hashtable[java.lang.String, Operand]):
        ...

    def name(self) -> str:
        ...

    def toList(self, list: java.util.ArrayList[Handle], position: Position, off: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`OperandValue.toList(ArrayList, Position, int)`
        """

    def toString(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> str:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def pcode(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        ...

    @property
    def handle(self) -> Handle:
        ...


class ConstantTemplate(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]
    REAL: typing.Final = 1
    HANDLE: typing.Final = 2
    JUMP_START: typing.Final = 3
    JUMP_NEXT: typing.Final = 4
    JUMP_CODESPACE: typing.Final = 5

    @typing.overload
    def __init__(self, val: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, t: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, o: Operand, sel1: typing.Union[jpype.JInt, int], sel2: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, o: Operand, sel1: typing.Union[jpype.JInt, int]):
        """
        Constructor ConstantTemplate.
        
        :param Operand o: the operand
        :param jpype.JInt or int sel1: the first selection
        """

    def operand(self) -> Operand:
        ...

    @typing.overload
    def resolve(self, position: Position, off: typing.Union[jpype.JInt, int]) -> int:
        """
        Method resolve.
        
        :param Position position: the position of the constant to resolve
        :param jpype.JInt or int off: the offset of the constant
        :return: long
        :rtype: int
        """

    @typing.overload
    def resolve(self, handles: java.util.HashMap[java.lang.Object, Handle], position: Position, off: typing.Union[jpype.JInt, int]) -> int:
        """
        
        
        :param java.util.HashMap[java.lang.Object, Handle] handles: optional map of handles to be used for resolving
        :return: long
        :rtype: int
        
        .. seealso::
        
            | :obj:`.resolve(Position, int)`
        """

    def select1(self) -> int:
        ...

    def select2(self) -> int:
        ...

    def type(self) -> int:
        ...


class HandleTemplate(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sp: ConstantTemplate, p: VarnodeTemplate, sz: ConstantTemplate):
        ...

    @typing.overload
    def resolve(self, handles: java.util.HashMap[java.lang.Object, Handle], position: Position, off: typing.Union[jpype.JInt, int]) -> Handle:
        """
        Method resolve.
        
        :param java.util.HashMap[java.lang.Object, Handle] handles: 
        :return: HandleTemplate
        :rtype: Handle
        """

    @typing.overload
    def resolve(self, position: Position, off: typing.Union[jpype.JInt, int]) -> Handle:
        """
        
        
        :param Position position: 
        :param jpype.JInt or int off: 
        :return: 
        :rtype: Handle
        """


class MemoryBlockDefinition(java.lang.Object):
    """
    TODO To change the template for this generated type comment go to
    Window - Preferences - Java - Code Style - Code Templates
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, element: ghidra.xml.XmlElement):
        ...

    def createBlock(self, program: ghidra.program.model.listing.Program):
        """
        Create memory block within specified program based upon this block specification.
        
        :param ghidra.program.model.listing.Program program: target program
        :raises LockException: if program does not have exclusive access required when adding memory blocks.
        :raises MemoryConflictException: if this specification conflicts with an existing memory block in program
        :raises AddressOverflowException: if memory space constraints are violated by block specification
        :raises InvalidAddressException: if address defined by this block specification is invalid
        for the specified program.  May also indicate an improperly formatted address attribute.
        """


class OpTemplate(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, opc: typing.Union[jpype.JInt, int], in_: jpype.JArray[VarnodeTemplate], out: VarnodeTemplate, af: ghidra.program.model.address.AddressFactory):
        ...

    def getPcode(self, handles: java.util.HashMap[java.lang.Object, Handle], position: Position, opSequenceNumber: typing.Union[jpype.JInt, int], off: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.PcodeOp:
        """
        Method getPcode.
        
        :param java.util.HashMap[java.lang.Object, Handle] handles: 
        :return: PcodeOp
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    def input(self, i: typing.Union[jpype.JInt, int]) -> VarnodeTemplate:
        ...

    def omit(self) -> bool:
        ...

    def opcode(self) -> int:
        ...

    def output(self) -> VarnodeTemplate:
        ...

    def setOmit(self, ref: Operand):
        ...


class UnimplementedConstructor(ConstructorPcodeTemplate):
    """
    Template for a constructor which is officially "unimplemented" as opposed to a
    constructor which does nothing (like a NOP). Any instruction which is "unimplemented"
    in this way will have its disassembly printed correctly but will be treated as an
    instruction which does nothing (and falls through) for any analysis that needs
    control-flow information or semantics. Actually anything that tries to get semantic
    information (via the getPcode call) will cause an exception to be thrown, as opposed
    to a NOP instruction which would return an empty pcode op array. The caller can then
    catch the exception and treat the instruction as special, or it can ignore the exception
    in which case the instruction behaves exactly like a NOP.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ConstructorPcodeTemplate(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addPcodeOpTemplate(self, opT: java.lang.Object):
        ...

    def delaySlotDepth(self) -> int:
        ...

    def getFlowFlags(self) -> int:
        ...

    def getPcode(self, pcode: java.util.ArrayList[ghidra.program.model.pcode.PcodeOp], position: Position, off: typing.Union[jpype.JInt, int], delayPcode: java.util.ArrayList[ghidra.program.model.pcode.PcodeOp]) -> Handle:
        """
        Method getPcode.  Recursive pcode generation method.
        
        :param java.util.ArrayList[ghidra.program.model.pcode.PcodeOp] pcode: - current list of pcode instructions to which we will append new instructions
        :param Position position: 
        :param jpype.JInt or int off: 
        :param java.util.ArrayList[ghidra.program.model.pcode.PcodeOp] delayPcode: - pcode for instruction(s) in delay slot
        :return: HandleTemplate - handle for the result of this constructors pcode
        :rtype: Handle
        """

    def optimize(self):
        """
        The default pcode generated for a constructor is typically
        not very efficient.  For example, for an add instruction,
        we might generate something like
         
        tmp1 = LOAD register_space register1
        tmp2 = LOAD register_space register2
        tmp3 = ADD tmp1 tmp2
                STORE register_space register3 tmp3
         
        This routine marks opcodes and varnodes as potentially omitable,
        which allows us to generate much simpler pcode whenever there
        are no dynamic references involved.  In the case above we would
        replace the 4 pcode ops above with a single pcode op:
         
        register3 = ADD register1 register2
        """

    def result(self) -> HandleTemplate:
        ...

    def trimToSize(self):
        ...

    @property
    def flowFlags(self) -> jpype.JInt:
        ...


class VarnodeTemplate(java.io.Serializable):
    """
    To change this generated comment edit the template variable "typecomment":
    Window>Preferences>Java>Templates.
    To enable and disable the creation of type comments go to
    Window>Preferences>Java>Code Generation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: ConstantTemplate, offset: ConstantTemplate, size: ConstantTemplate, addressFactory: ghidra.program.model.address.AddressFactory, ou: typing.Union[jpype.JBoolean, bool]):
        ...

    def loadomit(self) -> bool:
        ...

    def offset(self) -> ConstantTemplate:
        ...

    def oneuse(self) -> bool:
        ...

    @typing.overload
    def resolve(self, handles: java.util.HashMap[java.lang.Object, Handle], position: Position, bufoff: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        """
        Method resolve.
        
        :param java.util.HashMap[java.lang.Object, Handle] handles: 
        :return: Varnode
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @typing.overload
    def resolve(self, position: Position, bufoff: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        """
        Resolves a varnode at the given position and buffer offset
        
        :param Position position: the position
        :param jpype.JInt or int bufoff: the buffer offset
        :return: the resolved :obj:`raw varnode <Varnode>`. (**Only** contains an address and size)
        :rtype: ghidra.program.model.pcode.Varnode
        :raises java.lang.Exception: if an error occurs resolving the varnode
        """

    def setDef(self, opTemplate: OpTemplate):
        """
        Method setDef.
        
        :param OpTemplate opTemplate:
        """

    def setReplace(self, op: Operand, load: typing.Union[jpype.JBoolean, bool]):
        ...

    def size(self) -> ConstantTemplate:
        ...

    def space(self) -> ConstantTemplate:
        ...


class OperandValue(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def getAllHandles(self, handles: java.util.ArrayList[Handle], position: Position, offset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def getHandle(self, pcode: java.util.ArrayList[ghidra.program.model.pcode.PcodeOp], position: Position, off: typing.Union[jpype.JInt, int]) -> Handle:
        """
        Method getHandle.
        
        :param java.util.ArrayList[ghidra.program.model.pcode.PcodeOp] pcode: 
        :param Position position: 
        :param jpype.JInt or int off: 
        :return: Handle
        :rtype: Handle
        """

    @typing.overload
    def getHandle(self, position: Position, off: typing.Union[jpype.JInt, int]) -> Handle:
        """
        
        
        :param Position position: 
        :param jpype.JInt or int off: 
        :return: Handle
        :rtype: Handle
        """

    def getInfo(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> ConstructorInfo:
        ...

    def getSize(self) -> int:
        """
        Get the size in bits of the value used in the instruction to create this value.
        """

    def length(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> int:
        ...

    def toList(self, list: java.util.ArrayList[Handle], position: Position, off: typing.Union[jpype.JInt, int]):
        """
        Construct operand representation as a list of objects
        
        :param java.util.ArrayList[Handle] list: the list to fill
        :param Position position: the operand position
        :param jpype.JInt or int off: the offset
        """

    def toString(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> str:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...


class BinaryExpression(OperandValue, ExpressionValue):

    class_: typing.ClassVar[java.lang.Class]
    INVALID_OP: typing.Final = -1
    ADD: typing.Final = 0
    SUB: typing.Final = 1
    MUL: typing.Final = 2
    DIV: typing.Final = 3
    EQ: typing.Final = 4
    AND: typing.Final = 5

    def __init__(self, op: typing.Union[jpype.JInt, int], l: ExpressionTerm, r: ExpressionTerm, c: ghidra.program.model.address.AddressSpace):
        ...

    def linkRelativeOffsets(self, opHash: java.util.Hashtable[java.lang.String, Operand]):
        """
        Method linkRelativeOffsets.
        
        :param java.util.Hashtable[java.lang.String, Operand] opHash:
        """

    def setSpace(self, space: ghidra.program.model.address.AddressSpace):
        ...


class ExpressionTerm(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, v: ExpressionValue, off: Offset):
        ...

    def getValue(self) -> ExpressionValue:
        ...

    def length(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...

    def linkRelativeOffsets(self, opHash: java.util.Hashtable[java.lang.String, Operand]):
        """
        Method linkRelativeOffsets.
        
        :param java.util.Hashtable[java.lang.String, Operand] opHash:
        """

    def longValue(self, buf: ghidra.program.model.mem.MemBuffer, off: typing.Union[jpype.JInt, int]) -> int:
        ...

    def setSpace(self, space: ghidra.program.model.address.AddressSpace):
        """
        Sets the address space of the expression value
        
        :param ghidra.program.model.address.AddressSpace space: the address space to set
        """

    @property
    def value(self) -> ExpressionValue:
        ...


class ExpressionValue(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]

    def length(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> int:
        ...

    def longValue(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> int:
        ...


class Position(java.lang.Object):
    """
    To change this generated comment edit the template variable "typecomment":
    Window>Preferences>Java>Templates.
    To enable and disable the creation of type comments go to
    Window>Preferences>Java>Code Generation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, b: ghidra.program.model.mem.MemBuffer, start: ghidra.program.model.address.Address, next: ghidra.program.model.address.Address, c: ghidra.program.model.lang.ProcessorContext):
        ...

    def buffer(self) -> ghidra.program.model.mem.MemBuffer:
        ...

    def context(self) -> ghidra.program.model.lang.ProcessorContext:
        ...

    def nextAddr(self) -> ghidra.program.model.address.Address:
        ...

    def startAddr(self) -> ghidra.program.model.address.Address:
        ...


class ConstructorInfo(java.lang.Object):
    """
    Structure for collecting cached information about an instruction
    """

    class_: typing.ClassVar[java.lang.Class]
    RETURN: typing.Final = 1
    CALL_INDIRECT: typing.Final = 2
    BRANCH_INDIRECT: typing.Final = 4
    CALL: typing.Final = 8
    JUMPOUT: typing.Final = 16
    NO_FALLTHRU: typing.Final = 32
    BRANCH_TO_END: typing.Final = 64

    def __init__(self, ln: typing.Union[jpype.JInt, int], fl: typing.Union[jpype.JInt, int]):
        ...

    def addLength(self, l: typing.Union[jpype.JInt, int]):
        ...

    def getFlowFlags(self) -> int:
        ...

    def getLength(self) -> int:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def flowFlags(self) -> jpype.JInt:
        ...


class SledException(java.lang.RuntimeException):
    """
    Exceptions generated from parsing the SLED/SSL configuration files (load time)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, e: java.lang.Exception):
        """
        
        
        :param java.lang.Exception e:
        """

    @typing.overload
    def __init__(self):
        """
        
        Constructs a SledException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs a SledException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class Handle(java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]
    SPACE: typing.Final = 0
    OFFSET: typing.Final = 1
    SIZE: typing.Final = 2

    def __init__(self, p: ghidra.program.model.pcode.Varnode, sp: typing.Union[jpype.JInt, int], sz: typing.Union[jpype.JInt, int]):
        ...

    def dynamic(self) -> bool:
        ...

    def getLong(self, select1: typing.Union[jpype.JInt, int], select2: typing.Union[jpype.JInt, int]) -> int:
        """
        Method getLong.
        
        :param jpype.JInt or int select1: 
        :param jpype.JInt or int select2: 
        :return: long
        :rtype: int
        """

    def getPtr(self) -> ghidra.program.model.pcode.Varnode:
        ...

    def getSize(self) -> int:
        ...

    def getSpace(self) -> int:
        ...

    def isAddress(self) -> bool:
        ...

    def isCodeAddress(self) -> bool:
        ...

    def isConstant(self) -> bool:
        ...

    def isDataAddress(self) -> bool:
        ...

    def isRegister(self) -> bool:
        ...

    def isUnique(self) -> bool:
        ...

    @property
    def constant(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> jpype.JBoolean:
        ...

    @property
    def dataAddress(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def unique(self) -> jpype.JBoolean:
        ...

    @property
    def codeAddress(self) -> jpype.JBoolean:
        ...

    @property
    def space(self) -> jpype.JLong:
        ...

    @property
    def register(self) -> jpype.JBoolean:
        ...

    @property
    def ptr(self) -> ghidra.program.model.pcode.Varnode:
        ...



__all__ = ["PcodeFieldFactory", "Offset", "Constant", "Label", "Operand", "ConstantTemplate", "HandleTemplate", "MemoryBlockDefinition", "OpTemplate", "UnimplementedConstructor", "ConstructorPcodeTemplate", "VarnodeTemplate", "OperandValue", "BinaryExpression", "ExpressionTerm", "ExpressionValue", "Position", "ConstructorInfo", "SledException", "Handle"]
