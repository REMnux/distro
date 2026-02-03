from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.program.model.scalar
import java.lang # type: ignore


class DWARFExpressionOpCode(java.lang.Enum[DWARFExpressionOpCode]):
    """
    DWARF expression opcodes, and their expected operands.
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_OP_unknown_opcode: typing.Final[DWARFExpressionOpCode]
    DW_OP_addr: typing.Final[DWARFExpressionOpCode]
    DW_OP_deref: typing.Final[DWARFExpressionOpCode]
    DW_OP_const1u: typing.Final[DWARFExpressionOpCode]
    DW_OP_const1s: typing.Final[DWARFExpressionOpCode]
    DW_OP_const2u: typing.Final[DWARFExpressionOpCode]
    DW_OP_const2s: typing.Final[DWARFExpressionOpCode]
    DW_OP_const4u: typing.Final[DWARFExpressionOpCode]
    DW_OP_const4s: typing.Final[DWARFExpressionOpCode]
    DW_OP_const8u: typing.Final[DWARFExpressionOpCode]
    DW_OP_const8s: typing.Final[DWARFExpressionOpCode]
    DW_OP_constu: typing.Final[DWARFExpressionOpCode]
    DW_OP_consts: typing.Final[DWARFExpressionOpCode]
    DW_OP_dup: typing.Final[DWARFExpressionOpCode]
    DW_OP_drop: typing.Final[DWARFExpressionOpCode]
    DW_OP_over: typing.Final[DWARFExpressionOpCode]
    DW_OP_pick: typing.Final[DWARFExpressionOpCode]
    DW_OP_swap: typing.Final[DWARFExpressionOpCode]
    DW_OP_rot: typing.Final[DWARFExpressionOpCode]
    DW_OP_xderef: typing.Final[DWARFExpressionOpCode]
    DW_OP_abs: typing.Final[DWARFExpressionOpCode]
    DW_OP_and: typing.Final[DWARFExpressionOpCode]
    DW_OP_div: typing.Final[DWARFExpressionOpCode]
    DW_OP_minus: typing.Final[DWARFExpressionOpCode]
    DW_OP_mod: typing.Final[DWARFExpressionOpCode]
    DW_OP_mul: typing.Final[DWARFExpressionOpCode]
    DW_OP_neg: typing.Final[DWARFExpressionOpCode]
    DW_OP_not: typing.Final[DWARFExpressionOpCode]
    DW_OP_or: typing.Final[DWARFExpressionOpCode]
    DW_OP_plus: typing.Final[DWARFExpressionOpCode]
    DW_OP_plus_uconst: typing.Final[DWARFExpressionOpCode]
    DW_OP_shl: typing.Final[DWARFExpressionOpCode]
    DW_OP_shr: typing.Final[DWARFExpressionOpCode]
    DW_OP_shra: typing.Final[DWARFExpressionOpCode]
    DW_OP_xor: typing.Final[DWARFExpressionOpCode]
    DW_OP_bra: typing.Final[DWARFExpressionOpCode]
    DW_OP_eq: typing.Final[DWARFExpressionOpCode]
    DW_OP_ge: typing.Final[DWARFExpressionOpCode]
    DW_OP_gt: typing.Final[DWARFExpressionOpCode]
    DW_OP_le: typing.Final[DWARFExpressionOpCode]
    DW_OP_lt: typing.Final[DWARFExpressionOpCode]
    DW_OP_ne: typing.Final[DWARFExpressionOpCode]
    DW_OP_skip: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit0: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit1: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit2: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit3: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit4: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit5: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit6: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit7: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit8: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit9: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit10: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit11: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit12: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit13: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit14: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit15: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit16: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit17: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit18: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit19: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit20: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit21: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit22: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit23: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit24: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit25: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit26: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit27: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit28: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit29: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit30: typing.Final[DWARFExpressionOpCode]
    DW_OP_lit31: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg0: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg1: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg2: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg3: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg4: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg5: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg6: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg7: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg8: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg9: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg10: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg11: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg12: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg13: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg14: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg15: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg16: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg17: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg18: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg19: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg20: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg21: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg22: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg23: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg24: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg25: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg26: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg27: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg28: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg29: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg30: typing.Final[DWARFExpressionOpCode]
    DW_OP_reg31: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg0: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg1: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg2: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg3: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg4: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg5: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg6: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg7: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg8: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg9: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg10: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg11: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg12: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg13: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg14: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg15: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg16: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg17: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg18: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg19: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg20: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg21: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg22: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg23: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg24: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg25: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg26: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg27: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg28: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg29: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg30: typing.Final[DWARFExpressionOpCode]
    DW_OP_breg31: typing.Final[DWARFExpressionOpCode]
    DW_OP_regx: typing.Final[DWARFExpressionOpCode]
    DW_OP_fbreg: typing.Final[DWARFExpressionOpCode]
    DW_OP_bregx: typing.Final[DWARFExpressionOpCode]
    DW_OP_piece: typing.Final[DWARFExpressionOpCode]
    DW_OP_deref_size: typing.Final[DWARFExpressionOpCode]
    DW_OP_xderef_size: typing.Final[DWARFExpressionOpCode]
    DW_OP_nop: typing.Final[DWARFExpressionOpCode]
    DW_OP_push_object_address: typing.Final[DWARFExpressionOpCode]
    DW_OP_call2: typing.Final[DWARFExpressionOpCode]
    DW_OP_call4: typing.Final[DWARFExpressionOpCode]
    DW_OP_call_ref: typing.Final[DWARFExpressionOpCode]
    DW_OP_form_tls_address: typing.Final[DWARFExpressionOpCode]
    DW_OP_call_frame_cfa: typing.Final[DWARFExpressionOpCode]
    DW_OP_bit_piece: typing.Final[DWARFExpressionOpCode]
    DW_OP_implicit_value: typing.Final[DWARFExpressionOpCode]
    DW_OP_stack_value: typing.Final[DWARFExpressionOpCode]
    DW_OP_implicit_pointer: typing.Final[DWARFExpressionOpCode]
    DW_OP_addrx: typing.Final[DWARFExpressionOpCode]
    DW_OP_constx: typing.Final[DWARFExpressionOpCode]
    DW_OP_entry_value: typing.Final[DWARFExpressionOpCode]
    DW_OP_const_type: typing.Final[DWARFExpressionOpCode]
    DW_OP_regval_type: typing.Final[DWARFExpressionOpCode]
    DW_OP_deref_type: typing.Final[DWARFExpressionOpCode]
    DW_OP_xderef_type: typing.Final[DWARFExpressionOpCode]
    DW_OP_convert: typing.Final[DWARFExpressionOpCode]
    DW_OP_reinterpret: typing.Final[DWARFExpressionOpCode]

    def getOpCodeValue(self) -> int:
        """
        :return: this opcode's raw numeric value
        :rtype: int
        """

    def getOperandTypes(self) -> jpype.JArray[DWARFExpressionOperandType]:
        """
        :return: the expected operand types that an instruction would have for this opcode
        :rtype: jpype.JArray[DWARFExpressionOperandType]
        """

    def getRelativeOpCodeOffset(self, baseOp: DWARFExpressionOpCode) -> int:
        """
        Calculates the relative opcode number of this opcode, as compared to a base opcode.
         
        
        Example: if this opcode was DW_OP_reg12 (0x5c), and the base op code was DW_OP_reg0 (0x50),
        the result value would be 12.
        
        :param DWARFExpressionOpCode baseOp: base opcode that this opcode is being compared to
        :return: numeric difference between this opcode and the base opcode
        :rtype: int
        """

    @staticmethod
    def isInRange(op: DWARFExpressionOpCode, lo: DWARFExpressionOpCode, hi: DWARFExpressionOpCode) -> bool:
        """
        :return: true if the specified opcode is in the range (inclusive) of the lo..hi opcodes
        :rtype: bool
        
        
        :param DWARFExpressionOpCode op: opcode to test
        :param DWARFExpressionOpCode lo: lowest opcode
        :param DWARFExpressionOpCode hi: highest opcode
        """

    @staticmethod
    def parse(opcode: typing.Union[jpype.JInt, int]) -> DWARFExpressionOpCode:
        """
        :return: the matching :obj:`DWARFExpressionOpCode` enum member, or null if unknown opcode
        :rtype: DWARFExpressionOpCode
        
        
        :param jpype.JInt or int opcode: numeric value of opcode (currently defined by DWARF as uint8)
        """

    def toString(self, regMapping: ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFExpressionOpCode:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFExpressionOpCode]:
        ...

    @property
    def operandTypes(self) -> jpype.JArray[DWARFExpressionOperandType]:
        ...

    @property
    def opCodeValue(self) -> jpype.JByte:
        ...

    @property
    def relativeOpCodeOffset(self) -> jpype.JInt:
        ...


class DWARFExpressionInstruction(java.lang.Object):
    """
    An immutable representation of a single :obj:`DWARFExpression` instruction and its operands.
     
    
    An instruction can take 0, 1, or 2 operands, only the last can be a blob.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: DWARFExpressionOpCode, operandTypes: jpype.JArray[DWARFExpressionOperandType], operands: jpype.JArray[jpype.JLong], blob: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Create a new DWARF expression instruction.
        
        :param DWARFExpressionOpCode op: enum opcode, ie. DW_OP_not from :obj:`DWARFExpressionOpCode`
        :param jpype.JArray[DWARFExpressionOperandType] operandTypes: 'datatype' of each operands
        :param jpype.JArray[jpype.JLong] operands: value of the operands, pre-converted into longs.
        :param jpype.JArray[jpype.JByte] blob: if an operand is a byte array (ie. for DW_OP_implicit_value), this is the bytes
        :param jpype.JInt or int offset: byte offset of this operation from the start of the DWARF expression.
        """

    def getBlob(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the byte array that contains the bytes of the blob operand
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getOffset(self) -> int:
        """
        :return: offset of this opcode, relative to the start of the :obj:`DWARFExpression`
        :rtype: int
        """

    def getOpCode(self) -> DWARFExpressionOpCode:
        """
        :return: :obj:`DWARFExpressionOpCode` of this instruction
        :rtype: DWARFExpressionOpCode
        """

    def getOperandCount(self) -> int:
        """
        :return: number of operands this instruction has
        :rtype: int
        """

    def getOperandRepresentation(self, opIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        :return: formatted string representation of the specified operand, patterned after readelf's
        format
        :rtype: str
        
        
        :param jpype.JInt or int opIndex: operand index
        """

    def getOperandValue(self, opindex: typing.Union[jpype.JInt, int]) -> int:
        """
        :return: the specified operand's value.  Not valid for blob operands
        :rtype: int
        
        
        :param jpype.JInt or int opindex: which operand to fetch.
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, addrSize: typing.Union[jpype.JByte, int], intSize: typing.Union[jpype.JInt, int]) -> DWARFExpressionInstruction:
        """
        Reads a single instruction from the stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` stream
        :param jpype.JByte or int addrSize: size of pointers
        :param jpype.JInt or int intSize: size of ints
        :return: new :obj:`DWARFExpressionInstruction`, never null.  Problematic instructions
        will have an opcode of :obj:`DW_OP_unknown_opcode <DWARFExpressionOpCode.DW_OP_unknown_opcode>`
        and will contain the remainder of the stream as its blob operand
        :rtype: DWARFExpressionInstruction
        :raises IOException: if error reading a primitive value from the stream
        """

    def toGenericForm(self) -> DWARFExpressionInstruction:
        """
        :return: a new instruction instance that is a copy of this instruction, but has had all 
        it's operands removed
        :rtype: DWARFExpressionInstruction
        """

    @property
    def operandRepresentation(self) -> java.lang.String:
        ...

    @property
    def blob(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def operandCount(self) -> jpype.JInt:
        ...

    @property
    def opCode(self) -> DWARFExpressionOpCode:
        ...

    @property
    def operandValue(self) -> jpype.JLong:
        ...


class DWARFExpressionOperandType(java.lang.Enum[DWARFExpressionOperandType]):
    """
    Enumeration that represents the different type of operands that a 
    :obj:`opcode <DWARFExpressionOpCode>` can take.
    """

    class_: typing.ClassVar[java.lang.Class]
    U_LEB128: typing.Final[DWARFExpressionOperandType]
    S_LEB128: typing.Final[DWARFExpressionOperandType]
    S_BYTE: typing.Final[DWARFExpressionOperandType]
    S_SHORT: typing.Final[DWARFExpressionOperandType]
    S_INT: typing.Final[DWARFExpressionOperandType]
    S_LONG: typing.Final[DWARFExpressionOperandType]
    U_BYTE: typing.Final[DWARFExpressionOperandType]
    U_SHORT: typing.Final[DWARFExpressionOperandType]
    U_INT: typing.Final[DWARFExpressionOperandType]
    U_LONG: typing.Final[DWARFExpressionOperandType]
    ADDR: typing.Final[DWARFExpressionOperandType]
    SIZED_BLOB: typing.Final[DWARFExpressionOperandType]
    DWARF_INT: typing.Final[DWARFExpressionOperandType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DWARFExpressionOperandType:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFExpressionOperandType]:
        ...


class DWARFExpressionUnsupportedOpException(DWARFExpressionException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instr: DWARFExpressionInstruction):
        ...

    def getInstruction(self) -> DWARFExpressionInstruction:
        ...

    @property
    def instruction(self) -> DWARFExpressionInstruction:
        ...


class DWARFExpressionEvaluator(java.lang.Object):
    """
    Evaluates a :obj:`DWARFExpression`.
     
    
    If an instruction needs a value in a register or memory location, the current :obj:`ValueReader`
    callback will be called to fetch the value.  The default implementation is to throw an exception,
    but future work may plug in a constant propagation callback.
    """

    class ValueReader(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        DUMMY: typing.Final[DWARFExpressionEvaluator.ValueReader]

        def getValue(self, vn: ghidra.program.model.pcode.Varnode) -> java.lang.Object:
            ...

        @property
        def value(self) -> java.lang.Object:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit):
        ...

    @typing.overload
    def evaluate(self, exprBytes: jpype.JArray[jpype.JByte]):
        """
        Executes the instructions found in the expression.
        
        :param jpype.JArray[jpype.JByte] exprBytes: raw bytes of the expression
        :raises DWARFExpressionException: if error
        """

    @typing.overload
    def evaluate(self, exprBytes: jpype.JArray[jpype.JByte], *stackArgs: typing.Union[jpype.JLong, int]):
        """
        Executes the instructions found in the expression.
        
        :param jpype.JArray[jpype.JByte] exprBytes: raw bytes of the expression
        :param jpype.JArray[jpype.JLong] stackArgs: any values to push onto the stack before execution
        :raises DWARFExpressionException: if error
        """

    @typing.overload
    def evaluate(self, expr: DWARFExpression, *stackArgs: typing.Union[jpype.JLong, int]):
        """
        Executes the instructions found in the expression.
        
        :param DWARFExpression expr: :obj:`DWARFException` to evaluate
        :param jpype.JArray[jpype.JLong] stackArgs: - pushed 0..N, so stackArgs[0] will be deepest, stackArgs[N] will be topmost.
        :raises DWARFExpressionException: if error
        """

    @typing.overload
    def evaluate(self, expr: DWARFExpression):
        ...

    def getDWARFCompilationUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    def getExpr(self) -> DWARFExpression:
        ...

    def getMaxStepCount(self) -> int:
        ...

    def getPtrSize(self) -> int:
        ...

    def hasNext(self) -> bool:
        """
        :return: true if there are instructions that can be evaluated
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        ...

    def peek(self) -> java.lang.Object:
        """
        Peek at the top value of the stack.
        
        :return: top value of the stack
        :rtype: java.lang.Object
        :raises DWARFExpressionException: if stack is empty
        """

    def pop(self) -> java.lang.Object:
        """
        Pop the top value off the stack.
        
        :return: top value of the stack
        :rtype: java.lang.Object
        :raises DWARFExpressionException: if stack is empty
        """

    def popLong(self) -> int:
        """
        Pop the top value off the stack, and coerce it into a scalar long.
        
        :return: top value of the stack, as a scalar long
        :rtype: int
        :raises DWARFExpressionException: if stack is empty or value can not be used as a long
        """

    def popScalar(self) -> ghidra.program.model.scalar.Scalar:
        """
        Pop the top value off the stack, and coerce it into a scalar.
        
        :return: top value of the stack, as a scalar
        :rtype: ghidra.program.model.scalar.Scalar
        :raises DWARFExpressionException: if stack is empty or value can not be used as a scalar
        """

    def popVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        Pop the top value off the stack, and coerce it into a varnode.
        
        :return: top value of the stack, as a varnode
        :rtype: ghidra.program.model.pcode.Varnode
        :raises DWARFExpressionException: if stack is empty or value can not be used as a varnode
        """

    @typing.overload
    def push(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def push(self, reg: ghidra.program.model.lang.Register):
        ...

    @typing.overload
    def push(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def push(self, l: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def push(self, val: java.lang.Object):
        ...

    def setExpression(self, expr: DWARFExpression):
        """
        Sets the current expression.
        
        :param DWARFExpression expr: :obj:`DWARFExpression`
        """

    def setFrameBaseStackLocation(self, offset: typing.Union[jpype.JInt, int]):
        ...

    def setFrameBaseVal(self, frameBaseVal: ghidra.program.model.pcode.Varnode):
        ...

    def setMaxStepCount(self, maxStepCount: typing.Union[jpype.JInt, int]):
        ...

    def setValReader(self, valReader: DWARFExpressionEvaluator.ValueReader):
        ...

    def step(self) -> bool:
        """
        Evaluates the next instruction in the expression.
        
        :return: true if there are more instructions
        :rtype: bool
        :raises DWARFExpressionException: if error
        """

    def withStaticStackRegisterValues(self, stackOffset: typing.Union[java.lang.Integer, int], stackFrameOffset: typing.Union[java.lang.Integer, int]) -> DWARFExpressionEvaluator.ValueReader:
        ...

    @property
    def ptrSize(self) -> jpype.JInt:
        ...

    @property
    def maxStepCount(self) -> jpype.JInt:
        ...

    @maxStepCount.setter
    def maxStepCount(self, value: jpype.JInt):
        ...

    @property
    def dWARFCompilationUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    @property
    def expr(self) -> DWARFExpression:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DWARFExpressionTerminalDerefException(DWARFExpressionUnsupportedOpException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: DWARFExpressionInstruction, varnode: ghidra.program.model.pcode.Varnode):
        ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode:
        ...


class DWARFExpressionException(java.lang.Exception):
    """
    A exception that is thrown when dealing with :obj:`DWARF expressions <DWARFExpression>`
    or when they are :obj:`evaluated. <DWARFExpressionEvaluator>`
     
    
    Use this class when you want to pass the :obj:`expression <DWARFExpression>` and
    the location in the expression that caused the problem back up the call chain.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], expr: DWARFExpression, instrIndex: typing.Union[jpype.JInt, int], cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    def getExpression(self) -> DWARFExpression:
        ...

    def getInstructionIndex(self) -> int:
        ...

    def setExpression(self, expr: DWARFExpression):
        ...

    def setInstructionIndex(self, instrIndex: typing.Union[jpype.JInt, int]):
        ...

    @property
    def expression(self) -> DWARFExpression:
        ...

    @expression.setter
    def expression(self, value: DWARFExpression):
        ...

    @property
    def instructionIndex(self) -> jpype.JInt:
        ...

    @instructionIndex.setter
    def instructionIndex(self, value: jpype.JInt):
        ...


class DWARFExpressionValueException(DWARFExpressionException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vn: ghidra.program.model.pcode.Varnode):
        ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode:
        ...


class DWARFExpression(java.lang.Object):
    """
    A :obj:`DWARFExpression` is an immutable list of :obj:`operations <DWARFExpressionInstruction>`
    and some factory methods to read an expression from its binary representation.
     
    
    Use a :obj:`DWARFExpressionEvaluator` to execute a :obj:`DWARFExpression`.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_SANE_EXPR: typing.Final = 256

    def findInstructionByOffset(self, offset: typing.Union[jpype.JLong, int]) -> int:
        """
        Finds the index of an :obj:`operation <DWARFExpressionInstruction>` by its offset
        from the beginning of the expression.
        
        :param jpype.JLong or int offset: byte offset of instruction to find
        :return: index of instruction at specified byte offset, or -1 if there is no instruction
        at the specified offset
        :rtype: int
        """

    def getInstruction(self, i: typing.Union[jpype.JInt, int]) -> DWARFExpressionInstruction:
        """
        :return: the requested instruction
        :rtype: DWARFExpressionInstruction
        
        
        :param jpype.JInt or int i: instruction index
        """

    def getInstructionCount(self) -> int:
        """
        :return: number of instructions in this expression
        :rtype: int
        """

    def isEmpty(self) -> bool:
        """
        :return: true if there are no instructions
        :rtype: bool
        """

    @staticmethod
    def read(exprBytes: jpype.JArray[jpype.JByte], cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit) -> DWARFExpression:
        """
        Deserializes a :obj:`DWARFExpression` from its raw bytes.
        
        :param jpype.JArray[jpype.JByte] exprBytes: bytes containing the expression
        :param ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit cu: the :obj:`DWARFCompilationUnit` that contained the expression
        :return: new :obj:`DWARFExpression`, never null
        :rtype: DWARFExpression
        :raises DWARFExpressionException: if error reading the expression, check 
        :meth:`DWARFExpressionException.getExpression() <DWARFExpressionException.getExpression>` for the partial results of the read
        """

    def toGenericForm(self) -> DWARFExpression:
        """
        Converts this :obj:`DWARFExpression` into a generic form, lacking any operand values.
         
        
        Useful for aggregating statistics about unsupported/problematic expressions encountered in
        a binary.
        
        :return: new :obj:`DWARFExpression` instance where each instruction has been stripped of all
        operands
        :rtype: DWARFExpression
        """

    @typing.overload
    def toString(self, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit) -> str:
        ...

    @typing.overload
    def toString(self, caretPosition: typing.Union[jpype.JInt, int], newlines: typing.Union[jpype.JBoolean, bool], offsets: typing.Union[jpype.JBoolean, bool], regMapping: ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings) -> str:
        """
        Returns a formatted string representing this expression.
        
        :param jpype.JInt or int caretPosition: index of which instruction to highlight as being the current
        instruction, or -1 to not highlight any instruction
        :param jpype.JBoolean or bool newlines: boolean flag, if true each instruction will be on its own line
        :param jpype.JBoolean or bool offsets: boolean flag, if true the byte offset in the expression will be listed
        next to each instruction
        :param ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings regMapping: mapping of dwarf to ghidra registers
        :return: formatted string
        :rtype: str
        """

    @property
    def instruction(self) -> DWARFExpressionInstruction:
        ...

    @property
    def instructionCount(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...



__all__ = ["DWARFExpressionOpCode", "DWARFExpressionInstruction", "DWARFExpressionOperandType", "DWARFExpressionUnsupportedOpException", "DWARFExpressionEvaluator", "DWARFExpressionTerminalDerefException", "DWARFExpressionException", "DWARFExpressionValueException", "DWARFExpression"]
