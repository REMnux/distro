from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf
import ghidra.program.model.lang
import java.lang # type: ignore
import java.util # type: ignore


class DWARFExpressionResult(java.lang.Object):
    """
    The result of executing a :obj:`DWARFExpression` with a :obj:`DWARFExpressionEvaluator`.
     
    
    Currently only holds the stack results, but future improvements should
    migrate result values (ie. stuff like :meth:`DWARFExpressionEvaluator.isDeref() <DWARFExpressionEvaluator.isDeref>`)
    from :obj:`DWARFExpressionEvaluator` to here.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, stack: java.util.ArrayDeque[java.lang.Long]):
        ...

    def pop(self) -> int:
        ...


class DWARFExpressionOperandType(java.lang.Enum[DWARFExpressionOperandType]):
    """
    Enumeration that represents the different type of operands that a 
    :obj:`opcode <DWARFExpressionOpCodes>` can take.
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
    def valueToString(value: typing.Union[jpype.JLong, int], operandType: DWARFExpressionOperandType) -> str:
        ...

    @staticmethod
    def values() -> jpype.JArray[DWARFExpressionOperandType]:
        ...


@typing.type_check_only
class DWARFExpressionOperation(java.lang.Object):
    """
    An immutable representation of a single :obj:`DWARFExpression` instruction and its operands.
     
    
    A DWARF expression operation can take 0, 1, or 2 operands.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, opcode: typing.Union[jpype.JInt, int], operandTypes: jpype.JArray[DWARFExpressionOperandType], operands: jpype.JArray[jpype.JLong], blob: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Create a new DWARF expression opcode element.
        
        :param jpype.JInt or int opcode: numeric value of the opcode, ie. DW_OP_not from :obj:`DWARFExpressionOpCodes`
        :param jpype.JArray[DWARFExpressionOperandType] operandTypes: 'datatype' of the operands
        :param jpype.JArray[jpype.JLong] operands: value of the operands, pre-converted into longs.
        :param jpype.JArray[jpype.JByte] blob: if an operand is a byte array (ie. for DW_OP_implicit_value), this is the bytes
        :param jpype.JInt or int offset: byte offset of this operation from the start of the DWARF expression.
        """

    def getBlob(self) -> jpype.JArray[jpype.JByte]:
        """
        Return the byte array that contains the bytes of the blob operand.
        
        :return: byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getOffset(self) -> int:
        """
        The offset of this opcode, relative to the start of the :obj:`DWARFExpression`.
        
        :return: 
        :rtype: int
        """

    def getOpCode(self) -> int:
        """
        See :obj:`DWARFExpressionOpCodes` for list of opcodes.
        
        :return: 
        :rtype: int
        """

    def getOperandValue(self, opindex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the operand value.
        
        :param jpype.JInt or int opindex: which operand to fetch.
        :return: value of operand as a long.
        :rtype: int
        """

    def getRelativeOpCodeOffset(self, baseOpCode: typing.Union[jpype.JInt, int]) -> int:
        """
        Calculates the relative opcode number of this opcode, as compared to a base opcode.
         
        
        Ie. If this opcode was DW_OP_reg12 (0x5c), and the base op code was DW_OP_reg0 (0x50),
        the result value would be 12.
        
        :param jpype.JInt or int baseOpCode: Ordinal value of the opcode that this opcode is being compared ot.
        :return: numeric difference between this opcode and the base opcode.
        :rtype: int
        """

    @property
    def blob(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def opCode(self) -> jpype.JInt:
        ...

    @property
    def operandValue(self) -> jpype.JLong:
        ...

    @property
    def relativeOpCodeOffset(self) -> jpype.JInt:
        ...


class DWARFExpressionEvaluatorContext(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit):
        ...

    def cu(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...


class DWARFExpressionOpCodes(java.lang.Object):
    """
    DWARF expression opcode consts from www.dwarfstd.org/doc/DWARF4.pdf
    """

    class_: typing.ClassVar[java.lang.Class]
    DW_OP_addr: typing.Final = 3
    DW_OP_deref: typing.Final = 6
    DW_OP_const1u: typing.Final = 8
    DW_OP_const1s: typing.Final = 9
    DW_OP_const2u: typing.Final = 10
    DW_OP_const2s: typing.Final = 11
    DW_OP_const4u: typing.Final = 12
    DW_OP_const4s: typing.Final = 13
    DW_OP_const8u: typing.Final = 14
    DW_OP_const8s: typing.Final = 15
    DW_OP_constu: typing.Final = 16
    DW_OP_consts: typing.Final = 17
    DW_OP_dup: typing.Final = 18
    DW_OP_drop: typing.Final = 19
    DW_OP_over: typing.Final = 20
    DW_OP_pick: typing.Final = 21
    DW_OP_swap: typing.Final = 22
    DW_OP_rot: typing.Final = 23
    DW_OP_xderef: typing.Final = 24
    DW_OP_abs: typing.Final = 25
    DW_OP_and: typing.Final = 26
    DW_OP_div: typing.Final = 27
    DW_OP_minus: typing.Final = 28
    DW_OP_mod: typing.Final = 29
    DW_OP_mul: typing.Final = 30
    DW_OP_neg: typing.Final = 31
    DW_OP_not: typing.Final = 32
    DW_OP_or: typing.Final = 33
    DW_OP_plus: typing.Final = 34
    DW_OP_plus_uconst: typing.Final = 35
    DW_OP_shl: typing.Final = 36
    DW_OP_shr: typing.Final = 37
    DW_OP_shra: typing.Final = 38
    DW_OP_xor: typing.Final = 39
    DW_OP_bra: typing.Final = 40
    DW_OP_eq: typing.Final = 41
    DW_OP_ge: typing.Final = 42
    DW_OP_gt: typing.Final = 43
    DW_OP_le: typing.Final = 44
    DW_OP_lt: typing.Final = 45
    DW_OP_ne: typing.Final = 46
    DW_OP_skip: typing.Final = 47
    DW_OP_lit0: typing.Final = 48
    DW_OP_lit1: typing.Final = 49
    DW_OP_lit2: typing.Final = 50
    DW_OP_lit3: typing.Final = 51
    DW_OP_lit4: typing.Final = 52
    DW_OP_lit5: typing.Final = 53
    DW_OP_lit6: typing.Final = 54
    DW_OP_lit7: typing.Final = 55
    DW_OP_lit8: typing.Final = 56
    DW_OP_lit9: typing.Final = 57
    DW_OP_lit10: typing.Final = 58
    DW_OP_lit11: typing.Final = 59
    DW_OP_lit12: typing.Final = 60
    DW_OP_lit13: typing.Final = 61
    DW_OP_lit14: typing.Final = 62
    DW_OP_lit15: typing.Final = 63
    DW_OP_lit16: typing.Final = 64
    DW_OP_lit17: typing.Final = 65
    DW_OP_lit18: typing.Final = 66
    DW_OP_lit19: typing.Final = 67
    DW_OP_lit20: typing.Final = 68
    DW_OP_lit21: typing.Final = 69
    DW_OP_lit22: typing.Final = 70
    DW_OP_lit23: typing.Final = 71
    DW_OP_lit24: typing.Final = 72
    DW_OP_lit25: typing.Final = 73
    DW_OP_lit26: typing.Final = 74
    DW_OP_lit27: typing.Final = 75
    DW_OP_lit28: typing.Final = 76
    DW_OP_lit29: typing.Final = 77
    DW_OP_lit30: typing.Final = 78
    DW_OP_lit31: typing.Final = 79
    DW_OP_reg0: typing.Final = 80
    DW_OP_reg1: typing.Final = 81
    DW_OP_reg2: typing.Final = 82
    DW_OP_reg3: typing.Final = 83
    DW_OP_reg4: typing.Final = 84
    DW_OP_reg5: typing.Final = 85
    DW_OP_reg6: typing.Final = 86
    DW_OP_reg7: typing.Final = 87
    DW_OP_reg8: typing.Final = 88
    DW_OP_reg9: typing.Final = 89
    DW_OP_reg10: typing.Final = 90
    DW_OP_reg11: typing.Final = 91
    DW_OP_reg12: typing.Final = 92
    DW_OP_reg13: typing.Final = 93
    DW_OP_reg14: typing.Final = 94
    DW_OP_reg15: typing.Final = 95
    DW_OP_reg16: typing.Final = 96
    DW_OP_reg17: typing.Final = 97
    DW_OP_reg18: typing.Final = 98
    DW_OP_reg19: typing.Final = 99
    DW_OP_reg20: typing.Final = 100
    DW_OP_reg21: typing.Final = 101
    DW_OP_reg22: typing.Final = 102
    DW_OP_reg23: typing.Final = 103
    DW_OP_reg24: typing.Final = 104
    DW_OP_reg25: typing.Final = 105
    DW_OP_reg26: typing.Final = 106
    DW_OP_reg27: typing.Final = 107
    DW_OP_reg28: typing.Final = 108
    DW_OP_reg29: typing.Final = 109
    DW_OP_reg30: typing.Final = 110
    DW_OP_reg31: typing.Final = 111
    DW_OP_breg0: typing.Final = 112
    DW_OP_breg1: typing.Final = 113
    DW_OP_breg2: typing.Final = 114
    DW_OP_breg3: typing.Final = 115
    DW_OP_breg4: typing.Final = 116
    DW_OP_breg5: typing.Final = 117
    DW_OP_breg6: typing.Final = 118
    DW_OP_breg7: typing.Final = 119
    DW_OP_breg8: typing.Final = 120
    DW_OP_breg9: typing.Final = 121
    DW_OP_breg10: typing.Final = 122
    DW_OP_breg11: typing.Final = 123
    DW_OP_breg12: typing.Final = 124
    DW_OP_breg13: typing.Final = 125
    DW_OP_breg14: typing.Final = 126
    DW_OP_breg15: typing.Final = 127
    DW_OP_breg16: typing.Final = 128
    DW_OP_breg17: typing.Final = 129
    DW_OP_breg18: typing.Final = 130
    DW_OP_breg19: typing.Final = 131
    DW_OP_breg20: typing.Final = 132
    DW_OP_breg21: typing.Final = 133
    DW_OP_breg22: typing.Final = 134
    DW_OP_breg23: typing.Final = 135
    DW_OP_breg24: typing.Final = 136
    DW_OP_breg25: typing.Final = 137
    DW_OP_breg26: typing.Final = 138
    DW_OP_breg27: typing.Final = 139
    DW_OP_breg28: typing.Final = 140
    DW_OP_breg29: typing.Final = 141
    DW_OP_breg30: typing.Final = 142
    DW_OP_breg31: typing.Final = 143
    DW_OP_regx: typing.Final = 144
    DW_OP_fbreg: typing.Final = 145
    DW_OP_bregx: typing.Final = 146
    DW_OP_piece: typing.Final = 147
    DW_OP_deref_size: typing.Final = 148
    DW_OP_xderef_size: typing.Final = 149
    DW_OP_nop: typing.Final = 150
    DW_OP_push_object_address: typing.Final = 151
    DW_OP_call2: typing.Final = 152
    DW_OP_call4: typing.Final = 153
    DW_OP_call_ref: typing.Final = 154
    DW_OP_form_tls_address: typing.Final = 155
    DW_OP_call_frame_cfa: typing.Final = 156
    DW_OP_bit_piece: typing.Final = 157
    DW_OP_implicit_value: typing.Final = 158
    DW_OP_stack_value: typing.Final = 159
    DW_OP_implicit_pointer: typing.Final = 160
    DW_OP_addrx: typing.Final = 161
    DW_OP_constx: typing.Final = 162
    DW_OP_entry_value: typing.Final = 163
    DW_OP_const_type: typing.Final = 164
    DW_OP_regval_type: typing.Final = 165
    DW_OP_deref_type: typing.Final = 166
    DW_OP_xderef_type: typing.Final = 167
    DW_OP_convert: typing.Final = 168
    DW_OP_reinterpret: typing.Final = 169
    DW_OP_lo_user: typing.Final = 224
    DW_OP_hi_user: typing.Final = 255
    UNSUPPORTED_OPCODES_LIST: typing.Final[jpype.JArray[jpype.JInt]]
    """
    These opcodes are known, but can not be evaluated in the current Ghidra DWARF code
    """

    UNSUPPORTED_OPCODES: typing.Final[java.util.Set[java.lang.Integer]]
    """
    These opcodes are known, but can not be evaluated in the current Ghidra DWARF code.
    """

    EMPTY_OPERANDTYPES: typing.Final[jpype.JArray[DWARFExpressionOperandType]]
    BLOBONLY_OPERANDTYPES: typing.Final[jpype.JArray[DWARFExpressionOperandType]]

    def __init__(self):
        ...

    @staticmethod
    def getOperandTypesFor(opcode: typing.Union[jpype.JInt, int]) -> jpype.JArray[DWARFExpressionOperandType]:
        ...

    @staticmethod
    def isValidOpcode(opcode: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def toString(opcode: typing.Union[jpype.JInt, int]) -> str:
        ...


class DWARFExpressionEvaluator(java.lang.Object):
    """
    Evaluates a subset of DWARF expression opcodes.
     
    
    Limitations:
    
    Can not access memory during evaluation of expressions.
    
    Some opcodes must be the last operation in the expression (deref, regX)
    
    Can only specify offset from register for framebase and stack relative
    
     
    
    Result can be a numeric value (ie. static address) or a register 'name' or a stack based offset.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cu: ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit):
        ...

    @typing.overload
    def evaluate(self, exprBytes: jpype.JArray[jpype.JByte]) -> DWARFExpressionResult:
        ...

    @typing.overload
    def evaluate(self, _expr: DWARFExpression, *stackArgs: typing.Union[jpype.JLong, int]) -> DWARFExpressionResult:
        """
        
        
        :param DWARFExpression _expr: 
        :param jpype.JArray[jpype.JLong] stackArgs: - pushed 0..N, so stackArgs[0] will be deepest, stackArgs[N] will be topmost.
        :return: 
        :rtype: DWARFExpressionResult
        :raises DWARFExpressionException:
        """

    @typing.overload
    def evaluate(self, _expr: DWARFExpression) -> DWARFExpressionResult:
        ...

    def getDWARFCompilationUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    def getLastRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def getMaxStepCount(self) -> int:
        ...

    def getRawLastRegister(self) -> int:
        ...

    def getStackAsString(self) -> str:
        ...

    def getTerminalRegister(self) -> ghidra.program.model.lang.Register:
        """
        Returns the :obj:`register <Register>` that holds the contents of the object that the
        :obj:`expression <DWARFExpression>` points to.
         
        
        Note, you should check :meth:`isDeref() <.isDeref>` to see if the register is just a pointer
        to the object instead of the object itself.
        
        :return: 
        :rtype: ghidra.program.model.lang.Register
        """

    def isDeref(self) -> bool:
        ...

    def isDwarfStackValue(self) -> bool:
        ...

    def isRegisterLocation(self) -> bool:
        ...

    def isStackRelative(self) -> bool:
        ...

    def peek(self) -> int:
        ...

    def pop(self) -> int:
        ...

    def push(self, l: typing.Union[jpype.JLong, int]):
        ...

    def readExpr(self, exprBytes: jpype.JArray[jpype.JByte]) -> DWARFExpression:
        ...

    def setFrameBase(self, fb: typing.Union[jpype.JLong, int]):
        ...

    def setMaxStepCount(self, maxStepCount: typing.Union[jpype.JInt, int]):
        ...

    def useUnknownRegister(self) -> bool:
        ...

    @property
    def dwarfStackValue(self) -> jpype.JBoolean:
        ...

    @property
    def registerLocation(self) -> jpype.JBoolean:
        ...

    @property
    def deref(self) -> jpype.JBoolean:
        ...

    @property
    def rawLastRegister(self) -> jpype.JInt:
        ...

    @property
    def stackRelative(self) -> jpype.JBoolean:
        ...

    @property
    def maxStepCount(self) -> jpype.JInt:
        ...

    @maxStepCount.setter
    def maxStepCount(self, value: jpype.JInt):
        ...

    @property
    def lastRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def dWARFCompilationUnit(self) -> ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit:
        ...

    @property
    def stackAsString(self) -> java.lang.String:
        ...

    @property
    def terminalRegister(self) -> ghidra.program.model.lang.Register:
        ...


class DWARFExpressionException(java.lang.Exception):
    """
    A exception that is thrown when dealing with :obj:`DWARF expressions <DWARFExpression>`
    or when they are :obj:`evaluated. <DWARFExpressionEvaluator>`
     
    
    Use this class when you want to pass the :obj:`expression <DWARFExpression>` and
    the opcode / step in the expression that caused the problem back up the call chain.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], expr: DWARFExpression, step: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], expr: DWARFExpression, step: typing.Union[jpype.JInt, int], cause: java.lang.Throwable):
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

    def getMessage(self) -> str:
        ...

    def getStep(self) -> int:
        ...

    def setExpression(self, expr: DWARFExpression):
        ...

    def setStep(self, step: typing.Union[jpype.JInt, int]):
        ...

    @property
    def expression(self) -> DWARFExpression:
        ...

    @expression.setter
    def expression(self, value: DWARFExpression):
        ...

    @property
    def step(self) -> jpype.JInt:
        ...

    @step.setter
    def step(self, value: jpype.JInt):
        ...

    @property
    def message(self) -> java.lang.String:
        ...


class DWARFExpression(java.lang.Object):
    """
    A :obj:`DWARFExpression` is an immutable list of :obj:`operations <DWARFExpressionOperation>` and some factory methods to read
    an expression from its binary representation.
     
    
    Use a :obj:`DWARFExpressionEvaluator` to execute a :obj:`DWARFExpression`.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_SANE_EXPR: typing.Final = 256

    @staticmethod
    def exprToString(exprBytes: jpype.JArray[jpype.JByte], diea: ghidra.app.util.bin.format.dwarf.DIEAggregate) -> str:
        ...

    def findOpByOffset(self, offset: typing.Union[jpype.JLong, int]) -> int:
        """
        Finds the index of an :obj:`operation <DWARFExpressionOperation>` by its offset
        from the beginning of the expression.
        
        :param jpype.JLong or int offset: 
        :return: -1 if there is no op at the specified offset
        :rtype: int
        """

    def getLastActiveOpIndex(self) -> int:
        """
        Returns the index of the last operation that is not a NOP.
        
        :return: 
        :rtype: int
        """

    def getOp(self, i: typing.Union[jpype.JInt, int]) -> DWARFExpressionOperation:
        ...

    def getOpCount(self) -> int:
        ...

    @staticmethod
    @typing.overload
    def read(exprBytes: jpype.JArray[jpype.JByte], addrSize: typing.Union[jpype.JByte, int], isLittleEndian: typing.Union[jpype.JBoolean, bool], intSize: typing.Union[jpype.JInt, int]) -> DWARFExpression:
        ...

    @staticmethod
    @typing.overload
    def read(reader: ghidra.app.util.bin.BinaryReader, addrSize: typing.Union[jpype.JByte, int], intSize: typing.Union[jpype.JInt, int]) -> DWARFExpression:
        ...

    def toString(self, caretPosition: typing.Union[jpype.JInt, int], newlines: typing.Union[jpype.JBoolean, bool], offsets: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @property
    def op(self) -> DWARFExpressionOperation:
        ...

    @property
    def opCount(self) -> jpype.JInt:
        ...

    @property
    def lastActiveOpIndex(self) -> jpype.JInt:
        ...



__all__ = ["DWARFExpressionResult", "DWARFExpressionOperandType", "DWARFExpressionOperation", "DWARFExpressionEvaluatorContext", "DWARFExpressionOpCodes", "DWARFExpressionEvaluator", "DWARFExpressionException", "DWARFExpression"]
