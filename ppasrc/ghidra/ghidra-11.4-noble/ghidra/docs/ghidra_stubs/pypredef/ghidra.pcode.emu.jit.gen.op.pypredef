from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.op
import ghidra.program.model.pcode
import java.lang # type: ignore
import org.objectweb.asm # type: ignore


T = typing.TypeVar("T")
TB = typing.TypeVar("TB")
TO = typing.TypeVar("TO")


class FloatTruncOpGen(java.lang.Enum[FloatTruncOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatTruncOp]):
    """
    The generator for a :obj:`float_trunc <JitFloatTruncOp>`.
     
     
    
    This uses the unary operator generator and emits :obj:`.F2I`, :obj:`.F2L`, :obj:`.D2I`, or
    :obj:`.D2L`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatTruncOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatTruncOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatTruncOpGen]:
        ...


class CompareFloatOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for float comparison operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def condOpcode(self) -> int:
        """
        The JVM opcode to perform the conditional jump.
         
         
        
        The condition should correspond to the true case of the p-code operator.
        
        :return: the opcode
        :rtype: int
        """

    def dcmpOpcode(self) -> int:
        """
        The JVM opcode to perform the comparison with double operands on the stack.
        
        :return: the opcode
        :rtype: int
        """

    def fcmpOpcode(self) -> int:
        """
        The JVM opcode to perform the comparison with float operands on the stack.
        
        :return: the opcode
        :rtype: int
        """


class IntLessOpGen(java.lang.Enum[IntLessOpGen], CompareIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntLessOp]):
    """
    The generator for a :obj:`int_less <JitIntLessOp>`.
     
     
    
    This uses the integer comparison operator generator and simply emits :obj:`.IFLT`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntLessOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntLessOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntLessOpGen]:
        ...


class IntLeftOpGen(java.lang.Enum[IntLeftOpGen], ShiftIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntLeftOp]):
    """
    The generator for a :obj:`int_left <JitIntLeftOp>`.
     
     
    
    This uses the integer shift operator generator and simply invokes
    :meth:`JitCompiledPassage.intLeft(int, int) <JitCompiledPassage.intLeft>`, etc. depending on the types.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntLeftOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntLeftOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntLeftOpGen]:
        ...


class FloatDivOpGen(java.lang.Enum[FloatDivOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitFloatDivOp]):
    """
    The generator for a :obj:`float_div <JitFloatDivOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.FDIV` or :obj:`.DDIV` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatDivOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatDivOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatDivOpGen]:
        ...


class FloatNaNOpGen(java.lang.Enum[FloatNaNOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatNaNOp]):
    """
    The generator for a :obj:`float_nan <JitFloatNaNOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of :meth:`Float.isNaN(float) <Float.isNaN>` or
    :meth:`Double.isNaN(double) <Double.isNaN>`, depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatNaNOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatNaNOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatNaNOpGen]:
        ...


class FloatAbsOpGen(java.lang.Enum[FloatAbsOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatAbsOp]):
    """
    The generator for a :obj:`float_abs <JitFloatAbsOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of :meth:`Math.abs(float) <Math.abs>` or
    :meth:`Math.abs(double) <Math.abs>`, depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatAbsOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatAbsOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatAbsOpGen]:
        ...


class BranchIndOpGen(java.lang.Enum[BranchIndOpGen], OpGen[ghidra.pcode.emu.jit.op.JitBranchIndOp]):
    """
    The generator for a :obj:`branchind <JitBranchIndOp>`.
     
     
    
    This emits code to load the target from the operand and then retire it to the program counter,
    along with the current flow context and live variables. It then emits code to return null so that
    the :obj:`thread <JitPcodeThread>` knows to loop to the **Fetch** step for the new counter.
    """

    @typing.type_check_only
    class IndBranchGen(BranchOpGen.BranchGen[ghidra.pcode.emu.jit.JitPassage.RIndBranch, ghidra.pcode.emu.jit.op.JitBranchIndOp]):
        """
        A branch code generator for indirect branches
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[BranchIndOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BranchIndOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[BranchIndOpGen]:
        ...


class IntMultOpGen(java.lang.Enum[IntMultOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntMultOp]):
    """
    The generator for a :obj:`int_mult <JitIntMultOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.IMUL` or :obj:`.LMUL` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntMultOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntMultOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntMultOpGen]:
        ...


class IntOrOpGen(java.lang.Enum[IntOrOpGen], BitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitIntOrOp]):
    """
    The generator for a :obj:`int_or <JitIntOrOp>`.
     
     
    
    This uses the bitwise binary operator and emits :obj:`.IOR` or :obj:`.LOR` depending on the
    type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntOrOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntOrOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntOrOpGen]:
        ...


class IntRightOpGen(java.lang.Enum[IntRightOpGen], ShiftIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntRightOp]):
    """
    The generator for a :obj:`int_right <JitIntRightOp>`.
     
     
    
    This uses the integer shift operator generator and simply invokes
    :meth:`JitCompiledPassage.intRight(int, int) <JitCompiledPassage.intRight>`, etc. depending on the types.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntRightOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntRightOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntRightOpGen]:
        ...


class BoolAndOpGen(java.lang.Enum[BoolAndOpGen], BitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitBoolAndOp]):
    """
    The generator for a :obj:`bool_and <JitBoolAndOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolAnd`. Thus, this is identical to :obj:`IntAndOpGen`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[BoolAndOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BoolAndOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[BoolAndOpGen]:
        ...


class FloatNegOpGen(java.lang.Enum[FloatNegOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatNegOp]):
    """
    The generator for a :obj:`float_neg <JitFloatNegOp>`.
     
     
    
    This uses the unary operator generator and emits :obj:`.FNEG` or :obj:`.DNEG`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatNegOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatNegOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatNegOpGen]:
        ...


class BinOpGen(OpGen[T], typing.Generic[T]):
    """
    An extension that provides conveniences and common implementations for binary p-code operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def afterLeft(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: T, lType: ghidra.pcode.emu.jit.analysis.JitType, rType: ghidra.pcode.emu.jit.analysis.JitType, rv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit code between reading the left and right operands
         
         
        
        This is invoked immediately after emitting code to push the left operand onto the stack,
        giving the implementation an opportunity to perform any manipulations of that operand
        necessary to set up the operation, before code to push the right operand is emitted.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param T op: the operator
        :param ghidra.pcode.emu.jit.analysis.JitType lType: the actual type of the left operand
        :param ghidra.pcode.emu.jit.analysis.JitType rType: the actual type of the right operand
        :param org.objectweb.asm.MethodVisitor rv: the method visitor
        :return: the new actual type of the left operand
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    def generateBinOpRunCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: T, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, lType: ghidra.pcode.emu.jit.analysis.JitType, rType: ghidra.pcode.emu.jit.analysis.JitType, rv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit code for the binary operator
         
         
        
        At this point both operands are on the stack. After this returns, code to write the result
        from the stack into the destination operand will be emitted.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param T op: the operator
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the operator
        :param ghidra.pcode.emu.jit.analysis.JitType lType: the actual type of the left operand
        :param ghidra.pcode.emu.jit.analysis.JitType rType: the actual type of the right operand
        :param org.objectweb.asm.MethodVisitor rv: the method visitor
        :return: the actual type of the result
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """


class CopyOpGen(java.lang.Enum[CopyOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitCopyOp]):
    """
    The generator for a :obj:`copy <JitCopyOp>`.
     
     
    
    This uses the unary operator generator and emits nothing extra. The unary generator template will
    emit code to load the input operand, this emits nothing, and then the template emits code to
    write the output operand, effecting a simple copy.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[CopyOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CopyOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[CopyOpGen]:
        ...


class CatenateOpGen(java.lang.Enum[CatenateOpGen], OpGen[ghidra.pcode.emu.jit.op.JitCatenateOp]):
    """
    The generator for a :obj:`catenate <JitCatenateOp>`.
     
     
    
    We emit nothing. This generator ought never to be invoked, anyway, but things may change. The
    argument here is similar to that of :obj:`PhiOpGen`.
    
    
    .. seealso::
    
        | :obj:`JitVarScopeModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[CatenateOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CatenateOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[CatenateOpGen]:
        ...


class IntSRightOpGen(java.lang.Enum[IntSRightOpGen], ShiftIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntSRightOp]):
    """
    The generator for a :obj:`int_sright <JitIntSRightOp>`.
     
     
    
    This uses the integer shift operator generator and simply invokes
    :meth:`JitCompiledPassage.intSRight(int, int) <JitCompiledPassage.intSRight>`, etc. depending on the types.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSRightOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSRightOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSRightOpGen]:
        ...


class NopOpGen(java.lang.Enum[NopOpGen], OpGen[ghidra.pcode.emu.jit.op.JitOp]):
    """
    The generator for a :obj:`nop <JitNopOp>`.
     
     
    
    We emit nothing.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[NopOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> NopOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[NopOpGen]:
        ...


class ShiftIntBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for integer shift operators
     
     
    
    This is just going to invoke one of the :meth:`JitCompiledPassage.intLeft(int, int) <JitCompiledPassage.intLeft>`,
    :meth:`JitCompiledPassage.intRight(int, int) <JitCompiledPassage.intRight>`, :meth:`JitCompiledPassage.intSRight(int, int) <JitCompiledPassage.intSRight>`,
    etc. methods, depending on the operand types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def methodName(self) -> str:
        """
        The name of the static method in :obj:`JitCompiledPassage` to invoke
        
        :return: the name
        :rtype: str
        """


class IntAddOpGen(java.lang.Enum[IntAddOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntAddOp]):
    """
    The generator for a :obj:`int_add <JitIntAddOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.IADD` or :obj:`.LADD` depending
    on the type.
     
     
    
    NOTE: The multi-precision integer parts of this are a work in progress.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntAddOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntAddOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntAddOpGen]:
        ...


class IntRemOpGen(java.lang.Enum[IntRemOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntRemOp]):
    """
    The generator for a :obj:`int_rem <JitIntRemOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.INVOKESTATIC` on
    :meth:`Integer.remainderUnsigned(int, int) <Integer.remainderUnsigned>` or :meth:`Long.remainderUnsigned(long, long) <Long.remainderUnsigned>`
    depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntRemOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntRemOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntRemOpGen]:
        ...


class IntSCarryOpGen(java.lang.Enum[IntSCarryOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntSCarryOp]):
    """
    The generator for a :obj:`int_scarry <JitIntSCarryOp>`.
     
     
    
    This uses the binary operator generator and emits :obj:`.INVOKESTATIC` on
    :meth:`JitCompiledPassage.sCarryIntRaw(int, int) <JitCompiledPassage.sCarryIntRaw>` or
    :meth:`JitCompiledPassage.sCarryLongRaw(long, long) <JitCompiledPassage.sCarryLongRaw>` depending on the type. We must then emit a
    shift and mask to extract the correct bit.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSCarryOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSCarryOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSCarryOpGen]:
        ...


class IntSDivOpGen(java.lang.Enum[IntSDivOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntSDivOp]):
    """
    The generator for a :obj:`int_sdiv <JitIntSDivOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.IDIV` or :obj:`.LDIV` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSDivOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSDivOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSDivOpGen]:
        ...


class FloatFloorOpGen(java.lang.Enum[FloatFloorOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatFloorOp]):
    """
    The generator for a :obj:`float_floor <JitFloatFloorOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of :meth:`Math.floor(double) <Math.floor>`,
    possibly surrounding it with conversions from and to float.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatFloorOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatFloorOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatFloorOpGen]:
        ...


class IntLessEqualOpGen(java.lang.Enum[IntLessEqualOpGen], CompareIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntLessEqualOp]):
    """
    The generator for a :obj:`int_lessequal <JitIntLessEqualOp>`.
     
     
    
    This uses the integer comparison operator generator and simply emits :obj:`.IFLE`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntLessEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntLessEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntLessEqualOpGen]:
        ...


class Int2CompOpGen(java.lang.Enum[Int2CompOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitInt2CompOp]):
    """
    The generator for a :obj:`int_2comp <JitInt2CompOp>`.
     
     
    
    This uses the unary operator generator and emits :obj:`.INEG` or :obj:`.LNEG`, depending on
    type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[Int2CompOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Int2CompOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[Int2CompOpGen]:
        ...


class IntAndOpGen(java.lang.Enum[IntAndOpGen], BitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitIntAndOp]):
    """
    The generator for a :obj:`int_and <JitIntAndOp>`.
     
     
    
    This uses the bitwise binary operator and emits :obj:`.IAND` or :obj:`.LAND` depending on the
    type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntAndOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntAndOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntAndOpGen]:
        ...


class IntEqualOpGen(java.lang.Enum[IntEqualOpGen], CompareIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntEqualOp]):
    """
    The generator for a :obj:`int_equal <JitIntEqualOp>`.
     
     
    
    This uses the integer comparison operator generator and simply emits :obj:`.IF_ICMPEQ` or
    :obj:`.IFEQ` depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntEqualOpGen]:
        ...


class FloatFloat2FloatOpGen(java.lang.Enum[FloatFloat2FloatOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatFloat2FloatOp]):
    """
    The generator for a :obj:`float_float2float <JitFloatFloat2FloatOp>`.
     
     
    
    This uses the unary operator generator and emits :obj:`.F2D` or :obj:`.D2F`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatFloat2FloatOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatFloat2FloatOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatFloat2FloatOpGen]:
        ...


class IntSLessEqualOpGen(java.lang.Enum[IntSLessEqualOpGen], CompareIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntSLessEqualOp]):
    """
    The generator for a :obj:`int_slessequal <JitIntSLessEqualOp>`.
     
     
    
    This uses the integer comparison operator generator and simply emits :obj:`.IF_ICMPLE` or
    :obj:`.IFLE` depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSLessEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSLessEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSLessEqualOpGen]:
        ...


class IntSubOpGen(java.lang.Enum[IntSubOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntSubOp]):
    """
    The generator for a :obj:`int_sub <JitIntSubOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.ISUB` or :obj:`.LSUB` depending
    on the type.
     
     
    
    NOTE: The multi-precision integer parts of this are a work in progress.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSubOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSubOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSubOpGen]:
        ...


class FloatCeilOpGen(java.lang.Enum[FloatCeilOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatCeilOp]):
    """
    The generator for a :obj:`float_ceil <JitFloatCeilOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of :meth:`Math.ceil(double) <Math.ceil>`,
    possibly surrounding it with conversions from and to float.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatCeilOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatCeilOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatCeilOpGen]:
        ...


class UnOpGen(OpGen[T], typing.Generic[T]):
    """
    An extension that provides conveniences and common implementations for unary p-code operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateUnOpRunCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: T, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, uType: ghidra.pcode.emu.jit.analysis.JitType, rv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit code for the unary operator
         
         
        
        At this point the operand is on the stack. After this returns, code to write the result from
        the stack into the destination operand will be emitted.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param T op: the operator
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the operator
        :param ghidra.pcode.emu.jit.analysis.JitType uType: the actual type of the operand
        :param org.objectweb.asm.MethodVisitor rv: the method visitor
        :return: the actual type of the result
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """


class BoolOrOpGen(java.lang.Enum[BoolOrOpGen], BitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitBoolOrOp]):
    """
    The generator for a :obj:`bool_or <JitBoolOrOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolOr`. Thus, this is identical to :obj:`IntOrOpGen`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[BoolOrOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BoolOrOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[BoolOrOpGen]:
        ...


class FloatLessOpGen(java.lang.Enum[FloatLessOpGen], CompareFloatOpGen[ghidra.pcode.emu.jit.op.JitFloatLessOp]):
    """
    The generator for a :obj:`float_less <JitFloatLessOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :obj:`.FCMPG` or
    :obj:`.DCMPG` depending on the type and then :obj:`.IFLT`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatLessOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatLessOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatLessOpGen]:
        ...


class IntCarryOpGen(java.lang.Enum[IntCarryOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntCarryOp]):
    """
    The generator for a :obj:`int_carry <JitIntCarryOp>`.
     
     
    
    This uses the binary operator generator. First we have to consider which strategy we are going to
    use. If the p-code type is strictly smaller than its host JVM type, we can simply add the two
    operands and examine the next bit up. This is accomplished by emitting :obj:`.IADD` or
    :obj:`.LADD`, depending on the type, followed by a shift right and a mask.
     
     
    
    If the p-code type exactly fits its host JVM type, we still add, but we will need to compare the
    result to one of the operands. Thus, we override
    :meth:`afterLeft <.afterLeft>`
    and emit code to duplicate the left operand. We can then add and invoke
    :meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>` to determine whether there was overflow. If there was,
    then we know the carry bit would have been set. We can spare the conditional flow by just
    shifting the sign bit into the 1's place.
     
     
    
    NOTE: The multi-precision integer parts of this are a work in progress.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntCarryOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntCarryOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntCarryOpGen]:
        ...


class BitwiseBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for bitwise binary operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateMpIntBinOp(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, mv: org.objectweb.asm.MethodVisitor):
        """
        **WIP**: The implementation for multi-precision ints.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the type of each operand, including the reuslt
        :param org.objectweb.asm.MethodVisitor mv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def intOpcode(self) -> int:
        """
        The JVM opcode to implement this operator with int operands on the stack.
        
        :return: the opcode
        :rtype: int
        """

    def longOpcode(self) -> int:
        """
        The JVM opcode to implement this operator with long operands on the stack.
        
        :return: the opcode
        :rtype: int
        """


class UnimplementedOpGen(java.lang.Enum[UnimplementedOpGen], OpGen[ghidra.pcode.emu.jit.op.JitUnimplementedOp]):
    """
    The generator for a :obj:`unimplemented <JitUnimplementedOp>`.
     
     
    
    This emits code to retire the program counter, context, and live variables, then throw a
    :obj:`DecodePcodeExecutionException` or :obj:`LowlevelError`. The former case is constructed by
    :meth:`JitCompiledPassage.createDecodeError(String, long) <JitCompiledPassage.createDecodeError>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[UnimplementedOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> UnimplementedOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[UnimplementedOpGen]:
        ...


class FloatMultOpGen(java.lang.Enum[FloatMultOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitFloatMultOp]):
    """
    The generator for a :obj:`float_mult <JitFloatMultOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.FMUL` or :obj:`.DMUL` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatMultOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatMultOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatMultOpGen]:
        ...


class FloatInt2FloatOpGen(java.lang.Enum[FloatInt2FloatOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatInt2FloatOp]):
    """
    The generator for a :obj:`float_int2float <JitFloatInt2FloatOp>`.
     
     
    
    This uses the unary operator generator and emits :obj:`.I2F`, :obj:`.I2D`, :obj:`.L2F`, or
    :obj:`.L2D`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatInt2FloatOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatInt2FloatOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatInt2FloatOpGen]:
        ...


class IntZExtOpGen(java.lang.Enum[IntZExtOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitIntZExtOp]):
    """
    The generator for a :obj:`int_zext <JitIntZExtOp>`.
     
     
    
    This uses the unary operator generator and emits nothing extra. The unary generator template will
    emit code to load the input operand, this emits nothing, and then the template emits code to
    write the output operand, including the necessary type conversion. That type conversion performs
    the zero extension.
     
     
    
    Note that this implementation is equivalent to :obj:`CopyOpGen`, except that differences in
    operand sizes are expected.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntZExtOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntZExtOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntZExtOpGen]:
        ...


class PhiOpGen(java.lang.Enum[PhiOpGen], OpGen[ghidra.pcode.emu.jit.op.JitPhiOp]):
    """
    The generator for a :obj:`phi <JitPhiOp>`.
     
     
    
    We emit nothing. This generator ought not to be invoked, anyway, but things may change. In the
    meantime, the design is that we allocate a JVM local per varnode. Since phi nodes are meant to
    track possible definitions of the *same* varnode, there is no need to a phi node to emit
    any code. The value, whichever option it happens to be, is already in its local variable.
    
    
    .. seealso::
    
        | :obj:`JitVarScopeModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[PhiOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PhiOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[PhiOpGen]:
        ...


class FloatSubOpGen(java.lang.Enum[FloatSubOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitFloatSubOp]):
    """
    The generator for a :obj:`float_sub <JitFloatSubOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.FSUB` or :obj:`.DSUB` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatSubOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatSubOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatSubOpGen]:
        ...


class FloatSqrtOpGen(java.lang.Enum[FloatSqrtOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatSqrtOp]):
    """
    The generator for a :obj:`float_sqrt <JitFloatSqrtOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of :meth:`Math.sqrt(double) <Math.sqrt>`,
    possibly surrounding it with conversions from and to float.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatSqrtOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatSqrtOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatSqrtOpGen]:
        ...


class BranchOpGen(java.lang.Enum[BranchOpGen], OpGen[ghidra.pcode.emu.jit.op.JitBranchOp]):
    """
    The generator for a :obj:`branch <JitBranchOp>`.
     
     
    
    With an :obj:`IntBranch` record, this simply looks up the label for the target block and emits a
    block transition followed by a :obj:`goto <.GOTO>`.
     
     
    
    With an :obj:`ExtBranch` record, this emits code to retire the target to the program counter,
    along with the target context and live variables. It then emits code to request the chained entry
    point from the target's exit slot and return it. The :obj:`thread <JitPcodeThread>` can then
    immediately execute the chained passage entry.
    """

    @typing.type_check_only
    class BranchGen(java.lang.Object, typing.Generic[TB, TO]):
        """
        A branch code generator
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IntBranchGen(BranchOpGen.BranchGen[ghidra.pcode.emu.jit.JitPassage.RIntBranch, ghidra.pcode.emu.jit.op.JitOp]):
        """
        A branch code generator for internal branches
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtBranchGen(BranchOpGen.BranchGen[ghidra.pcode.emu.jit.JitPassage.RExtBranch, ghidra.pcode.emu.jit.op.JitOp]):
        """
        A branch code generator for external branches
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[BranchOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BranchOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[BranchOpGen]:
        ...


class CallOtherOpGen(java.lang.Enum[CallOtherOpGen], OpGen[ghidra.pcode.emu.jit.op.JitCallOtherOpIf]):
    """
    The generator for a :obj:`callother <JitCallOtherOpIf>`.
     
     
    
    The checks if Direct invocation is possible. If so, it emits code using
    :meth:`generateRunCodeUsingDirectStrategy(JitCodeGenerator, JitCallOtherOpIf, JitBlock, MethodVisitor) <.generateRunCodeUsingDirectStrategy>`.
    If not, it emits code using
    :meth:`generateRunCodeUsingRetirementStrategy(JitCodeGenerator, PcodeOp, JitBlock, PcodeUseropDefinition, MethodVisitor) <.generateRunCodeUsingRetirementStrategy>`.
    Direct invocation is possible when the userop is :meth:`functional <PcodeUseropDefinition.isFunctional>` and all of its parameters and return type have a supported primitive type.
    (``char`` is not supported.) Regarding the invocation strategies, see
    :obj:`JitDataFlowUseropLibrary` and note that the Inline strategy is already handled by this
    point.
     
     
    
    For the Standard strategy, we emit code to retire the program counter, decode context, and all
    live variables. We then request a field to hold the userop and emit code to load it. We then emit
    code to prepare its arguments and place them on the stack, namely the output varnode and an array
    for the input varnodes. We request a field for each varnode and emit code to load them as needed.
    For the array, we emit code to construct and fill it. We then emit code to invoke
    :meth:`JitCompiledPassage.invokeUserop(PcodeUseropDefinition, Varnode, Varnode[]) <JitCompiledPassage.invokeUserop>`. The userop
    definition handles retrieving all of its inputs and writing the output, directly to the
    :obj:`state <JitBytesPcodeExecutorState>`. Thus, we now need only to emit code to re-birth all the
    live variables. If any errors occur, execution is interrupted as usual, and our state is
    consistent.
     
     
    
    For the Direct strategy, we wish to avoid retirement and re-birth, so we request an
    :obj:`ExceptionHandler`. We request a field for the userop, just as in the Standard strategy,
    but we emit code to invoke :meth:`PcodeUseropDefinition.getDefiningLibrary() <PcodeUseropDefinition.getDefiningLibrary>` instead. We can use
    :meth:`PcodeUseropDefinition.getJavaMethod() <PcodeUseropDefinition.getJavaMethod>` *at generation time* to reflect its Java
    definition. We then emit code to cast the library and load each of the operands onto the JVM
    stack. We then emit the invocation of the Java method, guarded by the exception handler. We then
    have to consider whether the userop has an output operand and whether its definition returns a
    value. If both are true, we emit code to write the result. If neither is true, we're done. If a
    result is returned, but no output operand is provided, we *must* still emit a :obj:`pop <.POP>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[CallOtherOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def canDoDirectInvocation(op: ghidra.pcode.emu.jit.op.JitCallOtherOpIf) -> bool:
        """
        Check if the Direct invocation strategy is applicable (see class documentation)
        
        :param ghidra.pcode.emu.jit.op.JitCallOtherOpIf op: the p-code op use-def node
        :return: true if applicable
        :rtype: bool
        """

    @staticmethod
    def generateRunCodeUsingDirectStrategy(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: ghidra.pcode.emu.jit.op.JitCallOtherOpIf, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit code to implement the Direct strategy (see the class documentation)
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.op.JitCallOtherOpIf op: the p-code op use-def node
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    def generateRunCodeUsingRetirementStrategy(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: ghidra.program.model.pcode.PcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any], rv: org.objectweb.asm.MethodVisitor):
        """
        Emit code to implement the Standard strategy (see the class documentation)
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        :param ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any] userop: the userop definition, wrapped by the :obj:`JitDataFlowUseropLibrary`
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CallOtherOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[CallOtherOpGen]:
        ...


class IntSBorrowOpGen(java.lang.Enum[IntSBorrowOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntSBorrowOp]):
    """
    The generator for a :obj:`int_sborrow <JitIntSBorrowOp>`.
     
     
    
    This uses the binary operator generator and emits :obj:`.INVOKESTATIC` on
    :meth:`JitCompiledPassage.sBorrowIntRaw(int, int) <JitCompiledPassage.sBorrowIntRaw>` or
    :meth:`JitCompiledPassage.sBorrowLongRaw(long, long) <JitCompiledPassage.sBorrowLongRaw>` depending on the type. We must then emit a
    shift and mask to extract the correct bit.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSBorrowOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSBorrowOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSBorrowOpGen]:
        ...


class FloatNotEqualOpGen(java.lang.Enum[FloatNotEqualOpGen], CompareFloatOpGen[ghidra.pcode.emu.jit.op.JitFloatNotEqualOp]):
    """
    The generator for a :obj:`float_notequal <JitFloatNotEqualOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :obj:`.FCMPL` or
    :obj:`.DCMPL` depending on the type and then :obj:`.IFNE`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatNotEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatNotEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatNotEqualOpGen]:
        ...


class BoolNegateOpGen(java.lang.Enum[BoolNegateOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitBoolNegateOp]):
    """
    The generator for a :obj:`bool_negate <JitBoolNegateOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolNegate`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[BoolNegateOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BoolNegateOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[BoolNegateOpGen]:
        ...


class CallOtherMissingOpGen(java.lang.Enum[CallOtherMissingOpGen], OpGen[ghidra.pcode.emu.jit.op.JitCallOtherMissingOp]):
    """
    The generator for a :obj:`callother-missing <JitCallOtherMissingOp>`.
     
     
    
    This emits code to retire the program counter, context, and live variables, then throw a
    :obj:`SleighLinkException`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[CallOtherMissingOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CallOtherMissingOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[CallOtherMissingOpGen]:
        ...


class LzCountOpGen(java.lang.Enum[LzCountOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitLzCountOp]):
    """
    The generator for a :obj:`lzcount <JitLzCountOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of
    :meth:`Integer.numberOfLeadingZeros(int) <Integer.numberOfLeadingZeros>` or :meth:`Long.numberOfLeadingZeros(long) <Long.numberOfLeadingZeros>`, depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[LzCountOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LzCountOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[LzCountOpGen]:
        ...


class FloatEqualOpGen(java.lang.Enum[FloatEqualOpGen], CompareFloatOpGen[ghidra.pcode.emu.jit.op.JitFloatEqualOp]):
    """
    The generator for a :obj:`float_equal <JitFloatEqualOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :obj:`.FCMPL` or
    :obj:`.DCMPL` depending on the type and then :obj:`.IFEQ`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatEqualOpGen]:
        ...


class CBranchOpGen(java.lang.Enum[CBranchOpGen], OpGen[ghidra.pcode.emu.jit.op.JitCBranchOp]):
    """
    The generator for a :obj:`cbranch <JitCBranchOp>`.
     
     
    
    First, emits code to load the condition onto the JVM stack.
     
     
    
    With an :obj:`IntBranch` record, this looks up the label for the target block and checks if a
    transition is necessary. If one is necessary, it emits an :obj:`ifeq <.IFEQ>` with the transition
    and :obj:`goto <.GOTO>` it guards. The ``ifeq`` skips to the fall-through case. If a
    transition is not necessary, it simply emits an :obj:`ifne <.IFNE>` to the target label.
     
     
    
    With an :obj:`ExtBranch` record, this does the same as :obj:`BranchOpGen` but guarded by an
    :obj:`ifeq <.IFEQ>` that skips to the fall-through case.
    """

    @typing.type_check_only
    class IntCBranchGen(BranchOpGen.IntBranchGen):
        """
        A branch code generator for internal conditional branches
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtCBranchGen(BranchOpGen.ExtBranchGen):
        """
        A branch code generator for external conditional branches
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[CBranchOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CBranchOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[CBranchOpGen]:
        ...


class BoolXorOpGen(java.lang.Enum[BoolXorOpGen], BitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitBoolXorOp]):
    """
    The generator for a :obj:`bool_xor <JitBoolXorOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolXor`. Thus, this is identical to :obj:`IntXorOpGen`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[BoolXorOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BoolXorOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[BoolXorOpGen]:
        ...


class SubPieceOpGen(java.lang.Enum[SubPieceOpGen], OpGen[ghidra.pcode.emu.jit.op.JitSubPieceOp]):
    """
    The generator for a :obj:`subpiece <JitSubPieceOp>`.
     
     
    
    NOTE: The multi-precision int parts of this are a work in progress.
     
     
    
    This is not quite like a normal binary operator, because the second operand is always a constant.
    It behaves more like a class of unary operators, if you ask me. Thus, we do not extend
    :obj:`BinOpGen`. We first emit code to load the operand. Then, because the shift amount is
    constant, we can deal with it at *generation time*. We emit code to shift right by that
    constant amount, accounting for bits and bytes. The masking, if required, is taken care of by the
    variable writing code, given the resulting type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[SubPieceOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SubPieceOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[SubPieceOpGen]:
        ...


class LoadOpGen(java.lang.Enum[LoadOpGen], OpGen[ghidra.pcode.emu.jit.op.JitLoadOp]):
    """
    The generator for a :obj:`load <JitLoadOp>`.
     
     
    
    These ops are currently presumed to be indirect memory accesses. **TODO**: If we fold
    constants, we could convert some of these to direct.
     
     
    
    We request a field to pre-fetch the :obj:`space <JitBytesPcodeExecutorStateSpace>` and emit code
    to load it onto the stack. We then emit code to load the offset onto the stack and convert it to
    a JVM long, if necessary. The varnode size is loaded by emitting an :obj:`ldc <Opcodes.LDC>`, and
    finally we emit an invocation of :meth:`JitBytesPcodeExecutorStateSpace.read(long, int) <JitBytesPcodeExecutorStateSpace.read>`. The
    result is a byte array, so we finish by emitting the appropriate conversion and write the result
    to the output operand.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[LoadOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LoadOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[LoadOpGen]:
        ...


class IntSExtOpGen(java.lang.Enum[IntSExtOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitIntSExtOp]):
    """
    The generator for a :obj:`int_sext <JitIntSExtOp>`.
     
     
    
    We implement this using a left then signed-right shift. This uses the unary operator generator
    and emits :obj:`.ISHL` and :obj:`.ISHR` or :obj:`.LSHL` and :obj:`.LSHR`, depending on type.
    Additional type conversions may be emitted first. As a special case, sign extension from
    :obj:`int4 <IntJitType.I4>` to :obj:`int8 <LongJitType.I8>` is implemented with by emitting only
    :obj:`.I2L`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSExtOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSExtOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSExtOpGen]:
        ...


class OpGen(org.objectweb.asm.Opcodes, typing.Generic[T]):
    """
    The bytecode generator for a specific p-code op
     
     
    
    The :obj:`JitCodeGenerator` selects the correct generator for each :obj:`PcodeOp` using
    :meth:`JitDataFlowModel.getJitOp(PcodeOp) <JitDataFlowModel.getJitOp>` and :meth:`lookup(JitOp) <.lookup>`. The following table lists
    each p-code op, its use-def class, its generator class, and a brief strategy for its bytecode
    implementation.
     
     
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                      P-code Op                       |         Use-Def Type          |        Generator Type         |                                                        Bytecodes / Methods                                                        |
    +======================================================+===============================+===============================+===================================================================================================================================+
    |*Misc Data*                                           |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`unimplemented <PcodeOp.UNIMPLEMENTED>`          |:obj:`JitUnimplementedOp`      |:obj:`UnimplementedOpGen`      |:obj:`new <Opcodes.NEW>`, :obj:`athrow <Opcodes.ATHROW>`                                                                           |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`copy <PcodeOp.COPY>`                            |:obj:`JitCopyOp`               |:obj:`CopyOpGen`               |none; defers to :obj:`VarGen`                                                                                                      |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`load <PcodeOp.LOAD>`                            |:obj:`JitLoadOp`               |:obj:`LoadOpGen`               |:meth:`JitCompiledPassage.readIntLE4(byte[], int) <JitCompiledPassage.readIntLE4>`, etc.                                           |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`store <PcodeOp.STORE>`                          |:obj:`JitStoreOp`              |:obj:`StoreOpGen`              |:meth:`JitCompiledPassage.writeIntLE4(int, byte[], int) <JitCompiledPassage.writeIntLE4>`, etc.                                    |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Control Flow*                                        |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`branch <PcodeOp.BRANCH>`,                       |:obj:`JitBranchOp`             |:obj:`BranchOpGen`             |:obj:`goto <Opcodes.GOTO>`, :obj:`areturn <Opcodes.ARETURN>`                                                                       |
    |:obj:`call <PcodeOp.CALL>`                            |                               |                               |                                                                                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`cbranch <PcodeOp.CBRANCH>`                      |:obj:`JitCBranchOp`            |:obj:`CBranchOpGen`            |:obj:`ifeq <Opcodes.IFEQ>`, :obj:`ifne <Opcodes.IFEQ>`, :obj:`goto <Opcodes.GOTO>`,                                                |
    |                                                      |                               |                               |:obj:`areturn <Opcodes.ARETURN>`                                                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`branchind <PcodeOp.BRANCHIND>`,                 |:obj:`JitBranchIndOp`          |:obj:`BranchIndOpGen`          |:obj:`areturn <Opcodes.ARETURN>`                                                                                                   |
    |:obj:`callind <PcodeOp.CALLIND>`,                     |                               |                               |                                                                                                                                   |
    |:obj:`return <PcodeOp.RETURN>`                        |                               |                               |                                                                                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`callother <PcodeOp.CALLOTHER>`                  |:obj:`JitCallOtherOp`,         |:obj:`CallOtherOpGen`,         |See :obj:`JitDataFlowUseropLibrary`:                                                                                               |
    |                                                      |:obj:`JitCallOtherDefOp`,      |:obj:`CallOtherMissingOpGen`,  |                                                                                                                                   |
    |                                                      |:obj:`JitCallOtherMissingOp`,  |:obj:`NopOpGen`                |* Standard:                                                                                                                        |
    |                                                      |:obj:`JitNopOp`                |                               |:meth:`PcodeUseropDefinition.execute(PcodeExecutor, PcodeUseropLibrary, PcodeOp) <PcodeUseropDefinition.execute>`                  |
    |                                                      |                               |                               |* Inlining: userop's p-code                                                                                                        |
    |                                                      |                               |                               |* Direct: :obj:`invokevirtual <Opcodes.INVOKEVIRTUAL>`                                                                             |
    |                                                      |                               |                               |* Missing: :obj:`new <Opcodes.NEW>`, :obj:`athrow <Opcodes.ATHROW>`                                                                |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Integer Comparison*                                  |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_equal <PcodeOp.INT_EQUAL>`                  |:obj:`JitIntEqualOp`           |:obj:`IntEqualOpGen`           |:obj:`if_icmpeq <Opcodes.IF_ICMPEQ>`, :obj:`ifeq <Opcodes.IFEQ>`                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_notequal <PcodeOp.INT_NOTEQUAL>`            |:obj:`JitIntNotEqualOp`        |:obj:`IntNotEqualOpGen`        |:obj:`if_icmpne <Opcodes.IF_ICMPNE>`, :obj:`ifne <Opcodes.IFNE>`                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sless <PcodeOp.INT_SLESS>`                  |:obj:`JitIntSLessOp`           |:obj:`IntSLessOpGen`           |:obj:`if_icmplt <Opcodes.IF_ICMPLT>`, :obj:`iflt <Opcodes.IFLT>`                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_slessequal <PcodeOp.INT_SLESSEQUAL>`        |:obj:`JitIntSLessEqualOp`      |:obj:`IntSLessEqualOpGen`      |:obj:`if_icmple <Opcodes.IF_ICMPLE>`, :obj:`ifle <Opcodes.IFLE>`                                                                   |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_less <PcodeOp.INT_LESS>`                    |:obj:`JitIntLessOp`            |:obj:`IntLessOpGen`            |:meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>`, :obj:`iflt <Opcodes.IFLT>`, etc.                              |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_lessequal <PcodeOp.INT_LESSEQUAL>`          |:obj:`JitIntLessEqualOp`       |:obj:`IntLessEqualOpGen`       |:meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>`, :obj:`ifle <Opcodes.IFLE>`, etc.                              |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Integer Arithmetic*                                  |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_zext <PcodeOp.INT_ZEXT>`                    |:obj:`JitIntZExtOp`            |:obj:`IntZExtOpGen`            |none; defers to :obj:`VarGen` and :obj:`TypeConversions`                                                                           |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sext <PcodeOp.INT_SEXT>`                    |:obj:`JitIntSExtOp`            |:obj:`IntSExtOpGen`            |:obj:`ishl <Opcodes.ISHL>`, :obj:`ishr <Opcodes.ISHR>`, etc.                                                                       |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_add <PcodeOp.INT_ADD>`                      |:obj:`JitIntAddOp`             |:obj:`IntAddOpGen`             |:obj:`iadd <Opcodes.IADD>`, :obj:`ladd <Opcodes.LADD>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sub <PcodeOp.INT_SUB>`                      |:obj:`JitIntSubOp`             |:obj:`IntSubOpGen`             |:obj:`isub <Opcodes.ISUB>`, :obj:`lsub <Opcodes.LSUB>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_carry <PcodeOp.INT_CARRY>`                  |:obj:`JitIntCarryOp`           |:obj:`IntCarryOpGen`           |:meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>`, :obj:`iadd <Opcodes.IADD>`, :obj:`ishr <Opcodes.ISHR>`, etc.  |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_scarry <PcodeOp.INT_SCARRY>`                |:obj:`JitIntSCarryOp`          |:obj:`IntSCarryOpGen`          |:meth:`JitCompiledPassage.sCarryIntRaw(int, int) <JitCompiledPassage.sCarryIntRaw>`, :obj:`ishr <Opcodes.ISHR>`, etc.              |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sborrow <PcodeOp.INT_SBORROW>`              |:obj:`JitIntSBorrowOp`         |:obj:`IntSBorrowOpGen`         |:meth:`JitCompiledPassage.sBorrowIntRaw(int, int) <JitCompiledPassage.sBorrowIntRaw>`, :obj:`ishr <Opcodes.ISHR>`, etc.            |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_2comp <PcodeOp.INT_2COMP>`                  |:obj:`JitInt2CompOp`           |:obj:`Int2CompOpGen`           |:obj:`ineg <Opcodes.INEG>`, :obj:`lneg <Opcodes.LNEG>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_negate <PcodeOp.INT_NEGATE>`                |:obj:`JitIntNegateOp`          |:obj:`IntNegateOpGen`          |:obj:`iconst_m1 <Opcodes.ICONST_M1>`, :obj:`ixor <Opcodes.IXOR>`, etc.                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_xor <PcodeOp.INT_XOR>`                      |:obj:`JitIntXorOp`             |:obj:`IntXorOpGen`             |:obj:`ixor <Opcodes.IXOR>`, :obj:`lxor <Opcodes.LXOR>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_and <PcodeOp.INT_AND>`                      |:obj:`JitIntAndOp`             |:obj:`IntAndOpGen`             |:obj:`iand <Opcodes.IAND>`, :obj:`land <Opcodes.LAND>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_or <PcodeOp.INT_OR>`                        |:obj:`JitIntOrOp`              |:obj:`IntOrOpGen`              |:obj:`ior <Opcodes.IOR>`, :obj:`lor <Opcodes.LOR>`                                                                                 |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_left <PcodeOp.INT_LEFT>`                    |:obj:`JitIntLeftOp`            |:obj:`IntLeftOpGen`            |:meth:`JitCompiledPassage.intLeft(int, int) <JitCompiledPassage.intLeft>`, etc.                                                    |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_right <PcodeOp.INT_RIGHT>`                  |:obj:`JitIntRightOp`           |:obj:`IntRightOpGen`           |:meth:`JitCompiledPassage.intRight(int, int) <JitCompiledPassage.intRight>`, etc.                                                  |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sright <PcodeOp.INT_SRIGHT>`                |:obj:`JitIntSRightOp`          |:obj:`IntSRightOpGen`          |:meth:`JitCompiledPassage.intSRight(int, int) <JitCompiledPassage.intSRight>`, etc.                                                |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_mult <PcodeOp.INT_MULT>`                    |:obj:`JitIntMultOp`            |:obj:`IntMultOpGen`            |:obj:`imul <Opcodes.IMUL>`, :obj:`lmul <Opcodes.LMUL>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_div <PcodeOp.INT_DIV>`                      |:obj:`JitIntDivOp`             |:obj:`IntDivOpGen`             |:meth:`Integer.divideUnsigned(int, int) <Integer.divideUnsigned>`, etc.                                                            |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sdiv <PcodeOp.INT_SDIV>`                    |:obj:`JitIntSDivOp`            |:obj:`IntSDivOpGen`            |:obj:`idiv <Opcodes.IDIV>`, :obj:`ldiv <Opcodes.LDIV>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_rem <PcodeOp.INT_REM>`                      |:obj:`JitIntRemOp`             |:obj:`IntRemOpGen`             |:meth:`Integer.remainderUnsigned(int, int) <Integer.remainderUnsigned>`, etc.                                                      |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_srem <PcodeOp.INT_SREM>`                    |:obj:`JitIntSRemOp`            |:obj:`IntSRemOpGen`            |:obj:`irem <Opcodes.IREM>`, :obj:`lrem <Opcodes.LREM>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Boolean Logic*                                       |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`bool_negate <PcodeOp.BOOL_NEGATE>`              |:obj:`JitBoolNegateOp`         |:obj:`BoolNegateOpGen`         |Conditional jumps to :obj:`ldc <Opcodes.LDC>` 0 or 1                                                                               |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`bool_xor <PcodeOp.BOOL_XOR>`                    |:obj:`JitBoolXorOp`            |:obj:`BoolXorOpGen`            |Conditional jumps to :obj:`ldc <Opcodes.LDC>` 0 or 1                                                                               |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`bool_and <PcodeOp.BOOL_AND>`                    |:obj:`JitBoolAndOp`            |:obj:`BoolAndOpGen`            |Conditional jumps to :obj:`ldc <Opcodes.LDC>` 0 or 1                                                                               |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`bool_or <PcodeOp.BOOL_OR>`                      |:obj:`JitBoolOrOp`             |:obj:`BoolOrOpGen`             |Conditional jumps to :obj:`ldc <Opcodes.LDC>` 0 or 1                                                                               |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Float Comparison*                                    |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_equal <PcodeOp.FLOAT_EQUAL>`              |:obj:`JitFloatEqualOp`         |:obj:`FloatEqualOpGen`         |:obj:`fcmpl <Opcodes.FCMPL>`, :obj:`dcmpl <Opcodes.FCMPL>`, :obj:`ifeq <Opcodes.IFNE>`                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_notequal <PcodeOp.FLOAT_NOTEQUAL>`        |:obj:`JitFloatNotEqualOp`      |:obj:`FloatNotEqualOpGen`      |:obj:`fcmpl <Opcodes.FCMPL>`, :obj:`dcmpl <Opcodes.FCMPL>`, :obj:`ifne <Opcodes.IFEQ>`                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_less <PcodeOp.FLOAT_LESS>`                |:obj:`JitFloatLessOp`          |:obj:`FloatLessOpGen`          |:obj:`fcmpg <Opcodes.FCMPG>`, :obj:`dcmpg <Opcodes.FCMPL>`, :obj:`iflt <Opcodes.IFGE>`                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_lessequal <PcodeOp.FLOAT_LESSEQUAL>`      |:obj:`JitFloatLessEqualOp`     |:obj:`FloatLessEqualOpGen`     |:obj:`fcmpg <Opcodes.FCMPG>`, :obj:`dcmpg <Opcodes.FCMPL>`, :obj:`ifle <Opcodes.IFGT>`                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_nan <PcodeOp.FLOAT_NAN>`                  |:obj:`JitFloatNaNOp`           |:obj:`FloatNaNOpGen`           |:meth:`Float.isNaN(float) <Float.isNaN>`, :meth:`Double.isNaN(double) <Double.isNaN>`                                              |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Float Arithmetic*                                    |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_add <PcodeOp.FLOAT_ADD>`                  |:obj:`JitFloatAddOp`           |:obj:`FloatAddOpGen`           |:obj:`fadd <Opcodes.FADD>`, :obj:`dadd <Opcodes.DADD>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_div <PcodeOp.FLOAT_DIV>`                  |:obj:`JitFloatDivOp`           |:obj:`FloatDivOpGen`           |:obj:`fdiv <Opcodes.FDIV>`, :obj:`ddiv <Opcodes.DDIV>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_mult <PcodeOp.FLOAT_MULT>`                |:obj:`JitFloatMultOp`          |:obj:`FloatMultOpGen`          |:obj:`fmul <Opcodes.FMUL>`, :obj:`dmul <Opcodes.DMUL>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_sub <PcodeOp.FLOAT_SUB>`                  |:obj:`JitFloatSubOp`           |:obj:`FloatSubOpGen`           |:obj:`fsub <Opcodes.FSUB>`, :obj:`dsub <Opcodes.DSUB>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_neg <PcodeOp.FLOAT_NEG>`                  |:obj:`JitFloatNegOp`           |:obj:`FloatNegOpGen`           |:obj:`fneg <Opcodes.FNEG>`, :obj:`dneg <Opcodes.DNEG>`                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_abs <PcodeOp.FLOAT_ABS>`                  |:obj:`JitFloatAbsOp`           |:obj:`FloatAbsOpGen`           |:meth:`Math.abs(float) <Math.abs>`, :meth:`Math.abs(double) <Math.abs>`                                                            |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_sqrt <PcodeOp.FLOAT_SQRT>`                |:obj:`JitFloatSqrtOp`          |:obj:`FloatSqrtOpGen`          |:meth:`Math.sqrt(double) <Math.sqrt>`                                                                                              |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_int2float <PcodeOp.FLOAT_INT2FLOAT>`      |:obj:`JitFloatInt2FloatOp`     |:obj:`FloatInt2FloatOpGen`     |:obj:`i2f <Opcodes.I2F>`, :obj:`i2d <Opcodes.I2D>`, :obj:`l2f <Opcodes.L2F>`, :obj:`l2d <Opcodes.L2D>`                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_float2float <PcodeOp.FLOAT_FLOAT2FLOAT>`  |:obj:`JitFloatFloat2FloatOp`   |:obj:`FloatFloat2FloatOpGen`   |:obj:`f2d <Opcodes.F2D>`, :obj:`d2f <Opcodes.D2F>`                                                                                 |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_trunc <PcodeOp.FLOAT_TRUNC>`              |:obj:`JitFloatTruncOp`         |:obj:`FloatTruncOpGen`         |:obj:`f2i <Opcodes.F2I>`, :obj:`f2l <Opcodes.F2L>`, :obj:`d2i <Opcodes.D2I>`, :obj:`d2l <Opcodes.D2L>`                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_ceil <PcodeOp.FLOAT_CEIL>`                |:obj:`JitFloatCeilOp`          |:obj:`FloatCeilOpGen`          |:meth:`Math.ceil(double) <Math.ceil>`                                                                                              |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_floor <PcodeOp.FLOAT_FLOOR>`              |:obj:`JitFloatFloorOp`         |:obj:`FloatFloorOpGen`         |:meth:`Math.floor(double) <Math.floor>`                                                                                            |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`float_round <PcodeOp.FLOAT_ROUND>`              |:obj:`JitFloatRoundOp`         |:obj:`FloatRoundOpGen`         |+0.5 then :meth:`Math.floor(double) <Math.floor>`                                                                                  |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Miscellaneous*                                       |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`subpiece <PcodeOp.SUBPIECE>`                    |:obj:`JitSubPieceOp`           |:obj:`SubPieceOpGen`           |:obj:`iushr <Opcodes.IUSHR>`, :obj:`lushr <Opcodes.LUSHR>`                                                                         |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`popcount <PcodeOp.POPCOUNT>`                    |:obj:`JitPopCountOp`           |:obj:`PopCountOpGen`           |:meth:`Integer.bitCount(int) <Integer.bitCount>`, etc.                                                                             |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`lzcount <PcodeOp.LZCOUNT>`                      |:obj:`JitLzCountOp`            |:obj:`LzCountOpGen`            |:meth:`Integer.numberOfLeadingZeros(int) <Integer.numberOfLeadingZeros>`, etc.                                                     |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |*Synthetic*                                           |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |(none)                                                |:obj:`JitCatenateOp`           |:obj:`CatenateOpGen`           |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |(none)                                                |:obj:`JitSynthSubPieceOp`      |:obj:`SynthSubPieceOpGen`      |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |(none)                                                |:obj:`JitPhiOp`                |:obj:`PhiOpGen`                |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    
     
     
    
    There are other p-code ops. Some are only used in "high" p-code, and so we need not implement
    them here. Others are used in abstract virtual machines, e.g., :obj:`PcodeOp.NEW` or are just
    not yet implemented, e.g., :obj:`PcodeOp.SEGMENTOP`.
     
     
    
    The mapping from :obj:`PcodeOp` opcode to :obj:`JitOp` is done in, e.g.,
    :meth:`JitOp.binOp(PcodeOp, JitOutVar, JitVal, JitVal) <JitOp.binOp>`, and the mapping from :obj:`JitOp` to
    :obj:`OpGen` is done in :meth:`lookup(JitOp) <.lookup>`.
     
     
    
    The synthetic use-def nodes do not correspond to any p-code op. They are synthesized based on
    access patterns to the :obj:`JitDataFlowState`. Their generators do not emit any bytecode. See
    :obj:`JitVarScopeModel` regarding coalescing and allocating variables.
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateInitCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: T, iv: org.objectweb.asm.MethodVisitor):
        """
        Emit bytecode into the class constructor.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param T op: the p-code op (use-def node) to translate
        :param org.objectweb.asm.MethodVisitor iv: the visitor for the class constructor
        """

    def generateRunCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, op: T, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit bytecode into the :meth:`run <JitCompiledPassage.run>` method.
         
         
        
        This method must emit the code needed to load any input operands, convert them to the
        appropriate type, perform the actual operation, and then if applicable, store the output
        operand. The implementations should delegate to
        :meth:`JitCodeGenerator.generateValReadCode(JitVal, JitTypeBehavior) <JitCodeGenerator.generateValReadCode>`,
        :meth:`JitCodeGenerator.generateVarWriteCode(JitVar, JitType) <JitCodeGenerator.generateVarWriteCode>`, and :obj:`TypeConversions`
        appropriately.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param T op: the p-code op (use-def node) to translate
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the basic block containing the p-code op
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method.
        """

    @staticmethod
    def lookup(op: T) -> OpGen[T]:
        """
        Lookup the generator for a given p-code op use-def node
        
        :param T: the class of the op:param T op: the :obj:`JitOp` whose generator to look up
        :return: the generator
        :rtype: OpGen[T]
        """


class StoreOpGen(java.lang.Enum[StoreOpGen], OpGen[ghidra.pcode.emu.jit.op.JitStoreOp]):
    """
    The generator for a :obj:`store <JitStoreOp>`.
     
     
    
    These ops are currently presumed to be indirect memory accesses. **TODO**: If we fold
    constants, we could convert some of these to direct.
     
     
    
    We request a field to pre-fetch the :obj:`space <JitBytesPcodeExecutorStateSpace>` and emit code
    to load it onto the stack. We then emit code to load the offset onto the stack and convert it to
    a JVM long, if necessary. The varnode size is loaded by emitting an :obj:`ldc <Opcodes.LDC>`. We
    must now emit code to load the value and convert it to a byte array. The conversion depends on
    the type of the value. Finally, we emit an invocation of
    :meth:`JitBytesPcodeExecutorStateSpace.write(long, byte[], int, int) <JitBytesPcodeExecutorStateSpace.write>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[StoreOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> StoreOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[StoreOpGen]:
        ...


class FloatAddOpGen(java.lang.Enum[FloatAddOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitFloatAddOp]):
    """
    The generator for a :obj:`float_add <JitFloatAddOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.FADD` or :obj:`.DADD` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatAddOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatAddOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatAddOpGen]:
        ...


class IntNegateOpGen(java.lang.Enum[IntNegateOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitIntNegateOp]):
    """
    The generator for a :obj:`int_negate <JitIntNegateOp>`.
     
     
    
    There is no bitwise "not" operator in the JVM. We borrow the pattern we see output by the Java
    compiler for ``int negate(n) {return ~n;}``. It XORs the input with a register of 1s.
    This uses the unary operator generator and emits the equivalent code.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntNegateOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntNegateOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntNegateOpGen]:
        ...


class IntSLessOpGen(java.lang.Enum[IntSLessOpGen], CompareIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntSLessOp]):
    """
    The generator for a :obj:`int_sless <JitIntSLessOp>`.
     
     
    
    This uses the integer comparison operator generator and simply emits :obj:`.IF_ICMPLT` or
    :obj:`.IFLT` depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSLessOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSLessOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSLessOpGen]:
        ...


class IntNotEqualOpGen(java.lang.Enum[IntNotEqualOpGen], CompareIntBinOpGen[ghidra.pcode.emu.jit.op.JitIntNotEqualOp]):
    """
    The generator for a :obj:`int_notequal <JitIntNotEqualOp>`.
     
     
    
    This uses the integer comparison operator generator and simply emits :obj:`.IF_ICMPNE` or
    :obj:`.IFNE` depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntNotEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntNotEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntNotEqualOpGen]:
        ...


class FloatLessEqualOpGen(java.lang.Enum[FloatLessEqualOpGen], CompareFloatOpGen[ghidra.pcode.emu.jit.op.JitFloatLessEqualOp]):
    """
    The generator for a :obj:`float_lessequal <JitFloatLessEqualOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :obj:`.FCMPG` or
    :obj:`.DCMPG` depending on the type and then :obj:`.IFLE`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatLessEqualOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatLessEqualOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatLessEqualOpGen]:
        ...


class FloatRoundOpGen(java.lang.Enum[FloatRoundOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitFloatRoundOp]):
    """
    The generator for a :obj:`float_round <JitFloatRoundOp>`.
     
     
    
    The JVM does provide a :meth:`Math.round(float) <Math.round>` method, however it returns an int. (It has
    similar for doubles with the same problem.) That would be suitable if a type conversion were also
    desired, but that is not the case. Thus, we construct a rounding function without conversion:
    ``round(x) = floor(x + 0.5)``. This uses the unary operator generator and emits the bytecode
    to implement that definition, applying type conversions as needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FloatRoundOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FloatRoundOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FloatRoundOpGen]:
        ...


class CompareIntBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for integer comparison operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateIntJump(self, lblTrue: org.objectweb.asm.Label, rv: org.objectweb.asm.MethodVisitor):
        """
        Emits bytecode for the JVM int case
        
        :param org.objectweb.asm.Label lblTrue: the target bytecode label for the true case
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def generateLongJump(self, lblTrue: org.objectweb.asm.Label, rv: org.objectweb.asm.MethodVisitor):
        """
        Emits bytecode for the JVM long case
        
        :param org.objectweb.asm.Label lblTrue: the target bytecode label for the true case
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def icmpOpcode(self) -> int:
        """
        The JVM opcode to perform the conditional jump for signed integers.
        
        :return: the opcode
        :rtype: int
        """

    def ifOpcode(self) -> int:
        """
        The JVM opcode to perform the conditional jump for unsigned or long integers.
         
        This is emitted *after* the application of :obj:`.LCMP` or the comparator method.
        
        :return: the opcode
        :rtype: int
        """

    def isSigned(self) -> bool:
        """
        Whether the comparison of p-code integers is signed
         
         
        
        If the comparison is unsigned, we will emit invocations of
        :meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>` or :meth:`Long.compareUnsigned(long, long) <Long.compareUnsigned>`,
        followed by a conditional jump corresponding to this p-code comparison op. If the comparison
        is signed, and the type fits in a JVM int, we emit the conditional jump of ints directly
        implementing this p-code comparison op. If the type requires a JVM long, we first emit an
        :obj:`lcmp <.LCMP>`, followed by the same opcode that would be used in the unsigned case.
        
        :return: true if signed, false if not
        :rtype: bool
        """

    @property
    def signed(self) -> jpype.JBoolean:
        ...


class IntSRemOpGen(java.lang.Enum[IntSRemOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntSRemOp]):
    """
    The generator for a :obj:`int_srem <JitIntSRemOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.IREM` or :obj:`.LREM` depending
    on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntSRemOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntSRemOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntSRemOpGen]:
        ...


class IntXorOpGen(java.lang.Enum[IntXorOpGen], BitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitIntXorOp]):
    """
    The generator for a :obj:`int_xor <JitIntXorOp>`.
     
     
    
    This uses the bitwise binary operator and emits :obj:`.IXOR` or :obj:`.LXOR` depending on the
    type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntXorOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntXorOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntXorOpGen]:
        ...


class IntDivOpGen(java.lang.Enum[IntDivOpGen], BinOpGen[ghidra.pcode.emu.jit.op.JitIntDivOp]):
    """
    The generator for a :obj:`int_add <JitIntAddOp>`.
     
     
    
    This uses the binary operator generator and simply emits :obj:`.INVOKESTATIC` on
    :meth:`Integer.divideUnsigned(int, int) <Integer.divideUnsigned>` or :meth:`Long.divideUnsigned(long, long) <Long.divideUnsigned>` depending on
    the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntDivOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntDivOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntDivOpGen]:
        ...


class SynthSubPieceOpGen(java.lang.Enum[SynthSubPieceOpGen], OpGen[ghidra.pcode.emu.jit.op.JitSynthSubPieceOp]):
    """
    The generator for a :obj:`synth-subpiece <JitSynthSubPieceOp>`.
     
     
    
    We emit nothing. This generator ought never to be invoked, anyway, but things may change. The
    argument here is similar to that of :obj:`PhiOpGen`.
    
    
    .. seealso::
    
        | :obj:`JitVarScopeModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[SynthSubPieceOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SynthSubPieceOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[SynthSubPieceOpGen]:
        ...


class PopCountOpGen(java.lang.Enum[PopCountOpGen], UnOpGen[ghidra.pcode.emu.jit.op.JitPopCountOp]):
    """
    The generator for a :obj:`popcount <JitPopCountOp>`.
     
     
    
    This uses the unary operator generator and emits an invocation of :meth:`Integer.bitCount(int) <Integer.bitCount>`
    or :meth:`Long.bitCount(long) <Long.bitCount>`, depending on the type.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[PopCountOpGen]
    """
    The generator singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PopCountOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[PopCountOpGen]:
        ...



__all__ = ["FloatTruncOpGen", "CompareFloatOpGen", "IntLessOpGen", "IntLeftOpGen", "FloatDivOpGen", "FloatNaNOpGen", "FloatAbsOpGen", "BranchIndOpGen", "IntMultOpGen", "IntOrOpGen", "IntRightOpGen", "BoolAndOpGen", "FloatNegOpGen", "BinOpGen", "CopyOpGen", "CatenateOpGen", "IntSRightOpGen", "NopOpGen", "ShiftIntBinOpGen", "IntAddOpGen", "IntRemOpGen", "IntSCarryOpGen", "IntSDivOpGen", "FloatFloorOpGen", "IntLessEqualOpGen", "Int2CompOpGen", "IntAndOpGen", "IntEqualOpGen", "FloatFloat2FloatOpGen", "IntSLessEqualOpGen", "IntSubOpGen", "FloatCeilOpGen", "UnOpGen", "BoolOrOpGen", "FloatLessOpGen", "IntCarryOpGen", "BitwiseBinOpGen", "UnimplementedOpGen", "FloatMultOpGen", "FloatInt2FloatOpGen", "IntZExtOpGen", "PhiOpGen", "FloatSubOpGen", "FloatSqrtOpGen", "BranchOpGen", "CallOtherOpGen", "IntSBorrowOpGen", "FloatNotEqualOpGen", "BoolNegateOpGen", "CallOtherMissingOpGen", "LzCountOpGen", "FloatEqualOpGen", "CBranchOpGen", "BoolXorOpGen", "SubPieceOpGen", "LoadOpGen", "IntSExtOpGen", "OpGen", "StoreOpGen", "FloatAddOpGen", "IntNegateOpGen", "IntSLessOpGen", "IntNotEqualOpGen", "FloatLessEqualOpGen", "FloatRoundOpGen", "CompareIntBinOpGen", "IntSRemOpGen", "IntXorOpGen", "IntDivOpGen", "SynthSubPieceOpGen", "PopCountOpGen"]
