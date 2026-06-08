from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.gen.opnd
import ghidra.pcode.emu.jit.gen.util
import ghidra.pcode.emu.jit.op
import ghidra.pcode.emu.jit.var
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


LIB = typing.TypeVar("LIB")
LJT = typing.TypeVar("LJT")
LT = typing.TypeVar("LT")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
N2 = typing.TypeVar("N2")
NI = typing.TypeVar("NI")
NR = typing.TypeVar("NR")
OJT = typing.TypeVar("OJT")
OT = typing.TypeVar("OT")
RJT = typing.TypeVar("RJT")
RT = typing.TypeVar("RT")
T = typing.TypeVar("T")
TB = typing.TypeVar("TB")
THIS = typing.TypeVar("THIS")
TO = typing.TypeVar("TO")
UJT = typing.TypeVar("UJT")
UT = typing.TypeVar("UT")


class FloatTruncOpGen(java.lang.Enum[FloatTruncOpGen], FloatConvertUnOpGen[ghidra.pcode.emu.jit.op.JitFloatTruncOp]):
    """
    The generator for a :obj:`float_trunc <JitFloatTruncOp>`.
     
     
    
    This uses the unary operator generator and emits :meth:`f2i <Op.f2i>`,
    :meth:`f2l <Op.f2l>`, :meth:`d2i <Op.d2i>`, or :meth:`d2l <Op.d2l>`.
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


class IntLessOpGen(java.lang.Enum[IntLessOpGen], IntCompareBinOpGen[ghidra.pcode.emu.jit.op.JitIntLessOp]):
    """
    The generator for a :obj:`int_less <JitIntLessOp>`.
     
     
    
    This uses the (unsigned) integer comparison operator generator and simply emits
    :meth:`iflt <Op.iflt>`.
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


class IntLeftOpGen(java.lang.Enum[IntLeftOpGen], IntShiftBinOpGen[ghidra.pcode.emu.jit.op.JitIntLeftOp]):
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


class FloatDivOpGen(java.lang.Enum[FloatDivOpGen], FloatOpBinOpGen[ghidra.pcode.emu.jit.op.JitFloatDivOp]):
    """
    The generator for a :obj:`float_div <JitFloatDivOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`fdiv <Op.fdiv>` or
    :meth:`ddiv <Op.ddiv>` depending on the type.
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


class FloatAbsOpGen(java.lang.Enum[FloatAbsOpGen], FloatOpUnOpGen[ghidra.pcode.emu.jit.op.JitFloatAbsOp]):
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
    class IndBranchGen(BranchOpGen.UBranchGen[ghidra.pcode.emu.jit.JitPassage.RIndBranch, ghidra.pcode.emu.jit.op.JitBranchIndOp]):
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


class IntMultOpGen(java.lang.Enum[IntMultOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntMultOp]):
    """
    The generator for a :obj:`int_mult <JitIntMultOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`imul <Op.imul>` or
    :meth:`lmul <Op.lmul>` depending on the type.
     
    
    For multi-precision multiplication, this emits code to invoke
    :meth:`JitCompiledPassage.mpIntMultiply(int[], int[], int[]) <JitCompiledPassage.mpIntMultiply>`
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[IntMultOpGen]
    """
    The generator singleton
    """


    def genRunMpInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: ghidra.pcode.emu.jit.op.JitIntMultOp, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
        """
        Generate the mp-int multiply code.
         
        
        **NOTE:** I'd really like to know how many legs of the input operands are actually
        relevant. Very often, the following idiom is used:
         
         
        temp: 16 = zext(r1) * zext(r2);
        r0 = temp(0);
         
         
        
        That ensures all the operand sizes match, which is often (at least conventionally) required
        by the Sleigh compiler. However, if r1 and r2 are each only 64 bits, and I can keep track of
        that fact, then I could perform about half as many multiplies and adds. It also be nice if I
        can look ahead and see that only 64 bits of temp is actually used. The same is true of
        :obj:`IntDivOpGen`, :obj:`IntRemOpGen`, :obj:`IntSDivOpGen`, and :obj:`IntSRemOpGen`.
         
        
        **IDEA:** It would be quite a change, but perhaps generating a temporary JVM-level DFG
        would be useful for culling. The difficulty here is knowing whether or not a temp (unique) is
        used by a later cross-build. Maybe with the right API calls, I could derive that without
        additional Sleigh compiler support. If used, I should not cull any computations, so that the
        retired value is the full value.
        
        :param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the code emitter with an empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the owning compiled passage
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.op.JitIntMultOp op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the (uniform) type of the inputs and output operands
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for op-temporary variables
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> IntMultOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[IntMultOpGen]:
        ...


class IntOrOpGen(java.lang.Enum[IntOrOpGen], IntBitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitIntOrOp]):
    """
    The generator for a :obj:`int_or <JitIntOrOp>`.
     
     
    
    This uses the bitwise binary operator and emits :meth:`ior <Op.ior>` or
    :meth:`lor <Op.lor>` depending on the type.
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


class IntRightOpGen(java.lang.Enum[IntRightOpGen], IntShiftBinOpGen[ghidra.pcode.emu.jit.op.JitIntRightOp]):
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


class BoolAndOpGen(java.lang.Enum[BoolAndOpGen], IntBitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitBoolAndOp]):
    """
    The generator for a :obj:`bool_and <JitBoolAndOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolAnd`. Thus, this is identical to :obj:`IntAndOpGen`.
    
    
    
    .. admonition:: Implementation Note
    
        Because having bits other than the least significant set in the inputs is "undefined
        behavior," we could technically optimize this by only ANDing the least significant leg
        when we're dealing with mp-ints.
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


class FloatNegOpGen(java.lang.Enum[FloatNegOpGen], FloatOpUnOpGen[ghidra.pcode.emu.jit.op.JitFloatNegOp]):
    """
    The generator for a :obj:`float_neg <JitFloatNegOp>`.
     
     
    
    This uses the unary operator generator and emits :meth:`fneg <Op.fneg>` or
    :meth:`dneg <Op.dneg>`.
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

    class TakeOut(java.lang.Enum[BinOpGen.TakeOut]):
        """
        A choice of static method parameter to take as operator output
        """

        class_: typing.ClassVar[java.lang.Class]
        OUT: typing.Final[BinOpGen.TakeOut]
        """
        The out (first) parameter
        """

        LEFT: typing.Final[BinOpGen.TakeOut]
        """
        The left (second) parameter
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BinOpGen.TakeOut:
            ...

        @staticmethod
        def values() -> jpype.JArray[BinOpGen.TakeOut]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def ext(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext:
        """
        When loading and storing variables, the kind of extension to apply
        
        :return: the extension kind
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext
        """

    def genMpDelegationToStaticMethod(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, methodName: typing.Union[java.lang.String, str], op: ghidra.pcode.emu.jit.op.JitBinOp, slackLeft: typing.Union[jpype.JInt, int], takeOut: BinOpGen.TakeOut, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
        """
        Emit bytecode that implements an mp-int binary operator via delegation to a static method on
        :obj:`JitCompiledPassage`. The method must have the signature:
         
         
        void method(int[] out, int[] inL, int[] inR);
         
         
         
        
        This method presumes that the left operand's legs are at the top of the stack,
        least-significant leg on top, followed by the right operand legs, also least-significant leg
        on top. This will allocate the output array, move the operands into their respective input
        arrays, invoke the method, and then place the result legs on the stack, least-significant leg
        on top.
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the type of the operands
        :param java.lang.String or str methodName: the name of the method in :obj:`JitCompiledPassage` to invoke
        :param ghidra.pcode.emu.jit.op.JitBinOp op: the p-code op
        :param jpype.JInt or int slackLeft: the number of extra ints to allocate for the left operand's array. This is
                    to facilitate Knuth's division algorithm, which may require an extra leading leg
                    in the dividend after normalization.
        :param BinOpGen.TakeOut takeOut: indicates which operand of the static method to actually take for the output.
                    This is to facilitate the remainder operator, because Knuth's algorithm leaves the
                    remainder where there dividend was.
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the empty stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]
        """

    def isSigned(self) -> bool:
        """
        Whether this operator is signed
         
        
        In many cases, the operator itself is not affected by the signedness of the operands;
        however, if size adjustments to the operands are needed, this can determine how those
        operands are extended.
        
        :return: true for signed, false if not
        :rtype: bool
        """

    def rExt(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext:
        """
        When loading the right operand, the kind of extension to apply
        
        :return: the extension kind
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext
        """

    @property
    def signed(self) -> jpype.JBoolean:
        ...


class CopyOpGen(java.lang.Enum[CopyOpGen], IntExtUnOpGen[ghidra.pcode.emu.jit.op.JitCopyOp]):
    """
    The generator for a :obj:`copy <JitCopyOp>`.
     
    
    This is identical to :obj:`IntZExtOpGen`, except that we expect (require?) the output and input
    operand to agree in size, and so we don't actually expect any extension. In the event that is not
    the case, it seems agreeable that zero extension is applied.
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


class IntSRightOpGen(java.lang.Enum[IntSRightOpGen], IntShiftBinOpGen[ghidra.pcode.emu.jit.op.JitIntSRightOp]):
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


class IntAddOpGen(java.lang.Enum[IntAddOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntAddOp]):
    """
    The generator for a :obj:`int_add <JitIntAddOp>`.
     
    
    This uses the binary operator generator and simply emits :meth:`iadd <Op.iadd>` or
    :meth:`ladd <Op.ladd>` depending on the type.
     
    
    The multi-precision integer logic is not such a simple matter.
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


class IntRemOpGen(java.lang.Enum[IntRemOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntRemOp]):
    """
    The generator for a :obj:`int_rem <JitIntRemOp>`.
     
     
    
    This uses the binary operator generator and simply emits
    :meth:`Op.invokestatic(Emitter, TRef, String, ghidra.pcode.emu.jit.gen.util.Methods.MthDesc, boolean) <Op.invokestatic>`
    on :meth:`Integer.remainderUnsigned(int, int) <Integer.remainderUnsigned>` or :meth:`Long.remainderUnsigned(long, long) <Long.remainderUnsigned>`
    depending on the type.
     
    
    For multi-precision remainder, this emits code to invoke
    :meth:`JitCompiledPassage.mpIntDivide(int[], int[], int[]) <JitCompiledPassage.mpIntDivide>`, but selects what remains in the left
    operand as the result.
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


class IntSCarryOpGen(java.lang.Enum[IntSCarryOpGen], IntPredBinOpGen[ghidra.pcode.emu.jit.op.JitIntSCarryOp]):
    """
    The generator for a :obj:`int_scarry <JitIntSCarryOp>`.
     
    
    This uses the binary operator generator and emits
    :meth:`invokestatic <Op.invokestatic>` on :meth:`JitCompiledPassage.sCarryIntRaw(int, int) <JitCompiledPassage.sCarryIntRaw>` or
    :meth:`JitCompiledPassage.sCarryLongRaw(long, long) <JitCompiledPassage.sCarryLongRaw>` depending on the type. We must then emit a
    shift and mask to extract the correct bit.
     
    
    For multi-precision signed borrow, we delegate to
    :meth:`JitCompiledPassage.sCarryMpInt(int[], int[], int) <JitCompiledPassage.sCarryMpInt>`, which requires no follow-on bit
    extraction.
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


class IntSDivOpGen(java.lang.Enum[IntSDivOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntSDivOp]):
    """
    The generator for a :obj:`int_sdiv <JitIntSDivOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`idiv <Op.idiv>` or
    :meth:`ldiv <Op.ldiv>` depending on the type.
     
    
    For multi-precision division, this emits code to invoke
    :meth:`JitCompiledPassage.mpIntSignedDivide(int[], int[], int[]) <JitCompiledPassage.mpIntSignedDivide>`.
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


class FloatFloorOpGen(java.lang.Enum[FloatFloorOpGen], FloatOpUnOpGen[ghidra.pcode.emu.jit.op.JitFloatFloorOp]):
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


class IntLessEqualOpGen(java.lang.Enum[IntLessEqualOpGen], IntCompareBinOpGen[ghidra.pcode.emu.jit.op.JitIntLessEqualOp]):
    """
    The generator for a :obj:`int_lessequal <JitIntLessEqualOp>`.
     
     
    
    This uses the (unsigned) integer comparison operator generator and simply emits
    :meth:`ifle <Op.ifle>`.
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


class Int2CompOpGen(java.lang.Enum[Int2CompOpGen], IntOpUnOpGen[ghidra.pcode.emu.jit.op.JitInt2CompOp]):
    """
    The generator for a :obj:`int_2comp <JitInt2CompOp>`.
     
    
    This uses the unary operator generator and emits :meth:`ineg <Op.ineg>` or
    :meth:`lneg <Op.lneg>`, depending on type.
     
    
    The multi-precision logic is similar to :obj:`IntAddOpGen`. We follow the process "flip the bits
    and add 1", so for each leg, we consider that it may have a carry in. We then invert all the bits
    using ^-1 and then add that carry in. The least significant leg is assumed to have a carry in,
    effecting the +1.
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


class IntAndOpGen(java.lang.Enum[IntAndOpGen], IntBitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitIntAndOp]):
    """
    The generator for a :obj:`int_and <JitIntAndOp>`.
     
     
    
    This uses the bitwise binary operator and emits :meth:`iand <Op.iand>` or
    :meth:`land <Op.land>` depending on the type.
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


class IntEqualOpGen(java.lang.Enum[IntEqualOpGen], IntCompareBinOpGen[ghidra.pcode.emu.jit.op.JitIntEqualOp]):
    """
    The generator for a :obj:`int_equal <JitIntEqualOp>`.
     
     
    
    To avoid jumps, this delegates to :meth:`Integer.compare(int, int) <Integer.compare>`, which is signed, and then
    inverts the result.
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


class FloatFloat2FloatOpGen(java.lang.Enum[FloatFloat2FloatOpGen], FloatConvertUnOpGen[ghidra.pcode.emu.jit.op.JitFloatFloat2FloatOp]):
    """
    The generator for a :obj:`float_float2float <JitFloatFloat2FloatOp>`.
     
     
    
    This uses the unary operator generator and emits :meth:`f2d <Op.f2d>` or
    :meth:`d2f <Op.d2f>`.
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


class IntPredBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for integer operators whose outputs are boolean
    """

    class_: typing.ClassVar[java.lang.Class]

    def delegateIntFlagbit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, methodName: typing.Union[java.lang.String, str]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for integer operands that delegates to a method on
        :obj:`JitCompiledPassage`
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type of the operands
        :param java.lang.String or str methodName: the name of the method
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def delegateLongFlagbit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, methodName: typing.Union[java.lang.String, str]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for long operands that delegates to a method on :obj:`JitCompiledPassage`
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType type: the p-code type of the operands
        :param java.lang.String or str methodName: the name of the method
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def delegateMpIntFlagbit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope, methodName: typing.Union[java.lang.String, str]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for multi-precision integer operands that delegates to a method on
        :obj:`JitCompiledPassage`
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the operands
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param java.lang.String or str methodName: the name of the method
        :return: the emitter typed with the resulting stack, i.e., containing only the result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genRunMpInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with multi-precision operands.
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the operands
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., containing only the result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with integer operands on the stack.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type of the operands
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForLong(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with long operands on the stack.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType type: the p-code type of the operands
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """


class FloatConvertUnOpGen(UnOpGen[T], typing.Generic[T]):
    """
    An extension for float conversion operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def gen(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, ut: UJT, ot: OJT, opcode: java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, UT]], ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, OT]]], scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
        """
        An implementation based on a given bytecode op
        
        :param THIS: the type of the generated passage:param UT: the JVM type of the input operand:param UJT: the p-code type of the input operand:param OT: the JVM type of the output operand:param OJT: the p-code type of the output operand:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op
        :param UJT ut: the p-code type of the input operand
        :param OJT ot: the p-code type of the output operand
        :param java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, UT]], ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, OT]]] opcode: a method reference, e.g., to :meth:`Op.f2d(Emitter) <Op.f2d>` for the conversion
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]
        """


class FloatOpBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for floating-point binary operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def opForDouble(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]:
        """
        Emit the JVM bytecode to perform the operator with double operands on the stack.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]
        """

    def opForFloat(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]:
        """
        Emit the JVM bytecode to perform the operator with float operands on the stack.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]
        """


class IntSLessEqualOpGen(java.lang.Enum[IntSLessEqualOpGen], IntCompareBinOpGen[ghidra.pcode.emu.jit.op.JitIntSLessEqualOp]):
    """
    The generator for a :obj:`int_slessequal <JitIntSLessEqualOp>`.
     
     
    
    This uses the (signed) integer comparison operator generator and simply emits
    :meth:`if_icmple <Op.if_icmple>` or :meth:`ifle <Op.ifle>` depending on the type.
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


class FloatCompareBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for float comparison operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def opForCondJump(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N1, N1]:
        """
        Emit the JVM opcode to perform the conditional jump.
         
        
        The condition should correspond to the true case of the p-code operator.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack including the comparison result:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the target label and emitter typed with the resulting stack, i.e., with the
                comparison result popped
        :rtype: ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N1, N1]
        """

    def opForDoubleCmp(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the comparison with double operands on the stack.
         
        
        The result should be as defined by :meth:`Comparator.compare(Object, Object) <Comparator.compare>`.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForFloatCmp(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the comparison with float operands on the stack.
         
        
        The result should be as defined by :meth:`Comparator.compare(Object, Object) <Comparator.compare>`.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """


class IntSubOpGen(java.lang.Enum[IntSubOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntSubOp]):
    """
    The generator for a :obj:`int_sub <JitIntSubOp>`.
     
    
    This uses the binary operator generator and simply emits :meth:`isub <Op.isub>` or
    :meth:`lsub <Op.lsub>` depending on the type.
     
    
    This uses the same multi-precision integer strategy and pattern as :obj:`IntAddOpGen`.
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


class FloatCeilOpGen(java.lang.Enum[FloatCeilOpGen], FloatOpUnOpGen[ghidra.pcode.emu.jit.op.JitFloatCeilOp]):
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

    def ext(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext:
        """
        When loading and storing variables, the kind of extension to apply
        
        :return: the extension kind
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext
        """

    def isSigned(self) -> bool:
        """
        Whether this operator is signed
         
        
        In many cases, the operator itself is not affected by the signedness of the operands;
        however, if size adjustments to the operands are needed, this can determine how those
        operands are extended.
        
        :return: true for signed, false if not
        :rtype: bool
        """

    @property
    def signed(self) -> jpype.JBoolean:
        ...


class BoolOrOpGen(java.lang.Enum[BoolOrOpGen], IntBitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitBoolOrOp]):
    """
    The generator for a :obj:`bool_or <JitBoolOrOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolOr`. Thus, this is identical to :obj:`IntOrOpGen`.
    
    
    
    .. admonition:: Implementation Note
    
        Because having bits other than the least significant set in the inputs is "undefined
        behavior," we could technically optimize this by only ANDing the least significant leg
        when we're dealing with mp-ints.
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


class FloatLessOpGen(java.lang.Enum[FloatLessOpGen], FloatCompareBinOpGen[ghidra.pcode.emu.jit.op.JitFloatLessOp]):
    """
    The generator for a :obj:`float_less <JitFloatLessOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :meth:`fcmpg <Op.fcmpg>` or :meth:`dcmpg <Op.dcmpg>` depending on the type and then :meth:`iflt <Op.iflt>`.
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


class IntCarryOpGen(java.lang.Enum[IntCarryOpGen], IntPredBinOpGen[ghidra.pcode.emu.jit.op.JitIntCarryOp]):
    """
    The generator for a :obj:`int_carry <JitIntCarryOp>`.
     
    
    This uses the integer predicate operator generator. First we have to consider which strategy we
    are going to use. If the p-code type is strictly smaller than its host JVM type, we can simply
    add the two operands and examine the next bit up. This is accomplished by emitting
    :meth:`iadd <Op.iadd>` or :meth:`ladd <Op.ladd>`, depending on the type, followed
    by a shift right and a mask.
     
    
    If the p-code type exactly fits its host JVM type, we still add, but we will need to compare the
    result to one of the operands. Thus, we emit code to duplicate the left operand. We can then add
    and invoke :meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>` (or similar for longs) to determine whether
    there was overflow. If there was, then we know the carry bit would have been set. We can spare
    the conditional flow by just shifting the sign bit into the 1's place.
     
    
    For multi-precision integers, we invoke the subroutines in :obj:`IntAddOpGen`, but do not store
    the results, because we only need the carry. When we reach the end, we take advantage of the fact
    that the final stack result is actually the full 33-bit result for the last leg. We can just
    shift it the required number of bytes (depending on the type of the input operands) and mask for
    the desired carry bit.
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


class IntCompareBinOpGen(IntPredBinOpGen[T], typing.Generic[T]):
    """
    An extension for integer comparison operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def genBool(self, lblEmTrue: ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N, N]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Assuming a conditional jump bytecode was just emitted, emit bytecode to push 0 (false) onto
        the stack for the fall-through case, or 1 (true) onto the stack for the taken case.
        
        :param N: the incoming stack, i.e., that after emitting the conditional jump:param ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N, N] lblEmTrue: the target label of the conditional jump just emitted, and the emitter typed
                    with the incoming stack
        :return: the emitter with the resulting stack, i.e., having pushed the boolean result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genIntViaIf(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], opIf: java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[N0], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N1, N1]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        A utility that emits the given ``if<cond>`` along with the logic that pushes the correct
        result depending on whether or not the jump is taken.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack including the predicate, which is compared with 0:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[N0], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N1, N1]] opIf: a method reference, e.g., to :meth:`Op.ifge(Emitter, Lbl) <Op.ifge>` for the conditional
                    jump
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genIntViaIfIcmp(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], opIfIcmp: java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[N0], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for (signed) int operands that simply emits the given ``if_icmp<cond>``
        jump.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[N0], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]] opIfIcmp: a method reference, e.g., to :meth:`Op.if_icmpge(Emitter, Lbl) <Op.if_icmpge>` for the
                    conditional jump
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genIntViaUcmpThenIf(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], opIf: java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for (unsigned) int operands that invokes
        :meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>` and then emits the given ``if<cond>`` jump.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]] opIf: a method reference, e.g., to :meth:`Op.ifge(Emitter, Lbl) <Op.ifge>` for the conditional
                    jump
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genLongViaLcmpThenIf(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], opIf: java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for (signed) long operands that emits :meth:`lcmp <Op.lcmp>` and
        then emits the given ``if<cond>`` jump.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]] opIf: a method reference, e.g., to :meth:`Op.ifge(Emitter, Lbl) <Op.ifge>` for the conditional
                    jump
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genLongViaUcmpThenIf(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], opIf: java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        An implementation for (unsigned) long operands that invokes
        :meth:`Long.compareUnsigned(long, long) <Long.compareUnsigned>` and then emits the given ``if<cond>`` jump.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param java.util.function.Function[ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]], ghidra.pcode.emu.jit.gen.util.Lbl.LblEm[N2, N2]] opIf: a method reference, e.g., to :meth:`Op.ifge(Emitter, Lbl) <Op.ifge>` for the conditional
                    jump
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    @staticmethod
    def not_(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Invert the boolean on top of the stack
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the boolean on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """


class FloatMultOpGen(java.lang.Enum[FloatMultOpGen], FloatOpBinOpGen[ghidra.pcode.emu.jit.op.JitFloatMultOp]):
    """
    The generator for a :obj:`float_mult <JitFloatMultOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`fmul <Op.fmul>` or
    :meth:`dmul <Op.dmul>` depending on the type.
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


class FloatInt2FloatOpGen(java.lang.Enum[FloatInt2FloatOpGen], FloatConvertUnOpGen[ghidra.pcode.emu.jit.op.JitFloatInt2FloatOp]):
    """
    The generator for a :obj:`float_int2float <JitFloatInt2FloatOp>`.
     
     
    
    This uses the unary operator generator and emits :meth:`i2f <Op.i2f>`,
    :meth:`i2d <Op.i2d>`, :meth:`l2f <Op.l2f>`, or :meth:`l2d <Op.l2d>`.
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


class IntZExtOpGen(java.lang.Enum[IntZExtOpGen], IntExtUnOpGen[ghidra.pcode.emu.jit.op.JitIntZExtOp]):
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
    track possible definitions of the *same* varnode, there is no need for a phi node to emit
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


class IntShiftBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for integer shift operators
     
     
    
    This is just going to invoke one of the :meth:`JitCompiledPassage.intLeft(int, int) <JitCompiledPassage.intLeft>`,
    :meth:`JitCompiledPassage.intRight(int, int) <JitCompiledPassage.intRight>`, :meth:`JitCompiledPassage.intSRight(int, int) <JitCompiledPassage.intSRight>`, or
    one of their overloaded methods, depending on the operand types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def genShiftMpMp(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], outVar: ghidra.pcode.emu.jit.var.JitVar, outType: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, lVal: ghidra.pcode.emu.jit.var.JitVal, lType: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, rVal: ghidra.pcode.emu.jit.var.JitVal, rType: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope, mdesc: ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        The implementation when both operands are mp-ints
        
        :param THIS: the type of the generated passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.var.JitVar outVar: the output operand
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType outType: the p-code type of the output value
        :param ghidra.pcode.emu.jit.var.JitVal lVal: the left operand
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType lType: the p-code type of the left operand
        :param ghidra.pcode.emu.jit.var.JitVal rVal: the right operand
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType rType: the p-code type of the right operand
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]] mdesc: the descriptor of the (overloaded) method
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genShiftMpPrim(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], outVar: ghidra.pcode.emu.jit.var.JitVar, outType: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, lVal: ghidra.pcode.emu.jit.var.JitVal, lType: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, rVal: ghidra.pcode.emu.jit.var.JitVal, rType: RJT, scope: ghidra.pcode.emu.jit.gen.util.Scope, mdesc: ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], RT]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        The implementation when the left operand is an mp-int and the right is a primitive
        
        :param THIS: the type of the generated passage:param RT: the JVM type of the right operand:param RJT: the p-code type of the right operand:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.var.JitVar outVar: the output operand
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType outType: the p-code type of the output value
        :param ghidra.pcode.emu.jit.var.JitVal lVal: the left operand
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType lType: the p-code type of the left operand
        :param ghidra.pcode.emu.jit.var.JitVal rVal: the right operand
        :param RJT rType: the p-code type of the right operand
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], RT]] mdesc: the descriptor of the (overloaded) method
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genShiftPrimMp(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], outVar: ghidra.pcode.emu.jit.var.JitVar, outType: LJT, lVal: ghidra.pcode.emu.jit.var.JitVal, lType: LJT, rVal: ghidra.pcode.emu.jit.var.JitVal, rType: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope, mdesc: ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[LT, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, LT], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        The implementation when the left operand is a primitive and the right operand is an mp-int
        
        :param THIS: the type of the generated passage:param LT: the JVM type of the left operand:param LJT: the p-code type of the left operand:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.var.JitVar outVar: the output operand
        :param LJT outType: the p-code type of the output value
        :param ghidra.pcode.emu.jit.var.JitVal lVal: the left operand
        :param LJT lType: the p-code type of the left operand
        :param ghidra.pcode.emu.jit.var.JitVal rVal: the right operand
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType rType: the p-code type of the right operand
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[LT, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, LT], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]] mdesc: the descriptor of the (overloaded) method
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genShiftPrimPrim(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], outVar: ghidra.pcode.emu.jit.var.JitVar, outType: LJT, lVal: ghidra.pcode.emu.jit.var.JitVal, lType: LJT, rVal: ghidra.pcode.emu.jit.var.JitVal, rType: RJT, scope: ghidra.pcode.emu.jit.gen.util.Scope, mdesc: ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[LT, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, LT], RT]]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        The implementation when both operands are simple primitives
        
        :param THIS: the type of the generated passage:param LT: the JVM type of the left operand:param LJT: the p-code type of the left operand:param RT: the JVM type of the right operand:param RJT: the p-code type of the right operand:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.var.JitVar outVar: the output operand
        :param LJT outType: the p-code type of the output value
        :param ghidra.pcode.emu.jit.var.JitVal lVal: the left operand
        :param LJT lType: the p-code type of the left operand
        :param ghidra.pcode.emu.jit.var.JitVal rVal: the right operand
        :param RJT rType: the p-code type of the right operand
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[LT, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, LT], RT]] mdesc: the descriptor of the (overloaded) method
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def methodName(self) -> str:
        """
        The name of the static method in :obj:`JitCompiledPassage` to invoke
        
        :return: the name
        :rtype: str
        """


class FloatSubOpGen(java.lang.Enum[FloatSubOpGen], FloatOpBinOpGen[ghidra.pcode.emu.jit.op.JitFloatSubOp]):
    """
    The generator for a :obj:`float_sub <JitFloatSubOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`fsub <Op.fsub>` or
    :meth:`dsub <Op.dsub>` depending on the type.
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


class FloatSqrtOpGen(java.lang.Enum[FloatSqrtOpGen], FloatOpUnOpGen[ghidra.pcode.emu.jit.op.JitFloatSqrtOp]):
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
    block transition followed by a :meth:`goto <Op.goto_>`.
     
     
    
    With an :obj:`ExtBranch` record, this emits code to retire the target to the program counter,
    along with the target context and live variables. It then emits code to request the chained entry
    point from the target's exit slot and return it. The :obj:`thread <JitPcodeThread>` can then
    immediately execute the chained passage entry.
    """

    @typing.type_check_only
    class BranchGen(java.lang.Object, typing.Generic[NR, NI, TB, TO]):
        """
        A branch code generator
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UBranchGen(BranchOpGen.BranchGen[ghidra.pcode.emu.jit.gen.util.Emitter.Dead, ghidra.pcode.emu.jit.gen.util.Emitter.Bot, TB, TO], typing.Generic[TB, TO]):
        """
        An abstract branch code generator for unconditional branches.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IntBranchGen(BranchOpGen.UBranchGen[ghidra.pcode.emu.jit.JitPassage.RIntBranch, ghidra.pcode.emu.jit.op.JitOp]):
        """
        A branch code generator for internal branches
        
        
        .. admonition:: Implementation Note
        
            We leave ``TO:=``:obj:`JitOp` here, because we want :obj:`IntCBranchGen` to
            be able to delegate to this instance.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtBranchGen(BranchOpGen.UBranchGen[ghidra.pcode.emu.jit.JitPassage.RExtBranch, ghidra.pcode.emu.jit.op.JitOp]):
        """
        A branch code generator for external branches
        
        
        .. admonition:: Implementation Note
        
            We leave ``TO:=``:obj:`JitOp` here, because we want :obj:`ExtCBranchGen` to
            be able to delegate to this instance.
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
    :meth:`genRunDirectStrategy(Emitter, Local, JitCodeGenerator, JitCallOtherOpIf, JitBlock, Scope) <.genRunDirectStrategy>`.
    If not, it emits code using
    :meth:`genRunRetirementStrategy(Emitter, Local, JitCodeGenerator, PcodeOp, JitBlock, PcodeUseropDefinition) <.genRunRetirementStrategy>`.
    Direct invocation is possible when the userop is :meth:`functional <PcodeUseropDefinition.isFunctional>` and all of its parameters and return type have a supported primitive type.
    (``char`` is not supported.) Regarding the invocation strategies, see
    :obj:`JitDataFlowUseropLibrary` and note that the Inline strategy is already handled by this
    point.
     
     
    
    For the Standard strategy, we emit code to retire the program counter, decode context, and all
    live variables. We then request a field to hold the :obj:`PcodeOp.CALLOTHER` p-code op and the
    userop, and emit code to load them. We then emit code to invoke
    :meth:`JitCompiledPassage.invokeUserop(PcodeUseropDefinition, PcodeOp) <JitCompiledPassage.invokeUserop>`. The userop definition
    handles retrieving all of its inputs and writing the output, directly to the
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
    result is returned, but no output operand is provided, we *must* still emit a
    :meth:`pop <Op.pop>`.
    """

    @typing.type_check_only
    class PlacedParam(java.lang.Record, typing.Generic[N]):

        class_: typing.ClassVar[java.lang.Class]

        def args(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
            ...

        def em(self) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def params(self) -> java.util.List[java.lang.reflect.Parameter]:
            ...

        def toString(self) -> str:
            ...


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
    def genRunDirectStrategy(em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: ghidra.pcode.emu.jit.op.JitCallOtherOpIf, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> OpGen.OpResult:
        """
        Emit code to implement the Direct strategy (see the class documentation)
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.op.JitCallOtherOpIf op: the p-code op use-def node
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the result of emitting the userop's bytecode
        :rtype: OpGen.OpResult
        """

    @staticmethod
    def genRunRetirementStrategy(em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: ghidra.program.model.pcode.PcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any]) -> OpGen.OpResult:
        """
        Emit code to implement the Standard strategy (see the class documentation)
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        :param ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any] userop: the userop definition, wrapped by the :obj:`JitDataFlowUseropLibrary`
        :return: the result of emitting the userop's bytecode
        :rtype: OpGen.OpResult
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CallOtherOpGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[CallOtherOpGen]:
        ...


class IntSBorrowOpGen(java.lang.Enum[IntSBorrowOpGen], IntPredBinOpGen[ghidra.pcode.emu.jit.op.JitIntSBorrowOp]):
    """
    The generator for a :obj:`int_sborrow <JitIntSBorrowOp>`.
     
    
    This uses the binary operator generator and emits
    :meth:`invokestatic <Op.invokestatic>` on :meth:`JitCompiledPassage.sBorrowIntRaw(int, int) <JitCompiledPassage.sBorrowIntRaw>` or
    :meth:`JitCompiledPassage.sBorrowLongRaw(long, long) <JitCompiledPassage.sBorrowLongRaw>` depending on the type. We must then emit a
    shift and mask to extract the correct bit.
     
    
    For multi-precision signed borrow, we delegate to
    :meth:`JitCompiledPassage.sBorrowMpInt(int[], int[], int) <JitCompiledPassage.sBorrowMpInt>`, which requires no follow-on bit
    extraction.
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


class FloatNotEqualOpGen(java.lang.Enum[FloatNotEqualOpGen], FloatCompareBinOpGen[ghidra.pcode.emu.jit.op.JitFloatNotEqualOp]):
    """
    The generator for a :obj:`float_notequal <JitFloatNotEqualOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :meth:`fcmpl <Op.fcmpl>` or :meth:`dcmpl <Op.dcmpl>` depending on the type and then :meth:`ifne <Op.ifne>`.
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


class BoolNegateOpGen(java.lang.Enum[BoolNegateOpGen], IntOpUnOpGen[ghidra.pcode.emu.jit.op.JitBoolNegateOp]):
    """
    The generator for a :obj:`bool_negate <JitBoolNegateOp>`.
     
    
    This emits ^1, as observed in code emitted by ``javac``. For multi-precision, we perform that
    operation only on the least-significant leg.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolNegate`. Additionally, boolean operands ought to be a
        byte, but certainly no larger than an int (4 bytes).
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


class FloatOpUnOpGen(UnOpGen[T], typing.Generic[T]):
    """
    An extension for floating-point unary operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def opForDouble(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]:
        """
        Emit the JVM bytecode to perform the operator with double operands on the stack.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the input operand on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]
        """

    def opForFloat(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]:
        """
        Emit the JVM bytecode to perform the operator with float operands on the stack.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the input operand on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]
        """


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


class IntCountUnOpGen(UnOpGen[T], typing.Generic[T]):
    """
    An extension for unary integer operators that count bits
    """

    class_: typing.ClassVar[java.lang.Class]

    def genRunMpInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with mp-int operands.
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the input operand
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., with only the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with int operands on the stack.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the input operand on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type of the input operand
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForLong(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with long operands on the stack.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the input operand on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType type: the p-code type of the input operand
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """


class LzCountOpGen(java.lang.Enum[LzCountOpGen], IntCountUnOpGen[ghidra.pcode.emu.jit.op.JitLzCountOp]):
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


class IntBitwiseBinOpGen(IntOpBinOpGen[T], typing.Generic[T]):
    """
    An extension for bitwise binary operators
     
    
    This provides a simple strategy for multi-precision integer implementation. Since all bit
    positions are considered independently, we just apply the same
    :meth:`opForInt(Emitter, IntJitType) <.opForInt>` operator to each pair of corresponding legs independently
    to compute each corresponding output leg.
    """

    class_: typing.ClassVar[java.lang.Class]


class IntExtUnOpGen(UnOpGen[T], typing.Generic[T]):
    """
    An extension for unary integer extension operators
     
    
    The strategy here is to do nothing more than invoke the readers and writers. Because those are
    responsible for converting between the types, with the appropriate signedness, the work of
    extension is already done. We need only to know whether or not the operators should be treated as
    signed or unsigned. Thankfully, that method is already required by a super interface.
    """

    class_: typing.ClassVar[java.lang.Class]


class FloatEqualOpGen(java.lang.Enum[FloatEqualOpGen], FloatCompareBinOpGen[ghidra.pcode.emu.jit.op.JitFloatEqualOp]):
    """
    The generator for a :obj:`float_equal <JitFloatEqualOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :meth:`fcmpl <Op.fcmpl>` or :meth:`dcmpl <Op.dcmpl>` depending on the type and then :meth:`ifeq <Op.ifeq>`.
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


class IntOpBinOpGen(BinOpGen[T], typing.Generic[T]):
    """
    An extension for integer binary operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def genRunMpInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
        """
        Emit the JVM bytecode to perform the operator with multi-precision operands.
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the operands
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the empty stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]
        """

    def opForInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with intF operands on the stack.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type of the operands
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForLong(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TLong]]:
        """
        Emit the JVM bytecode to perform the operator with long operands on the stack.
        
        :param N2: the tail of the incoming stack:param N1: the tail of the incoming stack including the right operand:param N0: the incoming stack with the right and left operands on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType type: the p-code type of the operands
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TLong]]
        """


class CBranchOpGen(java.lang.Enum[CBranchOpGen], OpGen[ghidra.pcode.emu.jit.op.JitCBranchOp]):
    """
    The generator for a :obj:`cbranch <JitCBranchOp>`.
     
     
    
    First, emits code to load the condition onto the JVM stack.
     
     
    
    With an :obj:`IntBranch` record, this looks up the label for the target block and checks if a
    transition is necessary. If one is necessary, it emits an :meth:`ifeq <Op.ifeq>` with the
    transition and :meth:`goto <Op.goto_>` it guards. The ``ifeq`` skips to the
    fall-through case. If a transition is not necessary, it simply emits an :meth:`ifne <Op.ifne>` to the target label.
     
     
    
    With an :obj:`ExtBranch` record, this does the same as :obj:`BranchOpGen` but guarded by an
    :meth:`ifeq <Op.ifeq>` that skips to the fall-through case.
    """

    @typing.type_check_only
    class CBranchGen(BranchOpGen.BranchGen[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], TB, TO], typing.Generic[TB, TO]):
        """
        An abstract branch code generator for conditional branches.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IntCBranchGen(CBranchOpGen.CBranchGen[ghidra.pcode.emu.jit.JitPassage.RIntBranch, ghidra.pcode.emu.jit.op.JitCBranchOp]):
        """
        A branch code generator for internal conditional branches
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExtCBranchGen(CBranchOpGen.CBranchGen[ghidra.pcode.emu.jit.JitPassage.RExtBranch, ghidra.pcode.emu.jit.op.JitCBranchOp]):
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


class BoolXorOpGen(java.lang.Enum[BoolXorOpGen], IntBitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitBoolXorOp]):
    """
    The generator for a :obj:`bool_xor <JitBoolXorOp>`.
    
    
    .. admonition:: Implementation Note
    
        It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
        This allows us to use bitwise logic instead of having to check for any non-zero value,
        just like :obj:`OpBehaviorBoolXor`. Thus, this is identical to :obj:`IntXorOpGen`.
    
    
    
    .. admonition:: Implementation Note
    
        Because having bits other than the least significant set in the inputs is "undefined
        behavior," we could technically optimize this by only ANDing the least significant leg
        when we're dealing with mp-ints.
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
     
    
    This is not quite like a normal binary operator, because the second operand is always a constant.
    It behaves more like a class of unary operators, if you ask me. Thus, we do not extend
    :obj:`BinOpGen`. We first emit code to load the operand. Then, because the shift amount is
    constant, we can deal with it at *generation time*. We emit code to shift right by that
    constant amount, accounting for bits and bytes. The masking, if required, is taken care of by the
    variable writing code, given the resulting type.
     
    
    To avoid loading parts of the (left) operand that will just get dropped by this operator, we
    instead provide the subpiecing arguments (namely the offset and destination operand size) to the
    value-loading logic. This is done via the :meth:`ValGen.subpiece(int, int) <ValGen.subpiece>` method. We can then
    load only those parts that are actually needed.
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
    a JVM long, if necessary. The varnode size is loaded by emitting an
    :meth:`ldc <Op.ldc__i>`, and finally we emit an invocation of
    :meth:`JitBytesPcodeExecutorStateSpace.read(long, int) <JitBytesPcodeExecutorStateSpace.read>`. The result is a byte array, so we finish
    by emitting the appropriate conversion and write the result to the output operand.
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


class IntSExtOpGen(java.lang.Enum[IntSExtOpGen], IntExtUnOpGen[ghidra.pcode.emu.jit.op.JitIntSExtOp]):
    """
    The generator for a :obj:`int_sext <JitIntSExtOp>`.
     
    
    This works exactly the same as :obj:`IntZExtOpGen` except that the conversions use sign
    extension.
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


class OpGen(java.lang.Object, typing.Generic[T]):
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
    |:obj:`int_zext <PcodeOp.INT_ZEXT>`                    |:obj:`JitIntZExtOp`            |:obj:`IntZExtOpGen`            |none; defers to :obj:`VarGen` and :obj:`Opnd`                                                                                      |
    +------------------------------------------------------+-------------------------------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |:obj:`int_sext <PcodeOp.INT_SEXT>`                    |:obj:`JitIntSExtOp`            |:obj:`IntSExtOpGen`            |none; defers to :obj:`VarGen` and :obj:`Opnd`                                                                                      |
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

    class OpResult(java.lang.Object):
        """
        The result of emitting code for a p-code op
        """

        class_: typing.ClassVar[java.lang.Class]


    class LiveOpResult(java.lang.Record, OpGen.OpResult):
        """
        The result when bytecode after that emitted is reachable
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]) -> None:
            ...

        def em(self) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class DeadOpResult(java.lang.Record, OpGen.OpResult):
        """
        The result when bytecode after that emitted is not reachable
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Dead]) -> None:
            ...

        def em(self) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Dead]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def genRun(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], localCtxmod: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TInt], retReq: ghidra.pcode.emu.jit.gen.util.Methods.RetReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> OpGen.OpResult:
        """
        Emit bytecode into the :meth:`run <JitCompiledPassage.run>` method.
         
         
        
        This method must emit the code needed to load any input operands, convert them to the
        appropriate type, perform the actual operation, and then if applicable, store the output
        operand. The implementations should delegate to
        :meth:`JitCodeGenerator.genReadToStack(Emitter, Local, JitVal, ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType, Ext) <JitCodeGenerator.genReadToStack>`,
        :meth:`JitCodeGenerator.genWriteFromStack(Emitter, Local, JitVar, ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType, Ext, Scope) <JitCodeGenerator.genWriteFromStack>`
        or similar for mp-int types.
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TInt] localCtxmod: a handle to the local holding ``ctxmod``
        :param ghidra.pcode.emu.jit.gen.util.Methods.RetReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint]] retReq: an indication of what must be returned by this
                    :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>` method.
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op (use-def node) to translate
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the basic block containing the p-code op
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the result of emitting the p-code op's bytecode
        :rtype: OpGen.OpResult
        """

    @staticmethod
    def generateSyserrInts(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], opnd: ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        For debugging: emit code to print the values of the given operand to stderr.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType] opnd: the operand whose values to print
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
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
    a JVM long, if necessary. The varnode size is loaded by emitting an
    :meth:`ldc <Op.ldc__i>`. We must now emit code to load the value and convert it to a
    byte array. The conversion depends on the type of the value. Finally, we emit an invocation of
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


class FloatAddOpGen(java.lang.Enum[FloatAddOpGen], FloatOpBinOpGen[ghidra.pcode.emu.jit.op.JitFloatAddOp]):
    """
    The generator for a :obj:`float_add <JitFloatAddOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`fadd <Op.fadd>` or
    :meth:`dadd <Op.dadd>` depending on the type.
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


class IntNegateOpGen(java.lang.Enum[IntNegateOpGen], IntOpUnOpGen[ghidra.pcode.emu.jit.op.JitIntNegateOp]):
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


class IntSLessOpGen(java.lang.Enum[IntSLessOpGen], IntCompareBinOpGen[ghidra.pcode.emu.jit.op.JitIntSLessOp]):
    """
    The generator for a :obj:`int_sless <JitIntSLessOp>`.
     
     
    
    This uses the (signed) integer comparison operator generator and simply emits
    :meth:`if_icmplt <Op.if_icmplt>` or :meth:`iflt <Op.iflt>` depending on the type.
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


class IntNotEqualOpGen(java.lang.Enum[IntNotEqualOpGen], IntCompareBinOpGen[ghidra.pcode.emu.jit.op.JitIntNotEqualOp]):
    """
    The generator for a :obj:`int_notequal <JitIntNotEqualOp>`.
     
     
    
    To avoid jumps, this delegates to :meth:`Integer.compare(int, int) <Integer.compare>`, which is signed, and then
    masks the result.
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


class FloatLessEqualOpGen(java.lang.Enum[FloatLessEqualOpGen], FloatCompareBinOpGen[ghidra.pcode.emu.jit.op.JitFloatLessEqualOp]):
    """
    The generator for a :obj:`float_lessequal <JitFloatLessEqualOp>`.
     
     
    
    This uses the float comparison operator generator and simply emits :meth:`fcmpg <Op.fcmpg>` or :meth:`dcmpg <Op.dcmpg>` depending on the type and then :meth:`ifle <Op.ifle>`.
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


class FloatRoundOpGen(java.lang.Enum[FloatRoundOpGen], FloatOpUnOpGen[ghidra.pcode.emu.jit.op.JitFloatRoundOp]):
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


class IntSRemOpGen(java.lang.Enum[IntSRemOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntSRemOp]):
    """
    The generator for a :obj:`int_srem <JitIntSRemOp>`.
     
     
    
    This uses the binary operator generator and simply emits :meth:`irem <Op.irem>` or
    :meth:`lrem <Op.lrem>` depending on the type.
     
    
    For multi-precision remainder, this emits code to invoke
    :meth:`JitCompiledPassage.mpIntSignedDivide(int[], int[], int[]) <JitCompiledPassage.mpIntSignedDivide>`, but selects what remains in
    the left operand as the result.
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


class IntXorOpGen(java.lang.Enum[IntXorOpGen], IntBitwiseBinOpGen[ghidra.pcode.emu.jit.op.JitIntXorOp]):
    """
    The generator for a :obj:`int_xor <JitIntXorOp>`.
     
     
    
    This uses the bitwise binary operator and emits :meth:`ixor <Op.ixor>` or
    :meth:`lxor <Op.lxor>` depending on the type.
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


class IntDivOpGen(java.lang.Enum[IntDivOpGen], IntOpBinOpGen[ghidra.pcode.emu.jit.op.JitIntDivOp]):
    """
    The generator for a :obj:`int_add <JitIntAddOp>`.
     
    
    This uses the binary operator generator and simply emits
    :meth:`invokestatic <Op.invokestatic>` on :meth:`Integer.divideUnsigned(int, int) <Integer.divideUnsigned>` or *
    :meth:`Long.divideUnsigned(long, long) <Long.divideUnsigned>` depending on the type.
     
    
    For multi-precision division, this emits code to invoke
    :meth:`JitCompiledPassage.mpIntDivide(int[], int[], int[]) <JitCompiledPassage.mpIntDivide>`.
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


class PopCountOpGen(java.lang.Enum[PopCountOpGen], IntCountUnOpGen[ghidra.pcode.emu.jit.op.JitPopCountOp]):
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


class IntOpUnOpGen(UnOpGen[T], typing.Generic[T]):
    """
    An extension for integer unary operators
    """

    class_: typing.ClassVar[java.lang.Class]

    def genRunMpInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], op: T, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
        """
        Emit the JVM bytecode to perform the operator with multi-precision operands.
        
        :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot] em: the emitter typed with the empty stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param T op: the p-code op
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the operands
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the empty stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]
        """

    def opForInt(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit the JVM bytecode to perform the operator with int operands on the stack.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the input operand on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def opForLong(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TLong]]:
        """
        Emit the JVM bytecode to perform the operator with long operands on the stack.
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack with the input operand on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :return: the emitter typed with the resulting stack, i.e., the tail with the result pushed
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TLong]]
        """



__all__ = ["FloatTruncOpGen", "IntLessOpGen", "IntLeftOpGen", "FloatDivOpGen", "FloatNaNOpGen", "FloatAbsOpGen", "BranchIndOpGen", "IntMultOpGen", "IntOrOpGen", "IntRightOpGen", "BoolAndOpGen", "FloatNegOpGen", "BinOpGen", "CopyOpGen", "CatenateOpGen", "IntSRightOpGen", "NopOpGen", "IntAddOpGen", "IntRemOpGen", "IntSCarryOpGen", "IntSDivOpGen", "FloatFloorOpGen", "IntLessEqualOpGen", "Int2CompOpGen", "IntAndOpGen", "IntEqualOpGen", "FloatFloat2FloatOpGen", "IntPredBinOpGen", "FloatConvertUnOpGen", "FloatOpBinOpGen", "IntSLessEqualOpGen", "FloatCompareBinOpGen", "IntSubOpGen", "FloatCeilOpGen", "UnOpGen", "BoolOrOpGen", "FloatLessOpGen", "IntCarryOpGen", "UnimplementedOpGen", "IntCompareBinOpGen", "FloatMultOpGen", "FloatInt2FloatOpGen", "IntZExtOpGen", "PhiOpGen", "IntShiftBinOpGen", "FloatSubOpGen", "FloatSqrtOpGen", "BranchOpGen", "CallOtherOpGen", "IntSBorrowOpGen", "FloatNotEqualOpGen", "BoolNegateOpGen", "FloatOpUnOpGen", "CallOtherMissingOpGen", "IntCountUnOpGen", "LzCountOpGen", "IntBitwiseBinOpGen", "IntExtUnOpGen", "FloatEqualOpGen", "IntOpBinOpGen", "CBranchOpGen", "BoolXorOpGen", "SubPieceOpGen", "LoadOpGen", "IntSExtOpGen", "OpGen", "StoreOpGen", "FloatAddOpGen", "IntNegateOpGen", "IntSLessOpGen", "IntNotEqualOpGen", "FloatLessEqualOpGen", "FloatRoundOpGen", "IntSRemOpGen", "IntXorOpGen", "IntDivOpGen", "SynthSubPieceOpGen", "PopCountOpGen", "IntOpUnOpGen"]
