from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.var
import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore
import org.apache.commons.collections4 # type: ignore


class JitIntSRemOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SREM`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatTestOp(JitFloatBinOp):
    """
    A binary p-code operator use-def node with :obj:`float <JitTypeBehavior.FLOAT>` inputs and a
    boolean (:obj:`int <JitTypeBehavior.INTEGER>`) output.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitIntAndOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_AND`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatNotEqualOp(java.lang.Record, JitFloatTestOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_NOTEQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntXorOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_XOR`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitNopOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`NopPcodeOp` or an inlined :obj:`PcodeOp.CALLOTHER`.
     
     
    
    When a callother is inlined, we preserve the original op for bookkeeping, but ensure that no code
    is emitted for it by wrapping it in this use-def node class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...


class JitIntLessEqualOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_LESSEQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntAddOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_ADD`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatRoundOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_ROUND`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntDivOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_DIV`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntCarryOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_CARRY`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitCopyOp(java.lang.Record, JitUnOp):
    """
    The use-def node for a :obj:`PcodeOp.COPY`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitFloatTruncOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_TRUNC`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntRemOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_REM`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntSubOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SUB`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitBoolNegateOp(java.lang.Record, JitBoolUnOp):
    """
    The use-def node for a :obj:`PcodeOp.BOOL_NEGATE`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitStoreOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`PcodeOp.STORE`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, space: ghidra.program.model.address.AddressSpace, offset: ghidra.pcode.emu.jit.var.JitVal, value: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def offset(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def offsetType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We'd like the offset to be an :obj:`int <JitTypeBehavior.INTEGER>`.
        
        :return: :obj:`JitTypeBehavior.INTEGER`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def toString(self) -> str:
        ...

    def value(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def valueType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We do not require a particular type for the value.
        
        :return: :obj:`JitTypeBehavior.ANY`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """


class JitIntMultOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_MULT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatSqrtOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_SQRT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitBranchIndOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`PcodeOp.BRANCHIND`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, target: ghidra.pcode.emu.jit.var.JitVal, branch: ghidra.pcode.emu.jit.JitPassage.RIndBranch):
        ...

    def branch(self) -> ghidra.pcode.emu.jit.JitPassage.RIndBranch:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def target(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def targetType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We'd like the offset to be an :obj:`int <JitTypeBehavior.INTEGER>`.
        
        :return: :obj:`JitTypeBehavior.INTEGER`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def toString(self) -> str:
        ...


class JitUnOp(JitDefOp):
    """
    A p-code operator use-def node with one input and one output.
    """

    class_: typing.ClassVar[java.lang.Class]

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        The use-def node for the input operand
        
        :return: the input
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def uType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        The required type behavior for the operand
        
        :return: the behavior
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """


class JitFloatInt2FloatOp(java.lang.Record, JitUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_INT2FLOAT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitDefOp(JitOp):
    """
    A p-code operator use-def node with an output
    """

    class_: typing.ClassVar[java.lang.Class]

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        """
        The the use-def variable node for the output.
        
        :return: the output
        :rtype: ghidra.pcode.emu.jit.var.JitOutVar
        """

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        The required type behavior for the output
        
        :return: the behavior
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """


class JitCallOtherOpIf(JitOp):
    """
    A use-def node for a :obj:`PcodeOp.CALLOTHER`.
     
     
    
    This requires the :meth:`userop() <.userop>` to exist. For the case of a missing userop, we use
    :obj:`JitCallOtherMissingOp`.
     
     
    
    **TODO**: We have several considerations remaining, esp., since we'd like to handle system
    calls via userops efficiently:
     
     
    1. There are more inputs than listed in the op itself. In fact, the invocation is just
    ``syscall()``. The actual inputs are at least ``RAX`` and whatever parameters that
    specific syscall wants.
    2. We'd like to be able to evaluate ``RAX`` statically.
    3. We Might like to inject the p-code rather than trying to compile and run it separately. Then,
    in the case of a syscall, the actual Java callback should have known inputs and outputs. Would
    probablynot want to embed a huge if-elseif tree for syscall numbers, though, which is
    why we'd like to evaluate RAX ahead of time. What if we can't, though? My thought is to retire
    all the variables and just interpret the syscall.
    """

    class_: typing.ClassVar[java.lang.Class]

    def args(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        The arguments to the userop.
        
        :return: the list of use-def value nodes
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        """

    def dfState(self) -> ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState:
        """
        Get the captured data flow state at the call site.
        
        :return: the state
        :rtype: ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState
        """

    def inputTypes(self) -> java.util.List[ghidra.pcode.emu.jit.analysis.JitTypeBehavior]:
        """
        The type behavior for each parameter in the userop definition
         
         
        
        These should correspond to each argument (input).
        
        :return: the list of behaviors
        :rtype: java.util.List[ghidra.pcode.emu.jit.analysis.JitTypeBehavior]
        """

    def userop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object]:
        """
        The userop definition.
        
        :return: the definition from the library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object]
        """


class JitIntSDivOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SDIV`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitSyntheticOp(JitOp):
    """
    A synthetic p-code operator use-def node.
     
     
    
    Synthetic nodes do not correspond to a :obj:`PcodeOp` emitted in the actual decoded passage.
    Instead, they are created as part of the data flow analysis. They are used by downstream
    analyzers, but do not directly result in any emitted bytecode.
    
    
    .. seealso::
    
        | :obj:`JitVarScopeModel`
    """

    class_: typing.ClassVar[java.lang.Class]


class JitIntUnOp(JitUnOp):
    """
    A unary p-code operator use-def node with :obj:`int <JitTypeBehavior.INTEGER>` types.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitCallOtherMissingOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`PcodeOp.CALLOTHER` when the userop turns up missing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, opName: typing.Union[java.lang.String, str]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def opName(self) -> str:
        ...

    def toString(self) -> str:
        ...


class JitFloatLessOp(java.lang.Record, JitFloatTestOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_LESS`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitBinOp(JitDefOp):
    """
    A p-code operator use-def node with two inputs and one output.
    """

    class_: typing.ClassVar[java.lang.Class]

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        The use-def node for the left input operand
        
        :return: the input
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def lType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        The required type behavior for the left operand
        
        :return: the behavior
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        The use-def node for the right input operand
        
        :return: the input
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def rType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        The required type behavior for the right operand
        
        :return: the behavior
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """


class JitFloatNegOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_NEG`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntSCarryOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SCARRY`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatEqualOp(java.lang.Record, JitFloatTestOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_EQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitBoolBinOp(JitBinOp):
    """
    A binary p-code operator use-def node with boolean (:obj:`int <JitTypeBehavior.INTEGER>`) types.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitSubPieceOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.SUBPIECE`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal, offset: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def offset(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntZExtOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_ZEXT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitFloatBinOp(JitBinOp):
    """
    A binary p-code operator use-def node with :obj:`float <JitTypeBehavior.FLOAT>` types.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitIntNegateOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_NEGATE`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitPopCountOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.POPCOUNT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitFloatFloat2FloatOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_FLOAT2FLOAT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitBoolUnOp(JitUnOp):
    """
    A unary p-code operator use-def node with boolean (:obj:`int <JitTypeBehavior.INTEGER>`) types.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitCallOtherOp(java.lang.Record, JitCallOtherOpIf):
    """
    The use-def node for a :obj:`PcodeOp.CALLOTHER` without an output operand.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object], args: java.util.List[ghidra.pcode.emu.jit.var.JitVal], inputTypes: java.util.List[ghidra.pcode.emu.jit.analysis.JitTypeBehavior], dfState: ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState):
        ...

    def args(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        ...

    def dfState(self) -> ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def inputTypes(self) -> java.util.List[ghidra.pcode.emu.jit.analysis.JitTypeBehavior]:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...

    def userop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object]:
        ...


class JitIntLeftOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_LEFT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntSBorrowOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SBORROW`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntEqualOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_EQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntTestOp(JitIntBinOp):
    """
    A binary p-code operator use-def node with :obj:`int <JitTypeBehavior.INTEGER>` inputs and a
    boolean (:obj:`int <JitTypeBehavior.INTEGER>`) output.
    
    
    .. admonition:: Implementation Note
    
        Correct. This doesn't change anything, because boolean is int. Nevertheless, we keep
        this here because it forms a useful category of p-code ops. Also, if we ever need to
        formalize the "boolean" type, we'll already have this in place.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitFloatDivOp(java.lang.Record, JitFloatBinOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_DIV`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatNaNOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_NAN`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntNotEqualOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_NOTEQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitBoolOrOp(java.lang.Record, JitBoolBinOp):
    """
    The use-def node for a :obj:`PcodeOp.BOOL_OR`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntSLessOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SLESS`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatAbsOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_ABS`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitInt2CompOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_2COMP`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitFloatAddOp(java.lang.Record, JitFloatBinOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_ADD`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitLoadOp(java.lang.Record, JitDefOp):
    """
    The use-def node for a :obj:`PcodeOp.LOAD`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, space: ghidra.program.model.address.AddressSpace, offset: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def offset(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def offsetType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We'd like the offset to be an :obj:`int <JitTypeBehavior.INTEGER>`.
        
        :return: :obj:`JitTypeBehavior.INTEGER`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def toString(self) -> str:
        ...


class JitIntSRightOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SRIGHT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatMultOp(java.lang.Record, JitFloatBinOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_MULT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatSubOp(java.lang.Record, JitFloatBinOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_SUB`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitBoolAndOp(java.lang.Record, JitBoolBinOp):
    """
    The use-def node for a :obj:`PcodeOp.BOOL_AND`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitPhiOp(java.lang.Record, JitDefOp, JitSyntheticOp):
    """
    The synthetic use-def node for phi nodes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, out: ghidra.pcode.emu.jit.var.JitOutVar):
        """
        Construct a phi node without any options, yet.
        
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op that generated this phi node
        :param ghidra.pcode.emu.jit.var.JitOutVar out: the use-def variable node for the output
        """

    @typing.overload
    def __init__(self, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, out: ghidra.pcode.emu.jit.var.JitOutVar, options: org.apache.commons.collections4.BidiMap[ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow, ghidra.pcode.emu.jit.var.JitVal]):
        ...

    def addInputOption(self):
        """
        Add the :obj:`input <JitInputVar>` option, if not already present
        """

    def addOption(self, flow: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow, option: ghidra.pcode.emu.jit.var.JitVal):
        """
        Add an option assuming the given flow is taken
        
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow flow: the flow
        :param ghidra.pcode.emu.jit.var.JitVal option: the option
        """

    def block(self) -> ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hasInputOption(self) -> bool:
        """
        Check if one of the options is an :obj:`input <JitInputVar>` to the passage.
        
        :return: true if an input option is present.
        :rtype: bool
        """

    def hashCode(self) -> int:
        ...

    def optionType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We do not require a particular type for the value, but we note the result is the same.
        
        :return: :obj:`JitTypeBehavior.COPY`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def options(self) -> org.apache.commons.collections4.BidiMap[ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow, ghidra.pcode.emu.jit.var.JitVal]:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...


class JitFloatLessEqualOp(java.lang.Record, JitFloatTestOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_LESSEQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatCeilOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_CEIL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntOrOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_OR`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitBoolXorOp(java.lang.Record, JitBoolBinOp):
    """
    The use-def node for a :obj:`PcodeOp.BOOL_XOR`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitCallOtherDefOp(java.lang.Record, JitCallOtherOpIf, JitDefOp):
    """
    The use-def node for a :obj:`PcodeOp.CALLOTHER` with an output operand.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, type: ghidra.pcode.emu.jit.analysis.JitTypeBehavior, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object], args: java.util.List[ghidra.pcode.emu.jit.var.JitVal], inputTypes: java.util.List[ghidra.pcode.emu.jit.analysis.JitTypeBehavior], dfState: ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState):
        ...

    def args(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        ...

    def dfState(self) -> ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def inputTypes(self) -> java.util.List[ghidra.pcode.emu.jit.analysis.JitTypeBehavior]:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        ...

    def userop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object]:
        ...


class JitCatenateOp(java.lang.Record, JitDefOp, JitSyntheticOp):
    """
    The synthetic use-def node for concatenation.
    
     
    
    These are synthesized when memory/register access patterns cause multiple use-def variable nodes
    to be "read" at the same time. E.g., consider ``AL`` and ``AH`` to be written and then
    ``AX`` read.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, out: ghidra.pcode.emu.jit.var.JitOutVar, parts: java.util.List[ghidra.pcode.emu.jit.var.JitVal]):
        """
        Compact constructor for validation
        
        :param ghidra.pcode.emu.jit.var.JitOutVar out: the use-def variable node for the output
        :param java.util.List[ghidra.pcode.emu.jit.var.JitVal] parts: the inputs to be concatenated
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def iterParts(self, bigEndian: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Iterate over the parts from most to least significant
        
        :param jpype.JBoolean or bool bigEndian: the byte order off the machine
        :return: an iterable over the parts
        :rtype: java.lang.Iterable[ghidra.pcode.emu.jit.var.JitVal]
        """

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def partType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We'd like every part to be an :obj:`int <JitTypeBehavior.INTEGER>`.
        
        :return: :obj:`JitTypeBehavior.INTEGER`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def parts(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        ...

    def toString(self) -> str:
        ...


class JitSynthSubPieceOp(java.lang.Record, JitDefOp, JitSyntheticOp):
    """
    The synthetic use-def node for subpiece.
     
     
    
    These are synthesized when memory/register access patterns cause only part of a use-def variable
    node to be "read." E.g., consider ``AX`` to be written and then ``AL`` read. These are
    different than :obj:`JitSubPieceOp` in that the latter have an actual :obj:`PcodeOp`
    associated.
    
    
    .. admonition:: Implementation Note
    
        Bits are shifted to the right by offset bytes. Then bits are truncated from the left to
        force it to match the out var's size.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, out: ghidra.pcode.emu.jit.var.JitOutVar, offset: typing.Union[jpype.JInt, int], v: ghidra.pcode.emu.jit.var.JitVal):
        """
        Compact constructor for validation.
        
        :param ghidra.pcode.emu.jit.var.JitOutVar out: the use-def variable node for the output
        :param jpype.JInt or int offset: the offset, in bytes, to shift right
        :param ghidra.pcode.emu.jit.var.JitVal v: the input use-def value node
        """

    def abuts(self, right: JitSynthSubPieceOp) -> bool:
        """
        Check if this piece abuts the given piece.
         
         
        
        To "abut," the pieces must take the same value as input, and then this piece's offset must be
        exactly the other's offset plus its size. Consider this diagram:
         
         
        [this][right]
         
         
         
        
        We want this piece to be in the more-significant position immediately before the given piece.
        We thus compute ``diff`` the difference in offsets and check if that is equal to the size
        of the right piece. If it is, then we have:
        
         
        [offset=x+diff,size=s][offset=x,size=diff]
         
         
         
        
        And the "whole piece" is
         
         
        [offset=x,size=s+diff]
         
        
        :param JitSynthSubPieceOp right: the piece to the right, i.e., less significant
        :return: true if the two pieces can be expressed as one whole
        :rtype: bool
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def offset(self) -> int:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def v(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def vType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We'd like the input to be an :obj:`int <JitTypeBehavior.INTEGER>`.
        
        :return: :obj:`JitTypeBehavior.INTEGER`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """


class JitIntLessOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_LESS`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntSLessEqualOp(java.lang.Record, JitIntTestOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SLESSEQUAL`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitFloatUnOp(JitUnOp):
    """
    A unary p-code operator use-def node with :obj:`float <JitTypeBehavior.FLOAT>` types.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitLzCountOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.LZCOUNT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitBranchOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`PcodeOp.BRANCH`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, branch: ghidra.pcode.emu.jit.JitPassage.RBranch):
        ...

    def branch(self) -> ghidra.pcode.emu.jit.JitPassage.RBranch:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...


class JitIntSExtOp(java.lang.Record, JitIntUnOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_SEXT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitFloatFloorOp(java.lang.Record, JitFloatUnOp):
    """
    The use-def node for a :obj:`PcodeOp.FLOAT_FLOOR`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def toString(self) -> str:
        ...

    def u(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...


class JitIntRightOp(java.lang.Record, JitIntBinOp):
    """
    The use-def node for a :obj:`PcodeOp.INT_RIGHT`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def l(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def out(self) -> ghidra.pcode.emu.jit.var.JitOutVar:
        ...

    def r(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def toString(self) -> str:
        ...


class JitIntBinOp(JitBinOp):
    """
    A binary p-code operator use-def node with :obj:`int <JitTypeBehavior.INTEGER>` types.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitOp(java.lang.Object):
    """
    A p-code operator use-def node.
     
     
    
    For a table of p-code ops, use-def nodes, and code generators, see :obj:`OpGen`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def binOp(op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, l: ghidra.pcode.emu.jit.var.JitVal, r: ghidra.pcode.emu.jit.var.JitVal) -> JitDefOp:
        """
        Create a use-def node for a binary p-coe op
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :param ghidra.pcode.emu.jit.var.JitOutVar out: the (pre-made) output operand use-def node
        :param ghidra.pcode.emu.jit.var.JitVal l: the left input operand use-def node
        :param ghidra.pcode.emu.jit.var.JitVal r: the right input operand use-def node
        :return: the use-def node
        :rtype: JitDefOp
        """

    def canBeRemoved(self) -> bool:
        """
        Indicates the operation can be removed if its output is never used.
        
        :return: true if removable
        :rtype: bool
        """

    def inputs(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        The input operand use-def nodes in some defined order
        
        :return: the list of inputs
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        """

    def link(self):
        """
        Add this op to the :meth:`JitVal.uses() <JitVal.uses>` of each input operand, and (if applicable) set the
        :meth:`JitOutVar.definition() <JitOutVar.definition>` of the output operand to this op.
        """

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        The p-code op represented by this use-def node
        
        :return: the p-code op
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    @staticmethod
    def stubOp(op: ghidra.program.model.pcode.PcodeOp) -> JitOp:
        """
        Create a use-def node for a nop or unimplemented op.
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :return: the use-def node
        :rtype: JitOp
        """

    def typeFor(self, position: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        Get the required type behavior for the input at the given position in :meth:`inputs() <.inputs>`
        
        :param jpype.JInt or int position: the input position
        :return: the behavior
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    @staticmethod
    def unOp(op: ghidra.program.model.pcode.PcodeOp, out: ghidra.pcode.emu.jit.var.JitOutVar, u: ghidra.pcode.emu.jit.var.JitVal) -> JitUnOp:
        """
        Create a use-def node for a unary p-coe op
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :param ghidra.pcode.emu.jit.var.JitOutVar out: the (pre-made) output operand use-def node
        :param ghidra.pcode.emu.jit.var.JitVal u: the input operand use-def node
        :return: the use-def node
        :rtype: JitUnOp
        """

    def unlink(self):
        """
        Remove this op from the :meth:`JitVal.uses() <JitVal.uses>` of each input operand, and (if applicable)
        unset the :meth:`JitOutVar.definition() <JitOutVar.definition>` of the output operand.
        """


class JitUnimplementedOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`PcodeOp.UNIMPLEMENTED`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...


class JitCBranchOp(java.lang.Record, JitOp):
    """
    The use-def node for a :obj:`PcodeOp.CBRANCH`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, branch: ghidra.pcode.emu.jit.JitPassage.RBranch, cond: ghidra.pcode.emu.jit.var.JitVal):
        ...

    def branch(self) -> ghidra.pcode.emu.jit.JitPassage.RBranch:
        ...

    def cond(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    def condType(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
        """
        We'd like the condition to be an :obj:`int <JitTypeBehavior.INTEGER>` (boolean).
        
        :return: :obj:`JitTypeBehavior.INTEGER`
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeBehavior
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...



__all__ = ["JitIntSRemOp", "JitFloatTestOp", "JitIntAndOp", "JitFloatNotEqualOp", "JitIntXorOp", "JitNopOp", "JitIntLessEqualOp", "JitIntAddOp", "JitFloatRoundOp", "JitIntDivOp", "JitIntCarryOp", "JitCopyOp", "JitFloatTruncOp", "JitIntRemOp", "JitIntSubOp", "JitBoolNegateOp", "JitStoreOp", "JitIntMultOp", "JitFloatSqrtOp", "JitBranchIndOp", "JitUnOp", "JitFloatInt2FloatOp", "JitDefOp", "JitCallOtherOpIf", "JitIntSDivOp", "JitSyntheticOp", "JitIntUnOp", "JitCallOtherMissingOp", "JitFloatLessOp", "JitBinOp", "JitFloatNegOp", "JitIntSCarryOp", "JitFloatEqualOp", "JitBoolBinOp", "JitSubPieceOp", "JitIntZExtOp", "JitFloatBinOp", "JitIntNegateOp", "JitPopCountOp", "JitFloatFloat2FloatOp", "JitBoolUnOp", "JitCallOtherOp", "JitIntLeftOp", "JitIntSBorrowOp", "JitIntEqualOp", "JitIntTestOp", "JitFloatDivOp", "JitFloatNaNOp", "JitIntNotEqualOp", "JitBoolOrOp", "JitIntSLessOp", "JitFloatAbsOp", "JitInt2CompOp", "JitFloatAddOp", "JitLoadOp", "JitIntSRightOp", "JitFloatMultOp", "JitFloatSubOp", "JitBoolAndOp", "JitPhiOp", "JitFloatLessEqualOp", "JitFloatCeilOp", "JitIntOrOp", "JitBoolXorOp", "JitCallOtherDefOp", "JitCatenateOp", "JitSynthSubPieceOp", "JitIntLessOp", "JitIntSLessEqualOp", "JitFloatUnOp", "JitLzCountOp", "JitBranchOp", "JitIntSExtOp", "JitFloatFloorOp", "JitIntRightOp", "JitIntBinOp", "JitOp", "JitUnimplementedOp", "JitCBranchOp"]
