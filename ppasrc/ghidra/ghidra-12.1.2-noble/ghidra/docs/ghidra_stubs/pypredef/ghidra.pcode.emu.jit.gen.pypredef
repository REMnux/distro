from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit
import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.gen.opnd
import ghidra.pcode.emu.jit.gen.tgt
import ghidra.pcode.emu.jit.gen.util
import ghidra.pcode.emu.jit.var
import ghidra.pcode.error
import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.objectweb.asm # type: ignore


JT = typing.TypeVar("JT")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
T = typing.TypeVar("T")
THIS = typing.TypeVar("THIS")


class FieldForPcodeOp(StaticFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.PcodeOp]]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gen: JitCodeGenerator[typing.Any], op: ghidra.program.model.pcode.PcodeOp) -> None:
        ...


class FieldForSpaceIndirect(java.lang.Record, InstanceFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace]]):
    """
    A field request for a pre-fetched :obj:`JitBytesPcodeExecutorStateSpace`
     
     
    
    The field is used for indirect memory accesses. For those, the address space is given in the
    p-code, but the offset must be computed at run time. Thus, we can pre-fetch the state space, but
    not any particular page.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: ghidra.program.model.address.AddressSpace) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def toString(self) -> str:
        ...


class InstanceFieldReq(FieldReq[T], typing.Generic[T]):
    """
    An instance field request initialized in the class constructor
    """

    class_: typing.ClassVar[java.lang.Class]

    def genInit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: JitCodeGenerator[THIS], cv: org.objectweb.asm.ClassVisitor) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit the field declaration and its initialization bytecode
         
         
        
        The declaration is emitted into the class definition, and the initialization code is emitted
        into the class constructor.
        
        :param THIS: the type of the compiled passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param JitCodeGenerator[THIS] gen: the code generator
        :param org.objectweb.asm.ClassVisitor cv: the visitor for the class definition
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genLoad(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: JitCodeGenerator[THIS]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit code to load the field onto the JVM stack
        
        :param THIS: the type of the compiled passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param JitCodeGenerator[THIS] gen: the code generator
        :return: the emitter typed with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """


class FieldForExitSlot(java.lang.Record, InstanceFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot]]):
    """
    A field request for an :obj:`ExitSlot`.
     
     
    
    One of these is allocated per :meth:`ExtBranch.to() <ExtBranch.to>`. At run time, the first time a branch is
    encountered from this passage to the given target, the slot calls
    :meth:`getEntry <JitPcodeThread.getEntry>```(target)`` and keeps the reference. Each
    subsequent encounter uses the kept reference. This reference is what gets returned by
    :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>`, so now the thread already has in hand the next
    :obj:`EntryPoint` to execute.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, target: ghidra.pcode.emu.jit.JitPassage.AddrCtx) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def target(self) -> ghidra.pcode.emu.jit.JitPassage.AddrCtx:
        ...

    def toString(self) -> str:
        ...


@typing.type_check_only
class FieldForContext(java.lang.Record, StaticFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.RegisterValue]]):
    """
    A field request for pre-constructed contextreg value
    """

    class_: typing.ClassVar[java.lang.Class]

    def ctx(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...


class FieldForArrDirect(java.lang.Record, InstanceFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]]):
    """
    A field request for a pre-fetched page from the :obj:`JitBytesPcodeExecutorStateSpace`.
     
     
    
    The field is used for direct memory accesses. For those, the address space and fixed address is
    given in the p-code, so we are able to pre-fetch the page and access it directly at run time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address) -> None:
        ...

    def address(self) -> ghidra.program.model.address.Address:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...


class FieldForUserop(java.lang.Record, InstanceFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]]]):
    """
    A field request for a pre-fetched userop definition
     
     
    
    These are used to invoke userops using the Standard or Direct strategies.
    
    
    .. seealso::
    
        | :obj:`JitDataFlowUseropLibrary`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def userop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]:
        ...


class GenConsts(java.lang.Object):
    """
    Various constants (namely class names, type descriptions, method descriptions, etc. used during
    bytecode generation.
    """

    class WriteIntX(java.lang.Object):
        """
        This is just to assure all the methods referred to below have the same signature. The fields
        here should not be used in any code, written, generated, or otherwise.
        """

        class_: typing.ClassVar[java.lang.Class]
        AE1: typing.Final[GenConsts.WriteIntX]
        BE2: typing.Final[GenConsts.WriteIntX]
        BE3: typing.Final[GenConsts.WriteIntX]
        BE4: typing.Final[GenConsts.WriteIntX]
        LE2: typing.Final[GenConsts.WriteIntX]
        LE3: typing.Final[GenConsts.WriteIntX]
        LE4: typing.Final[GenConsts.WriteIntX]

        def writeIntX(self, value: typing.Union[jpype.JInt, int], arr: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> None:
            ...


    class WriteLongX(java.lang.Object):
        """
        This is just to assure all the methods referred to below have the same signature. The fields
        here should not be used in any code, written, generated, or otherwise.
        """

        class_: typing.ClassVar[java.lang.Class]
        AE1: typing.Final[GenConsts.WriteLongX]
        BE2: typing.Final[GenConsts.WriteLongX]
        BE3: typing.Final[GenConsts.WriteLongX]
        BE4: typing.Final[GenConsts.WriteLongX]
        BE5: typing.Final[GenConsts.WriteLongX]
        BE6: typing.Final[GenConsts.WriteLongX]
        BE7: typing.Final[GenConsts.WriteLongX]
        BE8: typing.Final[GenConsts.WriteLongX]
        LE2: typing.Final[GenConsts.WriteLongX]
        LE3: typing.Final[GenConsts.WriteLongX]
        LE4: typing.Final[GenConsts.WriteLongX]
        LE5: typing.Final[GenConsts.WriteLongX]
        LE6: typing.Final[GenConsts.WriteLongX]
        LE7: typing.Final[GenConsts.WriteLongX]
        LE8: typing.Final[GenConsts.WriteLongX]

        def writeLongX(self, value: typing.Union[jpype.JLong, int], arr: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SIZE: typing.Final = 4096
    TARR_OBJECT: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[java.lang.Object]]]
    TARR_VARNODE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[ghidra.program.model.pcode.Varnode]]]
    TR_DOUBLE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Double]]
    TR_FLOAT: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Float]]
    TR_INTEGER: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Integer]]
    TR_LONG: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Long]]
    T_ADDRESS: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.Address]]
    T_ADDRESS_FACTORY: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.AddressFactory]]
    T_ADDRESS_SPACE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.AddressSpace]]
    T_ADDR_CTX: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitPassage.AddrCtx]]
    T_ARRAY_LIST: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.util.ArrayList[typing.Any]]]
    T_ASSERTION_ERROR: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.AssertionError]]
    T_DECODE_PCODE_EXECUTION_EXCEPTION: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.DecodePcodeExecutionException]]
    T_ENTRY_POINT: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint]]
    T_EXIT_SLOT: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot]]
    T_ILLEGAL_ARGUMENT_EXCEPTION: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.IllegalArgumentException]]
    T_JIT_BYTES_PCODE_EXECUTOR_STATE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitBytesPcodeExecutorState]]
    T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace]]
    T_JIT_COMPILED_PASSAGE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage]]
    T_JIT_PCODE_THREAD: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitPcodeThread]]
    T_JIT_THREAD_BYTES_PCODE_EXECUTOR_STATE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitThreadBytesPcodeExecutorState]]
    T_LANGUAGE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.Language]]
    T_LIST: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.util.List[typing.Any]]]
    T_LOWLEVEL_ERROR: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.error.LowlevelError]]
    T_MATH: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Math]]
    T_OBJECT: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Object]]
    T_PCODE_OP: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.PcodeOp]]
    T_PCODE_USEROP_DEFINITION: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any]]]
    T_PCODE_USEROP_DEFINITION__BYTEARR: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]]]
    T_PCODE_USEROP_LIBRARY: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary[typing.Any]]]
    T_PRINT_STREAM: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.io.PrintStream]]
    T_REGISTER_VALUE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.RegisterValue]]
    T_SLEIGH_LINK_EXCEPTION: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.SleighLinkException]]
    T_STRING: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]
    T_SYSTEM: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.System]]
    T_THROWABLE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Throwable]]
    T_VARNODE: typing.Final[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.Varnode]]
    MDESC_ADDR_CTX__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.RegisterValue]], ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.Address]]]]
    MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.AddressSpace], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_ADDRESS_SPACE__GET_ADDRESS: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.Address], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_ARRAY_LIST__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Bot]]
    MDESC_ASSERTION_ERROR__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Object]]]]
    MDESC_DOUBLE__DOUBLE_TO_RAW_LONG_BITS: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]]
    MDESC_DOUBLE__IS_NAN: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]]
    MDESC_DOUBLE__LONG_BITS_TO_DOUBLE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_FLOAT__FLOAT_TO_RAW_INT_BITS: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]]
    MDESC_FLOAT__INT_BITS_TO_FLOAT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_FLOAT__IS_NAN: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]]
    MDESC_ILLEGAL_ARGUMENT_EXCEPTION__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_INTEGER__BIT_COUNT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_INTEGER__COMPARE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_INTEGER__TO_UNSIGNED_LONG: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_INTEGER__VALUE_OF: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Integer], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_LANGUAGE: typing.Final[java.lang.String]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_SPACE_FOR: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.AddressSpace]]]]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__GET_DIRECT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__READ: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__WRITE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__COUNT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_CONTEXT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.RegisterValue], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.Language]], ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_DECODE_ERROR: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.DecodePcodeExecutionException], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_EXIT_SLOT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.RegisterValue]]]]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_OP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.PcodeOp], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.Address]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[ghidra.program.model.pcode.Varnode]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.Varnode]]]]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_VARNODE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.Varnode], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.AddressFactory]], ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]], ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot]]]]
    MDESC_JIT_COMPILED_PASSAGE__GET_LANGUAGE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.Language], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_JIT_COMPILED_PASSAGE__GET_USEROP_DEFINITION: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_JIT_COMPILED_PASSAGE__INVOKE_USEROP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.PcodeOp]]]]
    MDESC_JIT_COMPILED_PASSAGE__MP_INT_BINOP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]]
    MDESC_JIT_COMPILED_PASSAGE__READ_BOOL_N: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__READ_INTX: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__READ_LONGX: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__SET_$OR_WRITE_COUNTER_AND_CONTEXT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.lang.RegisterValue]]]]
    MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_INT_RAW: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_LONG_RAW: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_MP_INT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_THROWABLE__PRINT_STACK_TRACE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Bot]]
    MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JByte]]], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_JIT_PCODE_THREAD__GET_STATE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.emu.jit.JitThreadBytesPcodeExecutorState], ghidra.pcode.emu.jit.gen.util.Emitter.Bot]]
    MDESC_LANGUAGE__GET_ADDRESS_FACTORY: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.address.AddressFactory], ghidra.pcode.emu.jit.gen.util.Emitter.Bot]]
    MDESC_LANGUAGE__GET_DEFAULT_SPACE: typing.Final[java.lang.String]
    MDESC_LIST__ADD: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Object]]]]
    MDESC_LONG__BIT_COUNT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_LONG__COMPARE: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_LONG__NUMBER_OF_LEADING_ZEROS: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_LOWLEVEL_ERROR__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_OBJECT__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Bot]]
    MDESC_PCODE_USEROP_DEFINITION__GET_DEFINING_LIBRARY: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.pcode.exec_.PcodeUseropLibrary[typing.Any]], ghidra.pcode.emu.jit.gen.util.Emitter.Bot]]
    MDESC_PRINT_STREAM__PRINTLN: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_SLEIGH_LINK_EXCEPTION__$INIT: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String]]]]
    MDESC_STRING__FORMATTED: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.String], ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[java.lang.Object]]]]]
    MDESC_$DOUBLE_UNOP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TDouble]]]
    MDESC_$FLOAT_UNOP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TFloat]]]
    MDESC_$INT_BINOP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_$LONG_BINOP: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_$SHIFT_AA: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]]
    MDESC_$SHIFT_AJ: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_$SHIFT_AI: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TVoid, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_$SHIFT_JA: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]]
    MDESC_$SHIFT_JJ: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_$SHIFT_JI: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TLong], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]
    MDESC_$SHIFT_IA: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]]
    MDESC_$SHIFT_IJ: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TLong]]]
    MDESC_$SHIFT_II: typing.Final[ghidra.pcode.emu.jit.gen.util.Methods.MthDesc[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TInt], ghidra.pcode.emu.jit.gen.util.Types.TInt]]]


class FieldForVarnode(java.lang.Record, StaticFieldReq[ghidra.pcode.emu.jit.gen.util.Types.TRef[ghidra.program.model.pcode.Varnode]]):
    """
    A field request for a pre-constructed varnode
     
     
    
    These are used to invoke userops using the Standard strategy.
    
    
    .. seealso::
    
        | :obj:`JitDataFlowUseropLibrary`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vn: ghidra.program.model.pcode.Varnode) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class JitCodeGenerator(java.lang.Object, typing.Generic[THIS]):
    """
    The bytecode generator for JIT-accelerated emulation.
     
     
    
    This implements the Code Generation phase of the :obj:`JitCompiler`. With all the prior
    analysis, code generation is just a careful process of visiting all of the ops, variables, and
    analytic results to ensure everything is incorporated and accounted for.
     
     
    ********************
    The Target Classfile
    ********************
    
     
    
    The target is a classfile that implements :obj:`JitCompiledPassage`. As such, it must implement
    all of the specified methods in that interface as well as a constructor having a specific
    :obj:`signature <JitCompiledPassageClass.CONSTRUCTOR_TYPE>`. That signature takes a
    :obj:`JitPcodeThread` and, being a constructor, returns ``void``. We will also need to
    generate a static initializer to populate some metadata and pre-fetch any static things, e.g.,
    the :obj:`SleighLanguage` for the emulation target. The fields are:
     
     
    * ``static``:obj:`String```LANGUAGE_ID`` - The language ID (as in
    :obj:`LanguageID` of the emulation target
    * ``static``:obj:`Language```LANGUAGE`` - The language (ISA) of the emulation
    target
    * ``static``:obj:`AddressFactory```ADDRESS_FACTORY`` - The address factory of
    the language
    * ``static``:obj:`List```<``:obj:`AddrCtx```> ENTRIES`` - The list of
    entry points
    * :obj:`JitPcodeThread```thread`` - The bound thread for this instance of the
    compiled passage
    * :obj:`JitBytesPcodeExecutorState```state`` - The run-time machine state for this
    thread of emulation
    
     
     
    ==================
    Static Initializer
    ==================
    
     
    
    In the Java language, statements in a class's ``static`` block, as well as the initial values
    of static fields are implemented by the classfile's ``<clinit>`` method. We use it to
    pre-construct ``contextreg`` values and :obj:`varnode <Varnode>` refs for use in birthing and
    retirement. They are kept in static fields. We also initialize the static ``ENTRIES`` field,
    which is public (via reflection) and describes each entry point generated. It has the type
    ``List<``:obj:`AddrCtx```>``. A call to :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>` should pass
    in the position of the desired entry point in the ``ENTRIES`` list.
     
     
    ===========
    Constructor
    ===========
    
     
    
    In the Java language, statements in a class's constructor, as well as the initial values of
    instance fields are implemented by the classfile's ``<init>`` methods. We provide a single
    constructor that accepts a :obj:`JitPcodeThread`. Upon construction, the generated
    :obj:`JitCompiledPassage` is "bound" to the given thread. The constructor pre-fetches parts of
    the thread's :obj:`state <JitBytesPcodeExecutorState>` and :obj:`userop definitions <SleighPcodeUseropDefinition>`, and it allocates :obj:`ExitSlot`s. Each of these are kept in instance
    fields.
     
     
    ===================
    ``thread()`` Method
    ===================
    
     
    
    This method implements :meth:`JitCompiledPassage.thread() <JitCompiledPassage.thread>`, a simple getter for the
    ``thread`` field.
     
     
    ================
    ``run()`` Method
    ================
    
     
    
    This method implements :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>`, the actual semantics of the
    translated machine instructions selected for the passage. It accepts a single parameter, which is
    the position in the ``ENTRIES`` list of the desired entry point ``blockId``. The
    structure is as follows:
     
     
    1. Entry point dispatch - a large ``switch`` statement on the entry ``blockId``
    2. P-code translation - the block-by-block op-by-op translation of the p-code to bytecode
    3. Exception handlers - exception handlers as requested by various elements of the p-code
    translation
    4. Parameter declarations - ``this`` and ``blockId``
    5. Allocated local declarations - declares all locals allocated by
    :obj:`JitAllocationModel`
    
     
     
    --------------------
    Entry Point Dispatch
    --------------------
    
     
    
    This part of the run method dispatches execution to the correct entry point within the translated
    passage. It consists of these sub-parts:
     
     
    1. Switch table - a :obj:`tableswitch <Opcodes.TABLESWITCH>` to jump to the code for the scope
    transition into the entry block given by``blockId``
    2. Scope transitions - for each block, birth its live varnodes then jump to the block's
    translation
    3. Default case - throws an :obj:`IllegalArgumentException` for an invalid ``blockId``
    
     
     
    
    This first ensure that a valid entry point was given in ``blockId``. If not, we jump to the
    default case which throws an exception. Otherwise, we jump to the appropriate entry transition.
    Every block flow edge is subject to a scope transition wherein varnodes that leave scope must be
    retired and varnodes that enter scope must be birthed. We generate an entry transition for each
    possible entry block. That transition births all the varnodes that are in scope for that entry
    block then jumps to the entry block's p-code translation.
     
     
    ------------------
    P-code Translation
    ------------------
    
     
    
    Here, most of the generation is performed via delegation to an object model, based on the use-def
    graph. We first iterate over the blocks, in the same order as they appear in the decoded passage.
    This will ensure that fall-through control transitions in the p-code map to fall-through
    transitions in the emitted bytecode. If the block is the target of a bytecode jump, i.e., it's an
    entry block or the target of a p-code branch, then we emit a label at the start of the block. We
    then iterate over each p-code op in the block delegating each to the appropriate generator. We
    emit "line number" information for each op to help debug crashes. A generator may register an
    exception handler to be emitted later in the "exception handlers" part of the ``run`` method.
    If the block has fall through, we emit the appropriate scope transition before proceeding to the
    next block. Note that scope transitions for branch ops are emitted by the generators for those
    ops.
     
     
    
    For details about individual p-code op translations, see :obj:`OpGen`. For details about
    individual SSA value (constant and variable) translations, see :obj:`VarGen`. For details about
    emitting scope transitions, see :obj:`BlockTransition`.
    
    
    .. admonition:: Implementation Note
    
        Throughout most of the code that emits bytecode, there are (human-generated) comments
        to track the contents of the JVM stack. Items pushed onto the stack appear at the
        right. If type is important, then those are denoted using :TYPE after the relevant
        variable. TODO: It'd be nice to have a bytecode API that enforces stack structure using
        the compiler (somehow), but that's probably overkill. Also, I have yet to see what the
        official classfile API will bring.
    """

    @typing.type_check_only
    class VarnodeKey(java.lang.Record):
        """
        The key for a varnode, to ensure we control the definition of :meth:`equality <Object.equals>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, vn: ghidra.program.model.pcode.Varnode) -> None:
            """
            Extract/construct the key for a given varnode
            
            :param ghidra.program.model.pcode.Varnode vn: the varnode
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def offset(self) -> int:
            ...

        def size(self) -> int:
            ...

        def space(self) -> int:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class PcodeOpKey(java.lang.Record):
        """
        The key for a p-code op, to ensure we control "equality"
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, op: ghidra.program.model.pcode.PcodeOp) -> None:
            """
            Extract/construct thhe key for a given op
            
            :param ghidra.program.model.pcode.PcodeOp op: the p-code op
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def ins(self) -> java.util.List[JitCodeGenerator.VarnodeKey]:
            ...

        def opcode(self) -> int:
            ...

        def out(self) -> JitCodeGenerator.VarnodeKey:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class GenBlockResult(java.lang.Record):
        """
        The result of generating code for a block of p-code ops
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def opIdx(self) -> int:
            ...

        def opResult(self) -> ghidra.pcode.emu.jit.gen.op.OpGen.OpResult:
            ...

        def toString(self) -> str:
            ...


    class RetireMode(java.lang.Enum[JitCodeGenerator.RetireMode]):
        """
        The manners in which the program counter and decode context can be "retired."
        """

        class_: typing.ClassVar[java.lang.Class]
        WRITE: typing.Final[JitCodeGenerator.RetireMode]
        """
        Retire into the emulator's counter/context and its machine state
        
        
        .. seealso::
        
            | :obj:`JitCompiledPassage.writeCounterAndContext(long, RegisterValue)`
        """

        SET: typing.Final[JitCodeGenerator.RetireMode]
        """
        Retire into the emulator's counter/context, but not its machine state
        
        
        .. seealso::
        
            | :obj:`JitCompiledPassage.setCounterAndContext(long, RegisterValue)`
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitCodeGenerator.RetireMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitCodeGenerator.RetireMode]:
            ...


    class PcGen(java.lang.Object):
        """
        A mechanism to emit bytecode that loads a program counter
        """

        class_: typing.ClassVar[java.lang.Class]

        def gen(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TLong]]:
            """
            Emit bytecode to load a program counter
            
            :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
            :return: the emitter typed with the resulting stack, i.e., having pushed the counter value
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TLong]]
            """

        @staticmethod
        def loadOffset(address: ghidra.program.model.address.Address) -> JitCodeGenerator.PcGen:
            """
            Create a generator that loads a constant program counter value
            
            :param ghidra.program.model.address.Address address: the program counter
            :return: the generator
            :rtype: JitCodeGenerator.PcGen
            """

        @staticmethod
        def loadTarget(localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: JitCodeGenerator[THIS], target: ghidra.pcode.emu.jit.var.JitVal) -> JitCodeGenerator.PcGen:
            """
            Create a generator that loads a variable program counter
            
            :param THIS: the type of the generated passage:param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
            :param JitCodeGenerator[THIS] gen: the code generator
            :param ghidra.pcode.emu.jit.var.JitVal target: the value (probably a variable) to load to get the program counter
            :return: the generator
            :rtype: JitCodeGenerator.PcGen
            """


    class LineNumberer(java.lang.Object):
        """
        For testing and debugging: A means to inject granular line number information
         
         
        
        Typically, this is used to assign every bytecode offset (emitted by a certain generator) a
        line number, so that tools expecting/requiring line numbers will display something useful.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mv: org.objectweb.asm.MethodVisitor) -> None:
            """
            Prepare to number lines on the given method visitor
            
            :param org.objectweb.asm.MethodVisitor mv: the method visitor
            """

        def nextLine(self) -> None:
            """
            Increment the line number and add info on the next bytecode index
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lookup: java.lang.invoke.MethodHandles.Lookup, context: ghidra.pcode.emu.jit.analysis.JitAnalysisContext, cfm: ghidra.pcode.emu.jit.analysis.JitControlFlowModel, dfm: ghidra.pcode.emu.jit.analysis.JitDataFlowModel, vsm: ghidra.pcode.emu.jit.analysis.JitVarScopeModel, tm: ghidra.pcode.emu.jit.analysis.JitTypeModel, am: ghidra.pcode.emu.jit.analysis.JitAllocationModel, oum: ghidra.pcode.emu.jit.analysis.JitOpUseModel) -> None:
        """
        Construct a code generator for the given passage's target classfile
         
         
        
        This constructor chooses the name for the target classfile based on the passage's entry seed.
        It has the form: `` Passage$at_*address*_*context*``. The address is
        as rendered by :meth:`Address.toString() <Address.toString>` but with characters replaced to make it a valid JVM
        classfile name. The decode context is rendered in hexadecimal. This constructor also declares
        the fields and methods, and emits the definition for :meth:`JitCompiledPassage.thread() <JitCompiledPassage.thread>`.
        
        :param java.lang.invoke.MethodHandles.Lookup lookup: a means of accessing user-defined components, namely userops
        :param ghidra.pcode.emu.jit.analysis.JitAnalysisContext context: the analysis context for the passage
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel cfm: the control flow model
        :param ghidra.pcode.emu.jit.analysis.JitDataFlowModel dfm: the data flow model
        :param ghidra.pcode.emu.jit.analysis.JitVarScopeModel vsm: the variable scope model
        :param ghidra.pcode.emu.jit.analysis.JitTypeModel tm: the type model
        :param ghidra.pcode.emu.jit.analysis.JitAllocationModel am: the allocation model
        :param ghidra.pcode.emu.jit.analysis.JitOpUseModel oum: the op use model
        """

    def genExit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, pcGen: JitCodeGenerator.PcGen, ctx: ghidra.program.model.lang.RegisterValue) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit code to exit the passage
         
         
        
        This retires all the variables of the current block as well as the program counter and decode
        context. It does not generate the actual :obj:`areturn <Opcodes.ARETURN>` or
        :obj:`athrow <Opcodes.ATHROW>`, but everything required up to that point.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op at which we are exiting
        :param JitCodeGenerator.PcGen pcGen: as in :meth:`genRetirePcCtx(Emitter, Local, PcGen, RegisterValue, RetireMode) <.genRetirePcCtx>`
        :param ghidra.program.model.lang.RegisterValue ctx: as in :meth:`genRetirePcCtx(Emitter, Local, PcGen, RegisterValue, RetireMode) <.genRetirePcCtx>`
        :return: the emitter with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genReadLegToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVal, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, leg: typing.Union[jpype.JInt, int], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit bytecode to load one leg of a multi-precision value from the varnode onto the JVM stack.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVal v: the (source) value to read
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the complete multi-precision value
        :param jpype.JInt or int leg: the index of the leg to load, 0 being least significant
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genReadToArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVal, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
        """
        Emit bytecode to load the varnode's value into an integer array in little-endian order,
        pushing its ref onto the JVM stack.
         
        
        Ideally, multi-precision integers should be loaded into a series of locals, i.e., using
        :meth:`genReadToOpnd(Emitter, Local, JitVal, MpIntJitType, Ext, Scope) <.genReadToOpnd>`, but this may not
        always be the best course of action. The first case is for userops, where it'd be onerous and
        counter-intuitive for a user to receive a single varnode in several parameters. The
        annotation system to sort that all out would also be atrocious and not easily made compatible
        with non-JIT emulation. Instead, mp-int arguments are received via ``int[]`` parameters.
         
        The second case is for more complicated p-code ops. One notable example is
        :obj:`int_mult <IntMultOpGen>`. Theoretically, yes, we could emit all of the operations to
        compute the product using long multiplication inline; however, for large operands, that would
        produce an enormous number of bytecodes. Given the 64KB-per-method limit, we could quickly
        squeeze ourselves out of efficient translation of lengthy passages. The ``slack``
        parameter is provided since some of these algorithms (e.g., division) need an extra leg as
        scratch space. If we don't allocate it here, we force complexity into the implementation, as
        it would need to provide its own locals or re-allocate and copy the array.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVal v: the (source) value to read
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the complete multi-precision value
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param jpype.JInt or int slack: the number of additional, more significant, elements to allocate in the array
        :return: the emitter typed with the resulting stack, i.e., having the ref pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
        """

    def genReadToBool(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVal) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit bytecode to load the varnode's value, interpreted as a boolean, as an integer onto the
        JVM stack.
         
        
        Any non-zero value is considered true, though ideally, slaspec authors should ensure all
        booleans are 1) 1-byte ints, and 2) only ever take the value 0 (false) or 1 (true).
        Nevertheless, we can't assume this guidance is followed. When we know a large (esp.
        multi-precision) variable is being used as a boolean, we have some opportunity for
        short-circuiting.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVal v: the (source) value to read
        :return: the emitter typed with the resulting stack, i.e., having the int boolean pushed onto
                it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genReadToOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVal, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]:
        """
        Emit bytecode to read the given value into a series of locals
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVal v: the (source) value to read
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the required p-code type of the value
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the operand containing the locals, and the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]
        """

    def genReadToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVal, type: JT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit bytecode to read the given value onto the JVM stack.
         
         
        
        Although the value may be assigned a type by the :obj:`JitTypeModel`, the type needed by a
        given op might be different.
        
        :param T: the required JVM type of the value:param JT: the required p-code type of the value:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVal v: the (source) value to read
        :param JT type: the required p-code type of the value
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the code visitor typed with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """

    def genRetirePcCtx(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], pcGen: JitCodeGenerator.PcGen, ctx: ghidra.program.model.lang.RegisterValue, mode: JitCodeGenerator.RetireMode) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode to set the emulator's counter and contextreg.
         
         
        
        Within a translated passage, there's no need to keep constant track of the program counter
        (nor decode context), since all the decoding has already been done. However, whenever we exit
        the passage and return control back to the emulator (whether by ``return`` or
        ``throw``) we must "retire" the program counter and decode context, as if the emulator
        had interpreted all the instructions just executed. This ensures that the emulator has the
        correct seed when seeking its next entry point, which may require decoding a new passage.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param JitCodeGenerator.PcGen pcGen: a means to emit bytecode to load the counter (as a long) onto the JVM stack. For
                    errors, this is the address of the op causing the error. For branches, this is the
                    branch target, which may be loaded from a varnode for an indirect branch.
        :param ghidra.program.model.lang.RegisterValue ctx: the contextreg value. For errors, this is the decode context of the op causing the
                    error. For branches, this is the decode context at the target.
        :param JitCodeGenerator.RetireMode mode: whether to set the machine state, too
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genWriteFromArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVar, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode to store a varnode's value from an array of integer legs, in little endian
        order
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack having the array ref on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVar v: the (destination) variable to write
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the value on the stack
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., having popped the array
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def genWriteFromOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVar, opnd: ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode to store a varnode's value from several locals.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVar v: the (destination) variable to write
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType] opnd: the operand whose locals contain the value to be stored
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genWriteFromStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], v: ghidra.pcode.emu.jit.var.JitVar, type: JT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode to write the value on the JVM stack into the given variable.
         
         
        
        Although the destination variable may be assigned a type by the :obj:`JitTypeModel`, the
        type of the value on the stack may not match. This method needs to know that type so that, if
        necessary, it can convert it to the appropriate JVM type for the local variable that holds
        it.
        
        :param T: the JVM type of the value on the stack:param JT: the p-code type of the value on the stack:param N1: the tail of the incoming stack:param N0: the incoming stack having the value on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.var.JitVar v: the (destination) variable to write
        :param JT type: the p-code type of the value on the stack
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., having popped the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def getAddressForOp(self, op: ghidra.program.model.pcode.PcodeOp) -> ghidra.program.model.address.Address:
        """
        Get the address that generated the given p-code op.
         
         
        
        NOTE: The decoder rewrites ops to ensure they have the decode address, even if they were
        injected or from an inlined userop.
        
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :return: the address, i.e., the program counter at the time the op is executed
        :rtype: ghidra.program.model.address.Address
        """

    def getAllocationModel(self) -> ghidra.pcode.emu.jit.analysis.JitAllocationModel:
        """
        Get the allocation model
        
        :return: the model
        :rtype: ghidra.pcode.emu.jit.analysis.JitAllocationModel
        """

    def getAnalysisContext(self) -> ghidra.pcode.emu.jit.analysis.JitAnalysisContext:
        """
        Get the analysis context
        
        :return: the context
        :rtype: ghidra.pcode.emu.jit.analysis.JitAnalysisContext
        """

    def getErrorMessage(self, op: ghidra.program.model.pcode.PcodeOp) -> str:
        """
        Get the error message for a given p-code op.
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op generating the error
        :return: the message
        :rtype: str
        
        .. seealso::
        
            | :obj:`JitPassage.getErrorMessage(PcodeOp)`
        """

    def getExitContext(self, op: ghidra.program.model.pcode.PcodeOp) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the context of the instruction that generated the given p-code op.
         
         
        
        This is necessary when exiting the passage, whether due to an exception or "normal" exit. The
        emulator's context must be updated so that it can resume execution appropriately.
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op causing the exit
        :return: the contextreg value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getOpEntry(self, op: ghidra.program.model.pcode.PcodeOp) -> ghidra.pcode.emu.jit.JitPassage.AddrCtx:
        """
        Check if the given p-code op is the first of an instruction.
        
        :param ghidra.program.model.pcode.PcodeOp op: the op to check
        :return: the address-context pair
        :rtype: ghidra.pcode.emu.jit.JitPassage.AddrCtx
        
        .. seealso::
        
            | :obj:`JitPassage.getOpEntry(PcodeOp)`
        """

    def getTypeModel(self) -> ghidra.pcode.emu.jit.analysis.JitTypeModel:
        """
        Get the type model
        
        :return: the model
        :rtype: ghidra.pcode.emu.jit.analysis.JitTypeModel
        """

    def getVariableScopeModel(self) -> ghidra.pcode.emu.jit.analysis.JitVarScopeModel:
        """
        Get the variable scope model
        
        :return: the model
        :rtype: ghidra.pcode.emu.jit.analysis.JitVarScopeModel
        """

    def labelForBlock(self, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> ghidra.pcode.emu.jit.gen.util.Lbl[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]:
        """
        Get the label at the start of a block's translation
        
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block
        :return: the label
        :rtype: ghidra.pcode.emu.jit.gen.util.Lbl[ghidra.pcode.emu.jit.gen.util.Emitter.Bot]
        """

    def load(self) -> ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass:
        """
        Generate the classfile for this passage and load it into this JVM.
        
        :return: the translation, wrapped in utilities that knows how to process and instantiate it
        :rtype: ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass
        """

    def requestExceptionHandler(self, op: ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> ExceptionHandler:
        """
        Request an exception handler that can retire state for a given op
        
        :param ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp op: the op that might throw an exception
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        :return: the exception handler request
        :rtype: ExceptionHandler
        """

    def requestFieldForArrDirect(self, address: ghidra.program.model.address.Address) -> FieldForArrDirect:
        """
        Request a field for the bytes backing the page at the given address
        
        :param ghidra.program.model.address.Address address: the address contained by the desired page
        :return: the field request
        :rtype: FieldForArrDirect
        """

    def requestFieldForExitSlot(self, target: ghidra.pcode.emu.jit.JitPassage.AddrCtx) -> FieldForExitSlot:
        """
        Request a field for the :obj:`ExitSlot` for the given target
        
        :param ghidra.pcode.emu.jit.JitPassage.AddrCtx target: the target address and decode context
        :return: the field request
        :rtype: FieldForExitSlot
        """

    def requestFieldForSpaceIndirect(self, space: ghidra.program.model.address.AddressSpace) -> FieldForSpaceIndirect:
        """
        Request a field for a :obj:`JitBytesPcodeExecutorStateSpace` for the given address space
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: the field request
        :rtype: FieldForSpaceIndirect
        """

    def requestFieldForUserop(self, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]]) -> FieldForUserop:
        """
        Request a field for the given userop
        
        :param ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[jpype.JArray[jpype.JByte]] userop: the userop
        :return: the field request
        :rtype: FieldForUserop
        """

    def requestStaticFieldForOp(self, op: ghidra.program.model.pcode.PcodeOp) -> FieldForPcodeOp:
        """
        Request a field for the given p-code op
         
        
        This will request fields for each varnode for the op's operands
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op
        :return: the field request
        :rtype: FieldForPcodeOp
        """

    def requestStaticFieldForVarnode(self, vn: ghidra.program.model.pcode.Varnode) -> FieldForVarnode:
        """
        Request a field for the given varnode
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the field request
        :rtype: FieldForVarnode
        """

    def resolveType(self, val: ghidra.pcode.emu.jit.var.JitVal, type: ghidra.pcode.emu.jit.analysis.JitTypeBehavior) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Resolve the type of the given value to the given behavior
        
        :param ghidra.pcode.emu.jit.var.JitVal val: the value
        :param ghidra.pcode.emu.jit.analysis.JitTypeBehavior type: the behavior
        :return: the type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @property
    def exitContext(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def opEntry(self) -> ghidra.pcode.emu.jit.JitPassage.AddrCtx:
        ...

    @property
    def analysisContext(self) -> ghidra.pcode.emu.jit.analysis.JitAnalysisContext:
        ...

    @property
    def allocationModel(self) -> ghidra.pcode.emu.jit.analysis.JitAllocationModel:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def addressForOp(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def variableScopeModel(self) -> ghidra.pcode.emu.jit.analysis.JitVarScopeModel:
        ...

    @property
    def typeModel(self) -> ghidra.pcode.emu.jit.analysis.JitTypeModel:
        ...


class StaticFieldReq(FieldReq[T], typing.Generic[T]):
    """
    A static field request initialized in the class initializer
    """

    class_: typing.ClassVar[java.lang.Class]

    def genClInitCode(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: JitCodeGenerator[typing.Any], cv: org.objectweb.asm.ClassVisitor) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit the field declaration and its initialization bytecode
         
         
        
        The declaration is emitted into the class definition, and the initialization code is emitted
        into the class initializer.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param JitCodeGenerator[typing.Any] gen: the code generator
        :param org.objectweb.asm.ClassVisitor cv: the visitor for the class definition
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genLoad(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: JitCodeGenerator[typing.Any]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit code to load the field onto the JVM stack
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param JitCodeGenerator[typing.Any] gen: the code generator
        :return: the emitter typed with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """


class ExceptionHandler(java.lang.Record):
    """
    A requested exception handler
     
     
    
    When an exception occurs, we must retire all of the variables before we pop the
    :meth:`run <JitCompiledPassage.run>` method's frame. We also write out the program counter and
    disassembly context so that the emulator can resume appropriately. After that, we re-throw the
    exception.
     
     
    
    When the code generator knows the code it's emitting can cause a user exception, e.g., the Direct
    invocation of a userop, and there are live variables in scope, then it should request a handler
    (via :meth:`JitCodeGenerator.requestExceptionHandler(DecodedPcodeOp, JitBlock) <JitCodeGenerator.requestExceptionHandler>`) and surround the
    code in a ``try-catch`` on :obj:`Throwable` directing it to this handler.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> None:
        """
        Construct a handler, generating a new label
        
        :param ghidra.program.model.pcode.PcodeOp op: the op which may cause an exception
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        """

    @typing.overload
    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, lbl: ghidra.pcode.emu.jit.gen.util.Lbl[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Throwable]]]) -> None:
        ...

    def block(self) -> ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def genRun(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Dead], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: JitCodeGenerator[THIS]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Dead]:
        """
        Emit the handler's code into the :meth:`run <JitCompiledPassage.run>` method.
        
        :param THIS: the type of the compiled passage:param ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Dead] em: the dead emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param JitCodeGenerator[THIS] gen: the code generator
        :return: the dead emitter
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Dead]
        """

    def hashCode(self) -> int:
        ...

    def lbl(self) -> ghidra.pcode.emu.jit.gen.util.Lbl[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[ghidra.pcode.emu.jit.gen.util.Emitter.Bot, ghidra.pcode.emu.jit.gen.util.Types.TRef[java.lang.Throwable]]]:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...


class FieldReq(java.lang.Object, typing.Generic[T]):
    """
    A field request for a pre-fetched or pre-constructed element
    """

    class_: typing.ClassVar[java.lang.Class]

    def name(self) -> str:
        """
        Derive a suitable name for the field
        
        :return: the name
        :rtype: str
        """



__all__ = ["FieldForPcodeOp", "FieldForSpaceIndirect", "InstanceFieldReq", "FieldForExitSlot", "FieldForContext", "FieldForArrDirect", "FieldForUserop", "GenConsts", "FieldForVarnode", "JitCodeGenerator", "StaticFieldReq", "ExceptionHandler", "FieldReq"]
