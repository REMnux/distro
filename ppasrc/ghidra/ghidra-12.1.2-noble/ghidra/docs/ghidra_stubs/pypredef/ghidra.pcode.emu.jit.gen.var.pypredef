from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.alloc
import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.gen.opnd
import ghidra.pcode.emu.jit.gen.util
import ghidra.pcode.emu.jit.var
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore


FT = typing.TypeVar("FT")
JT = typing.TypeVar("JT")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
T = typing.TypeVar("T")
THIS = typing.TypeVar("THIS")
TT = typing.TypeVar("TT")
V = typing.TypeVar("V")


class WholeInputVarGen(java.lang.Enum[WholeInputVarGen], InputVarGen):
    """
    The generator for a (whole) local variable that is input to the passage.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[WholeInputVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> WholeInputVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[WholeInputVarGen]:
        ...


class MissingVarGen(java.lang.Enum[MissingVarGen], VarGen[ghidra.pcode.emu.jit.var.JitMissingVar]):
    """
    The generator for a missing (local) variable.
     
     
    
    In principle, a :obj:`JitMissingVar` should never show up in the use-def graph, since they
    should all be replaced by :obj:`phi <JitPhiOp>` outputs. We can be certain these should never show
    up as an output, so we prohibit any attempt to generate code that writes to a missing variable.
    However, we wait until run time to make that assertion about reads. In theory, it's possible the
    generator will generate unreachable code that reads from a variable; however, that code is
    unreachable. First, how does this happen? Second, what if it does?
     
     
    
    To answer the first question, we note that the passage decoder should never decode any statically
    unreachable instructions. However, the p-code emitted by those instructions may technically
    contain unreachable ops.
     
     
    
    To answer the second, we note that the ASM library has a built-in control-flow analyzer, and it
    ought to detect the unreachable code. In my observation, it replaces that code with
    :obj:`nop <Opcodes.NOP>` and/or :obj:`athrow <Opcodes.ATHROW>`. Still, in case it doesn't, or in
    case something changes in a later version (or if/when we port this to the JDK's upcoming
    classfile API), we emit our own bytecode to throw an :obj:`AssertionError`.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[MissingVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MissingVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[MissingVarGen]:
        ...


class SubMemoryOutVarGen(java.lang.Record, SubMemoryVarGen[ghidra.pcode.emu.jit.var.JitMemoryOutVar], MemoryOutVarGen):
    """
    The generator for a subpiece of a memory output variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, byteOffset: typing.Union[jpype.JInt, int], maxByteSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteOffset(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def maxByteSize(self) -> int:
        ...

    def toString(self) -> str:
        ...


class SubDirectMemoryVarGen(java.lang.Record, SubMemoryVarGen[ghidra.pcode.emu.jit.var.JitDirectMemoryVar], DirectMemoryVarGen):
    """
    The generator for a subpiece of a direct memory variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, byteOffset: typing.Union[jpype.JInt, int], maxByteSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteOffset(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def maxByteSize(self) -> int:
        ...

    def toString(self) -> str:
        ...


class VarGen(ValGen[V], typing.Generic[V]):
    """
    The bytecode generator for a specific use-def variable (operand) access
     
     
    
    For a table of value types, their use-def types, their generator classes, and relevant read/write
    opcodes, see :obj:`JitVal`. This interface is an extension of the :obj:`JitVal` interface that
    allows writing. The only non-:obj:`JitVar` :obj:`JitVal` is :obj:`JitConstVal`. As such, most
    of the variable-access logic is actually contained here.
    
    
    .. seealso::
    
        | :obj:`ValGen`
    """

    class BlockTransition(java.lang.Record, typing.Generic[THIS]):
        """
        A means to emit bytecode on transitions between :obj:`blocks <JitBlock>`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS]) -> None:
            """
            Construct a "nop" or blank transition.
             
             
            
            The transition is mutable, so it's common to create one in this fashion and then populate
            it.
            
            :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
            """

        @typing.overload
        def __init__(self, localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], toRetire: java.util.Set[ghidra.program.model.pcode.Varnode], toBirth: java.util.Set[ghidra.program.model.pcode.Varnode]) -> None:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def gen(self) -> ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS]:
            ...

        def genFwd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
            """
            Emit bytecode for the transition
            
            :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
            :return: the emitter with ...
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
            """

        def genInv(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
            """
            Emit bytecode for the reverse transition
             
             
            
            Sometimes "transitions" are used around hazards, notably :obj:`CallOtherOpGen`. This
            method is used after the hazard to restore the live variables in scope.
            (:meth:`genFwd(Emitter) <.genFwd>` is used before the hazard.) Variables that were retired and
            re-birthed here. There should not have been any variables birthed going into the hazard.
            
            :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
            :return: the emitter with ...
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
            """

        def hashCode(self) -> int:
            ...

        def localThis(self) -> ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]]:
            ...

        def needed(self) -> bool:
            """
            Check if a transition is actually needed.
             
             
            
            When a transition is not needed, some smaller control-flow constructs (e.g., in
            :obj:`CBranchOpGen`) can be averted.
            
            :return: true if bytecode must be emitted
            :rtype: bool
            """

        def toBirth(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
            ...

        def toRetire(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def computeBlockTransition(localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], from_: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, to: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> VarGen.BlockTransition[THIS]:
        """
        Compute the retired and birthed varnodes for a transition between the given blocks.
         
         
        
        Either block may be ``null`` to indicate entering or leaving the passage. Additionally,
        the ``to`` block should be ``null`` when generating transitions around a hazard.
        
        :param THIS: the type of the generated class:param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock from: the block control flow is leaving (whether by branch or fall through)
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock to: the block control flow is entering
        :return: the means of generating bytecode at the transition
        :rtype: VarGen.BlockTransition[THIS]
        """

    @staticmethod
    def genBirth(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], toBirth: java.util.Set[ghidra.program.model.pcode.Varnode]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        For block transitions: emit bytecode that births (loads) variables from the
        :obj:`state <JitBytesPcodeExecutorState>` into their allocated JVM locals.
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param java.util.Set[ghidra.program.model.pcode.Varnode] toBirth: the set of varnodes to load
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    @staticmethod
    def genReadValDirectToStack(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], type: JT, vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit bytecode that loads the given varnode with the given p-code type from the
        :obj:`state <JitBytesPcodeExecutorState>` onto the stack.
         
         
        
        This is used for direct memory accesses and for register/unique scope transitions. The JVM
        type of the operand is determined by the ``type`` argument.
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param JT type: the p-code type of the variable
        :param ghidra.program.model.pcode.Varnode vn: the varnode to read from the state
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """

    @staticmethod
    def genRetire(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], toRetire: java.util.Set[ghidra.program.model.pcode.Varnode]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        For block transitions: emit bytecode the retires (writes) variables into the
        :obj:`state <JitBytesPcodeExecutorState>` from their allocated JVM locals.
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param java.util.Set[ghidra.program.model.pcode.Varnode] toRetire: the set of varnodes to write
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    @staticmethod
    def genVarnodeInit(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode necessary to support access to the given varnode
         
         
        
        This applies to all varnode types: ``memory``, ``unique``, and ``register``, but
        not ``const``. For memory varnodes, we need to pre-fetch the byte arrays backing their
        pages, so we can access them at the translation site. For unique and register varnodes, we
        also need to pre-fetch the byte arrays backing their pages, so we can birth and retire them
        at :obj:`transitions <BlockTransition>`. Technically, the methods for generating the read and
        write code will already call :meth:`JitCodeGenerator.requestFieldForArrDirect(Address) <JitCodeGenerator.requestFieldForArrDirect>`;
        however, we'd like to ensure the fields appear in the classfile in a comprehensible order, so
        we have the generator iterate the variables in address order and invoke this method, where we
        make the request first.
        
        :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genWriteFromArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Write a value from an array operand into the given variable
        
        :param THIS: the type of the generated class:param N1: the tail of the stack (...):param N0: ..., arrayref:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the variable to write
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the array operand
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply when adjusting from varnode size to JVM size
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for temporaries
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def genWriteFromOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, opnd: ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Write a value from a local operand into the given variable
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the variable to write
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType] opnd: the source operand
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply when adjusting from varnode size to JVM size
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for temporaries
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genWriteFromStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, type: JT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Write a value from a stack operand into the given variable
        
        :param THIS: the type of the generated class:param T: the JVM type of the stack operand:param JT: the p-code type of the stack operand:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the variable to write
        :param JT type: the p-code type of the stack operand
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply when adjusting from varnode size to JVM size
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for temporaries
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def genWriteValDirectFromStack(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], type: JT, vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode that writes the given varnode with the given p-code type in the
        :obj:`state <JitBytesPcodeExecutorState>` from a stack operand.
         
         
        
        This is used for direct memory accesses and for register/unique scope transitions. The
        expected JVM type of the stack variable is described by the ``type`` argument.
        
        :param THIS: the type of the generated class:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param JT type: the type of the operand on the stack
        :param ghidra.program.model.pcode.Varnode vn: the varnode to write in the state
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    @staticmethod
    @typing.overload
    def genWriteValDirectFromStack(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], type: JT, v: ghidra.pcode.emu.jit.var.JitVarnodeVar) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode that writes the given use-def variable in the :obj:`state <JitBytesPcodeExecutorState>` from a stack operand.
         
         
        
        The expected type is given by the ``type`` argument. Since the variable is being written
        directly into the state, which is just raw bytes/bits, we ignore the "assigned" type and
        convert using the given type instead.
        
        :param THIS: the type of the generated class:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param JT type: the type of the operand on the stack
        :param ghidra.pcode.emu.jit.var.JitVarnodeVar v: the use-def variable node
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    @staticmethod
    def lookup(v: V) -> VarGen[V]:
        """
        Lookup the generator for a given p-code variable use-def node
        
        :param V: the class of the variable:param V v: the :obj:`JitVar` whose generator to look up
        :return: the generator
        :rtype: VarGen[V]
        """


class DirectMemoryVarGen(MemoryVarGen[ghidra.pcode.emu.jit.var.JitDirectMemoryVar]):
    """
    The generator for a direct memory variable.
     
     
    
    This prohibits generation of code to write the variable.
    """

    class_: typing.ClassVar[java.lang.Class]


class LocalVarGen(VarGen[V], typing.Generic[V]):
    """
    The generator for local variable access.
     
     
    
    These variables are presumed to be allocated as JVM locals. The generator emits
    :obj:`iload <Opcodes.ILOAD>` and :obj:`istore <Opcodes.ISTORE>` and or depending on the assigned
    type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getHandler(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], v: V) -> ghidra.pcode.emu.jit.alloc.VarHandler:
        """
        Get the handler for a given p-code variable
         
        
        This is made to be overridden for the implementation of subpiece handlers.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param V v: the value
        :return: the handler
        :rtype: ghidra.pcode.emu.jit.alloc.VarHandler
        """


class SubLocalOutVarGen(java.lang.Record, SubLocalVarGen[ghidra.pcode.emu.jit.var.JitLocalOutVar], LocalOutVarGen):
    """
    The generator for a subpiece of a local variable that is defined within the passage.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, byteOffset: typing.Union[jpype.JInt, int], maxByteSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteOffset(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def maxByteSize(self) -> int:
        ...

    def toString(self) -> str:
        ...


class SubLocalVarGen(LocalVarGen[V], typing.Generic[V]):
    """
    A generator for a subpiece of a local variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def byteOffset(self) -> int:
        """
        :return: 
        :rtype: int
        the number of bytes to the right of the subpiece
        """

    def maxByteSize(self) -> int:
        """
        :return: the size of the subpiece
        :rtype: int
        """


class ValGen(java.lang.Object, typing.Generic[V]):
    """
    The bytecode generator for a specific value (operand) access.
     
     
    
    The :obj:`JitCodeGenerator` selects the correct generator for each input operand using
    :meth:`lookup(JitVal) <.lookup>` and each output operand :meth:`VarGen.lookup(JitVar) <VarGen.lookup>`. The op generator
    has already retrieved the :obj:`JitOp` whose operands are of the :obj:`JitVal` class.
     
     
    +---------------------------------------+-----------------------------+----------------------------+--------------------------------------------------------+----------------------------------------------------------+
    |             Varnode Type              |        Use-Def Type         |       Generator Type       |                Read Bytecodes / Methods                |                Write Bytecodes / Methods                 |
    +=======================================+=============================+============================+========================================================+==========================================================+
    |:meth:`constant <Varnode.isConstant>`  |:obj:`JitConstVal`           |:obj:`ConstValGen`          |:meth:`ldc <Op.ldc__i>`                                 |
    +---------------------------------------+-----------------------------+----------------------------+--------------------------------------------------------+----------------------------------------------------------+
    |:meth:`unique <Varnode.isUnique>`,     |:obj:`JitInputVar`,          |:obj:`InputVarGen`,         |:meth:`iload <Op.iload>`, :meth:`lload <Op.lload>`,     |:meth:`istore <Op.istore>`, :meth:`lstore <Op.lstore>`,   |
    |:meth:`register <Varnode.isRegister>`  |:obj:`JitLocalOutVar`,       |:obj:`LocalOutVarGen`       |:meth:`fload <Op.fload>`, :meth:`dload <Op.dload>`      |:meth:`fstore <Op.fstore>`, :meth:`dstore <Op.dstore>`    |
    |                                       |:obj:`JitMissingVar`         |                            |                                                        |                                                          |
    +---------------------------------------+-----------------------------+----------------------------+--------------------------------------------------------+----------------------------------------------------------+
    |:meth:`memory <Varnode.isAddress>`     |:obj:`JitDirectMemoryVar`,   |:obj:`DirectMemoryVarGen`,  |:meth:`readInt* <JitCompiledPassage.readInt1>`,         |:meth:`writeInt* <JitCompiledPassage.writeInt1>`,         |
    |                                       |:obj:`JitMemoryOutVar`       |:obj:`MemoryOutVarGen`      |:meth:`readLong* <JitCompiledPassage.readLong1>`, etc.  |:meth:`writeLong* <JitCompiledPassage.writeLong1>`, etc.  |
    +---------------------------------------+-----------------------------+----------------------------+--------------------------------------------------------+----------------------------------------------------------+
    |*indirect                              |:obj:`JitIndirectMemoryVar`  |None                        |
    +---------------------------------------+-----------------------------+----------------------------+--------------------------------------------------------+----------------------------------------------------------+
    
    
    
    .. admonition:: Implementation Note
    
        Memory-mapped registers are treated as ``memory`` varnodes, not ``register``,
        because they are shared by all threads. **TODO**: A :obj:`JitConfiguration` flag
        that says "the machine is single threaded!" so we can optimize memory accesses in the
        same manner we do registers and uniques.
    
    
    
    .. admonition:: Implementation Note
    
        The memory variables are all generally handled as if ints, and then :obj:`type
        conversions <Opnd>` are applied if necessary to access them as floating point.
    
    
    
    .. admonition:: Implementation Note
    
        :obj:`JitMissingVar` is a special case of ``unique`` and ``register`` variable
        where the definition could not be found. It is used as an intermediate result in the
        :obj:`JitDataFlowModel`, but should be converted to a :obj:`JitOutVar` defined by a
        :obj:`JitPhiOp` before it enters the use-def graph.
    
    
    
    .. admonition:: Implementation Note
    
        :obj:`JitIndirectMemoryVar` is a singleton dummy used in the :obj:`JitDataFlowModel`.
        It is immediately thrown away, as indirect memory access is instead modeled by
        :obj:`JitLoadOp` and :obj:`JitStoreOp`.
    
    
    
    .. seealso::
    
        | :obj:`VarGen`
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def castBack(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], to: ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType[TT, typing.Any], from_: ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType[FT, typing.Any]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]:
        ...

    def genReadLegToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, leg: typing.Union[jpype.JInt, int], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit code to read a leg of the value onto the stack
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the value
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the desired p-code type
        :param jpype.JInt or int leg: the leg index, 0 being the least significant
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genReadToArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
        """
        Emit code to read the value into an array
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the value
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the desired p-code type
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary variables
        :param jpype.JInt or int slack: the number of extra (more significant) elements to allocate in the array
        :return: the operand and emitter with ..., arrayref
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
        """

    def genReadToBool(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit code to read the value onto the stack as a boolean
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the value
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genReadToOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]:
        """
        Emit code to read the value into local variables
         
        
        NOTE: In some cases, this may not emit any code at all. It may simple compose the operand
        from locals already allocated for a variable being "read."
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the value
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the desired p-code type
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary variables
        :return: the operand and emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]
        """

    def genReadToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V, type: JT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit code to read the value onto the stack
        
        :param THIS: the type of the generated class:param T: the desired JVM type:param JT: the desired p-code type:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the value
        :param JT type: the desired p-code type
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """

    def genValInit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS], v: V) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit code to prepare any class-level items required to use this variable
         
        
        For example, if this represents a direct memory variable, then this can prepare a reference
        to the portion of the state involved, allowing it to access it readily.
         
        
        This should be used to emit code into the constructor.
        
        :param THIS: the type of the generated class:param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to ``this``
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :param V v: the value
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    @staticmethod
    def lookup(v: V) -> ValGen[V]:
        """
        Lookup the generator for a given p-code value use-def node
        
        :param V: the class of the value:param V v: the :obj:`JitVal` whose generator to look up
        :return: the generator
        :rtype: ValGen[V]
        """

    def subpiece(self, byteOffset: typing.Union[jpype.JInt, int], maxByteSize: typing.Union[jpype.JInt, int]) -> ValGen[V]:
        """
        Create a generator for a :obj:`PcodeOp.SUBPIECE` of a value.
        
        :param jpype.JInt or int byteOffset: the number of least-significant bytes to remove
        :param jpype.JInt or int maxByteSize: the maximum size of the resulting variable. In general, a subpiece should
                    never exceed the size of the parent varnode, but if it does, this will truncate
                    that excess.
        :return: the resulting subpiece generator
        :rtype: ValGen[V]
        """


class WholeMemoryOutVarGen(java.lang.Enum[WholeMemoryOutVarGen], MemoryOutVarGen):
    """
    The generator for a (whole) memory output variable.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[WholeMemoryOutVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> WholeMemoryOutVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[WholeMemoryOutVarGen]:
        ...


class SubMemoryVarGen(MemoryVarGen[V], typing.Generic[V]):
    """
    A generator for a subpiece of a memory variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def byteOffset(self) -> int:
        """
        :return: 
        :rtype: int
        the number of bytes to the right of the subpiece
        """

    def maxByteSize(self) -> int:
        """
        :return: the size of the subpiece
        :rtype: int
        """


class MemoryVarGen(VarGen[V], typing.Generic[V]):
    """
    The generator for memory variables.
     
     
    
    These variables affect the :obj:`state <JitBytesPcodeExecutorState>` immediately, i.e., they are
    not birthed or retired as local JVM variables. The generator delegates to the appropriate
    :obj:`AccessGen` for this variable's varnode and assigned type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getVarnode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], v: V) -> ghidra.program.model.pcode.Varnode:
        """
        Get the varnode actually accessed for the given p-code variable
         
        
        This is made to be overridden for the implementation of subpiece access.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param V v: the value
        :return: the varnode
        :rtype: ghidra.program.model.pcode.Varnode
        """


class ConstValGen(java.lang.Enum[ConstValGen], ValGen[ghidra.pcode.emu.jit.var.JitConstVal]):
    """
    The generator for a constant value.
     
     
    
    This can load directly the requested constant as the required JVM type onto the JVM stack. It
    simply emits an :obj:`ldc <Opcodes.LDC>` bytecode.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[ConstValGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ConstValGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[ConstValGen]:
        ...


class WholeDirectMemoryVarGen(java.lang.Enum[WholeDirectMemoryVarGen], DirectMemoryVarGen):
    """
    The generator for a (whole) direct memory variable.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[WholeDirectMemoryVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> WholeDirectMemoryVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[WholeDirectMemoryVarGen]:
        ...


class FailValGen(java.lang.Enum[FailValGen], ValGen[ghidra.pcode.emu.jit.var.JitFailVal]):
    """
    The generator that is forbidden from actually generating.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[FailValGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FailValGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[FailValGen]:
        ...


class SubInputVarGen(java.lang.Record, SubLocalVarGen[ghidra.pcode.emu.jit.var.JitInputVar], InputVarGen):
    """
    The generator for a subpiece of a local variable that is input to the passage.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, byteOffset: typing.Union[jpype.JInt, int], maxByteSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteOffset(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def maxByteSize(self) -> int:
        ...

    def toString(self) -> str:
        ...


class WholeLocalOutVarGen(java.lang.Enum[WholeLocalOutVarGen], LocalOutVarGen):
    """
    The generator for a (whole) local variable that is defined within the passage.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[WholeLocalOutVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> WholeLocalOutVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[WholeLocalOutVarGen]:
        ...


class LocalOutVarGen(LocalVarGen[ghidra.pcode.emu.jit.var.JitLocalOutVar]):
    """
    The generator for a local variable that is defined within the passage.
    """

    class_: typing.ClassVar[java.lang.Class]


class MemoryOutVarGen(MemoryVarGen[ghidra.pcode.emu.jit.var.JitMemoryOutVar]):
    """
    The generator for a memory output variable.
    """

    class_: typing.ClassVar[java.lang.Class]


class InputVarGen(LocalVarGen[ghidra.pcode.emu.jit.var.JitInputVar]):
    """
    The generator for a local variable that is input to the passage.
     
     
    
    This prohibits generation of code to write the variable.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["WholeInputVarGen", "MissingVarGen", "SubMemoryOutVarGen", "SubDirectMemoryVarGen", "VarGen", "DirectMemoryVarGen", "LocalVarGen", "SubLocalOutVarGen", "SubLocalVarGen", "ValGen", "WholeMemoryOutVarGen", "SubMemoryVarGen", "MemoryVarGen", "ConstValGen", "WholeDirectMemoryVarGen", "FailValGen", "SubInputVarGen", "WholeLocalOutVarGen", "LocalOutVarGen", "MemoryOutVarGen", "InputVarGen"]
