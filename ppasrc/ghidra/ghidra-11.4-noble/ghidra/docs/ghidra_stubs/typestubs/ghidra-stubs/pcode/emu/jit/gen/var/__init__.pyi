from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.var
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore
import org.objectweb.asm # type: ignore


V = typing.TypeVar("V")


class MissingVarGen(java.lang.Enum[MissingVarGen], VarGen[ghidra.pcode.emu.jit.var.JitMissingVar]):
    """
    The generator for a missing (local) variable.
     
     
    
    In principle, a :obj:`JitMissingVar` should never show up in the use-def graph, since they
    should all be replaced by :obj:`phi <JitPhiOp>` outputs. We can be certain these should never show
    up as an output, so we prohibit any attempt to generate code that writes to a missing variable.
    However, we wait until run time to make that assertion about reads. In theory, it's possible the
    generator will generate unreachable code that reads from a variable; however, that code is
    unreachable. First how does this happen? Second, what if it does?
     
     
    
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

    class BlockTransition(java.lang.Record):
        """
        A means to emit bytecode on transitions between :obj:`blocks <JitBlock>`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator):
            """
            Construct a "nop" or blank transition.
             
             
            
            The transition is mutable, so it's common to create one in this fashion and then populate
            it.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            """

        @typing.overload
        def __init__(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, toRetire: java.util.Set[ghidra.program.model.pcode.Varnode], toBirth: java.util.Set[ghidra.program.model.pcode.Varnode]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def gen(self) -> ghidra.pcode.emu.jit.gen.JitCodeGenerator:
            ...

        def generate(self, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode for the transition
            
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def generateInv(self, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode for the reverse transition
             
             
            
            Sometimes "transitions" are used around hazards, notably :obj:`CallOtherOpGen`. This
            method is used after the hazard to restore the live variables in scope.
            (:meth:`generate(MethodVisitor) <.generate>` is used before the hazard.) Variables that were retired
            and re-birthed here. There should not have been any variables birthed going into the
            hazard.
            
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def hashCode(self) -> int:
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
    def computeBlockTransition(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, from_: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, to: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> VarGen.BlockTransition:
        """
        Compute the retired and birthed varnodes for a transition between the given blocks.
         
         
        
        Either block may be ``null`` to indicate entering or leaving the passage. Additionally,
        the ``to`` block should be ``null`` when generating transitions around a hazard.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock from: the block control flow is leaving (whether by branch or fall through)
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock to: the block control flow is entering
        :return: the means of generating bytecode at the transition
        :rtype: VarGen.BlockTransition
        """

    @staticmethod
    def generateBirthCode(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, toBirth: java.util.Set[ghidra.program.model.pcode.Varnode], rv: org.objectweb.asm.MethodVisitor):
        """
        For block transitions: emit bytecode that births (loads) variables from the
        :obj:`state <JitBytesPcodeExecutorState>` into their allocated JVM locals.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param java.util.Set[ghidra.program.model.pcode.Varnode] toBirth: the set of varnodes to load
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    def generateRetireCode(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, toRetire: java.util.Set[ghidra.program.model.pcode.Varnode], rv: org.objectweb.asm.MethodVisitor):
        """
        For block transitions: emit bytecode the retires (writes) variables into the
        :obj:`state <JitBytesPcodeExecutorState>` from their allocated JVM locals.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param java.util.Set[ghidra.program.model.pcode.Varnode] toRetire: the set of varnodes to write
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    def generateValInitCode(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, vn: ghidra.program.model.pcode.Varnode):
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
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        """

    @staticmethod
    @typing.overload
    def generateValReadCodeDirect(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: ghidra.pcode.emu.jit.analysis.JitType, vn: ghidra.program.model.pcode.Varnode, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit bytecode that loads the given varnode with the given p-code type from the
        :obj:`state <JitBytesPcodeExecutorState>` onto the JVM stack.
         
         
        
        This is used for direct memory accesses and for register/unique scope transitions. The JVM
        type of the stack variable is determined by the ``type`` argument.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType type: the p-code type of the variable
        :param ghidra.program.model.pcode.Varnode vn: the varnode to read from the state
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    @typing.overload
    def generateValReadCodeDirect(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, v: ghidra.pcode.emu.jit.var.JitVarnodeVar, typeReq: ghidra.pcode.emu.jit.analysis.JitTypeBehavior, rv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit bytecode that loads the given use-def variable from the
        :obj:`state <JitBytesPcodeExecutorState>` onto the JVM stack.
         
         
        
        The actual type is determined by resolving the ``typeReq`` argument against the given
        variable. Since the variable is being loaded directly from the state, which is just raw
        bytes/bits, we ignore the "assigned" type and convert directly the type required by the
        operand.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.var.JitVarnodeVar v: the use-def variable node
        :param ghidra.pcode.emu.jit.analysis.JitTypeBehavior typeReq: the type (behavior) required by the operand.
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        :return: the resulting p-code type (which also describes the JVM type) of the value on the JVM
                stack
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @staticmethod
    @typing.overload
    def generateValWriteCodeDirect(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: ghidra.pcode.emu.jit.analysis.JitType, vn: ghidra.program.model.pcode.Varnode, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit bytecode that writes the given varnode with the given p-code type in the
        :obj:`state <JitBytesPcodeExecutorState>` from the JVM stack.
         
         
        
        This is used for direct memory accesses and for register/unique scope transitions. The
        expected JVM type of the stack variable is described by the ``type`` argument.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType type: the p-code type of the variable
        :param ghidra.program.model.pcode.Varnode vn: the varnode to write in the state
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    @typing.overload
    def generateValWriteCodeDirect(gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, v: ghidra.pcode.emu.jit.var.JitVarnodeVar, type: ghidra.pcode.emu.jit.analysis.JitType, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit bytecode that writes the given use-def variable in the :obj:`state <JitBytesPcodeExecutorState>` from the JVM stack.
         
         
        
        The expected type is given by the ``type`` argument. Since the variable is being written
        directly into the state, which is just raw bytes/bits, we ignore the "assigned" type and
        convert using the given type instead.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param ghidra.pcode.emu.jit.var.JitVarnodeVar v: the use-def variable node
        :param ghidra.pcode.emu.jit.analysis.JitType type: the p-code type of the value on the stack, as required by the operand
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def generateVarWriteCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, v: V, type: ghidra.pcode.emu.jit.analysis.JitType, rv: org.objectweb.asm.MethodVisitor):
        """
        Write a value from the stack into the given variable
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param V v: the variable to write
        :param ghidra.pcode.emu.jit.analysis.JitType type: the p-code type (which also determines the expected JVM type) of the value on the
                    stack
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    @staticmethod
    def lookup(v: V) -> VarGen[V]:
        """
        Lookup the generator for a given p-code variable use-def node
        
        :param V: the class of the variable:param V v: the :obj:`JitVar` whose generator to look up
        :return: the generator
        :rtype: VarGen[V]
        """


class DirectMemoryVarGen(java.lang.Enum[DirectMemoryVarGen], MemoryVarGen[ghidra.pcode.emu.jit.var.JitDirectMemoryVar]):
    """
    The generator for a direct memory variable.
     
     
    
    This prohibits generation of code to write the variable.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[DirectMemoryVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DirectMemoryVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[DirectMemoryVarGen]:
        ...


class LocalVarGen(VarGen[V], typing.Generic[V]):
    """
    The generator for local variable access.
     
     
    
    These variables are presumed to be allocated as JVM locals. The generator emits
    :obj:`iload <Opcodes.ILOAD>` and :obj:`istore <Opcodes.ISTORE>` and or depending on the assigned
    type.
    """

    class_: typing.ClassVar[java.lang.Class]


class ValGen(java.lang.Object, typing.Generic[V]):
    """
    The bytecode generator for a specific value (operand) access.
     
     
    
    The :obj:`JitCodeGenerator` selects the correct generator for each input operand using
    :meth:`lookup(JitVal) <.lookup>` and each output operand :meth:`VarGen.lookup(JitVar) <VarGen.lookup>`. The op generator
    has already retrieved the :obj:`JitOp` whose operands are of the :obj:`JitVal` class.
     
     
    +---------------------------------------+-----------------------------+----------------------------+-------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |             Varnode Type              |        Use-Def Type         |       Generator Type       |                                 Read Bytecodes / Methods                                  |                                    Write Bytecodes / Methods                                    |
    +=======================================+=============================+============================+===========================================================================================+=================================================================================================+
    |:meth:`constant <Varnode.isConstant>`  |:obj:`JitConstVal`           |:obj:`ConstValGen`          |:obj:`ldc <Opcodes.LDC>`                                                                   |
    +---------------------------------------+-----------------------------+----------------------------+-------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |:meth:`unique <Varnode.isUnique>`,     |:obj:`JitInputVar`,          |:obj:`InputVarGen`,         |See :meth:`SimpleJitType.opcodeLoad() <SimpleJitType.opcodeLoad>`:                         |See :meth:`SimpleJitType.opcodeStore() <SimpleJitType.opcodeStore>`:                             |
    |:meth:`register <Varnode.isRegister>`  |:obj:`JitLocalOutVar`,       |:obj:`LocalOutVarGen`       |:obj:`iload <Opcodes.ILOAD>`, :obj:`lload <Opcodes.LLOAD>`, :obj:`fload <Opcodes.FLOAD>`,  |:obj:`istore <Opcodes.ISTORE>`, :obj:`lstore <Opcodes.LSTORE>`, :obj:`fstore <Opcodes.FSTORE>`,  |
    |                                       |:obj:`JitMissingVar`         |                            |:obj:`dload <Opcodes.DLOAD>`                                                               |:obj:`dstore <Opcodes.DSTORE>`                                                                   |
    +---------------------------------------+-----------------------------+----------------------------+-------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |:meth:`memory <Varnode.isAddress>`     |:obj:`JitDirectMemoryVar`,   |:obj:`DirectMemoryVarGen`,  |:meth:`readInt* <JitCompiledPassage.readInt1>`,                                            |:meth:`writeInt* <JitCompiledPassage.writeInt1>`,                                                |
    |                                       |:obj:`JitMemoryOutVar`       |:obj:`MemoryOutVarGen`      |:meth:`readLong* <JitCompiledPassage.readLong1>`, etc.                                     |:meth:`writeLong* <JitCompiledPassage.writeLong1>`, etc.                                         |
    +---------------------------------------+-----------------------------+----------------------------+-------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |*indirect                              |:obj:`JitIndirectMemoryVar`  |None                        |
    +---------------------------------------+-----------------------------+----------------------------+-------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    
    
    
    .. admonition:: Implementation Note
    
        Memory-mapped registers are treated as ``memory`` varnodes, not ``register``,
        because they are shared by all threads. **TODO**: A :obj:`JitConfiguration` flag
        that says "the machine is single threaded!" so we can optimize memory accesses in the
        same manner we do registers and uniques.
    
    
    
    .. admonition:: Implementation Note
    
        There are remnants of experiments and fragments in anticipation of multi-precision
        integer variables. These are not supported yet, but some of the components for mp-int
        support are used in degenerate form to support normal ints. Many of these components
        have "``Mp``" in the name.
    
    
    
    .. admonition:: Implementation Note
    
        The memory variables are all generally handled as if ints, and then
        :obj:`type conversions <TypeConversions>` are applied if necessary to access them as
        floating point.
    
    
    
    .. admonition:: Implementation Note
    
        :obj:`JitMissingVar` is a special case of ``unique`` and ``register`` variable
        where the definition could not be found. It is used as an intermediate result the
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

    def generateValInitCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, v: V, iv: org.objectweb.asm.MethodVisitor):
        """
        Prepare any class-level items required to use this variable
         
         
        
        For example, if this represents a direct memory variable, then this can prepare a reference
        to the portion of the state involved, allowing it to access it readily.
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param V v: the value
        :param org.objectweb.asm.MethodVisitor iv: the constructor visitor
        """

    def generateValReadCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, v: V, typeReq: ghidra.pcode.emu.jit.analysis.JitTypeBehavior, rv: org.objectweb.asm.MethodVisitor) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Read the value onto the stack
        
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
        :param V v: the value to read
        :param ghidra.pcode.emu.jit.analysis.JitTypeBehavior typeReq: the required type of the value
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        :return: the actual p-code type (which determines the JVM type) of the value on the stack
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    @staticmethod
    def lookup(v: V) -> ValGen[V]:
        """
        Lookup the generator for a given p-code value use-def node
        
        :param V: the class of the value:param V v: the :obj:`JitVal` whose generator to look up
        :return: the generator
        :rtype: ValGen[V]
        """


class MemoryVarGen(VarGen[V], typing.Generic[V]):
    """
    The generator for memory variables.
     
     
    
    These variables affect the :obj:`state <JitBytesPcodeExecutorState>` immediately, i.e., they are
    not birthed or retired as local JVM variables. The generator delegates to the appropriate
    :obj:`TypedAccessGen` for this variable's varnode and assigned type.
    """

    class_: typing.ClassVar[java.lang.Class]


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


class LocalOutVarGen(java.lang.Enum[LocalOutVarGen], LocalVarGen[ghidra.pcode.emu.jit.var.JitLocalOutVar]):
    """
    The generator for a local variable that is defined within the passage.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[LocalOutVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LocalOutVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[LocalOutVarGen]:
        ...


class MemoryOutVarGen(java.lang.Enum[MemoryOutVarGen], MemoryVarGen[ghidra.pcode.emu.jit.var.JitMemoryOutVar]):
    """
    The generator for a memory output variable.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[MemoryOutVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MemoryOutVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[MemoryOutVarGen]:
        ...


class InputVarGen(java.lang.Enum[InputVarGen], LocalVarGen[ghidra.pcode.emu.jit.var.JitInputVar]):
    """
    The generator for a local variable that is input to the passage.
     
     
    
    This prohibits generation of code to write the variable.
    """

    class_: typing.ClassVar[java.lang.Class]
    GEN: typing.Final[InputVarGen]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> InputVarGen:
        ...

    @staticmethod
    def values() -> jpype.JArray[InputVarGen]:
        ...



__all__ = ["MissingVarGen", "VarGen", "DirectMemoryVarGen", "LocalVarGen", "ValGen", "MemoryVarGen", "ConstValGen", "FailValGen", "LocalOutVarGen", "MemoryOutVarGen", "InputVarGen"]
