from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.gen.tgt
import ghidra.pcode.emu.jit.var
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang # type: ignore
import org.objectweb.asm # type: ignore


class FieldForSpaceIndirect(java.lang.Record, InstanceFieldReq):
    """
    A field request for a pre-fetched :obj:`JitBytesPcodeExecutorStateSpace`
     
     
    
    The field is used for indirect memory accesses. For those, the address space is given in the
    p-code, but the offset must be computed at run time. Thus, we can pre-fetch the state space, but
    not any particular page.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def toString(self) -> str:
        ...


class InstanceFieldReq(FieldReq):
    """
    An instance field request initialized in the class constructor
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateInitCode(self, gen: JitCodeGenerator, cv: org.objectweb.asm.ClassVisitor, iv: org.objectweb.asm.MethodVisitor):
        """
        Emit the field declaration and its initialization bytecode
         
         
        
        The declaration is emitted into the class definition, and the initialization code is emitted
        into the class constructor.
        
        :param JitCodeGenerator gen: the code generator
        :param org.objectweb.asm.ClassVisitor cv: the visitor for the class definition
        :param org.objectweb.asm.MethodVisitor iv: the visitor for the class constructor
        """


class FieldForExitSlot(java.lang.Record, InstanceFieldReq):
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

    def __init__(self, target: ghidra.pcode.emu.jit.JitPassage.AddrCtx):
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
class FieldForContext(java.lang.Record, StaticFieldReq):
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


class FieldForArrDirect(java.lang.Record, InstanceFieldReq):
    """
    A field request for a pre-fetched page from the :obj:`JitBytesPcodeExecutorStateSpace`.
     
     
    
    The field is used for direct memory accesses. For those, the address space and fixed address is
    given in the p-code, so we are able to pre-fetch the page and access it directly at run time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address):
        ...

    def address(self) -> ghidra.program.model.address.Address:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...


class FieldForUserop(java.lang.Record, InstanceFieldReq):
    """
    A field request for a pre-fetched userop definition
     
     
    
    These are used to invoke userops using the Standard or Direct strategies.
    
    
    .. seealso::
    
        | :obj:`JitDataFlowUseropLibrary`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def userop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any]:
        ...


class GenConsts(java.lang.Object):
    """
    Various constants (namely class names, type descriptions, method descriptions, etc. used during
    bytecode generation.
    """

    class_: typing.ClassVar[java.lang.Class]
    BLOCK_SIZE: typing.Final = 4096
    TDESC_ADDRESS: typing.Final[java.lang.String]
    TDESC_ADDRESS_FACTORY: typing.Final[java.lang.String]
    TDESC_ADDRESS_SPACE: typing.Final[java.lang.String]
    TDESC_BYTE_ARR: typing.Final[java.lang.String]
    TDESC_EXIT_SLOT: typing.Final[java.lang.String]
    TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE: typing.Final[java.lang.String]
    TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE: typing.Final[java.lang.String]
    TDESC_JIT_PCODE_THREAD: typing.Final[java.lang.String]
    TDESC_LANGUAGE: typing.Final[java.lang.String]
    TDESC_LIST: typing.Final[java.lang.String]
    TDESC_PCODE_USEROP_DEFINITION: typing.Final[java.lang.String]
    TDESC_REGISTER_VALUE: typing.Final[java.lang.String]
    TDESC_STRING: typing.Final[java.lang.String]
    TDESC_VARNODE: typing.Final[java.lang.String]
    TSIG_LIST_ADDRCTX: typing.Final[java.lang.String]
    MDESC_ADDR_CTX__$INIT: typing.Final[java.lang.String]
    MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE: typing.Final[java.lang.String]
    MDESC_ADDRESS_SPACE__GET_ADDRESS: typing.Final[java.lang.String]
    MDESC_ARRAY_LIST__$INIT: typing.Final[java.lang.String]
    MDESC_ASSERTION_ERROR__$INIT: typing.Final[java.lang.String]
    MDESC_DOUBLE__DOUBLE_TO_RAW_LONG_BITS: typing.Final[java.lang.String]
    MDESC_DOUBLE__IS_NAN: typing.Final[java.lang.String]
    MDESC_DOUBLE__LONG_BITS_TO_DOUBLE: typing.Final[java.lang.String]
    MDESC_FLOAT__FLOAT_TO_RAW_INT_BITS: typing.Final[java.lang.String]
    MDESC_FLOAT__INT_BITS_TO_FLOAT: typing.Final[java.lang.String]
    MDESC_FLOAT__IS_NAN: typing.Final[java.lang.String]
    MDESC_ILLEGAL_ARGUMENT_EXCEPTION__$INIT: typing.Final[java.lang.String]
    MDESC_INTEGER__BIT_COUNT: typing.Final[java.lang.String]
    MDESC_INTEGER__COMPARE_UNSIGNED: typing.Final[java.lang.String]
    MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS: typing.Final[java.lang.String]
    MDESC_INTEGER__TO_UNSIGNED_LONG: typing.Final[java.lang.String]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_LANGUAGE: typing.Final[java.lang.String]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_SPACE_FOR: typing.Final[java.lang.String]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__GET_DIRECT: typing.Final[java.lang.String]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__READ: typing.Final[java.lang.String]
    MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__WRITE: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__COUNT: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_CONTEXT: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_DECODE_ERROR: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_EXIT_SLOT: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__CREATE_VARNODE: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__GET_LANGUAGE: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__GET_USEROP_DEFINITION: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__INVOKE_USEROP: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__READ_INTX: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__READ_LONGX: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__WRITE_COUNTER_AND_CONTEXT: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__SET_COUNTER_AND_CONTEXT: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__S_CARRY_INT_RAW: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__S_CARRY_LONG_RAW: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX: typing.Final[java.lang.String]
    MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX: typing.Final[java.lang.String]
    MDESC_JIT_PCODE_THREAD__GET_STATE: typing.Final[java.lang.String]
    MDESC_LANGUAGE__GET_ADDRESS_FACTORY: typing.Final[java.lang.String]
    MDESC_LANGUAGE__GET_DEFAULT_SPACE: typing.Final[java.lang.String]
    MDESC_LIST__ADD: typing.Final[java.lang.String]
    MDESC_LONG__BIT_COUNT: typing.Final[java.lang.String]
    MDESC_LONG__COMPARE_UNSIGNED: typing.Final[java.lang.String]
    MDESC_LONG__NUMBER_OF_LEADING_ZEROS: typing.Final[java.lang.String]
    MDESC_LOW_LEVEL_ERROR__$INIT: typing.Final[java.lang.String]
    MDESC_PCODE_USEROP_DEFINITION__GET_DEFINING_LIBRARY: typing.Final[java.lang.String]
    MDESC_SLEIGH_LINK_EXCEPTION__$INIT: typing.Final[java.lang.String]
    MDESC_$DOUBLE_UNOP: typing.Final[java.lang.String]
    MDESC_$FLOAT_UNOP: typing.Final[java.lang.String]
    MDESC_$INT_BINOP: typing.Final[java.lang.String]
    MDESC_$LONG_BINOP: typing.Final[java.lang.String]
    MDESC_$SHIFT_JJ: typing.Final[java.lang.String]
    MDESC_$SHIFT_JI: typing.Final[java.lang.String]
    MDESC_$SHIFT_IJ: typing.Final[java.lang.String]
    MDESC_$SHIFT_II: typing.Final[java.lang.String]
    NAME_ADDR_CTX: typing.Final[java.lang.String]
    NAME_ADDRESS: typing.Final[java.lang.String]
    NAME_ADDRESS_FACTORY: typing.Final[java.lang.String]
    NAME_ADDRESS_SPACE: typing.Final[java.lang.String]
    NAME_ARRAY_LIST: typing.Final[java.lang.String]
    NAME_ASSERTION_ERROR: typing.Final[java.lang.String]
    NAME_DOUBLE: typing.Final[java.lang.String]
    NAME_EXIT_SLOT: typing.Final[java.lang.String]
    NAME_FLOAT: typing.Final[java.lang.String]
    NAME_ILLEGAL_ARGUMENT_EXCEPTION: typing.Final[java.lang.String]
    NAME_INTEGER: typing.Final[java.lang.String]
    NAME_JIT_BYTES_PCODE_EXECUTOR_STATE: typing.Final[java.lang.String]
    NAME_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE: typing.Final[java.lang.String]
    NAME_JIT_COMPILED_PASSAGE: typing.Final[java.lang.String]
    NAME_JIT_PCODE_THREAD: typing.Final[java.lang.String]
    NAME_LANGUAGE: typing.Final[java.lang.String]
    NAME_LIST: typing.Final[java.lang.String]
    NAME_LONG: typing.Final[java.lang.String]
    NAME_LOW_LEVEL_ERROR: typing.Final[java.lang.String]
    NAME_MATH: typing.Final[java.lang.String]
    NAME_OBJECT: typing.Final[java.lang.String]
    NAME_PCODE_USEROP_DEFINITION: typing.Final[java.lang.String]
    NAME_SLEIGH_LINK_EXCEPTION: typing.Final[java.lang.String]
    NAME_THROWABLE: typing.Final[java.lang.String]
    NAME_VARNODE: typing.Final[java.lang.String]


class FieldForVarnode(java.lang.Record, StaticFieldReq):
    """
    A field request for a pre-constructed varnode
     
     
    
    These are used to invoke userops using the Standard strategy.
    
    
    .. seealso::
    
        | :obj:`JitDataFlowUseropLibrary`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vn: ghidra.program.model.pcode.Varnode):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class JitCodeGenerator(java.lang.Object):
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
    * ``static``:obj:`List```<``:obj:`AddrCtx```> ENTRIES`` - The lsit of
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
     
     
    1. Parameter declarations - ``this`` and ``blockId``
    2. Allocated local declarations - declares all locals allocated by
    :obj:`JitAllocationModel`
    3. Entry point dispatch - a large ``switch`` statement on the entry ``blockId``
    4. P-code translation - the block-by-block op-by-op translation of the p-code to bytecode
    5. Exception handlers - exception handlers as requested by various elements of the p-code
    translation
    
     
     
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

        def __init__(self, vn: ghidra.program.model.pcode.Varnode):
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


    class LineNumberer(java.lang.Object):
        """
        For testing and debugging: A means to inject granular line number information
         
         
        
        Typically, this is used to assign every bytecode offset (emitted by a certain generator) a
        line number, so that tools expecting/requiring line numbers will display something useful.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mv: org.objectweb.asm.MethodVisitor):
            """
            Prepare to number lines on the given method visitor
            
            :param org.objectweb.asm.MethodVisitor mv: the method visitor
            """

        def nextLine(self):
            """
            Increment the line number and add info on the next bytecode index
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lookup: java.lang.invoke.MethodHandles.Lookup, context: ghidra.pcode.emu.jit.analysis.JitAnalysisContext, cfm: ghidra.pcode.emu.jit.analysis.JitControlFlowModel, dfm: ghidra.pcode.emu.jit.analysis.JitDataFlowModel, vsm: ghidra.pcode.emu.jit.analysis.JitVarScopeModel, tm: ghidra.pcode.emu.jit.analysis.JitTypeModel, am: ghidra.pcode.emu.jit.analysis.JitAllocationModel, oum: ghidra.pcode.emu.jit.analysis.JitOpUseModel):
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

    def generatePassageExit(self, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, pcGen: java.lang.Runnable, ctx: ghidra.program.model.lang.RegisterValue, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit code to exit the passage
         
         
        
        This retires all the variables of the current block as well as the program counter and decode
        context. It does not generate the actual :obj:`areturn <Opcodes.ARETURN>` or
        :obj:`athrow <Opcodes.ATHROW>`, but everything required up to that point.
        
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op at which we are exiting
        :param java.lang.Runnable pcGen: as in
                    :meth:`generateRetirePcCtx(Runnable, RegisterValue, RetireMode, MethodVisitor) <.generateRetirePcCtx>`
        :param ghidra.program.model.lang.RegisterValue ctx: as in
                    :meth:`generateRetirePcCtx(Runnable, RegisterValue, RetireMode, MethodVisitor) <.generateRetirePcCtx>`
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def generateRetirePcCtx(self, pcGen: java.lang.Runnable, ctx: ghidra.program.model.lang.RegisterValue, mode: JitCodeGenerator.RetireMode, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit bytecode to set the emulator's counter and contextreg.
         
         
        
        Within a translated passage, there's no need to keep constant track of the program counter
        (nor decode context), since all the decoding has already been done. However, whenever we exit
        the passage and return control back to the emulator (whether by ``return`` or
        ``throw``) we must "retire" the program counter and decode context, as if the emulator
        had interpreted all the instructions just executed. This ensures that the emulator has the
        correct seed when seeking its next entry point, which may require decoding a new passage.
        
        :param java.lang.Runnable pcGen: a means to emit bytecode to load the counter (as a long) onto the JVM stack. For
                    errors, this is the address of the op causing the error. For branches, this is the
                    branch target, which may be loaded from a varnode for an indirect branch.
        :param ghidra.program.model.lang.RegisterValue ctx: the contextreg value. For errors, this is the decode context of the op causing the
                    error. For branches, this is the decode context at the target.
        :param JitCodeGenerator.RetireMode mode: whether to set the machine state, too
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def generateValReadCode(self, v: ghidra.pcode.emu.jit.var.JitVal, typeReq: ghidra.pcode.emu.jit.analysis.JitTypeBehavior) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Emit into the :meth:`run <JitCompiledPassage.run>` method the bytecode to read the given
        value onto the JVM stack.
         
         
        
        Although the value may be assigned a type by the :obj:`JitTypeModel`, the type needed by a
        given op might be different. This method accepts the :obj:`JitTypeBehavior` for the operand
        and will ensure the value pushed onto the JVM stack is compatible with that type.
        
        :param ghidra.pcode.emu.jit.var.JitVal v: the value to read
        :param ghidra.pcode.emu.jit.analysis.JitTypeBehavior typeReq: the required type of the value
        :return: the actual type of the value on the stack
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    def generateVarWriteCode(self, v: ghidra.pcode.emu.jit.var.JitVar, type: ghidra.pcode.emu.jit.analysis.JitType):
        """
        Emit into the :meth:`run <JitCompiledPassage.run>` method the bytecode to write the value
        on the JVM stack into the given variable.
         
         
        
        Although the destination variable may be assigned a type by the :obj:`JitTypeModel`, the
        type of the value on the stack may not match. This method needs to know that type so that, if
        necessary, it can convert it to the appropriate JVM type for local variable that holds it.
        
        :param ghidra.pcode.emu.jit.var.JitVar v: the variable to write
        :param ghidra.pcode.emu.jit.analysis.JitType type: the actual type of the value on the stack
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

    def labelForBlock(self, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> org.objectweb.asm.Label:
        """
        Get the label at the start of a block's translation
        
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block
        :return: the label
        :rtype: org.objectweb.asm.Label
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

    def requestFieldForUserop(self, userop: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any]) -> FieldForUserop:
        """
        Request a field for the given userop
        
        :param ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[typing.Any] userop: the userop
        :return: the field request
        :rtype: FieldForUserop
        """

    def requestStaticFieldForVarnode(self, vn: ghidra.program.model.pcode.Varnode) -> FieldForVarnode:
        """
        Request a field for the given varnode
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the field request
        :rtype: FieldForVarnode
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


class StaticFieldReq(FieldReq):
    """
    A static field request initialized in the class initializer
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateClinitCode(self, gen: JitCodeGenerator, cv: org.objectweb.asm.ClassVisitor, sv: org.objectweb.asm.MethodVisitor):
        """
        Emit the field declaration and its initialization bytecode
         
         
        
        The declaration is emitted into the class definition, and the initialization code is emitted
        into the class initializer.
        
        :param JitCodeGenerator gen: the code generator
        :param org.objectweb.asm.ClassVisitor cv: the visitor for the class definition
        :param org.objectweb.asm.MethodVisitor sv: the visitor for the class (static) initializer
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
    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock):
        """
        Construct a handler, generating a new label
        
        :param ghidra.program.model.pcode.PcodeOp op: the op which may cause an exception
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op
        """

    @typing.overload
    def __init__(self, op: ghidra.program.model.pcode.PcodeOp, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock, label: org.objectweb.asm.Label):
        ...

    def block(self) -> ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def generateRunCode(self, gen: JitCodeGenerator, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit the handler's code into the :meth:`run <JitCompiledPassage.run>` method.
        
        :param JitCodeGenerator gen: the code generator
        :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
        """

    def hashCode(self) -> int:
        ...

    def label(self) -> org.objectweb.asm.Label:
        ...

    def op(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def toString(self) -> str:
        ...


class FieldReq(java.lang.Object):
    """
    A field request for a pre-fetched or pre-constructed element
    """

    class_: typing.ClassVar[java.lang.Class]

    def generateLoadCode(self, gen: JitCodeGenerator, rv: org.objectweb.asm.MethodVisitor):
        """
        Emit code to load the field onto the JVM stack
        
        :param JitCodeGenerator gen: the code generator
        :param org.objectweb.asm.MethodVisitor rv: the visitor often for the :meth:`run <JitCompiledPassage.run>` method, but could
                    be the static initializer or constructor
        """

    def name(self) -> str:
        """
        Derive a suitable name for the field
        
        :return: the name
        :rtype: str
        """



__all__ = ["FieldForSpaceIndirect", "InstanceFieldReq", "FieldForExitSlot", "FieldForContext", "FieldForArrDirect", "FieldForUserop", "GenConsts", "FieldForVarnode", "JitCodeGenerator", "StaticFieldReq", "ExceptionHandler", "FieldReq"]
