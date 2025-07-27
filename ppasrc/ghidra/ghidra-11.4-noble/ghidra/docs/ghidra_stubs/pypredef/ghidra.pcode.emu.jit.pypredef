from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.app.util
import ghidra.pcode.emu
import ghidra.pcode.emu.jit.decode
import ghidra.pcode.emu.jit.gen.tgt
import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.math # type: ignore
import java.util # type: ignore


class JitPcodeEmulator(ghidra.pcode.emu.PcodeEmulator):
    """
    An extension of :obj:`PcodeEmulator` that applies Just-in-Time (JIT) translation to accelerate
    execution.
     
     
    
    This is meant as a near drop-in replacement for the class it extends. Aside from some additional
    configuration, and some annotations you might add to a :obj:`PcodeUseropLibrary`, if applicable,
    you can simply replace ``new PcodeEmulator()`` with ``new JitPcodeEmulator(...)``.
     
     
    ##############################################################
    A JIT-Accelerated P-code Emulator for the Java Virtual Machine
    ##############################################################
    
     
     
    
    There are two major tasks to achieving JIT-accelerated p-code emulation: 1) The translation of
    p-code to a suitable target's machine language, and 2) The selection, decoding, and cache
    management of passages of machine code translations. For our purposes, the target language is JVM
    bytecode, which introduces some restrictions which make the translation process substantially
    different than targeting native machine language.
     
     
    ***********
    Terminology
    ***********
    
     
     
    
    Because of the potential for confusion of terms with similar meanings from similar disciplines,
    and to distinguish our particular use of the terms, we establish some definitions up front:
     
     
    * Basic block: A block of p-code ops for which there are no branches into or
    from, except at its top and bottom. Note that this definition pertains only to p-code ops in the
    same passage. Branches into a block from ops generated elsewhere in the translation source need
    not be considered. Note also that p-code basic blocks might not coincide with machine-code basic
    blocks.
    * Bytecode: Shorthand for "JVM bytecode." Others sometimes use this to mean any machine
    code, but for us "bytecode" only refers to the JVM's machine code.
    * Decode context: The input contextreg value for decoding an instruction. This is often
    paired with an address to seed passages, identify an instruction's "location," and identify an
    entry point.
    * Emulation host: The machine or environment on which the emulation target is being
    hosted. This is usually also thetranslation target. For our purposes, this is the JVM,
    often the same JVM executing Ghidra.
    * Emulation target: The machine being emulated. As opposed to the translation
    target or emulation host. While this can include many aspects of a target platform, we
    often just mean the Instruction Set Architecture (ISA, orlanguage) of the machine.
    * Entry point: An address (and contextreg value) by which execution may enter a passage.
    In addition to the decode seed, the translator may expose many entries into a given passage,
    usually at branch targets or the start of each basic block coinciding with an instruction.
    * Instruction: A single machine-code instruction.
    * Machine code: The sequence of bytes and/or decoded instructions executed by a
    machine.
    * Passage: A collection of strides connected by branches. Often each stride begins at
    the target of some branch in another stride.
    * P-code: An intermediate representation used by Ghidra in much of its analysis and
    execution modeling. For our purposes, we mean "low p-code," which is the common language into
    which the source machine code is translated before final translation to bytecode.
    * P-code op: A single p-code operation. A single instruction usually generates several
    p-code ops.
    * Stride: A contiguous sequence of instructions (and their emitted p-code) connected by
    fall-through. Note that conditional branches may appear in the middle of the stride. So long as
    fall-through is possible, the stride may continue.
    * Translation source: The machine code of the emulation target that is being
    translated and subsequently executed by theemulation host.
    * Translation target: The target of the JIT translation, usually the emulation
    host. For our purposes, this is always JVM bytecode.
    * Varnode: The triple (space,offset,size) giving the address and size of a variable in
    the emulation target's machine state. This is distinct from a variable node (see:obj:`JitVal`)
    in the:obj:`use-def <JitDataFlowModel>` graph. The name ":obj:`Varnode`" is an unfortunate
    inheritance from the Ghidra API, where theycan represent genuine variable nodes in the
    "high p-code" returned by the decompiler. However, the emulator consumes the "low p-code" where
    varnodes are mere triples, which is how we use the term.
    
     
     
    ************************
    Just-in-Time Translation
    ************************
    
     
    
    For details of the translation process, see :obj:`JitCompiler`.
     
     
    *****************
    Translation Cache
    *****************
    
     
    
    This class, aside from overriding and replacing the state and thread objects with respective
    extensions, manages a part of the translation cache. For reasons discussed in the translation
    section, there are two levels of caching. Once a passage is translated into a classfile, it must
    be loaded as a class and then instantiated for the thread executing it. Thus, at the machine (or
    emulator) level, each translated passage's class is cached. Then, each thread caches its instance
    of that class. When a thread encounters an address (and contextreg value) that it has not yet
    translated, it requests that the emulator perform that translation. The details of this check are
    described in :meth:`getEntryPrototype(AddrCtx, JitPassageDecoder) <.getEntryPrototype>` and
    :meth:`JitPcodeThread.getEntry(AddrCtx) <JitPcodeThread.getEntry>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, config: JitConfiguration, lookup: java.lang.invoke.MethodHandles.Lookup):
        """
        Create a JIT-accelerated p-code emulator
        
        :param ghidra.program.model.lang.Language language: the emulation target langauge
        :param JitConfiguration config: configuration options for this emulator
        :param java.lang.invoke.MethodHandles.Lookup lookup: a lookup in case the emulator (or its target) needs access to non-public
                    elements, e.g., to access a nested :obj:`PcodeUseropLibrary`.
        """

    def getConfiguration(self) -> JitConfiguration:
        """
        Get the configuration for this emulator.
        
        :return: the configuration
        :rtype: JitConfiguration
        """

    def getEntryPrototype(self, pcCtx: JitPassage.AddrCtx, decoder: ghidra.pcode.emu.jit.decode.JitPassageDecoder) -> ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPointPrototype:
        """
        Get the entry prototype for a given address and contextreg value.
         
         
        
        An **entry prototype** is a class representing a translated passage and an index
        identifying the point at which to enter the passage. The compiler numbers each entry point it
        generates and provides those indices via a static field in the output class. Those entry
        point indices are entered into the code cache for each translated passage. If no entry point
        exists for the requested address and contextreg value, the emulator will decode and translate
        a new passage at the requested seed.
        
         
        
        It's a bit odd to take the thread's decoder for a machine-level thing; however, all thread
        decoders ought to have the same behavior. The particular thread's decoder will have better
        cached instruction block state for decoding in the vicinity of its past execution, though.
        
        :param JitPassage.AddrCtx pcCtx: the counter and decoder context
        :param ghidra.pcode.emu.jit.decode.JitPassageDecoder decoder: the thread's decoder needing this entry point prototype
        :return: the entry point prototype
        :rtype: ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPointPrototype
        
        .. seealso::
        
            | :obj:`JitPcodeThread.getEntry(AddrCtx)`
        """

    def hasEntryPrototype(self, pcCtx: JitPassage.AddrCtx) -> bool:
        """
        Check if the emulator already has translated a given entry point.
         
         
        
        This is used by the decoder to detect if it should end a stride before reaching its natural
        end (i.e., a non-fall-through instruction.) This was a design decision to reduce
        re-translation of the same machine code. Terminating the stride will cause execution to exit
        the translated passage, but it will then immediately enter the existing translated passage.
        
        :param JitPassage.AddrCtx pcCtx: the program counter and contextreg value to check
        :return: true if the emulator has a translation which can be entered at the given pcCtx.
        :rtype: bool
        """

    @property
    def configuration(self) -> JitConfiguration:
        ...


class JitCompiler(java.lang.Object):
    """
    The Just-in-Time (JIT) translation engine that powers the :obj:`JitPcodeEmulator`.
     
     
    
    This is the translation engine from "any" machine language into JVM bytecode. The same caveats
    that apply to interpretation-based p-code emulation apply to JIT-accelerated emulation: Ghidra
    must have a Sleigh specification for the emulation target language, there must be userop
    libraries (built-in or user-provided) defining any userops encountered during the course of
    execution, all dependent code must be loaded or stubbed out, etc.
    
     
    
    A passage is decoded at a desired entry point using the :obj:`JitPassageDecoder`. This compiler
    then translates the passage into bytecode. It will produce a classfile which is then loaded and
    returned to the emulator (or other client). The provided class will have three principal methods,
    not counting getters: 1) The class initializer, which initializes static fields; 2) The
    constructor, which takes a thread and initializes instance fields, and 3) The
    :meth:`run <JitCompiledPassage.run>` method, which comprises the actual translation. A static
    field ``ENTRIES`` describes each entry point generated by the compiler. To execute the
    passage starting at a given entry point, the emulation thread must retrieve the index of the
    appropriate entry (i.e., address and contextreg value), instantiate the class, and then invoke
    the run method, passing it the entry index. The translated passage will read variables from the
    thread's :obj:`state <JitBytesPcodeExecutorState>` as needed, perform the equivalent operations as
    expressed in the source p-code, and then write the resulting variables back into the state.
    Memory variables are treated similarly, but without scope-based optimizations. In this manner,
    execution of the translated passage produces exactly the same effect on the emulation state as
    interpretation of the same p-code passage. The run method returns the next entry point to execute
    or ``null`` when the emulator must look up the next entry point.
    
     
    
    Translation of a passage takes place in distinct phases. See each respective class for details of
    its design and implementation:
     
     
    1. Control Flow Analysis: :obj:`JitControlFlowModel`
    2. Data Flow Analysis: :obj:`JitDataFlowModel`
    3. Variable Scope Analysis: :obj:`JitVarScopeModel`
    4. Type Assignment: :obj:`JitTypeModel`
    5. Variable Allocation: :obj:`JitAllocationModel`
    6. Operation Elimination: :obj:`JitOpUseModel`
    7. Code Generation: :obj:`JitCodeGenerator`
    
     
     
    *********************
    Control Flow Analysis
    *********************
    
     
    
    Some rudimentary control flow analysis is performed during decode, but the output of decode is a
    passage, i.e., collection of *strides*, not basic blocks. The control flow analysis breaks
    each stride down into basic blocks at the p-code level. Note that a single instruction's pcode
    (as well as any user instrumentation on that instruction's address) may have complex control
    flow. Additionally, branches that leave an instruction preclude execution of its remaining
    p-code. Thus, p-code basic blocks do not coincide precisely with instruction-level basic blocks.
    See :obj:`JitControlFlowModel`.
     
     
    ******************
    Data Flow Analysis
    ******************
    
     
    
    Most every following step consumes the control flow analysis. Data flow analysis interprets each
    basic block independently using an abstraction that produces a use-def graph. A varnode that is
    read before it is written produces a "missing" variable. Those missing variables are converted to
    *phi* nodes and later resolved during inter-block analysis. The graph is also able to
    consider aliasing, partial accesses, overlapping accesses, etc., by synthesizing operations to
    model those effects. See :obj:`JitDataFlowModel`.
     
     
    ***********************
    Variable Scope Analysis
    ***********************
    
     
    
    Because accessing :obj:`PcodeExecutorState` is expensive (relative to accessing a JVM local
    variable), the translation seeks to minimize such accesses. This is generally not recommended for
    memory accesses, as there is no telling in multi-threaded applications whether a given memory
    variable is shared/volatile or not. However, for registers and uniques, we can allocate the
    variables as JVM locals. Then we only "birth" them (read them in) when they come into scope and
    "retire" them (write them out) when they leave scope. This analyzer determines which variables
    are in scope (alive) in which basic blocks. See :obj:`JitVarScopeModel`.
     
     
    ***************
    Type Assignment
    ***************
    
     
    
    For those variables we allocate as JVM locals, we have to choose a type, because the JVM requires
    it. We have essentially 4 to choose from. (Though we could also choose a *reference* type,
    depending on the strategy we eventually choose for multi-precision arithmetic.) Those four are
    the JVM primitives: int, float, long, and double. For those more familiar with Java but not the
    JVM, the smaller integral primitives are all represented by JVM ints. The JVM does not permit
    type confusion, e.g., the application of float addition ``FADD`` to int variables. However,
    the emulation target may permit type confusion. (Those familiar with the constant 0x5f759df may
    appreciate intentional type confusion.) When this happens, we must explicitly convert by calling,
    e.g., :meth:`Float.floatToRawIntBits(float) <Float.floatToRawIntBits>`, which is essentially just a bit cast. Nevertheless,
    we seek to reduce the number of such calls we encode into the translation. See
    :obj:`JitTypeModel`.
     
     
    *******************
    Variable Allocation
    *******************
    
     
    
    Once we've decided the type of each use-def variable node, we allocate JVM locals and assign
    their types accordingly. To keep things simple and fast, we just allocate variables by varnode.
    Partial/overlapping accesses are coalesced to the containing varnode and cause the type to be a
    JVM int (to facilitate shifting and masking). Otherwise, types are assigned according to the most
    common use of the varnode, i.e., by taking a vote among the use-def variable nodes sharing that
    varnode. See :obj:`JitAllocationModel`.
     
     
    *********************
    Operation Elimination
    *********************
    
     
    
    Each instruction typically produces several p-code ops, the outputs of which may not actually be
    used by any subsequent op. This analysis seeks to identify such p-code ops and remove them. Since
    many ISAs employ "flags," which are set by nearly every arithmetic instruction, such ops are
    incredibly common. Worse yet, their computation is very expensive, because the JVM does not have
    comparable flag registers, nor does it provide opcodes for producing comparable values. We have
    to emit the bit banging operations ourselves. Thus, performing this elimination stands to improve
    execution speed significantly. However, eliminating these operations may lead to confusing
    results if execution is interrupted and the state inspected by a user. The effects of the
    eliminated operations will be missing. Even though they do not (or should not) matter, the user
    may expect to see them. Thus, this step can be toggled by
    :meth:`JitConfiguration.removeUnusedOperations() <JitConfiguration.removeUnusedOperations>`. See :obj:`JitOpUseModel`.
     
     
    ***************
    Code Generation
    ***************
    
     
    
    For simplicity, we seek to generate JVM bytecode in the same order as the source p-code ops.
    There are several details given the optimizations informed by all the preceding analysis. For
    example, the transfer of control to the requested entry point, the placement of variable birth
    and retirement on control flow edges (including fall-through).... We take an object-oriented
    approach to the translation of each p-code op, the handling of each variable's allocation and
    access, the conversion of types, etc. This phase outputs the final classfile bytes, which are
    then loaded as a hidden class. See :obj:`JitCodeGenerator`.
    
    
    .. admonition:: Implementation Note
    
        There are static fields in this class for configuring diagnostics. They are meant to be
        modified only temporarily by developers seeking to debug issues in the translation
        engine.
    """

    class Diag(java.lang.Enum[JitCompiler.Diag]):
        """
        Diagnostic toggles
        """

        class_: typing.ClassVar[java.lang.Class]
        PRINT_PASSAGE: typing.Final[JitCompiler.Diag]
        """
        Print each passage (instructions and p-code ops) before translation
        """

        PRINT_CFM: typing.Final[JitCompiler.Diag]
        """
        Print the contents (p-code) of each basic block and flows/branches among them
        """

        PRINT_DFM: typing.Final[JitCompiler.Diag]
        """
        Print the ops of each basic block in SSA (sort of) form
        """

        PRINT_VSM: typing.Final[JitCompiler.Diag]
        """
        Print the list of live variables for each basic block
        """

        PRINT_SYNTH: typing.Final[JitCompiler.Diag]
        """
        Print each synthetic operation, e.g., catenation, subpiece, phi
        """

        PRINT_OUM: typing.Final[JitCompiler.Diag]
        """
        Print each eliminated op
        """

        TRACE_CLASS: typing.Final[JitCompiler.Diag]
        """
        Enable ASM's trace for each generated classfile
        """

        DUMP_CLASS: typing.Final[JitCompiler.Diag]
        """
        Save the generated ``.class`` file to disk for offline examination
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitCompiler.Diag:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitCompiler.Diag]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ENABLE_DIAGNOSTICS: typing.Final[java.util.EnumSet[JitCompiler.Diag]]
    """
    The set of enabled diagnostic toggles.
     
     
    
    In production, this should be empty.
    """

    EXCLUDE_MAXS: typing.Final = -1
    """
    Exclude a given address offset from ASM's :obj:`ClassWriter.COMPUTE_MAXS` and
    :obj:`ClassWriter.COMPUTE_FRAMES`.
     
     
    
    Unfortunately, when automatic computation of frames and maxes fails, the ASM library offers
    little in terms of diagnostics. It usually crashes with an NPE or an AIOOBE. Worse, when this
    happens, it fails to output any of the classfile trace. To help with this, a developer may
    identify the address of the passage seed that causes such a failure and set this variable to
    its offset. This will prevent ASM from attempting this computation so that it at least prints
    the trace and dumps out the classfile to disk (if those :obj:`Diag`nostics are enabled).
     
     
    
    Once the trace/classfile is obtained, set this back to -1 and then apply debug prints in the
    crashing method. Since it's probably in the ASM library, you'll need to use your IDE /
    debugger to inject those prints. The way to do this in Eclipse is to set a "conditional
    breakpoint" then have the condition print the value and return false, so that execution
    continues. Sadly, this will still slow execution down considerably, so you'll want to set
    some other conditional breakpoint to catch when the troublesome passage is being translated.
    Probably the most helpful thing to print is the bytecode offset of each basic block ASM is
    processing as it computes the frames. Once it crashes, look at the last couple of bytecode
    offsets in the dumped classfile.
    """


    def __init__(self, config: JitConfiguration):
        """
        Construct a p-code to bytecode translator.
         
         
        
        In general, this should only be used by the JIT emulator and its test suite.
        
        :param JitConfiguration config: the configuration
        """

    def compilePassage(self, lookup: java.lang.invoke.MethodHandles.Lookup, passage: JitPassage) -> ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass:
        """
        Translate a passage using the given lookup
        
        :param java.lang.invoke.MethodHandles.Lookup lookup: a lookup that can access everything the passage may need, e.g., userop
                    libraries. Likely, this should come from the emulator, which may be in a script.
                    If you are unsure what to use here, use :meth:`MethodHandles.lookup() <MethodHandles.lookup>`. If you see
                    errors about accessing stuff during the compilation, ensure everything the
                    emulator needs is accessible from the method calling
                    :meth:`MethodHandles.lookup() <MethodHandles.lookup>`.
        :param JitPassage passage: the decoded passage to compile
        :return: the compiled class, not instantiated for any particular thread
        :rtype: ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass
        """

    def getConfiguration(self) -> JitConfiguration:
        """
        Get this compiler's configuration
        
        :return: the configuration
        :rtype: JitConfiguration
        """

    @property
    def configuration(self) -> JitConfiguration:
        ...


class JitPassage(ghidra.pcode.exec_.PcodeProgram):
    """
    A selection of instructions decoded from an emulation target, the generated p-code ops, and
    associated metadata.
     
     
    
    Note that the generated p-code ops include those injected by the emulator's client using
    :meth:`PcodeMachine.inject(Address, String) <PcodeMachine.inject>` and :meth:`PcodeThread.inject(Address, String) <PcodeThread.inject>`,
    which also includes breakpoints, i.e, :meth:`PcodeMachine.addBreakpoint(Address, String) <PcodeMachine.addBreakpoint>`.
    
    
    .. seealso::
    
        | :obj:`JitPassageDecoder`Passage decoding
    """

    class AddrCtx(java.lang.Comparable[JitPassage.AddrCtx]):
        """
        An address-context pair
         
         
        
        Because decode is sensitive to the contextreg value, we have to consider that visiting the
        same address with a different context could produce a completely different stride. Thus, we
        subsume the context value in a sense as part of the address when seeding the passage decoder,
        when referring to the "location" of p-code ops, when exiting a translated passage, etc.
        """

        class_: typing.ClassVar[java.lang.Class]
        NOWHERE: typing.Final[JitPassage.AddrCtx]
        """
        An address-context pair for synthetic p-code ops
         
         
        
        This is currently used in probing an instruction (possibly instrumented) for fall
        through, and in testing.
        """

        biCtx: typing.Final[java.math.BigInteger]
        """
        The contextreg value as a big integer
         
         
        
        This is 0 when the language does not have a context register
        """

        rvCtx: typing.Final[ghidra.program.model.lang.RegisterValue]
        """
        The contextreg as a register value
         
         
        
        This is ``null`` when the language does not have a context register
        """

        address: typing.Final[ghidra.program.model.address.Address]
        """
        The address
        """


        def __init__(self, ctx: ghidra.program.model.lang.RegisterValue, address: ghidra.program.model.address.Address):
            """
            Construct an address-context pair
            
            :param ghidra.program.model.lang.RegisterValue ctx: the contextreg value
            :param ghidra.program.model.address.Address address: the address
            """

        @staticmethod
        def fromInstruction(instruction: ghidra.program.model.listing.Instruction) -> JitPassage.AddrCtx:
            """
            Derive the address-context pair from an instruction
            
            :param ghidra.program.model.listing.Instruction instruction: the instruction
            :return: the instruction's address and input decode context
            :rtype: JitPassage.AddrCtx
            """

        @staticmethod
        def fromInstructionContext(insCtx: ghidra.program.model.lang.InstructionContext) -> JitPassage.AddrCtx:
            """
            Derive the address-context pair from an instruction's context
            
            :param ghidra.program.model.lang.InstructionContext insCtx: the context
            :return: the address and input decode context of the instruction whose context was given
            :rtype: JitPassage.AddrCtx
            """


    class Branch(java.lang.Object):
        """
        A branch in the p-code
        """

        class_: typing.ClassVar[java.lang.Class]

        def describeTo(self) -> str:
            """
            Get a string description of the branch target
            
            :return: the description
            :rtype: str
            """

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            """
            The op performing the branch
            
            :return: the "from" op
            :rtype: ghidra.program.model.pcode.PcodeOp
            """

        def isFall(self) -> bool:
            """
            Indicates whether this branch represents a fall-through case.
             
             
            
            Note that the :meth:`from() <.from>` may not be an actual branching p-code op when
            ``isFall`` is true. A "fall-through" branch happens in two cases. First, and most
            obvious, is to describe the fall-through case of a :obj:`conditional
            branch <PcodeOp.CBRANCH>`. Second is when for a p-code op the immediately precedes the target of some other
            branch. That branch causes a split in basic blocks, and so to encode the fall through
            from that op into the basic block immediately after, a fall-through branch is added.
            
            :return: true if this branch is the fall-through case.
            :rtype: bool
            """

        @property
        def fall(self) -> jpype.JBoolean:
            ...


    class SBranch(JitPassage.Branch):
        """
        A branch as analyzed within an instruction step
         
         
        
        After intra-instruction reachability is determined and this branch is to be added to the
        whole passage, it will be "upgraded" to a :obj:`PBranch`.
        """

        class_: typing.ClassVar[java.lang.Class]


    class PBranch(JitPassage.Branch):
        """
        A branch as analyzed within a passage
         
         
        
        Many implement this via :obj:`RBranch`.
        """

        class_: typing.ClassVar[java.lang.Class]


    class RBranch(JitPassage.PBranch):
        """
        A branch with known intra-instruction reachability
        """

        class_: typing.ClassVar[java.lang.Class]

        def reach(self) -> JitPassage.Reachability:
            """
            The intra-instruction reachability
            
            :return: the reachability
            :rtype: JitPassage.Reachability
            """


    class Reachability(java.lang.Enum[JitPassage.Reachability]):
        """
        Describes the manner in which something is reachable, wrt. dynamic context changes *within
        an instruction step*.
         
         
        
        At the moment, the only way context can be changed dynamically is via a p-code userop. Such
        ops must have the :meth:`PcodeUserop.modifiesContext() <PcodeUserop.modifiesContext>` attribute set. If such an op is known
        to have been executed when finishing an instruction (either by branch or fall-through), we
        must exit the compiled passage.
        """

        class_: typing.ClassVar[java.lang.Class]
        WITHOUT_CTXMOD: typing.Final[JitPassage.Reachability]
        """
        There is at least one path to reach it. None of them modify the context dynamically.
        """

        MAYBE_CTXMOD: typing.Final[JitPassage.Reachability]
        """
        There are at least two paths to reach it. Some modify the context dynamically, and some
        do not.
        """

        WITH_CTXMOD: typing.Final[JitPassage.Reachability]
        """
        There is at least one path to reach it. All of them modify the context dynamically.
        """


        def canReachWithoutCtxMod(self) -> bool:
            """
            Check if it is possible for this block to be reached without a context modification.
             
             
            
            This is true if there exists *any* path to this block that doesn't include a
            possible context modification.
            
            :return: true if reachable without context modification, false otherwise.
            :rtype: bool
            """

        def combine(self, that: JitPassage.Reachability) -> JitPassage.Reachability:
            """
            Consider this and another reachability as "or"
            
            :param JitPassage.Reachability that: the other reachability
            :return: the "or" of both
            :rtype: JitPassage.Reachability
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitPassage.Reachability:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitPassage.Reachability]:
            ...


    class IntBranch(JitPassage.Branch):
        """
        A branch to another p-code op in the same passage
         
         
        
        The :obj:`JitCodeGenerator` translates internal branches into JVM bytecodes for the
        equivalent branch to the translation of the target p-code op. Thus, we remain executing
        inside the :meth:`run <JitCompiledPassage.run>` method. This branch type incurs the least
        run-time cost.
        """

        class_: typing.ClassVar[java.lang.Class]

        def to(self) -> ghidra.program.model.pcode.PcodeOp:
            """
            The target pcode op
            
            :return: the op
            :rtype: ghidra.program.model.pcode.PcodeOp
            """


    class SIntBranch(java.lang.Record, JitPassage.IntBranch, JitPassage.SBranch):
        """
        An :obj:`IntBranch` as analyzed during one instruction step
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, to: ghidra.program.model.pcode.PcodeOp, isFall: typing.Union[jpype.JBoolean, bool]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def isFall(self) -> bool:
            ...

        def to(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def toString(self) -> str:
            ...

        def withReach(self, reach: JitPassage.Reachability) -> JitPassage.RIntBranch:
            """
            Upgrade this branch to an :obj:`RIntBranch` for inclusion in the passage.
            
            :param JitPassage.Reachability reach: see :meth:`RBranch.reach() <RBranch.reach>`
            :return: the branch
            :rtype: JitPassage.RIntBranch
            """

        @property
        def fall(self) -> jpype.JBoolean:
            ...


    class RIntBranch(java.lang.Record, JitPassage.IntBranch, JitPassage.RBranch):
        """
        A :obj:`IntBranch` as added to the passage
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, to: ghidra.program.model.pcode.PcodeOp, isFall: typing.Union[jpype.JBoolean, bool], reach: JitPassage.Reachability):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def isFall(self) -> bool:
            ...

        def reach(self) -> JitPassage.Reachability:
            ...

        def to(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def toString(self) -> str:
            ...

        @property
        def fall(self) -> jpype.JBoolean:
            ...


    class ExtBranch(JitPassage.Branch):
        """
        A branch to an address (and context value) not in the same passage
         
         
        
        When execution encounters this branch, the :meth:`run <JitCompiledPassage.run>` method
        sets the emulator's program counter and context to the :meth:`branch target <.to>` and
        returns the appropriate entry point for further execution.
         
         
        
        Note that this branch type is used by the decoder to track queued decode seeds as well.
        External branches that get decoded are changed into internal branches.
        """

        class_: typing.ClassVar[java.lang.Class]

        def to(self) -> JitPassage.AddrCtx:
            """
            The target address-context pair
            
            :return: the target
            :rtype: JitPassage.AddrCtx
            """


    class SExtBranch(java.lang.Record, JitPassage.ExtBranch, JitPassage.SBranch):
        """
        An :obj:`ExtBranch` as analyzed during one instruction step
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, to: JitPassage.AddrCtx):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def to(self) -> JitPassage.AddrCtx:
            ...

        def toString(self) -> str:
            ...

        def withReach(self, reach: JitPassage.Reachability) -> JitPassage.RExtBranch:
            """
            Upgrade this branch to an :obj:`RExtBranch` for inclusion in the passage.
            
            :param JitPassage.Reachability reach: see :meth:`RBranch.reach() <RBranch.reach>`
            :return: the branch
            :rtype: JitPassage.RExtBranch
            """


    class RExtBranch(java.lang.Record, JitPassage.ExtBranch, JitPassage.RBranch):
        """
        A :obj:`ExtBranch` as added to the passage
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, to: JitPassage.AddrCtx, reach: JitPassage.Reachability):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def reach(self) -> JitPassage.Reachability:
            ...

        def to(self) -> JitPassage.AddrCtx:
            ...

        def toIntBranch(self, to: ghidra.program.model.pcode.PcodeOp) -> JitPassage.RIntBranch:
            """
            Convert this external branch into an internal one
             
             
            
            This is called whenever it becomes the case that an external target is decoded an added
            to the passage, making it an internal branch. Notably, this happens when selecting a seed
            from the queue of externals, when flowing to a target that is already decoded, and when
            finishing up a passage where all remaining seeds must be examined.
            
            :param ghidra.program.model.pcode.PcodeOp to: the target p-code op
            :return: the resulting internal branch
            :rtype: JitPassage.RIntBranch
            """

        def toString(self) -> str:
            ...


    class IndBranch(JitPassage.Branch):
        """
        A branch to a dynamic address
         
         
        
        When execution encounters this branch, the :meth:`run <JitCompiledPassage.run>` method
        will set the emulator's program counter to the computed address and its context to
        :meth:`flowCtx() <.flowCtx>`, then return the appropriate entry point for further execution.
         
         
        
        TODO: Some analysis may be possible to narrow the possible addresses to a known few and then
        treat this as several :obj:`IntBranch`es; however, I worry this is too expensive for what it
        gets us. This will be necessary if we are to JIT, e.g., a switch table.
        """

        class_: typing.ClassVar[java.lang.Class]

        def flowCtx(self) -> ghidra.program.model.lang.RegisterValue:
            """
            The decode context after the branch is taken
            
            :return: the context
            :rtype: ghidra.program.model.lang.RegisterValue
            """


    class SIndBranch(java.lang.Record, JitPassage.IndBranch, JitPassage.SBranch):
        """
        An :obj:`IndBranch` as analyzed during one instruction step
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, flowCtx: ghidra.program.model.lang.RegisterValue):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def flowCtx(self) -> ghidra.program.model.lang.RegisterValue:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def withReach(self, reach: JitPassage.Reachability) -> JitPassage.RIndBranch:
            """
            Upgrade this branch to an :obj:`RIndBranch` for inclusion in the passage.
            
            :param JitPassage.Reachability reach: see :meth:`RBranch.reach() <RBranch.reach>`
            :return: the branch
            :rtype: JitPassage.RIndBranch
            """


    class RIndBranch(java.lang.Record, JitPassage.IndBranch, JitPassage.RBranch):
        """
        A :obj:`IndBranch` as added to the passage
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, flowCtx: ghidra.program.model.lang.RegisterValue, reach: JitPassage.Reachability):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def flowCtx(self) -> ghidra.program.model.lang.RegisterValue:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def reach(self) -> JitPassage.Reachability:
            ...

        def toString(self) -> str:
            ...


    class ErrBranch(java.lang.Record, JitPassage.SBranch, JitPassage.PBranch):
        """
        A "branch" representing an error
         
         
        
        When execution encounters this branch, the :meth:`run <JitCompiledPassage.run>` method
        throws an exception. This branch is used to encode error conditions that may not actually be
        encountered at run time. Some cases are:
         
         
        * An instruction decode error — synthesized as a :obj:`DecodeErrorPcodeOp`
        * An :obj:`unimplemented <PcodeOp.UNIMPLEMENTED>` instruction
        * A :obj:`call <PcodeOp.CALLOTHER>` to an undefined userop
        
         
         
        
        The decoder and translator may encounter such an error, but unless execution actually reaches
        the error, the emulator need not crash. Thus, we note the error and generate code that will
        actually throw it in the translation, only if it's actually encountered.
         
         
        
        Note that the :obj:`OpGen` for the specific p-code op generating the error will decide what
        exception type to throw.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: ghidra.program.model.pcode.PcodeOp, message: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def hashCode(self) -> int:
            ...

        def message(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class DecodedPcodeOp(ghidra.program.model.pcode.PcodeOp):
        """
        An extension of :obj:`PcodeOp` that carries along with it the address and decode context
        where it occurred.
         
         
        
        There is a difference between :obj:`.at`'s :obj:`address <AddrCtx.address>` vs.
        :meth:`seqnum <.getSeqnum>`'s :meth:`target <SequenceNumber.getTarget>`. The former is
        determined by the :obj:`JitPassageDecoder` and applied to all p-code ops generated at that
        address (and context value), including those from injected Sleigh. The latter is determined
        by the :obj:`Instruction` (or injected :obj:`PcodeProgram`), which have less information
        about their origins. There are also :obj:`DecodeErrorPcodeOp` and :obj:`NopPcodeOp`, which
        are synthesized by the :obj:`JitPassageDecoder` without an instruction or inject. This
        information is required for bookkeeping, esp., when updating the emulator's program counter
        and decode context when a p-code op produces an unexpected run-time error.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, at: JitPassage.AddrCtx, original: ghidra.program.model.pcode.PcodeOp):
            """
            Re-write a p-code op including its address and context value
             
             
            
            Aside from :obj:`.at`, everything is copied from the given original p-code op.
            
            :param JitPassage.AddrCtx at: the address and context value where the op was produced
            :param ghidra.program.model.pcode.PcodeOp original: the original p-code op
            """

        def getAt(self) -> JitPassage.AddrCtx:
            """
            Get the address and context value where this op was produced
            
            :return: the address-context pair
            :rtype: JitPassage.AddrCtx
            """

        def getContext(self) -> ghidra.program.model.lang.RegisterValue:
            """
            Get the decode context where this op was produced
            
            :return: the decode context
            :rtype: ghidra.program.model.lang.RegisterValue
            """

        def getCounter(self) -> ghidra.program.model.address.Address:
            """
            Get the address where this op was produced
            
            :return: the address
            :rtype: ghidra.program.model.address.Address
            """

        def isInstructionStart(self) -> bool:
            """
            Check if this op represents the start of an instruction
             
             
            
            If this p-code op was produced by an inject, this will return false! It only returns true
            for an op that is genuinely the first op in the result of :meth:`Instruction.getPcode() <Instruction.getPcode>`.
            **WARNING:** This should *not* be used for branching purposes, because branches
            to a given address are meant to target any injections there, too. Currently, this is used
            only to count the number of instructions actually executed.
            
            :return: true if this op is the first of an instruction
            :rtype: bool
            
            .. seealso::
            
                | :obj:`JitBlock.instructionCount()`
            
                | :obj:`JitCompiledPassage.count(int, int)`
            
                | :obj:`JitPcodeThread.count(int, int)`
            """

        @property
        def at(self) -> JitPassage.AddrCtx:
            ...

        @property
        def instructionStart(self) -> jpype.JBoolean:
            ...

        @property
        def context(self) -> ghidra.program.model.lang.RegisterValue:
            ...

        @property
        def counter(self) -> ghidra.program.model.address.Address:
            ...


    class ExitPcodeOp(ghidra.program.model.pcode.PcodeOp):
        """
        A synthetic p-code op that represents a return from the :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>`
        method.
         
         
        
        When execution encounters this op (and the corresponding :obj:`ExtBranch`), the emulator's
        program counter and context values are set to the :meth:`branch target <ExtBranch.to>`, and
        the appropriate entry point is returned.
         
         
        
        This is used in a few ways: The simplest, though perhaps not obvious, way is when the decoder
        encounters an existing entry point. We avoid re-translating the same instructions by forcing
        the stride to end. However, the last instruction in that stride would have fall through,
        causing dangling control flow. To mitigate that, we append a synthetic exit op to return the
        existing entry point. The emulator can then resume execution accordingly.
         
         
        
        The next is even less obvious. When the emulation client (or user) injects Sleigh, a common
        mistake is to forget control flow. The decoder detects this when "falling through" does not
        actually advance the program counter. In this case, we append this synthetic op to exit the
        translated passage. While it still results in an endless loop (just like the
        interpretation-based emulator), it's easier to interrupt and diagnose when we exit the
        translation between each "iteration."
         
         
        
        The last is a small hack: The decoder needs to know whether each instruction (possibly
        instrumented by an inject) falls through. To do this, it appends an exit op to the very end
        of the instruction's (and inject's) ops and performs rudimentary control flow analysis (see
        :obj:`BlockSplitter`). It then seeks a path from start to exit. If one is found, it has fall
        through. This "probe" op is *not* included in the decoded stride.
        """

        class_: typing.ClassVar[java.lang.Class]

        @staticmethod
        def cond(at: JitPassage.AddrCtx) -> JitPassage.ExitPcodeOp:
            """
            Construct a synthetic conditional exit op
            
            :param JitPassage.AddrCtx at: the address and context value to set on the emulator when exiting the
                        :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>` method
            :return: the op
            :rtype: JitPassage.ExitPcodeOp
            """

        @staticmethod
        def exit(at: JitPassage.AddrCtx) -> JitPassage.ExitPcodeOp:
            """
            Construct a synthetic exit op
            
            :param JitPassage.AddrCtx at: the address and context value to set on the emulator when exiting the
                        :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>` method
            :return: the op
            :rtype: JitPassage.ExitPcodeOp
            """


    class EntryPcodeOp(ghidra.program.model.pcode.PcodeOp):
        """
        A synthetic op representing the initial seed of a decoded passage.
         
         
        
        Because we use a queue of :obj:`ExtBranch`es as the seed queue, and the initial seed has no
        real :meth:`Branch.from() <Branch.from>`, we synthesize a :obj:`branch op <PcodeOp.BRANCH>` from the entry
        address to itself. This synthetic op is *not* included in the decoded stride.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, entry: JitPassage.AddrCtx):
            """
            Construct the passage entry p-code op.
            
            :param JitPassage.AddrCtx entry: the target address and decode context of the passage seed
            """


    class NopPcodeOp(JitPassage.DecodedPcodeOp):
        """
        A synthetic p-code op meant to encode "no operation"
         
         
        
        P-code does not have a NOP opcode, because there's usually no reason to produce such. A NOP
        machine instruction just produces an empty list of p-code ops, denoting "no operation."
        However, for bookkeeping purposes in our JIT translator, we occasionally need some op to hold
        an important place, but that op needs to do nothing. We use this in two situations:
         
         
        * An instruction (possibly because of an inject) that does nothing. Yes, essentially a NOP
        machine instruction. Because another op may target this instruction, and:obj:`Branch`es
        need to target a p-code op, we synthesize a p-code "nop" to hold that position. The
        alternative is to figure out what op immediately follows the branch target, but such an op
        may not have been decoded, yet. It's easier just to synthesize the nop.
        * A p-code branch to the end of an instruction. Most often a slaspec author that means to
        skip the remainder of an instruction will use``goto inst_next``; however, because of
        sub-table structuring and/or personal preferences, sometimes we see``goto <end>;`` where
        ``<end>`` is at the end of the instruction, and thus, no p-code op actually follows it.
        We essentially have the same situation and the NOP machine instruction where we can either
        synthesize a placeholder nop, or else we have to figure out what op does (or will) actually
        follow the label.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, at: JitPassage.AddrCtx, seq: typing.Union[jpype.JInt, int]):
            """
            Construct a synthetic p-code "nop"
            
            :param JitPassage.AddrCtx at: the address-context pair where the op was generated
            :param jpype.JInt or int seq: the sequence where the nop is inserted. For machine-code NOP, this should be
                        0. For a branch to the end of an instruction, this should be the next sequence
                        number (so that the branch targets this nop)
            """


    class DecodeErrorPcodeOp(JitPassage.DecodedPcodeOp):
        """
        A synthetic p-code op denoting a decode error
         
         
        
        The decoder may encounter several decode errors as it selects and decodes the passage. An
        instruction is selected because the JIT believes it *may* be executed by the emulator.
        (Predicting this and making good selections is a matter of further research.) Encounting a
        decode error along a possible path is not cause to throw an exception. However; if the
        emulator does in fact attempt to execute the bytes which it can't decode, then we do throw
        the exception. This p-code op is synthesized where such decode errors occur, and the
        translator will generate code that actually throw the exception. Note that the error message
        is placed in the corresponding :obj:`ErrBranch`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, at: JitPassage.AddrCtx):
            """
            Construct a p-code op representing an instruction decode error.
            
            :param JitPassage.AddrCtx at: the address and decode context where the error occurred
            """


    class DecodeErrorInstruction(ghidra.app.util.PseudoInstruction):
        """
        An instruction denoting a decode error
         
         
        
        The Sleigh disassembler normally denotes this with a :obj:`PseudoInstruction` having an
        :obj:`InvalidPrototype`. We essentially do the same here, but with custom types that are
        simpler to identify. Additionally, the types contain additional information, e.g., the error
        message. We also need the prototype to produce a single :obj:`DecodeErrorPcodeOp`.
        """

        @typing.type_check_only
        class DecodeErrorPrototype(ghidra.program.model.lang.InvalidPrototype):
            """
            The prototype for the decode error instruction
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, language: ghidra.program.model.lang.Language):
                ...


        @typing.type_check_only
        class DecodeErrorProcessorContext(ghidra.program.model.lang.ProcessorContext):
            """
            An implementation of :obj:`ProcessorContext` to satisfy the requirements of the
            :obj:`PseudoInstruction`.
             
             
            
            This need do little more than provide the decode context register value.
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, language: ghidra.program.model.lang.Language, ctx: ghidra.program.model.lang.RegisterValue):
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, ctx: ghidra.program.model.lang.RegisterValue, message: typing.Union[java.lang.String, str]):
            """
            Construct an instruction to indicate a decode error
            
            :param ghidra.program.model.lang.Language language: the emulation target langauge
            :param ghidra.program.model.address.Address address: the address where decode was attempted
            :param ghidra.program.model.lang.RegisterValue ctx: the input decode context
            :param java.lang.String or str message: a message for the :obj:`DecodePcodeExecutionException` if the emulator
                        attempts to execute this instruction
            :raises AddressOverflowException: never
            """

        def getMessage(self) -> str:
            """
            Get the message for the exception, should this instruction be "executed"
            
            :return: the error message
            :rtype: str
            """

        @property
        def message(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, entry: JitPassage.AddrCtx, code: java.util.List[ghidra.program.model.pcode.PcodeOp], decodeLibrary: ghidra.pcode.exec_.PcodeUseropLibrary[java.lang.Object], instructions: java.util.List[ghidra.program.model.listing.Instruction], branches: collections.abc.Mapping, entries: collections.abc.Mapping):
        """
        Construct a new passage
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the translation source language, i.e., the emulation target language. See
                    :meth:`getLanguage() <.getLanguage>`
        :param JitPassage.AddrCtx entry: see :meth:`getEntry() <.getEntry>`
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] code: the p-code ops, grouped by stride. Within each stride, they are ordered as
                    decoded and produced by their instructions. The strides are sorted by seed, with
                    precedence to the decode context value. See :meth:`getInstructions() <.getInstructions>`. See
                    :meth:`getCode() <.getCode>`.
        :param ghidra.pcode.exec_.PcodeUseropLibrary[java.lang.Object] decodeLibrary: see :meth:`getDecodeLibrary() <.getDecodeLibrary>`
        :param java.util.List[ghidra.program.model.listing.Instruction] instructions: see :meth:`getInstructions() <.getInstructions>`
        :param collections.abc.Mapping branches: see :meth:`getBranches() <.getBranches>`
        :param collections.abc.Mapping entries: see :meth:`getOpEntry(PcodeOp) <.getOpEntry>`
        """

    @staticmethod
    def decodeError(language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, ctx: ghidra.program.model.lang.RegisterValue, message: typing.Union[java.lang.String, str]) -> JitPassage.DecodeErrorInstruction:
        """
        Create an instruction to indicate a decode error
         
         
        
        The resulting instruction will produce a single :obj:`DecodeErrorPcodeOp`. The translator
        will generate code that throws a :obj:`DecodePcodeExecutionException` should execution reach
        it.
        
        :param ghidra.program.model.lang.Language language: the emulation target language
        :param ghidra.program.model.address.Address address: the address where decode was attempted
        :param ghidra.program.model.lang.RegisterValue ctx: the input decode context
        :param java.lang.String or str message: a message for the :obj:`DecodePcodeExecutionException`
        :return: the new "instruction"
        :rtype: JitPassage.DecodeErrorInstruction
        """

    def getBranches(self) -> java.util.Map[ghidra.program.model.pcode.PcodeOp, JitPassage.PBranch]:
        """
        Get all of the (non-fall-through) branches in the passage
        
        :return: the branches, keyed by :meth:`Branch.from() <Branch.from>`.
        :rtype: java.util.Map[ghidra.program.model.pcode.PcodeOp, JitPassage.PBranch]
        """

    def getDecodeLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[java.lang.Object]:
        """
        Get the userop library that was used during decode of the passage
         
         
        
        This often wraps the emulator's userop library. Downstream components, namely the
        :obj:`JitDataFlowModel`, will need this when translating :obj:`calls <PcodeOp.CALLOTHER>` to
        userops.
        
        :return: the library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[java.lang.Object]
        """

    def getEntry(self) -> JitPassage.AddrCtx:
        """
        Get the initial seed of this passage.
         
         
        
        This is informational only. It should be used in naming things and/or in diagnostics.
        
        :return: the address-context pair
        :rtype: JitPassage.AddrCtx
        """

    def getErrorMessage(self, op: ghidra.program.model.pcode.PcodeOp) -> str:
        """
        If the given p-code op is known to cause an error, e.g., an unimplemented instruction, get
        the error message.
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op causing the error
        :return: the message for the error caused
        :rtype: str
        """

    def getInstructions(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        """
        Get all of the instructions in the passage.
         
         
        
        These are grouped by stride. Within each stride, the instructions are listed in decode order.
        The strides are ordered by seed address-context pair, with context value taking precedence.
        
        :return: the list of instructions
        :rtype: java.util.List[ghidra.program.model.listing.Instruction]
        """

    def getOpEntry(self, op: ghidra.program.model.pcode.PcodeOp) -> JitPassage.AddrCtx:
        """
        Check if a given p-code op is the first of an instruction.
         
         
        
        **NOTE**: If an instruction is at an address with an inject, then the first op produced by
        the inject is considered the "entry" to the instruction. This is to ensure that any control
        flow to the injected address executes the injected code, not just the instruction's code.
        
        :param ghidra.program.model.pcode.PcodeOp op: the op to check.
        :return: the address-context pair that generated the op, if it is the first there, or
                ``null``
        :rtype: JitPassage.AddrCtx
        """

    @staticmethod
    def hasFallthrough(op: ghidra.program.model.pcode.PcodeOp) -> bool:
        """
        Check if a given p-code op could fall through
         
         
        
        Conditional branches and non-branching ops are the only ones that can fall through. Note that
        for JIT purposes, a :obj:`CALL <PcodeOp.CALL>` op *does not* fall through! For
        decompilation, it hints that it's branching to a subroutine that *usually* returns
        back to the caller, but the JIT compiler does not take that hint. 1) There's no guarantee it
        will actually return. 2) Even if it did, it would be via a :obj:`PcodeOp.RETURN`, which is
        an *indirect* branch. An indirect branch is not sufficient to join two strides in the
        same passage. Thus, we have little to gain by falling through a call, and the more likely
        outcome is the JIT and/or ASM library will eliminate the code following the call.
        
        :param ghidra.program.model.pcode.PcodeOp op: the op to consider
        :return: true if the op does or could fall through
        :rtype: bool
        """

    @property
    def instructions(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        ...

    @property
    def entry(self) -> JitPassage.AddrCtx:
        ...

    @property
    def opEntry(self) -> JitPassage.AddrCtx:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def branches(self) -> java.util.Map[ghidra.program.model.pcode.PcodeOp, JitPassage.PBranch]:
        ...

    @property
    def decodeLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[java.lang.Object]:
        ...


class JitThreadBytesPcodeExecutorState(ghidra.pcode.emu.ThreadPcodeExecutorState[jpype.JArray[jpype.JByte]], JitBytesPcodeExecutorState):
    """
    The equivalent to :obj:`ThreadPcodeExecutorState` that multiplexes shared and local state for
    the JIT-accelerated p-code emulator
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sharedState: JitDefaultBytesPcodeExecutorState, localState: JitDefaultBytesPcodeExecutorState):
        """
        Construct a new thread state
        
        :param JitDefaultBytesPcodeExecutorState sharedState: the shared portion (e.g., ram space)
        :param JitDefaultBytesPcodeExecutorState localState: the local portion (i.e., register, unique spaces)
        """


class JitConfiguration(java.lang.Record):
    """
    The configuration for a JIT-accelerated emulator.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a default configuration
        """

    @typing.overload
    def __init__(self, maxPassageInstructions: typing.Union[jpype.JInt, int], maxPassageOps: typing.Union[jpype.JInt, int], maxPassageStrides: typing.Union[jpype.JInt, int], removeUnusedOperations: typing.Union[jpype.JBoolean, bool], emitCounters: typing.Union[jpype.JBoolean, bool]):
        ...

    def emitCounters(self) -> bool:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def maxPassageInstructions(self) -> int:
        ...

    def maxPassageOps(self) -> int:
        ...

    def maxPassageStrides(self) -> int:
        ...

    def removeUnusedOperations(self) -> bool:
        ...

    def toString(self) -> str:
        ...


class JitJvmTypeUtils(java.lang.Enum[JitJvmTypeUtils]):
    """
    Some utilities for generating type signatures, suitable for use with
    :meth:`ClassVisitor.visitField(int, String, String, String, Object) <ClassVisitor.visitField>`.
     
     
    
    **WARNING:** It seems to me, the internal representation of signatures as accepted by the ASM
    API is not fixed from version to version. In the future, these utilities may need to be updated
    to work with multiple versions, if the representation changes in a newer classfile format.
    Hopefully, the upcoming classfile API will obviate the need for any of this.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def classToInternalName(cls: java.lang.Class[typing.Any]) -> str:
        """
        Get the internal name of a class as in :meth:`org.objectweb.asm.Type.getInternalName(Class) <org.objectweb.asm.Type.getInternalName>`.
        
        :param java.lang.Class[typing.Any] cls: the class
        :return: the internal name
        :rtype: str
        """

    @staticmethod
    def rawToInternalName(type: java.lang.reflect.Type) -> str:
        """
        Presume the given type is a :obj:`Class` and get its internal name
        
        :param java.lang.reflect.Type type: the type
        :return: the internal name
        :rtype: str
        """

    @staticmethod
    def typeToSignature(type: java.lang.reflect.Type) -> str:
        """
        Get the signature of the given type
         
         
        
        For the use case this supports, probably the best way to obtain a :obj:`Type` is via
        :obj:`TypeLiteral`.
         
         
        
        As of the JVM 21, internal type signatures are derived as:
         
         
        * ``sig(my.MyType) = Lmy/MyType.class;``
        * ``sig(my.MyType[]) = [sig(my.MyType)``
        * ``sig(my.MyType<Yet, Another, ...>) = Lmy/MyType<sig(Yet), sig(Another), ...>;``
        * Wildcard types as in :meth:`wildToSignature(WildcardType) <.wildToSignature>`
        * Type variables are not supported by these utilities
        
        
        :param java.lang.reflect.Type type: the type
        :return: the signature
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> JitJvmTypeUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[JitJvmTypeUtils]:
        ...

    @staticmethod
    def wildToSignature(wt: java.lang.reflect.WildcardType) -> str:
        """
        Get the signature of the given wildcard type
         
         
        * ``sig(?) = *``
        * ``sig(? super MyType) = -sig(MyType)``
        * ``sig(? extends MyType) = +sig(MyType)``
        
        
        :param java.lang.reflect.WildcardType wt: the type
        :return: the signature
        :rtype: str
        """


class JitBytesPcodeExecutorStatePiece(ghidra.pcode.exec_.AbstractBytesPcodeExecutorStatePiece[JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace]):
    """
    The state piece for :obj:`JitDefaultBytesPcodeExecutorState`
     
     
    
    This provides access to the internals so that translated passages can pre-fetch certain objects
    to optimize state accesses.
    """

    class JitBytesPcodeExecutorStateSpace(ghidra.pcode.exec_.BytesPcodeExecutorStateSpace[java.lang.Void]):
        """
        An object to manage state for a specific :obj:`AddressSpace`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, space: ghidra.program.model.address.AddressSpace, backing: java.lang.Void):
            """
            Construct a state space
            
            :param ghidra.program.model.lang.Language language: the emulation target language
            :param ghidra.program.model.address.AddressSpace space: the address space
            :param java.lang.Void backing: any extra read-through backing (not used)
            """

        def getDirect(self, offset: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
            """
            Pre-fetch the byte array for the block (page) containing the given offset
             
             
            
            A translated passage is likely to call this several times in its constructor to pre-fetch
            the byte arrays for variables (ram, register, and unique) that it accesses directly,
            i.e., with a fixed offset. The generated code will then access the byte array directly to
            read and write the variable values in the emulator's state.
            
            :param jpype.JLong or int offset: the :meth:`offset <Address.getOffset>` within this address space.
            :return: the byte array for the containing block
            :rtype: jpype.JArray[jpype.JByte]
            """

        def read(self, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
            """
            Read a variable from this (pre-fetched) state space
             
             
            
            A translated passage is likely to call
            :meth:`JitBytesPcodeExecutorStatePiece.getForSpace(AddressSpace, boolean) <JitBytesPcodeExecutorStatePiece.getForSpace>` once or twice
            in its constructor to pre-fetch the per-space backing of any indirect memory variables
            that it accesses, i.e., variables with a dynamic offset. These are usually required for
            :obj:`PcodeOp.LOAD` and :obj:`PcodeOp.STORE` ops. The generated code will then invoke
            this method (and :meth:`write <.write>`) passing in the offset to
            access variables in the emulator's state at runtime.
            
            :param jpype.JLong or int offset: the offset (known at runtime)
            :param jpype.JInt or int size: the size of the variable
            :return: the value of the variable as a byte array
            :rtype: jpype.JArray[jpype.JByte]
            """

        @property
        def direct(self) -> jpype.JArray[jpype.JByte]:
            ...


    @typing.type_check_only
    class JitBytesSpaceMap(ghidra.pcode.exec_.AbstractLongOffsetPcodeExecutorStatePiece.SimpleSpaceMap[JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace]):
        """
        A state space map that creates a :obj:`JitBytesPcodeExecutorStateSpace` for each needed
        :obj:`AddressSpace`
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a state piece
        
        :param ghidra.program.model.lang.Language language: the emulation target language
        """


class JitBytesPcodeExecutorState(ghidra.pcode.exec_.PcodeExecutorState[jpype.JArray[jpype.JByte]]):
    """
    The run-time executor state for the JIT-accelerated p-code emulator
    
    
    .. seealso::
    
        | :obj:`JitDefaultBytesPcodeExecutorState`
    
        | :obj:`JitBytesPcodeExecutorStatePiece`
    
        | :obj:`JitBytesPcodeExecutorStateSpace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getForSpace(self, space: ghidra.program.model.address.AddressSpace) -> JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace:
        """
        For generated code to side-step the space lookup
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: the state space
        :rtype: JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace
        """

    @property
    def forSpace(self) -> JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace:
        ...


class JitPcodeThread(ghidra.pcode.emu.BytesPcodeThread):
    """
    A JIT-accelerated thread of p-code emulation
     
     
    
    This class implements the actual JIT-accelerated execution loop. In contrast to the normal
    per-instruction Fetch-Execute-Store loop inherited from :obj:`DefaultPcodeThread`, this thread's
    :meth:`run() <.run>` method implements a per-*passage* Fetch-Decode-Translate-Execute loop.
     
     
     
    *****
    Fetch
    *****
    
     
    
    The Fetch step involves checking the code cache for an existing translation at the thread's
    current counter and decode context. Cache entries are keyed by *passage entry point*, that
    is an address (and context reg value, if applicable) within a passage where execution is
    permitted to enter. This typically consists of the passage's seed as well as each branch target
    in the same passage. If one is found, we skip the Decode and Translate steps, and proceed
    directly to Execute.
     
     
    ******
    Decode
    ******
    
     
    
    The Decode step involves decoding and selecting several instructions into a *passage*. A
    passage may comprise of several instructions connected by control flow. Often it is a few long
    strides of instructions connected by a few branches. The decoder will avoid selecting
    instructions that are already included in an existing translated passage. The reason for this
    complexity is that JVM bytecode cannot be rewritten or patched once loaded. For more details, see
    :obj:`JitPassageDecoder`.
     
     
    *********
    Translate
    *********
    
     
    
    The Translate step involves translating the selected passage of instructions. The result of this
    translation implements :obj:`JitCompiledPassage`. For details of this translation process, see
    :obj:`JitCompiler`. The compiled passage provides a list of its entry points. Each is added to
    the emulator's code cache. Among those should be the seed required by this iteration of the
    execution loop, and so that entry point is chosen.
     
     
    *******
    Execute
    *******
    
     
    
    The chosen entry point is then executed. This step is as simple as invoking the
    :meth:`EntryPoint.run() <EntryPoint.run>` method. This, in turn, invokes :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>`,
    providing the entry point's index as an argument. The index identifies to the translated passage
    the desired address of entry, and so it jumps directly to the corresponding translation. That
    translation performs all the equivalent operations of the selected instructions, adhering to any
    control flow within. When control flow exits the passage, the method returns, and the loop
    repeats.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], machine: JitPcodeEmulator):
        """
        Create a thread
         
         
        
        This should only be called by the emulator and its test suites.
        
        :param java.lang.String or str name: the name of the thread
        :param JitPcodeEmulator machine: the machine creating the thread
        """

    def count(self, instructions: typing.Union[jpype.JInt, int], trailingOps: typing.Union[jpype.JInt, int]):
        """
        This is called before each basic block is executed.
         
         
        
        This gives the thread an opportunity to track and control execution, if desired. It provides
        the number of instructions and additional p-code ops about to be completed. If the counts
        exceed a desired schedule, or if the thread is suspended, this method may throw an exception
        to interrupt execution. This can be toggled in the emulator's configuration.
        
        :param jpype.JInt or int instructions: the number of instruction about to be completed
        :param jpype.JInt or int trailingOps: the number of ops of a final partial instruction about to be completed. If
                    the block does not complete any instruction, this is the number of ops continuing
                    in the current (partial) instruction.
        
        .. seealso::
        
            | :obj:`JitConfiguration.emitCounters()`
        """

    def getDecoder(self) -> ghidra.pcode.emu.InstructionDecoder:
        """
        An accessor so the passage decoder can retrieve its thread's instruction decoder.
        
        :return: the decoder
        :rtype: ghidra.pcode.emu.InstructionDecoder
        """

    def getDefaultContext(self) -> ghidra.program.model.listing.ProgramContext:
        """
        An accessor so the passage decoder can query the language's default program context.
        
        :return: the context
        :rtype: ghidra.program.model.listing.ProgramContext
        """

    def getEntry(self, pcCtx: JitPassage.AddrCtx) -> ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint:
        """
        Get the translated and instantiated entry point for the given address and contextreg value.
         
         
        
        An **entry point** is an instance of a class representing a translated passage and an
        index identifying the point at which to enter the passage. In essence, it is an instance of
        an **entry prototype** for this thread.
         
         
        
        This will first check the cache for an existing instance. Then, it will delegate to the
        emulator. The emulator will check its cache for an existing translation. If one is found, we
        simply take it and instantiate it for this thread. Otherwise, the emulator translates a new
        passage at the given seed, and we instantiate it for this thread.
        
        :param JitPassage.AddrCtx pcCtx: the counter and decoder context
        :return: the entry point
        :rtype: ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint
        
        .. seealso::
        
            | :obj:`JitPcodeEmulator.getEntryPrototype(AddrCtx, JitPassageDecoder)`
        """

    def hasEntry(self, pcCtx: JitPassage.AddrCtx) -> bool:
        """
        Check if the *emulator* has an entry prototype for the given address and contextreg
        value.
         
         
        
        This simply passes through to the emulator. It does not matter whether or not this thread has
        instantiated the prototype or not. If any thread has caused the emulator to translate the
        given entry, this will return true.
        
        :param JitPassage.AddrCtx pcCtx: the address and contextreg to check
        :return: true if the emulator has a translation which can be entered at the given pcCtx.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`JitPcodeEmulator.hasEntryPrototype(AddrCtx)`
        """

    def setCounterAndContext(self, counter: ghidra.program.model.address.Address, context: ghidra.program.model.lang.RegisterValue):
        """
        Set the emulator's counter and context without affecting its machine state
        
        :param ghidra.program.model.address.Address counter: the counter
        :param ghidra.program.model.lang.RegisterValue context: the context
        
        .. admonition:: Implementation Note
        
            the reasons for doing this are a bit nuanced and they deal in the setting of the pc
            by p-code ops whilst it also makes hazardous userop invocations. The intended value
            of the pc may not survive if it gets clobbered with the current counter before
            execution reaches the "goto pc".
        """

    def writeCounterAndContext(self, counter: ghidra.program.model.address.Address, context: ghidra.program.model.lang.RegisterValue):
        """
        Write the given counter and context to the emulator and its machine state
        
        :param ghidra.program.model.address.Address counter: the counter
        :param ghidra.program.model.lang.RegisterValue context: the context
        """

    @property
    def entry(self) -> ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint:
        ...

    @property
    def defaultContext(self) -> ghidra.program.model.listing.ProgramContext:
        ...

    @property
    def decoder(self) -> ghidra.pcode.emu.InstructionDecoder:
        ...


class JitDefaultBytesPcodeExecutorState(ghidra.pcode.exec_.DefaultPcodeExecutorState[jpype.JArray[jpype.JByte]], JitBytesPcodeExecutorState):
    """
    The default implementation of :obj:`JitBytesPcodeExecutorState`.
     
     
    
    **NOTE**: This is distinct from :obj:`JitDataFlowState`, which is used during the
    interpretation and analysis of the passage to translate. This state, in contrast, is the concrete
    state of the emulation target, but accessible in special ways to the translation output. In
    particular, the constructor of each translation is permitted direct access to some of this
    state's internals, so that it can pre-fetch, e.g., backing arrays for direct memory access
    operations.
     
     
    
    This is just an extension of :obj:`DefaultPcodeExecutorState` that wraps the corresponding
    :obj:`JitBytesPcodeExecutorStatePiece`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a new state for the given language
        
        :param ghidra.program.model.lang.Language language: the emulation target language
        """



__all__ = ["JitPcodeEmulator", "JitCompiler", "JitPassage", "JitThreadBytesPcodeExecutorState", "JitConfiguration", "JitJvmTypeUtils", "JitBytesPcodeExecutorStatePiece", "JitBytesPcodeExecutorState", "JitPcodeThread", "JitDefaultBytesPcodeExecutorState"]
