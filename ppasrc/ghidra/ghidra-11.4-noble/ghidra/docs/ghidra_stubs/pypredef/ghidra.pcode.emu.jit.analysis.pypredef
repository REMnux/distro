from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.pcode.emu.jit
import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.op
import ghidra.pcode.emu.jit.var
import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.objectweb.asm # type: ignore


T = typing.TypeVar("T")


class JitDataFlowBlockAnalyzer(java.lang.Object):
    """
    An encapsulation of the per-block data flow analysis done by :obj:`JitDataFlowModel`
     
     
    
    One of these is created for each basic block in the passage. This does both the intra-block
    analysis and encapsulates parts of the inter-block analysis. The class also contains and provides
    access to some of the analytic results.
    
    
    .. seealso::
    
        | :obj:`JitDataFlowModel.getAnalyzer(JitBlock)`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getOutput(self, varnode: ghidra.program.model.pcode.Varnode) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Get an ordered list of all values involved in the latest definition of the given varnode.
        
        :param ghidra.program.model.pcode.Varnode varnode: the varnode whose definition(s) to retrieve
        :return: the list of values
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        
        .. seealso::
        
            | :obj:`JitDataFlowState.getDefinitions(Varnode)`
        """

    @typing.overload
    def getOutput(self, register: ghidra.program.model.lang.Register) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Get an ordered list of all values involved in the latest definition of the given register.
        
        :param ghidra.program.model.lang.Register register: the register whose definition(s) to retrieve
        :return: the list of values
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        
        .. seealso::
        
            | :obj:`JitDataFlowState.getDefinitions(Register)`
        """

    def getVar(self, vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Get the latest definition of the given varnode, synthesizing ops is required.
         
         
        
        NOTE: May produce phi nodes that need additional inter-block analysis
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the latest definition for the block analyzed
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        
        .. seealso::
        
            | :obj:`JitDataFlowModel.analyzeInterblock(Collection)`
        
            | :obj:`JitDataFlowState.getVar(AddressSpace, JitVal, int, boolean, Reason)`
        """

    def getVarnodesRead(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        """
        Get a complete catalog of all varnodes read, including overlapping, subregs, etc.
        
        :return: the set of varnodes
        :rtype: java.util.Set[ghidra.program.model.pcode.Varnode]
        """

    def getVarnodesWritten(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        """
        Get a complete catalog of all varnodes written, including overlapping, subregs, etc.
        
        :return: the set of varnodes
        :rtype: java.util.Set[ghidra.program.model.pcode.Varnode]
        """

    @property
    def output(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        ...

    @property
    def varnodesWritten(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def var(self) -> ghidra.pcode.emu.jit.var.JitVal:
        ...

    @property
    def varnodesRead(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...


class JitAnalysisContext(java.lang.Object):
    """
    A collection of state that is shared among several phases of the translation process.
    
    
    .. seealso::
    
        | :obj:`JitCompiler`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, config: ghidra.pcode.emu.jit.JitConfiguration, passage: ghidra.pcode.emu.jit.JitPassage):
        """
        Construct a new context, starting with the given configuration and source passage
        
        :param ghidra.pcode.emu.jit.JitConfiguration config: the JIT compiler's configuration
        :param ghidra.pcode.emu.jit.JitPassage passage: the passage selected for translation
        """

    def getConfiguration(self) -> ghidra.pcode.emu.jit.JitConfiguration:
        """
        Get the JIT compiler configuration
        
        :return: the configuration
        :rtype: ghidra.pcode.emu.jit.JitConfiguration
        """

    def getEndian(self) -> ghidra.program.model.lang.Endian:
        """
        Get the endianness of the translation source, i.e., emulation target.
        
        :return: the endianness
        :rtype: ghidra.program.model.lang.Endian
        """

    def getErrorMessage(self, op: ghidra.program.model.pcode.PcodeOp) -> str:
        """
        Get the error message for a given p-code op
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op generating the error
        :return: the message
        :rtype: str
        
        .. seealso::
        
            | :obj:`JitPassage.getErrorMessage(PcodeOp)`
        """

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        """
        Get the translation source (i.e., emulation target) language
        
        :return: the language
        :rtype: ghidra.app.plugin.processors.sleigh.SleighLanguage
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

    def getPassage(self) -> ghidra.pcode.emu.jit.JitPassage:
        """
        Get the source passage
        
        :return: the passage
        :rtype: ghidra.pcode.emu.jit.JitPassage
        """

    @property
    def opEntry(self) -> ghidra.pcode.emu.jit.JitPassage.AddrCtx:
        ...

    @property
    def passage(self) -> ghidra.pcode.emu.jit.JitPassage:
        ...

    @property
    def configuration(self) -> ghidra.pcode.emu.jit.JitConfiguration:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...

    @property
    def endian(self) -> ghidra.program.model.lang.Endian:
        ...


class JitDataFlowState(ghidra.pcode.exec_.PcodeExecutorState[ghidra.pcode.emu.jit.var.JitVal]):
    """
    An implementation of :obj:`PcodeExecutorState` for per-block data flow interpretation
     
     
    
    In p-code interpretation, this interface's purpose is to store the current value of varnodes in
    the emulation/interpretation state. Here we implement it using ``T:=``:obj:`JitVal`, and
    track the latest variable definition of vanodes in the data flow interpretation. The adaptation
    is fairly straightforward, except when varnode accesses do not match their latest definitions
    exactly, e.g., an access of ``EAX`` when the latest definition is for ``RAX``. Thus, this
    state object may synthesize :obj:`subpiece <JitSynthSubPieceOp>` and :obj:`catenate <JitCatenateOp>` ops to model the "off-cut" use of one or more such definitions. Additionally, in
    preparation for inter-block data flow analysis, when no definition is present for a varnode (or
    part of a varnode) access, this state will synthesize :obj:`phi <JitPhiOp>` ops. See
    :meth:`setVar <.setVar>` and
    :meth:`getVar <.getVar>` for details.
     
     
    
    This state only serves to analyze data flow through register and unique variables. Because we
    know these are only accessible to the thread, we stand to save much execution time by bypassing
    the :obj:`JitBytesPcodeExecutorState` at run time. We can accomplish this by mapping these
    variables to suitable JVM local variables. Thus, we have one map of entries for register space
    and another for unique space. Accesses to other spaces do not mutate or read from either of those
    maps, but this class may generate a suitable :obj:`JitVal` for the use-def graph.
    """

    class MiniDFState(java.lang.Object):
        """
        A minimal data flow machine state that can be captured by a :obj:`JitCallOtherOpIf`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def copy(self) -> JitDataFlowState.MiniDFState:
            """
            Copy this mini state
            
            :return: the copy
            :rtype: JitDataFlowState.MiniDFState
            """

        @typing.overload
        def getDefinitions(self, space: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
            """
            Get an ordered list of all values involved in the latest definition of the given varnode.
             
             
            
            In the simplest case, the list consists of exactly one SSA variable whose varnode exactly
            matches that requested. In other cases, e.g., when only a subregister is defined, the
            list may have several entries, some of which may be :obj:`missing <JitMissingVar>`.
             
             
            
            The list is ordered according to machine endianness. That is for little endian, the
            values are ordered from least to most significant parts of the varnode defined. This is
            congruent with how :meth:`JitDataFlowArithmetic.catenate(Varnode, List) <JitDataFlowArithmetic.catenate>` expects parts to
            be listed.
            
            :param ghidra.program.model.address.AddressSpace space: the address space of the varnode
            :param jpype.JLong or int offset: the offset of the varnode
            :param jpype.JInt or int size: the size in bytes of the varnode
            :return: the list of values
            :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
            """

        @typing.overload
        def getDefinitions(self, varnode: ghidra.program.model.pcode.Varnode) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
            """
            Get an ordered list of all values involved in the latest definition of the given varnode.
            
            :param ghidra.program.model.pcode.Varnode varnode: the varnode whose definitions to retrieve
            :return: the list of values
            :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
            
            .. seealso::
            
                | :obj:`.getDefinitions(AddressSpace, long, int)`
            """

        @typing.overload
        def getDefinitions(self, register: ghidra.program.model.lang.Register) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
            """
            Get an ordered list of all values involved in the latest definition of the given varnode.
            
            :param ghidra.program.model.lang.Register register: the register whose definitions to retrieve
            :return: the list of values
            :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
            
            .. seealso::
            
                | :obj:`.getDefinitions(AddressSpace, long, int)`
            """

        def getVar(self, varnode: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.var.JitVal:
            """
            Get the value of the given varnode
             
             
            
            This is the implementation of
            :meth:`JitDataFlowState.getVar(AddressSpace, JitVal, int, boolean, Reason) <JitDataFlowState.getVar>`, but only for
            uniques and registers.
            
            :param ghidra.program.model.pcode.Varnode varnode: the varnode
            :return: the value
            :rtype: ghidra.pcode.emu.jit.var.JitVal
            """

        def set(self, varnode: ghidra.program.model.pcode.Varnode, val: ghidra.pcode.emu.jit.var.JitVal):
            """
            Set one or more definition entries in the given map for the given varnode to the given
            value
             
             
            
            Ordinary, this just sets the one varnode to the given value; however, if the given value
            is the output of a :obj:`catenation <JitCatenateOp>`, then each input part is entered into
            the map separately, and the synthetic catenation dropped. The behavior avoids nested
            catenations.
            
            :param ghidra.program.model.pcode.Varnode varnode: the varnode
            :param ghidra.pcode.emu.jit.var.JitVal val: the value
            """

        @property
        def var(self) -> ghidra.pcode.emu.jit.var.JitVal:
            ...

        @property
        def definitions(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def captureState(self) -> JitDataFlowState.MiniDFState:
        """
        Capture the current state of intra-block analysis.
         
         
        
        This may be required for follow-up op-use analysis by a :obj:`JitCallOtherOpIf` invoked
        using the standard strategy. All live varnodes *at the time of the call* must be
        considered used.
        
        :return: the captured state
        :rtype: JitDataFlowState.MiniDFState
        """

    @typing.overload
    def getDefinitions(self, varnode: ghidra.program.model.pcode.Varnode) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Get an ordered list of all values involved in the latest definition of the given varnode.
        
        :param ghidra.program.model.pcode.Varnode varnode: the varnode whose definitions to retrieve
        :return: the list of values
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        
        .. seealso::
        
            | :obj:`MiniDFState.getDefinitions(AddressSpace, long, int)`
        """

    @typing.overload
    def getDefinitions(self, register: ghidra.program.model.lang.Register) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Get an ordered list of all values involved in the latest definition of the given varnode.
        
        :param ghidra.program.model.lang.Register register: the register whose definitions to retrieve
        :return: the list of values
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        
        .. seealso::
        
            | :obj:`MiniDFState.getDefinitions(AddressSpace, long, int)`
        """

    def getVarnodesRead(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        """
        Get a complete catalog of all varnodes read, including overlapping, subregs, etc.
        
        :return: the set of varnodes
        :rtype: java.util.Set[ghidra.program.model.pcode.Varnode]
        """

    def getVarnodesWritten(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        """
        Get a complete catalog of all varnodes written, including overlapping, subregs, etc.
        
        :return: the set of varnodes
        :rtype: java.util.Set[ghidra.program.model.pcode.Varnode]
        """

    @property
    def varnodesWritten(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def varnodesRead(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def definitions(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        ...


class JitDataFlowArithmetic(ghidra.pcode.exec_.PcodeArithmetic[ghidra.pcode.emu.jit.var.JitVal]):
    """
    A p-code arithmetic for interpreting p-code and constructing a use-def graph
     
     
    
    This is used for intra-block data flow analysis. We leverage the same API as is used for concrete
    p-code interpretation, but we use it for an abstraction. The type of the interpretation is
    ``T:=``:obj:`JitVal`, which can consist of constants and variables in the use-def graph. The
    arithmetic must be provided to the :obj:`JitDataFlowExecutor`. The intra-block portions of the
    use-def graph are populated as each block is interpreted by the executor.
     
     
    
    The general strategy for each of the arithmetic operations is to 1) generate the output SSA
    variable for the op, 2) generate the op node for the generated output and given inputs, 3) enter
    the op into the use-def graph as the definition of its output, 4) record the inputs and used by
    the new op, and finally 5) return the generated output.
     
     
    
    There should only need to be one of these per data flow model, not per block.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: JitAnalysisContext, dfm: JitDataFlowModel):
        """
        Construct the arithmetic
        
        :param JitAnalysisContext context: the analysis context
        :param JitDataFlowModel dfm: the owning data flow model
        """

    def catenate(self, outVn: ghidra.program.model.pcode.Varnode, parts: java.util.List[ghidra.pcode.emu.jit.var.JitVal]) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Construct the catenation of the given values to form the given output varnode.
         
         
        
        The result is added to the use-def graph. This is used to handle variable retrieval when the
        pattern of accesses indicates catenation. Consider the x86 assembly:
         
         
        MOV AH, byte ptr [...]
        MOV AL, byte ptr [...]
        MOV word ptr [...], AX
         
         
         
        
        On the third line, the value in ``AX`` is the catenation of whatever values were written
        into ``AH`` and ``AL``. Thus, we synthesize a catenation op node in the use-def
        graph.
        
        :param ghidra.program.model.pcode.Varnode outVn: the output varnode
        :param java.util.List[ghidra.pcode.emu.jit.var.JitVal] parts: the list of values to catenate, ordered by machine endianness
        :return: the output value
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        
        .. seealso::
        
            | :obj:`MiniDFState.getDefinitions(AddressSpace, long, int)`
        """

    def shaveFromLeft(self, amt: typing.Union[jpype.JInt, int], in1: ghidra.pcode.emu.jit.var.JitVal) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Remove ``amt`` bytes from the left of the value.
         
         
        
        The value is unaffected by the machine endianness, except to designate the output varnode.
        
        :param jpype.JInt or int amt: the number of bytes to remove
        :param ghidra.pcode.emu.jit.var.JitVal in1: the input
        :return: the output
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def shaveFromRight(self, amt: typing.Union[jpype.JInt, int], in1: ghidra.pcode.emu.jit.var.JitVal) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Remove ``amt`` bytes from the right of the value.
         
         
        
        The value is unaffected by the machine endianness, except to designate the output varnode.
        
        :param jpype.JInt or int amt: the number of bytes to remove
        :param ghidra.pcode.emu.jit.var.JitVal in1: the input
        :return: the output
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def subpiece(self, size: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], v: ghidra.pcode.emu.jit.var.JitVal) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Compute the subpiece of a value.
         
         
        
        The result is added to the use-def graph. The output varnode is computed from the input
        varnode and the subpiece parameters. This is used to handle variable retrieval when an access
        only include parts of a value previously written. Consider the x86 assembly:
         
         
        MOV RAX, qword ptr [...]
        MOV dword ptr [...], EAX
         
         
         
        
        The second line reads ``EAX``, which consists of only the lower part of ``RAX``.
        Thus, we synthesize a subpiece op. These are distinct from an actual :obj:`PcodeOp.SUBPIECE`
        op, since we sometimes needs to filter out synthetic ops.
        
        :param jpype.JInt or int size: the size of the output variable in bytes
        :param jpype.JInt or int offset: the subpiece offset (number of bytes shifted right)
        :param ghidra.pcode.emu.jit.var.JitVal v: the input value
        :return: the output value
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def truncFromLeft(self, in1Vn: ghidra.program.model.pcode.Varnode, amt: typing.Union[jpype.JInt, int], in1: ghidra.pcode.emu.jit.var.JitVal) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Remove ``amt`` bytes from the left of the *varnode*.
         
         
        
        "Left" is considered with respect to the machine endianness. If it is little endian, then the
        byte are shaved from the *right* of the value. This should be used when getting values
        from the state to remove pieces from off-cut values. It should be applied before the pieces
        are ordered according to machine endianness.
        
        :param ghidra.program.model.pcode.Varnode in1Vn: the varnode representing the input
        :param jpype.JInt or int amt: the number of bytes to remove
        :param ghidra.pcode.emu.jit.var.JitVal in1: the input (really a value read from the state)
        :return: the resulting value
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """

    def truncFromRight(self, in1Vn: ghidra.program.model.pcode.Varnode, amt: typing.Union[jpype.JInt, int], in1: ghidra.pcode.emu.jit.var.JitVal) -> ghidra.pcode.emu.jit.var.JitVal:
        """
        Remove ``amt`` bytes from the right of the *varnode*.
         
         
        
        "Right" is considered with respect to the machine endianness. If it is little endian, then
        the byte are shaved from the *left* of the value. This should be used when getting
        values from the state to remove pieces from off-cut values. It should be applied before the
        pieces are ordered according to machine endianness.
        
        :param ghidra.program.model.pcode.Varnode in1Vn: the varnode representing the input
        :param jpype.JInt or int amt: the number of bytes to remove
        :param ghidra.pcode.emu.jit.var.JitVal in1: the input (really a value read from the state)
        :return: the resulting value
        :rtype: ghidra.pcode.emu.jit.var.JitVal
        """


class JitOpUpwardVisitor(JitOpVisitor):
    """
    A visitor that traverses the use-def graph upward, that is from uses toward definitions
    """

    class_: typing.ClassVar[java.lang.Class]


class JitDataFlowModel(java.lang.Object):
    """
    The data flow analysis for JIT-accelerated emulation.
     
     
    
    This implements the Data Flow Analysis phase of the :obj:`JitCompiler`. The result is a use-def
    graph. The graph follows Static Single Assignment (SSA) form, in that each definition of a
    variable, even if it's at the same address as a previous definition, is given a unique
    identifier. The graph is bipartite with :obj:`ops <JitOp>` on one side and :obj:`values <JitVal>`
    on the other. Please node the distinction between a *varnode* and a *variable* in
    this context. A *varnode* refers to the address and size in the machine's state. For
    better or for worse, this is often referred to as a "variable" in other contexts. A
    *variable* in the SSA sense is a unique "instance" of a varnode with precisely one
    *definition*. Consider the following x86 assembly:
     
     
    MOV RAX, qword ptr [...]
    ADD RAX, RDX
    MOV qword ptr [...], RAX
     
     
     
    
    Ignoring RAM, there are two varnodes at play, named for the registers they represent: ``RAX``
    and ``RDX``. However, there are three variables. The first is an instance of ``RAX``,
    defined by the first ``MOV`` instruction. The second is an instance of ``RDX``, which is
    implicitly defined as an input to the passage. The third is another instance of ``RAX``,
    defined by the ``ADD`` instruction. These could be given unique names
    ``RAX``, ``RDX``, and ``RAX``, respectively.
    Thus, the ``ADD`` instruction uses ``RAX`` and ``RDX``, to
    define ``RAX``. The last ``MOV`` instruction uses ``RAX``. If
    we plot each instruction and variable in a graph, drawing edges for each use and definition, we
    get a use-def graph.
     
     
    
    Our analysis produces a use-def graph for the passage's p-code (not instructions) in two steps:
    First, we analyze each basic block independently. There are a lot of nuts and bolts in the
    implementation, but the analysis is achieved by straightforward interpretation of each block's
    p-code ops. Second, we connect the blocks' use-def graphs together using phi nodes where
    appropriate, according to the control flow.
     
     
    ********************
    Intra-block analysis
    ********************
    
     
    
    For each block, we create a p-code interpreter consisting of a :obj:`JitDataFlowState` and
    :obj:`JitDataFlowExecutor`. Both are given this model's :obj:`JitDataFlowArithmetic`, which
    populates the use-def graph. We then feed the block's p-code into the executor. The block gets a
    fresh :obj:`JitDataFlowState`, so that its result has no dependency on the interpretation of any
    other block, except in the numbering of variable identifiers; those must be unique across the
    model.
     
     
    
    During interpretation, varnode accesses generate value nodes. When a constant varnode is
    accessed, it simply creates a :obj:`JitConstVal`. When an op produces an output, it generates a
    :obj:`JitOutVar` and places it into the interpreter's :obj:`state <JitDataFlowState>` for its
    varnode. When a varnode is read, the interpreter examines its state for the last definition. If
    one is found, the variable is returned, its use noted, and nothing new is generated. Otherwise, a
    :obj:`JitMissingVar` is generated. Note that the interpreter does not track memory variables in
    its state, because the JIT translator does not seek to optimize these. At run time, such accesses
    will affect the emulator's state immediately. Registers and Sleigh uniques, on the other hand,
    are allocated as JVM locals, so we must know how they are used and defined. Direct memory
    accesses generate :obj:`JitDirectMemoryVar` and :obj:`JitMemoryOutVar`. Indirect memory
    accesses are denoted by the :obj:`load <JitLoadOp>` and :obj:`store <JitStoreOp>` op nodes, not as
    variables. There is a dummy :obj:`JitIndirectMemoryVar` singleton, so that the state can return
    something when the memory address is not fixed.
     
     
    ********************
    Inter-block analysis
    ********************
    
     
    
    Up to this point, each block's use-def sub-graph is disconnected from the others'. We define each
    :obj:`missing <JitMissingVar>` variable generated during block interpretation as a :obj:`phi <JitPhiOp>` op. A phi op is said to belong to the block that generated the missing variable. We seek
    options for the phi op by examining the block's inward flows. For each source block, we check the
    most recent definition of the sought varnode. If one is present, the option is added to the phi
    op. Otherwise, we create an option by generating another phi op and taking its output. The new
    phi op belongs to the source block, and we recurse to seek its options. If a cycle is
    encountered, or we encounter a block with no inward flows, we do not recurse. An
    :obj:`input <JitInputVar>` variable is generated whenever we encounter a passage entry, indicating
    the variable could be defined outside the passage.
    
     
    
    Note that the resulting phi ops may not adhere precisely to the formal definition of *phi
    node*. A phi op may have only one option. The recursive part of the option seeking algorithm
    generates chains of phi ops such that an option must come from an immediately upstream block,
    even if that block does not offer a direct definition. This may produce long chains when a
    varnode use is several block flows removed from a possible definition. We had considered
    simplifying/removing single-option phi ops afterward, but we found it too onerous, and the output
    bytecode is not improved. We do not generate bytecode for phi ops; they are synthetic and only
    used for analysis.
    """

    @typing.type_check_only
    class ValCollector(java.util.HashSet[ghidra.pcode.emu.jit.var.JitVal], JitOpUpwardVisitor):
        """
        An upward graph traversal for collecting all values in the use-def graph.
        
        
        .. seealso::
        
            | :obj:`.allValues()`
        
            | :obj:`.allValuesSorted()`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class GraphvizExporter(JitOpUpwardVisitor):
        """
        A diagnostic tool for visualizing the use-def graph.
         
         
        
        NOTE: This is only as complete as it needed to be for me to diagnose whatever issue I was
        having at the time.
        
        
        .. seealso::
        
            | :obj:`.exportGraphviz(File)`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, outFile: jpype.protocol.SupportsPath):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: JitAnalysisContext, cfm: JitControlFlowModel):
        """
        Construct the data flow model.
         
         
        
        Analysis is performed as part of constructing the model.
        
        :param JitAnalysisContext context: the analysis context
        :param JitControlFlowModel cfm: the control flow model
        """

    def allValues(self) -> java.util.Set[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Get all values (and variables) in the use-def graph
        
        :return: the set of values
        :rtype: java.util.Set[ghidra.pcode.emu.jit.var.JitVal]
        """

    def allValuesSorted(self) -> java.util.List[ghidra.pcode.emu.jit.var.JitVal]:
        """
        Same as :meth:`allValues() <.allValues>`, but sorted by ID with constants at the top
        
        :return: the list of values
        :rtype: java.util.List[ghidra.pcode.emu.jit.var.JitVal]
        """

    def dumpResult(self):
        """
        For diagnostics: Dump the analysis result to stderr
        
        
        .. seealso::
        
            | :obj:`Diag.PRINT_DFM`
        """

    def dumpSynth(self):
        """
        For diagnostics: Dump the synthetic ops to stderr
        
        
        .. seealso::
        
            | :obj:`Diag.PRINT_SYNTH`
        """

    def exportGraphviz(self, file: jpype.protocol.SupportsPath):
        """
        Generate a graphviz .dot file to visualize the use-def graph.
         
         
        
        **WARNING:** This is an internal diagnostic that is only as complete as it needed to be.
        
        :param jpype.protocol.SupportsPath file: the output file
        """

    def generateDirectMemoryVar(self, vn: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.var.JitDirectMemoryVar:
        """
        Generate a variable representing a direct memory access
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode, which ought to be neither register nor unique
        :return: the variable
        :rtype: ghidra.pcode.emu.jit.var.JitDirectMemoryVar
        """

    def generateIndirectMemoryVar(self, space: ghidra.program.model.address.AddressSpace, offset: ghidra.pcode.emu.jit.var.JitVal, size: typing.Union[jpype.JInt, int], quantize: typing.Union[jpype.JBoolean, bool]) -> ghidra.pcode.emu.jit.var.JitIndirectMemoryVar:
        """
        Generate a variable representing an indirect memory access
        
        :param ghidra.program.model.address.AddressSpace space: the address space containing the variable, which out to be neither register nor
                    unique
        :param ghidra.pcode.emu.jit.var.JitVal offset: another variable describing the (dynamic) offset of the variable in the given
                    space
        :param jpype.JInt or int size: the number of bytes in the variable
        :param jpype.JBoolean or bool quantize: true if the offset should be quantized (as in
                    :meth:`getVar <PcodeExecutorState.getVar>`).
        :return: the variable
        :rtype: ghidra.pcode.emu.jit.var.JitIndirectMemoryVar
        
        .. admonition:: Implementation Note
        
            because the load and store ops already encode these details (except maybe
            ``quantize``), this just returns a dummy instance.
        
        
        
        .. seealso::
        
            | :obj:`JitIndirectMemoryVar`
        
            | :obj:`JitLoadOp`
        
            | :obj:`JitStoreOp`
        """

    def generateOutVar(self, out: ghidra.program.model.pcode.Varnode) -> ghidra.pcode.emu.jit.var.JitOutVar:
        """
        Generate a new op output variable for eventual placement in the use-def graph
        
        :param ghidra.program.model.pcode.Varnode out: the varnode describing the corresponding :obj:`PcodeOp`'s
                    :meth:`output <PcodeOp.getOutput>`.
        :return: the generated variable
        :rtype: ghidra.pcode.emu.jit.var.JitOutVar
        
        .. seealso::
        
            | :obj:`JitDataFlowModel`
        """

    def getAnalyzer(self, block: JitControlFlowModel.JitBlock) -> JitDataFlowBlockAnalyzer:
        """
        Get the per-block data flow analyzer for the given basic block
        
        :param JitControlFlowModel.JitBlock block: the block
        :return: the analyzer
        :rtype: JitDataFlowBlockAnalyzer
        """

    def getArithmetic(self) -> JitDataFlowArithmetic:
        """
        Get the model's arithmetic that places p-code ops into the use-def graph
        
        :return: the arithmetic
        :rtype: JitDataFlowArithmetic
        """

    def getJitOp(self, op: ghidra.program.model.pcode.PcodeOp) -> ghidra.pcode.emu.jit.op.JitOp:
        """
        Get the use-def op node for the given p-code op
         
         
        
        NOTE: When used in testing, if the passage is manufactured from a :obj:`PcodeProgram`, the
        decoder will re-write the p-code ops as :obj:`DecodedPcodeOp`s. Be sure to pass an op to
        this method that comes from the resulting :obj:`JitPassage`, not the original program, or
        else this method will certainly return ``null``.
        
        :param ghidra.program.model.pcode.PcodeOp op: the p-code op from the source passage
        :return: the node from the use-def graph, if present, or ``null``
        :rtype: ghidra.pcode.emu.jit.op.JitOp
        """

    def getLibrary(self) -> JitDataFlowUseropLibrary:
        """
        Get a wrapper library that places userop calls into the use-def graph
        
        :return: the library
        :rtype: JitDataFlowUseropLibrary
        """

    def notifyOp(self, op: T) -> T:
        """
        Add the given :obj:`JitOp` to the use-def graph
        
        :param T: the type of the node:param T op: the op
        :return: the same op
        :rtype: T
        
        .. seealso::
        
            | :obj:`JitDataFlowModel`
        """

    def phiNodes(self) -> java.util.List[ghidra.pcode.emu.jit.op.JitPhiOp]:
        """
        Get all the phi nodes in the use-def graph.
        
        :return: the list of phi nodes
        :rtype: java.util.List[ghidra.pcode.emu.jit.op.JitPhiOp]
        """

    def synthNodes(self) -> java.util.List[ghidra.pcode.emu.jit.op.JitSyntheticOp]:
        """
        Get all the synthetic op nodes in the use-def graph.
        
        :return: the list of synthetic op nodes
        :rtype: java.util.List[ghidra.pcode.emu.jit.op.JitSyntheticOp]
        """

    @property
    def jitOp(self) -> ghidra.pcode.emu.jit.op.JitOp:
        ...

    @property
    def library(self) -> JitDataFlowUseropLibrary:
        ...

    @property
    def analyzer(self) -> JitDataFlowBlockAnalyzer:
        ...

    @property
    def arithmetic(self) -> JitDataFlowArithmetic:
        ...


class JitAllocationModel(java.lang.Object):
    """
    Type variable allocation phase for JIT-accelerated emulation.
     
     
    
    The implements the Variable Allocation phase of the :obj:`JitCompiler` using a very simple
    placement and another "voting" algorithm to decide the allocated JVM variable types. We place/map
    variables by their storage varnodes, coalescing them as needed. Coalescing is performed for
    overlapping, but not abutting varnodes. This allocation is anticipated by the
    :obj:`JitVarScopeModel`, which performs the actual coalescing. Because multiple SSA variables
    will almost certainly occupy the same varnode, we employ another voting system. For example, the
    register ``RAX`` may be re-used many times within a passage. In some cases, it might be used
    to return a floating-point value. In others (and *probably* more commonly) it will be used
    to return an integral value. The more common case in the passage determines the JVM type of the
    local variable allocated for ``RAX``. Note that variables which occupy only part of a
    coalesced varnode always vote for a JVM ``int``, because of the shifting and masking required
    to extract that part.
     
     
    
    The allocation process is very simple, presuming successful type assignment:
     
     
    1. Vote Tabulation
    2. Index Reservation
    3. Handler Creation
    
     
     
    ***************
    Vote Tabulation
    ***************
    
     
    
    Every SSA variable (excluding constants and memory variables) contributes a vote for the type of
    its allocated local. If the varnode matches exactly, the vote is for the JVM type of the
    variable's assigned p-code type. The type mapping is simple: For integral types, we allocate
    using the smaller JVM type that fits the p-code type. For floating-point types, we allocate using
    the JVM type that exactly matches the p-code type. If the varnode is larger, i.e., because it's
    the result of coalescing, then the vote is for the smaller JVM integer type that fits the full
    varnode. Consider the following p-code:
     
     
    1. RAX = FLOAT_ADD RCX, RDX
    2. EAX = FLOAT_ADD EBX, 0x3f800000:4 # 1.0f
     
     
     
    
    Several values and variables are at play here. We tabulate the type assignments and resulting
    votes:
     
     
    +------------------+----------------------------------+---------+------------+
    |     SSA Var      |               Type               | Varnode |    Vote    |
    +==================+==================================+=========+============+
    |``RCX``           |:obj:`float8 <DoubleJitType.F8>`  |``RCX``  |``double``  |
    +------------------+----------------------------------+---------+------------+
    |``RDX``           |:obj:`float8 <DoubleJitType.F8>`  |``RDX``  |``double``  |
    +------------------+----------------------------------+---------+------------+
    |``RAX``           |:obj:`float8 <DoubleJitType.F8>`  |``RAX``  |``double``  |
    +------------------+----------------------------------+---------+------------+
    |``EBX``           |:obj:`float4 <FloatJitType.F4>`   |``EBX``  |``float``   |
    +------------------+----------------------------------+---------+------------+
    |``0x3f800000:4``  |:obj:`float4 <FloatJitType.F4>`   |
    +------------------+----------------------------------+---------+------------+
    |``EAX``           |:obj:`float4 <FloatJitType.F4>`   |``RAX``  |``long``    |
    +------------------+----------------------------------+---------+------------+
    
     
    The registers ``RCX``, ``RDX``, and ``EBX`` are trivially allocated as locals of JVM
    types ``double``, ``double``, and ``float``, respectively. It is also worth noting
    that ``0x3f800000`` is allocated as a ``float`` constant in the classfile's constant
    pool. Now, we consider ``RAX``. The varnodes for ``RAX`` and
    ``EAX`` are coalesced to ``RAX``. ``RAX`` casts its vote for
    ``double``; whereas, ``EAX`` casts its vote for ``long``. This is because
    placing ``EAX``'s value into the larger varnode requires bitwise operators, which
    on the JVM, require integer operands. Thus the votes result in a tie, and favoring integral
    types, we allocate ``RAX`` in a JVM ``long``.
     
     
    *****************
    Index Reservation
    *****************
    
     
    
    After all the votes have been tabulated, we go through the results in address order, reserving
    JVM local indices and assigning types. Note that we must reserve two indices for every variable
    of type ``long`` or ``double``, as specific by the JVM. Each of these reservations is
    tracked in a :obj:`JvmLocal`. Note that index 0 is already reserved by the JVM for the
    ``this`` ref, so we start our counting at 1. Also, some portions of the code generator may
    need to allocate additional temporary locals, so we must allow access to the next free index
    after all reservations are complete.
     
     
    ****************
    Handler Creation
    ****************
    
     
    
    This actually extends a little beyond allocation, but this is a suitable place for it: All SSA
    values are assigned a handler, including constants and memory variables. Variables which access
    the same varnode get the same handler. For varnodes that are allocated in a JVM local, we create
    a handler that generates loads and stores to that local, e.g., :obj:`iload <Opcodes.ILOAD>`. For
    constant varnodes, we create a handler that generates :obj:`ldc <Opcodes.LDC>` instructions. For
    memory varnodes, we create a handler that generates a sequence of method invocations on the
    :obj:`state <JitBytesPcodeExecutorState>`. The code generator will delegate to these handlers in
    order to generate reads and writes of the corresponding variables, as well as to prepare any
    resources to facilitate access, e.g., pre-fetching items from the
    :obj:`state <JitBytesPcodeExecutorState>` in the generated constructor.
    
    
    .. admonition:: Implementation Note
    
        There are many artifacts below that anticipate supporting p-code types greater than 8
        bytes in size. One method to support that is to allocate multiple JVM locals per p-code
        varnode. Consider a 16-byte (128-bit) integer. We could allocate 4 JVM ``int``
        locals and then emit bytecode that performs the gradeschool-style arithmetic. I suspect
        this would perform better than just using refs to :obj:`BigInteger`, because it avoids
        heap pollution, and also may avoid some unnecessary arithmetic, esp., for the more
        significant portions that get dropped.
    
    
    
    .. admonition:: Implementation Note
    
        **TODO**: It would be nice to detect varnode re-use under a different type and
        generate the appropriate declarations and handlers. This doesn't seem terribly complex,
        and it stands to spare us some casts. What's not clear is whether this offers any real
        run-time benefit.
    """

    class JvmLocal(java.lang.Record):
        """
        An allocated JVM local
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, index: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], type: JitType.SimpleJitType, vn: ghidra.program.model.pcode.Varnode):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def generateBirthCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to bring this varnode into scope.
             
             
            
            This will copy the value from the :obj:`state <JitBytesPcodeExecutorState>` into the local
            variable.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def generateDeclCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, start: org.objectweb.asm.Label, end: org.objectweb.asm.Label, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode at the top of the :meth:`run <JitCompiledPassage.run>` method.
             
             
            
            This will declare all of the allocated locals for the entirety of the method.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param org.objectweb.asm.Label start: a label at the top of the method
            :param org.objectweb.asm.Label end: a label at the end of the method
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the run method
            """

        def generateInitCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, iv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode into the class constructor.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param org.objectweb.asm.MethodVisitor iv: the visitor for the class constructor
            """

        def generateLoadCode(self, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to load the varnode's value onto the JVM stack.
            
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def generateRetireCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to take this varnode out of scope.
             
             
            
            This will copy the value from the local variable into the
            :obj:`state <JitBytesPcodeExecutorState>`.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`JitCompiledPassage.run(int) <JitCompiledPassage.run>` method
            """

        def generateStoreCode(self, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to store the value on the JVM stack into the varnode.
            
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def hashCode(self) -> int:
            ...

        def index(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> JitType.SimpleJitType:
            ...

        def vn(self) -> ghidra.program.model.pcode.Varnode:
            ...


    class VarHandler(java.lang.Object):
        """
        A handler that knows how to load and store variable values onto and from the JVM stack.
        """

        class_: typing.ClassVar[java.lang.Class]

        def generateDeclCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, start: org.objectweb.asm.Label, end: org.objectweb.asm.Label, rv: org.objectweb.asm.MethodVisitor):
            """
            If needed, emit bytecode at the top of the :meth:`run <JitCompiledPassage.run>`
            method.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param org.objectweb.asm.Label start: a label at the top of the method
            :param org.objectweb.asm.Label end: a label at the end of the method
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the run method
            """

        def generateInitCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, iv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode into the class constructor.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param org.objectweb.asm.MethodVisitor iv: the visitor for the class constructor
            """

        def generateLoadCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: JitType, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to load the varnode's value onto the JVM stack.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param JitType type: the p-code type of the value expected on the JVM stack by the proceeding
                        bytecode
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def generateStoreCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: JitType, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to load the varnode's value onto the JVM stack.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param JitType type: the p-code type of the value produced on the JVM stack by the preceding
                        bytecode
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            """

        def type(self) -> JitType:
            """
            Get the p-code type of the variable this handler handles.
            
            :return: the type
            :rtype: JitType
            """


    class OneLocalVarHandler(JitAllocationModel.VarHandler):
        """
        A handler for p-code variables composed of a single JVM local variable.
        """

        class_: typing.ClassVar[java.lang.Class]

        def local(self) -> JitAllocationModel.JvmLocal:
            """
            Get the local variable into which this p-code variable is allocated
            
            :return: the local
            :rtype: JitAllocationModel.JvmLocal
            """


    class IntVarAlloc(java.lang.Record, JitAllocationModel.OneLocalVarHandler):
        """
        The handler for a p-code variable allocated in one JVM ``int``.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, local: JitAllocationModel.JvmLocal, type: JitType.IntJitType):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def local(self) -> JitAllocationModel.JvmLocal:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> JitType.IntJitType:
            ...


    class LongVarAlloc(java.lang.Record, JitAllocationModel.OneLocalVarHandler):
        """
        The handler for a p-code variable allocated in one JVM ``long``.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, local: JitAllocationModel.JvmLocal, type: JitType.LongJitType):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def local(self) -> JitAllocationModel.JvmLocal:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> JitType.LongJitType:
            ...


    class FloatVarAlloc(java.lang.Record, JitAllocationModel.OneLocalVarHandler):
        """
        The handler for a p-code variable allocated in one JVM ``float``.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, local: JitAllocationModel.JvmLocal, type: JitType.FloatJitType):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def local(self) -> JitAllocationModel.JvmLocal:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> JitType.FloatJitType:
            ...


    class DoubleVarAlloc(java.lang.Record, JitAllocationModel.OneLocalVarHandler):
        """
        The handler for a p-code variable allocated in one JVM ``double``.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, local: JitAllocationModel.JvmLocal, type: JitType.DoubleJitType):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def local(self) -> JitAllocationModel.JvmLocal:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> JitType.DoubleJitType:
            ...


    class MultiLocalPart(java.lang.Record):
        """
        A portion of a multi-local variable handler.
         
         
        
        This portion is allocated in a JVM local. When loading with a positive shift, the value is
        shifted to the right to place it into position.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, local: JitAllocationModel.JvmLocal, shift: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def generateLoadCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: JitType, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to load the value from this local and position it in a value on the JVM
            stack.
             
             
            
            If multiple parts are to be combined, the caller should emit a bitwise or after all loads
            but the first.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param JitType type: the p-code type of the value expected on the stack by the proceeding
                        bytecode, which may be to load additional parts
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            
            .. admonition:: Implementation Note
            
                We must keep temporary values in a variable of the larger of the local's or the
                expected type, otherwise bits may get dropped while positioning the value.
            """

        def generateStoreCode(self, gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator, type: JitType, rv: org.objectweb.asm.MethodVisitor):
            """
            Emit bytecode to extract this part from the value on the JVM stack and store it in the
            local variable.
             
             
            
            If multiple parts are to be stored, the caller should emit a :obj:`dup <Opcodes.DUP>` or
            :obj:`dup2 <Opcodes.DUP2>` before all stores but the last.
            
            :param ghidra.pcode.emu.jit.gen.JitCodeGenerator gen: the code generator
            :param JitType type: the p-code type of the value expected on the stack by the proceeding
                        bytecode, which may be to load additional parts
            :param org.objectweb.asm.MethodVisitor rv: the visitor for the :meth:`run <JitCompiledPassage.run>` method
            
            .. admonition:: Implementation Note
            
                We must keep temporary values in a variable of the larger of the local's or the
                expected type, otherwise bits may get dropped while positioning the value.
            """

        def hashCode(self) -> int:
            ...

        def local(self) -> JitAllocationModel.JvmLocal:
            ...

        def shift(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class MultiLocalVarHandler(java.lang.Record, JitAllocationModel.VarHandler):
        """
        The handler for a variable allocated in a composition of locals
        
         
        
        This can also handle a varnode that is a subpiece of a local variable allocated for a larger
        varnode. For example, this may handle ``EAX``, when we have allocated a ``long`` to
        hold all of ``RAX``.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parts: java.util.List[JitAllocationModel.MultiLocalPart], type: JitType):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def parts(self) -> java.util.List[JitAllocationModel.MultiLocalPart]:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> JitType:
            ...


    class NoHandler(java.lang.Enum[JitAllocationModel.NoHandler], JitAllocationModel.VarHandler):
        """
        A dummy handler for values/variables that are not allocated in JVM locals
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[JitAllocationModel.NoHandler]
        """
        Singleton
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitAllocationModel.NoHandler:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitAllocationModel.NoHandler]:
            ...


    @typing.type_check_only
    class VarDesc(java.lang.Record):
        """
        The descriptor of a p-code variable
         
         
        
        This is just a logical grouping of a varnode and its assigned p-code type.
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def language(self) -> ghidra.program.model.lang.Language:
            ...

        def name(self) -> str:
            """
            Derive a name for this variable, to use in the name of allocated local(s)
            
            :return: the name
            :rtype: str
            """

        def offset(self) -> int:
            ...

        def size(self) -> int:
            ...

        def spaceId(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def toVarnode(self) -> ghidra.program.model.pcode.Varnode:
            """
            Convert this descriptor back to a varnode
            
            :return: the varnode
            :rtype: ghidra.program.model.pcode.Varnode
            """

        def type(self) -> JitType:
            ...


    class FixedLocal(java.lang.Object):
        """
        A local that is always allocated in its respective method
        """

        class_: typing.ClassVar[java.lang.Class]

        def generateDeclCode(self, mv: org.objectweb.asm.MethodVisitor, nameThis: typing.Union[java.lang.String, str], startLocals: org.objectweb.asm.Label, endLocals: org.objectweb.asm.Label):
            """
            Generate the declaration of this variable.
             
             
            
            This is not required, but is nice to have when debugging generated code.
            
            :param org.objectweb.asm.MethodVisitor mv: the method visitor
            :param java.lang.String or str nameThis: the name of the class defining the containing method
            :param org.objectweb.asm.Label startLocals: the start label which should be placed at the top of the method
            :param org.objectweb.asm.Label endLocals: the end label which should be placed at the bottom of the method
            """

        def generateLoadCode(self, mv: org.objectweb.asm.MethodVisitor):
            """
            Generate a load of this variable onto the JVM stack.
            
            :param org.objectweb.asm.MethodVisitor mv: the method visitor
            """

        def generateStoreCode(self, mv: org.objectweb.asm.MethodVisitor):
            """
            Generate a store to this variable from the JVM stack.
            
            :param org.objectweb.asm.MethodVisitor mv: the method visitor
            """

        def index(self) -> int:
            """
            The JVM index of the local
            
            :return: the index
            :rtype: int
            """

        def opcodeLoad(self) -> int:
            """
            The JVM opcode used to load the variable
            
            :return: the load opcode
            :rtype: int
            """

        def opcodeStore(self) -> int:
            """
            The JVM opcode used to store the variable
            
            :return: the store opcode
            :rtype: int
            """

        def typeDesc(self, nameThis: typing.Union[java.lang.String, str]) -> str:
            """
            A JVM type descriptor for the local
            
            :param java.lang.String or str nameThis: the name of this class, in case it's the this pointer.
            :return: the type descriptor
            :rtype: str
            """

        def varName(self) -> str:
            """
            The name of the local
            
            :return: the name
            :rtype: str
            """


    class InitFixedLocal(java.lang.Enum[JitAllocationModel.InitFixedLocal], JitAllocationModel.FixedLocal):
        """
        Locals that exist in every compiled passage's constructor.
        """

        class_: typing.ClassVar[java.lang.Class]
        THIS: typing.Final[JitAllocationModel.InitFixedLocal]
        """
        Because we're compiling a non-static method, the JVM reserves index 0 for ``this``.
        """

        THREAD: typing.Final[JitAllocationModel.InitFixedLocal]
        """
        The parameter ``thread`` is reserved by the JVM into index 1.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitAllocationModel.InitFixedLocal:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitAllocationModel.InitFixedLocal]:
            ...


    class RunFixedLocal(java.lang.Enum[JitAllocationModel.RunFixedLocal], JitAllocationModel.FixedLocal):
        """
        Locals that exist in every compiled passage's :meth:`run <JitCompiledPassage.run>` method.
        """

        class_: typing.ClassVar[java.lang.Class]
        THIS: typing.Final[JitAllocationModel.RunFixedLocal]
        """
        Because we're compiling a non-static method, the JVM reserves index 0 for ``this``.
        """

        BLOCK_ID: typing.Final[JitAllocationModel.RunFixedLocal]
        """
        The parameter ``blockId`` is reserved by the JVM into index 1.
        """

        CTXMOD: typing.Final[JitAllocationModel.RunFixedLocal]
        """
        We declare a local variable to indicate that a context-modifying userop has been invoked.
        """

        ALL: typing.Final[java.util.List[JitAllocationModel.FixedLocal]]
        """
        All of the runtime locals
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitAllocationModel.RunFixedLocal:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitAllocationModel.RunFixedLocal]:
            ...


    @typing.type_check_only
    class TypeContest(java.lang.Record):
        """
        A content for assigning a type to a varnode
         
         
        
        Because several SSA variables can share one varnode, we let each cast a vote to determine the
        JVM type of the local(s) allocated to it.
        
        
        .. admonition:: Implementation Note
        
            **TODO**: This type contest could receive more detailed information from the
            type model, but perhaps that's more work than it's worth. I would have to
            communicate all votes, not just the winner....
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            """
            Start a new contest
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def map(self) -> java.util.Map[JitType, java.lang.Integer]:
            ...

        def toString(self) -> str:
            ...

        def vote(self, type: JitType):
            """
            Cast a vote for the given type
            
            :param JitType type: the type
            """

        def winner(self) -> JitType:
            """
            Choose the winner, favoring integral types
            
            :return: the winning type
            :rtype: JitType
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: JitAnalysisContext, dfm: JitDataFlowModel, vsm: JitVarScopeModel, tm: JitTypeModel):
        """
        Construct the allocation model.
        
        :param JitAnalysisContext context: the analysis context
        :param JitDataFlowModel dfm: the data flow moel
        :param JitVarScopeModel vsm: the variable scope model
        :param JitTypeModel tm: the type model
        """

    def allLocals(self) -> java.util.Collection[JitAllocationModel.JvmLocal]:
        """
        Get all of the locals allocated
        
        :return: the locals
        :rtype: java.util.Collection[JitAllocationModel.JvmLocal]
        """

    def getHandler(self, v: ghidra.pcode.emu.jit.var.JitVal) -> JitAllocationModel.VarHandler:
        """
        Get the handler for the given value (constant or variable in the use-def graph)
        
        :param ghidra.pcode.emu.jit.var.JitVal v: the value
        :return: the handler
        :rtype: JitAllocationModel.VarHandler
        """

    def localsForVn(self, vn: ghidra.program.model.pcode.Varnode) -> java.util.Collection[JitAllocationModel.JvmLocal]:
        """
        Get all of the locals allocated for the given varnode
        
        
        .. admonition:: Implementation Note
        
            This is used by the code generator to birth and retire the local variables, given
            that scope is analyzed in terms of varnodes.
        
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the locals
        :rtype: java.util.Collection[JitAllocationModel.JvmLocal]
        """

    def nextFreeLocal(self) -> int:
        """
        Get the next free local index without reserving it
         
         
        
        This should be used by operator code generators *after* all the
        :obj:`state <JitBytesPcodeExecutorState>` bypassing local variables have been allocated. The
        variables should be scoped to that operator only, so that the ids used are freed for the next
        operator.
        
        :return: the next id
        :rtype: int
        """

    @property
    def handler(self) -> JitAllocationModel.VarHandler:
        ...


class JitOpVisitor(java.lang.Object):
    """
    A visitor for traversing the use-def graph
     
     
    
    The default implementations here do nothing other than discern the type of an op and variable and
    dispatch the invocations appropriately. To traverse the graph upward, consider
    :obj:`JitOpUpwardVisitor`. Note no "downward" visitor is currently provided, because it was not
    needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def visitBinOp(self, binOp: ghidra.pcode.emu.jit.op.JitBinOp):
        """
        Visit a :obj:`JitBinOp`
        
        :param ghidra.pcode.emu.jit.op.JitBinOp binOp: the op visited
        """

    def visitBranchIndOp(self, branchIndOp: ghidra.pcode.emu.jit.op.JitBranchIndOp):
        """
        Visit a :obj:`JitBranchIndOp`
        
        :param ghidra.pcode.emu.jit.op.JitBranchIndOp branchIndOp: the op visited
        """

    def visitBranchOp(self, branchOp: ghidra.pcode.emu.jit.op.JitBranchOp):
        """
        Visit a :obj:`JitBranchOp`
        
        :param ghidra.pcode.emu.jit.op.JitBranchOp branchOp: the op visited
        """

    def visitCBranchOp(self, cBranchOp: ghidra.pcode.emu.jit.op.JitCBranchOp):
        """
        Visit a :obj:`JitCBranchOp`
        
        :param ghidra.pcode.emu.jit.op.JitCBranchOp cBranchOp: the op visited
        """

    def visitCallOtherDefOp(self, otherOp: ghidra.pcode.emu.jit.op.JitCallOtherDefOp):
        """
        Visit a :obj:`JitCallOtherDefOp`
        
        :param ghidra.pcode.emu.jit.op.JitCallOtherDefOp otherOp: the op visited
        """

    def visitCallOtherMissingOp(self, otherOp: ghidra.pcode.emu.jit.op.JitCallOtherMissingOp):
        """
        Visit a :obj:`JitCallOtherMissingOp`
        
        :param ghidra.pcode.emu.jit.op.JitCallOtherMissingOp otherOp: the op visited
        """

    def visitCallOtherOp(self, otherOp: ghidra.pcode.emu.jit.op.JitCallOtherOp):
        """
        Visit a :obj:`JitCallOtherOp`
        
        :param ghidra.pcode.emu.jit.op.JitCallOtherOp otherOp: the op visited
        """

    def visitCatenateOp(self, catOp: ghidra.pcode.emu.jit.op.JitCatenateOp):
        """
        Visit a :obj:`JitCatenateOp`
        
        :param ghidra.pcode.emu.jit.op.JitCatenateOp catOp: the op visited
        """

    def visitConstVal(self, constVal: ghidra.pcode.emu.jit.var.JitConstVal):
        """
        Visit a :obj:`JitConstVal`
        
        :param ghidra.pcode.emu.jit.var.JitConstVal constVal: the value visited
        """

    def visitDirectMemoryVar(self, dirMemVar: ghidra.pcode.emu.jit.var.JitDirectMemoryVar):
        """
        Visit a :obj:`JitDirectMemoryVar`
        
        :param ghidra.pcode.emu.jit.var.JitDirectMemoryVar dirMemVar: the variable visited
        """

    def visitFailVal(self, failVal: ghidra.pcode.emu.jit.var.JitFailVal):
        """
        Visit a :obj:`JitFailVal`
        
        :param ghidra.pcode.emu.jit.var.JitFailVal failVal: the value visited
        """

    def visitIndirectMemoryVar(self, indMemVar: ghidra.pcode.emu.jit.var.JitIndirectMemoryVar):
        """
        Visit a :obj:`JitIndirectMemoryVar`
         
         
        
        NOTE: These should not ordinarily appear in the use-def graph. There is only the one
        :obj:`JitIndirectMemoryVar.INSTANCE`, and it's used as a temporary dummy. Indirect memory
        access is instead modeled by the :obj:`JitLoadOp`.
        
        :param ghidra.pcode.emu.jit.var.JitIndirectMemoryVar indMemVar: the variable visited
        """

    def visitInputVar(self, inputVar: ghidra.pcode.emu.jit.var.JitInputVar):
        """
        Visit a :obj:`JitInputVar`
        
        :param ghidra.pcode.emu.jit.var.JitInputVar inputVar: the variable visited
        """

    def visitLoadOp(self, loadOp: ghidra.pcode.emu.jit.op.JitLoadOp):
        """
        Visit a :obj:`JitLoadOp`
        
        :param ghidra.pcode.emu.jit.op.JitLoadOp loadOp: the op visited
        """

    def visitMissingVar(self, missingVar: ghidra.pcode.emu.jit.var.JitMissingVar):
        """
        Visit a :obj:`JitMissingVar`
        
        :param ghidra.pcode.emu.jit.var.JitMissingVar missingVar: the variable visited
        """

    def visitNopOp(self, nopOp: ghidra.pcode.emu.jit.op.JitNopOp):
        """
        Visit a :obj:`JitNopOp`
        
        :param ghidra.pcode.emu.jit.op.JitNopOp nopOp: the op visited
        """

    def visitOp(self, op: ghidra.pcode.emu.jit.op.JitOp):
        """
        Visit an op node
         
         
        
        The default implementation dispatches this to the type-specific ``visit`` method.
        
        :param ghidra.pcode.emu.jit.op.JitOp op: the op visited
        """

    def visitOutVar(self, outVar: ghidra.pcode.emu.jit.var.JitOutVar):
        """
        Visit a :obj:`JitOutVar`
        
        :param ghidra.pcode.emu.jit.var.JitOutVar outVar: the variable visited
        """

    def visitPhiOp(self, phiOp: ghidra.pcode.emu.jit.op.JitPhiOp):
        """
        Visit a :obj:`JitPhiOp`
        
        :param ghidra.pcode.emu.jit.op.JitPhiOp phiOp: the op visited
        """

    def visitStoreOp(self, storeOp: ghidra.pcode.emu.jit.op.JitStoreOp):
        """
        Visit a :obj:`JitStoreOp`
        
        :param ghidra.pcode.emu.jit.op.JitStoreOp storeOp: the op visited
        """

    def visitSubPieceOp(self, pieceOp: ghidra.pcode.emu.jit.op.JitSynthSubPieceOp):
        """
        Visit a :obj:`JitSynthSubPieceOp`
        
        :param ghidra.pcode.emu.jit.op.JitSynthSubPieceOp pieceOp: the op visited
        """

    def visitUnOp(self, unOp: ghidra.pcode.emu.jit.op.JitUnOp):
        """
        Visit a :obj:`JitUnOp`
        
        :param ghidra.pcode.emu.jit.op.JitUnOp unOp: the op visited
        """

    def visitUnimplementedOp(self, unimplOp: ghidra.pcode.emu.jit.op.JitUnimplementedOp):
        """
        Visit a :obj:`JitUnimplementedOp`
        
        :param ghidra.pcode.emu.jit.op.JitUnimplementedOp unimplOp: the op visited
        """

    def visitVal(self, v: ghidra.pcode.emu.jit.var.JitVal):
        """
        Visit a :obj:`JitVal`
         
         
        
        The default implementation dispatches this to the type-specific ``visit`` method.
        
        :param ghidra.pcode.emu.jit.var.JitVal v: the value visited
        """

    def visitVar(self, v: ghidra.pcode.emu.jit.var.JitVar):
        """
        Visit a :obj:`JitVar`
         
         
        
        The default implementation dispatches this to the type-specific ``visit`` method.
        
        :param ghidra.pcode.emu.jit.var.JitVar v: the variable visited
        """


@typing.type_check_only
class JitDataFlowExecutor(ghidra.pcode.exec_.PcodeExecutor[ghidra.pcode.emu.jit.var.JitVal]):
    """
    A modification to :obj:`PcodeExecutor` that is specialized for the per-block data flow analysis.
     
     
    
    Normally, the p-code executor follows all of the control-flow branching, as you would expect in
    the interpretation-based p-code emulator. For analysis, we do not intend to actually follow
    branches. These should only ever occur at the end of a basic block, anyway.
     
     
    
    We do record the branch ops into the graph as :obj:`op nodes <JitOp>`. A conditional branch
    naturally participates in the data flow, as it uses the definition of its predicate varnode.
    Similarly, indirect branches use the definitions of their target varnodes. Direct branch
    operations are also added to the use-def graph, even though they do not use any variable
    definition. Architecturally, the code generator emits JVM bytecode from the op nodes in the
    use-def graph. For that to work, every p-code op must be entered into it. For bookkeeping, and
    because the code generator will need them, we look up the :obj:`Branch` records created by the
    passage decoder and store them in their respective branch op nodes.
     
     
    
    This is all accomplished by overriding :meth:`executeBranch(PcodeOp, PcodeFrame) <.executeBranch>` and similar
    branch execution methods. Additionally, we override :meth:`badOp(PcodeOp) <.badOp>` and
    :meth:`onMissingUseropDef(PcodeOp, PcodeFrame, String, PcodeUseropLibrary) <.onMissingUseropDef>`, because the
    inherited implementations will throw exceptions. We need not throw an exception until/unless we
    reach such bad code a run time. So, we enter them into the use-def graph as op nodes from which
    we later generate the code to throw the exception.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitType(java.lang.Object):
    """
    The p-code type of an operand.
     
     
    
    A type is an integer of floating-point value of a specific size in bytes. All values and
    variables in p-code are just bit vectors. The operators interpret those vectors according to a
    :obj:`JitTypeBehavior`. While types only technically belong to the operands, we also talk about
    values, variables, and varnodes being assigned types, so that we can allocate suitable JVM
    locals.
    """

    class SimpleJitType(JitType):
        """
        A p-code type that can be represented in a single JVM variable.
        """

        class_: typing.ClassVar[java.lang.Class]

        def asInt(self) -> JitType.SimpleJitType:
            """
            Re-apply the :obj:`integer <JitTypeBehavior.INTEGER>` behavior to this type
             
             
            
            This may be slightly faster than ``JitTypeBehavior.INTEGER.resolve(this)``, because
            each type can pick its int type directly, and integer types can just return ``this``.
            
            :return: this type as an int
            :rtype: JitType.SimpleJitType
            """

        def javaType(self) -> java.lang.Class[typing.Any]:
            """
            The JVM type of the variable that can represent a p-code variable of this type
            
            :return: the primitive class (not boxed)
            :rtype: java.lang.Class[typing.Any]
            """

        def opcodeLoad(self) -> int:
            """
            The JVM opcode to load a local variable of this type onto the stack
            
            :return: the opcode
            :rtype: int
            """

        def opcodeStore(self) -> int:
            """
            The JVM opcode to store a local variable of this type from the stack
            
            :return: the opcode
            :rtype: int
            """


    class IntJitType(java.lang.Record, JitType.SimpleJitType):
        """
        The p-code types for integers of size 1 through 4, i.e., that fit in a JVM int.
        """

        class_: typing.ClassVar[java.lang.Class]
        I1: typing.Final[JitType.IntJitType]
        """
        ``int1``: a 1-byte integer
        """

        I2: typing.Final[JitType.IntJitType]
        """
        ``int2``: a 2-byte integer
        """

        I3: typing.Final[JitType.IntJitType]
        """
        ``int3``: a 3-byte integer
        """

        I4: typing.Final[JitType.IntJitType]
        """
        ``int4``: a 4-byte integer
        """


        def __init__(self, size: typing.Union[jpype.JInt, int]):
            """
            Compact constructor to check the size
            
            :param jpype.JInt or int size: the size in bytes
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def forSize(size: typing.Union[jpype.JInt, int]) -> JitType.IntJitType:
            """
            Get the type for an integer of the given size 1 through 4
            
            :param jpype.JInt or int size: the size in bytes
            :return: the type
            :rtype: JitType.IntJitType
            :raises IllegalArgumentException: for any size *not* 1 through 4
            """

        def hashCode(self) -> int:
            ...

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class LongJitType(java.lang.Record, JitType.SimpleJitType):
        """
        The p-code types for integers of size 5 through 8, i.e., that fit in a JVM long.
        """

        class_: typing.ClassVar[java.lang.Class]
        I5: typing.Final[JitType.LongJitType]
        """
        ``int5``: a 5-byte integer
        """

        I6: typing.Final[JitType.LongJitType]
        """
        ``int6``: a 6-byte integer
        """

        I7: typing.Final[JitType.LongJitType]
        """
        ``int7``: a 7-byte integer
        """

        I8: typing.Final[JitType.LongJitType]
        """
        ``int8``: a 8-byte integer
        """


        def __init__(self, size: typing.Union[jpype.JInt, int]):
            """
            Compact constructor to check the size
            
            :param jpype.JInt or int size: the size in bytes
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def forSize(size: typing.Union[jpype.JInt, int]) -> JitType.LongJitType:
            """
            Get the type for an integer of the given size 5 through 8
            
            :param jpype.JInt or int size: the size in bytes
            :return: the type
            :rtype: JitType.LongJitType
            :raises IllegalArgumentException: for any size *not* 5 through 8
            """

        def hashCode(self) -> int:
            ...

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class FloatJitType(java.lang.Enum[JitType.FloatJitType], JitType.SimpleJitType):
        """
        The p-code type for floating-point of size 4, i.e., that fits in a JVM float.
        """

        class_: typing.ClassVar[java.lang.Class]
        F4: typing.Final[JitType.FloatJitType]
        """
        ``float4``: a 4-byte float
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitType.FloatJitType:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitType.FloatJitType]:
            ...


    class DoubleJitType(java.lang.Enum[JitType.DoubleJitType], JitType.SimpleJitType):
        """
        The p-code type for floating-point of size 8, i.e., that fits in a JVM double.
        """

        class_: typing.ClassVar[java.lang.Class]
        F8: typing.Final[JitType.DoubleJitType]
        """
        ``float8``: a 8-byte float
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitType.DoubleJitType:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitType.DoubleJitType]:
            ...


    class MpIntJitType(java.lang.Record, JitType):
        """
        **WIP**: The p-code types for integers of size 9 and greater.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, size: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def forSize(size: typing.Union[jpype.JInt, int]) -> JitType.MpIntJitType:
            """
            Get the type for an integer of the given size 9 or greater
            
            :param jpype.JInt or int size: the size in bytes
            :return: the type
            :rtype: JitType.MpIntJitType
            :raises IllegalArgumentException: for any size 8 or less
            """

        def hashCode(self) -> int:
            ...

        def legTypes(self) -> java.util.List[JitType.SimpleJitType]:
            """
            Get the p-code type that describes the part of the variable in each leg
             
             
            
            Each whole leg will have the type :obj:`IntJitType.I4`, and the partial leg, if
            applicable, will have its appropriate smaller integer type.
            
            :return: the list of types, each fitting in a JVM int.
            :rtype: java.util.List[JitType.SimpleJitType]
            """

        def legsAlloc(self) -> int:
            """
            The total number of JVM int variables ("legs") required to store the int
            
            :return: the total number of legs
            :rtype: int
            """

        def legsWhole(self) -> int:
            """
            The number of legs that are filled
            
            :return: the number of whole legs
            :rtype: int
            """

        def partialSize(self) -> int:
            """
            The number of bytes filled in the last leg, if partial
            
            :return: the number of bytes in the partial leg, or 0 if all legs are whole
            :rtype: int
            """

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class MpFloatJitType(java.lang.Record, JitType):
        """
        **WIP**: The p-code types for floats of size other than 4 and 8
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, size: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def forSize(size: typing.Union[jpype.JInt, int]) -> JitType.MpFloatJitType:
            """
            Get the type for a float of the given size other than 4 and 8
            
            :param jpype.JInt or int size: the size in bytes
            :return: the type
            :rtype: JitType.MpFloatJitType
            :raises IllegalArgumentException: for size 4 or 8
            """

        def hashCode(self) -> int:
            ...

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def compare(t1: JitType, t2: JitType) -> int:
        """
        Compare two types by preference. The type with the more preferred behavior then smaller size
        is preferred.
        
        :param JitType t1: the first type
        :param JitType t2: the second type
        :return: as in :meth:`Comparator.compare(Object, Object) <Comparator.compare>`
        :rtype: int
        """

    def ext(self) -> JitType:
        """
        Extend this p-code type to the p-code type that fills its entire host JVM type.
         
         
        
        This is useful, e.g., when multiplying two :obj:`int3 <IntJitType.I3>` values using
        :obj:`imul <Opcodes.IMUL>` that the result might be an :obj:`int4 <IntJitType.I4>` and so may
        need additional conversion.
        
        :return: the extended type
        :rtype: JitType
        """

    @staticmethod
    def forJavaType(cls: java.lang.Class[typing.Any]) -> JitType:
        """
        Identify the p-code type that is exactly represented by the given JVM type.
         
         
        
        This is used during Direct userop invocation to convert the arguments and return value.
        
        :param java.lang.Class[typing.Any] cls: the primitive class (not boxed)
        :return: the p-code type
        :rtype: JitType
        
        .. seealso::
        
            | :obj:`JitDataFlowUseropLibrary`
        """

    def nm(self) -> str:
        """
        Part of the name of a JVM local variable allocated for this type
        
        :return: the "type" part of a JVM local's name
        :rtype: str
        """

    def pref(self) -> int:
        """
        The preference for this type. Smaller is more preferred.
        
        :return: the preference
        :rtype: int
        """

    def size(self) -> int:
        """
        The size of this type
        
        :return: the size in bytes
        :rtype: int
        """


class JitOpUseModel(java.lang.Object):
    """
    The operator output use analysis for JIT-accelerated emulation.
     
     
    
    This implements the Operation Elimination phase of the :obj:`JitCompiler` using a simple graph
    traversal. The result is the set of :obj:`ops <JitOp>` whose outputs are (or could be) used by a
    downstream op. This includes all "sink" ops and all ops on which they depend.
     
     
    
    Some of the sink ops are easy to identify. These are ops that have direct effects on memory,
    control flow, or other aspects of the emulated machine:
     
     
    * Memory outputs - any p-code op whose output operand is a memory varnode.
    * Store ops - a :obj:`store <JitStoreOp>` op.
    * Branch ops - one of :obj:`branch <JitBranchOp>`, :obj:`cbranch <JitCBranchOp>`, or
    :obj:`branchind <JitBranchIndOp>`.
    * User ops with side effects - a :obj:`callother <JitCallOtherOpIf>` to a method where
    :meth:`hasSideEffects <PcodeUserop.hasSideEffects>```=true``.
    * Errors - e.g., :obj:`unimplemented <JitUnimplementedOp>`, :obj:`missing userop <JitCallOtherMissingOp>`.
    
     
     
    
    We identify these ops by invoking :meth:`JitOp.canBeRemoved() <JitOp.canBeRemoved>`. Ops that return ``false`` are
    "sink" ops.
     
     
    
    There is another class of ops to consider as "sinks," though: The definitions of SSA variables
    that could be retired. This could be from exiting the passage, flowing to a block with fewer live
    variables, or invoking a userop with the Standard strategy (see
    :obj:`JitDataFlowUseropLibrary`). Luckily, we have already performed :obj:`scope <JitVarScopeModel>` analysis, so we already know what varnodes are retired. However, to determine what SSA
    variables are retired, we have to consider where the retirement happens. For block transitions,
    it is always at the end of the block. Thus, we can use
    :meth:`JitDataFlowBlockAnalyzer.getVar(Varnode) <JitDataFlowBlockAnalyzer.getVar>`. For userops, we capture the intra-block
    analysis state into :meth:`JitCallOtherOpIf.dfState() <JitCallOtherOpIf.dfState>` *at the time of invocation*. We can
    then use :meth:`MiniDFState.getVar(Varnode) <MiniDFState.getVar>`. The defining op for each retired SSA variable is
    considered used.
     
     
    
    Retirement due to block flow requires a little more attention. Consider an op that defines a
    variable, where that op exists in a block that ends with a conditional branch. The analyzer does
    not know which flow the code will take, so we have to consider that it could take either. If for
    either branch, the variable goes out of scope and is retired, we have to consider the defining op
    as used.
     
     
    
    The remainder of the algorithm is simply an upward traversal of the use-def graph to collect all
    of the sink ops' dependencies. All the dependencies are considered used.
    
    
    .. admonition:: Implementation Note
    
        The :obj:`JitOpUpwardVisitor` permits seeding of values (constants and variables) and
        ops. Thus, we seed using the non-:meth:`removable <JitOp.canBeRemoved>` ops, and the
        retireable SSA variables. We do not have to get the variables' defining ops, since the
        visitor will do that for us.
    """

    @typing.type_check_only
    class OpUseCollector(JitOpUpwardVisitor):
        """
        The implementation of the graph traversal
         
         
        
        This implements the use-def upward visitor to collect the dependencies of ops and variables
        identified elsewhere in the code. By calling :meth:`visitOp(JitOp) <.visitOp>`,
        :meth:`visitVal(JitVal) <.visitVal>`, etc., all used ops are collected into :obj:`JitOpUseModel.used`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, block: JitControlFlowModel.JitBlock):
            """
            Construct a collector for the given block
            
            :param JitControlFlowModel.JitBlock block: the block whose ops are being examined
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: JitAnalysisContext, cfm: JitControlFlowModel, dfm: JitDataFlowModel, vsm: JitVarScopeModel):
        """
        Construct the operator use model
        
        :param JitAnalysisContext context: the analysis context
        :param JitControlFlowModel cfm: the control flow model
        :param JitDataFlowModel dfm: the data flow model
        :param JitVarScopeModel vsm: the variable scope model
        """

    def dumpResult(self):
        """
        For diagnostics: Dump the analysis result to stderr
        
        
        .. seealso::
        
            | :obj:`Diag.PRINT_OUM`
        """

    def isUsed(self, op: ghidra.pcode.emu.jit.op.JitOp) -> bool:
        """
        Check whether the given op node is used.
         
         
        
        If the op is used, then it cannot be eliminated.
        
        :param ghidra.pcode.emu.jit.op.JitOp op: the op to check
        :return: true if used, i.e., non-removable
        :rtype: bool
        """

    @property
    def used(self) -> jpype.JBoolean:
        ...


class JitControlFlowModel(java.lang.Object):
    """
    The control flow analysis for JIT-accelerated emulation.
     
     
    
    This implements the Control Flow Analysis phase of the :obj:`JitCompiler`. Some rudimentary
    analysis is performed during passage decoding — note the :obj:`BlockSplitter` is exported
    for use in :obj:`DecoderForOneStride`. This is necessary to evaluate whether an instruction
    (especially an inject-instrumented instruction) has fall-through. Without that information, the
    decoder cannot know whether it has reached the end of its stride. Note that the decoder records
    all the branches it encounters and includes them as metadata in the passage. Because branches
    need to record the source and target p-code op, the decoder is well suited. Additionally, it has
    to compute these anyway, and we'd rather avoid duplicative work by this analyzer.
     
     
    
    The decoded passage contains a good deal of information, but the primary inputs at this point are
    the ordered list of p-code ops and the branches. This model's primary responsibility is to break
    the passage down into basic blocks at the p-code level. Even though the p-code ops have all been
    concatenated together when constructing the passage, we know, by definition, that each stride
    will end with an unconditional branch (or else a synthesized :obj:`ExitPcodeOp`. Note also that
    :meth:`JitPassage.getBranches() <JitPassage.getBranches>` only includes the non-fall-through branches, because these are
    all that are recorded by the decoder. Thus, it is also this model's responsibility to create the
    fall-through branches. These will occur to represent the "false" case of any conditional
    branches, and to represent "unconditional fall through."
     
     
    
    The algorithm for this is fairly straightforward and has been implemented primarily in
    :obj:`BlockSplitter`. Most everything else in this class is data management and the types
    representing the model.
     
     
    
    **NOTE:** It is technically possible for a userop to branch, but this analysis does not
    consider that. Instead, the emulator will decide how to handle those. Conventionally, I'd rather
    a userop *never* perform control flow. Instead, I'd rather see things like
    ``pc = my_control_op(); goto [pc];``.
    """

    class UnterminatedFlowException(java.lang.IllegalArgumentException):
        """
        An exception thrown when control flow might run off the edge of the passage.
         
         
        
        By definition a passage is a collection of strides, and each stride is terminated by some op
        without fall through (or else a synthesized :obj:`ExitPcodeOp`. In particular, the last
        stride cannot end in fall through. If it did, there would be no op for it to fall through to.
        While this should never happen, it is easy in the course of development to allow it by
        accident. The control flow analysis can detect this as it finished splitting the passage into
        blocks. If the final block has fall through, the passage is said to have "unterminated flow,"
        and this exception is thrown. We do not wait until execution of the passage to throw this. It
        is thrown during translation, as it represents an assertion failure in the translation
        process. That is, the decoder produced an unsound passage.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            """
            Construct the exception
            """


    class BlockFlow(java.lang.Record):
        """
        A flow from one block to another
         
         
        
        This is just a wrapper around an :obj:`IntBranch` that allows us to quickly identify what
        two blocks it connects. Note that to connect two blocks in the passage, the branch must by
        definition be an :obj:`IntBranch`.
         
         
        
        If this flow represents entry into the passage, then :meth:`from() <.from>` and :meth:`branch() <.branch>`
        may be null
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: JitControlFlowModel.JitBlock, to: JitControlFlowModel.JitBlock, branch: ghidra.pcode.emu.jit.JitPassage.IntBranch):
            ...

        def branch(self) -> ghidra.pcode.emu.jit.JitPassage.IntBranch:
            ...

        @staticmethod
        def entry(to: JitControlFlowModel.JitBlock) -> JitControlFlowModel.BlockFlow:
            """
            Create an entry flow to the given block
            
            :param JitControlFlowModel.JitBlock to: the block to which execution flows
            :return: the flow
            :rtype: JitControlFlowModel.BlockFlow
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> JitControlFlowModel.JitBlock:
            ...

        def hashCode(self) -> int:
            ...

        def to(self) -> JitControlFlowModel.JitBlock:
            ...

        def toString(self) -> str:
            ...


    class JitBlock(ghidra.pcode.exec_.PcodeProgram):
        """
        A basic block of p-code
         
         
        
        This follows the formal definition of a basic block, but at the p-code level. All flows into
        the block enter at its first op, and all flows out of the block exit at its last op. The
        block also contains information about these flows as well as branches out of the passage via
        this block.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.pcode.exec_.PcodeProgram, code: java.util.List[ghidra.program.model.pcode.PcodeOp]):
            """
            Construct a new block
            
            :param ghidra.pcode.exec_.PcodeProgram program: the program (i.e., passage) from which this block is derived
            :param java.util.List[ghidra.program.model.pcode.PcodeOp] code: the subset of ops, in execution order, comprising this block
            """

        def branchesFrom(self) -> java.util.List[ghidra.pcode.emu.jit.JitPassage.IntBranch]:
            """
            Get internal branches leaving this block
            
            :return: the list of branches
            :rtype: java.util.List[ghidra.pcode.emu.jit.JitPassage.IntBranch]
            """

        def branchesOut(self) -> java.util.List[ghidra.pcode.emu.jit.JitPassage.Branch]:
            """
            Get branches leaving the passage from this block
            
            :return: the list of branches
            :rtype: java.util.List[ghidra.pcode.emu.jit.JitPassage.Branch]
            """

        def branchesTo(self) -> java.util.List[ghidra.pcode.emu.jit.JitPassage.IntBranch]:
            """
            Get internal branches entering this block
            
            :return: the list of branches
            :rtype: java.util.List[ghidra.pcode.emu.jit.JitPassage.IntBranch]
            """

        def end(self) -> ghidra.program.model.pcode.SequenceNumber:
            """
            Get the sequence number of the last op
             
             
            
            This is used for display and testing purposes only.
            
            :return: the sequence number
            :rtype: ghidra.program.model.pcode.SequenceNumber
            """

        def first(self) -> ghidra.program.model.pcode.PcodeOp:
            """
            Get the first p-code op in this block
            
            :return: the first p-code op
            :rtype: ghidra.program.model.pcode.PcodeOp
            """

        def flowsFrom(self) -> java.util.Map[ghidra.pcode.emu.jit.JitPassage.IntBranch, JitControlFlowModel.BlockFlow]:
            """
            Get (internal) flows leaving this block
            
            :return: the flows, keyed by branch
            :rtype: java.util.Map[ghidra.pcode.emu.jit.JitPassage.IntBranch, JitControlFlowModel.BlockFlow]
            """

        def flowsTo(self) -> java.util.Map[ghidra.pcode.emu.jit.JitPassage.IntBranch, JitControlFlowModel.BlockFlow]:
            """
            Get (internal) flows entering this block
            
            :return: the flows, keyed by branch
            :rtype: java.util.Map[ghidra.pcode.emu.jit.JitPassage.IntBranch, JitControlFlowModel.BlockFlow]
            """

        def getFallFrom(self) -> JitControlFlowModel.JitBlock:
            """
            If this block has fall through, find the block into which it falls
            
            :return: the block, or ``null``
            :rtype: JitControlFlowModel.JitBlock
            """

        def getTargetBlock(self, branch: ghidra.pcode.emu.jit.JitPassage.IntBranch) -> JitControlFlowModel.JitBlock:
            """
            Get the target block for the given internal branch, assuming it's from this block
            
            :param ghidra.pcode.emu.jit.JitPassage.IntBranch branch: the branch
            :return: the target block or null
            :rtype: JitControlFlowModel.JitBlock
            """

        def hasJumpTo(self) -> bool:
            """
            Check if there is an internal non-fall-through branch to this block
             
             
            
            This is used by the :obj:`JitCodeGenerator` to determine whether or not a block's
            bytecode needs to be labeled.
            
            :return: true if this block is targeted by a branch
            :rtype: bool
            """

        def instructionCount(self) -> int:
            """
            Get the number of instructions represented in this block
             
             
            
            This may get dicey as blocks are not necessarily split on instruction boundaries.
            Nevertheless, we seek to count the number of instructions executed at runtime, so that we
            can replay an execution, step in reverse, etc. What we actually do here is count the
            number of ops which are the first op produced by a decoded instruction.
            
            :return: the instruction count
            :rtype: int
            
            .. seealso::
            
                | :obj:`JitCompiledPassage.count(int, int)`
            
                | :obj:`JitPcodeThread.count(int, int)`
            """

        def start(self) -> ghidra.program.model.pcode.SequenceNumber:
            """
            Get the sequence number of the first op
             
             
            
            This is used for display and testing purposes only.
            
            :return: the sequence number
            :rtype: ghidra.program.model.pcode.SequenceNumber
            """

        def trailingOpCount(self) -> int:
            """
            Get the number of trailing ops in this block
             
             
            
            It is possible a block represents only partial execution of an instruction. Though
            :meth:`instructionCount() <.instructionCount>` will count this partial instruction, we can tell how far we
            got into it by examining this value. With this, we should be able to replay an execution
            to exactly the same p-code op step.
            
            :return: the trailing op count
            :rtype: int
            """

        @property
        def fallFrom(self) -> JitControlFlowModel.JitBlock:
            ...

        @property
        def targetBlock(self) -> JitControlFlowModel.JitBlock:
            ...


    class BlockSplitter(java.lang.Object):
        """
        A class that splits a sequence of ops and associated branches into basic blocks.
         
         
        
        This is the kernel of control flow analysis. It first indexes the branches by source and
        target op. Note that only non-fall-through branches are known at this point. Then, it
        traverses the list of ops. A split occurs following an op that is a branch source and/or
        preceding an op that is a branch target. A block is constructed when such a split point is
        encountered. In the case of a branch source, the branch is added to the newly constructed
        block. As traversal proceeds to the next op, it checks if the immediately-preceding block
        should have fall through (conditional or unconditional) by examining its last op. It adds a
        new fall-through branch if so. The end of the p-code op list is presumed a split point. If
        that final block "should have" fall through, an :obj:`UnterminatedFlowException` is thrown.
         
         
        
        Once all the splitting is done, we have the blocks and all the branches (internal or
        external) that leave each block. We then compute all the branches (internal) that enter each
        block and the associated flows in both directions.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.pcode.exec_.PcodeProgram):
            """
            Construct a new block splitter to process the given program
             
             
            
            No analysis is performed in the constructor. The client must call
            :meth:`addBranches(Collection) <.addBranches>` and then :meth:`splitBlocks() <.splitBlocks>`.
            
            :param ghidra.pcode.exec_.PcodeProgram program: the program, i.e., list of p-code ops
            """

        def addBranches(self, branches: collections.abc.Sequence):
            """
            Notify the splitter of the given branches before analysis
             
             
            
            The splitter immediately indexes the given branches by source and target op.
            
            :param collections.abc.Sequence branches: the branches
            """

        def splitBlocks(self) -> java.util.SequencedMap[ghidra.program.model.pcode.PcodeOp, JitControlFlowModel.JitBlock]:
            """
            Perform the actual analysis
            
            :return: the resulting split blocks, keyed by :meth:`JitBlock.start() <JitBlock.start>`
            :rtype: java.util.SequencedMap[ghidra.program.model.pcode.PcodeOp, JitControlFlowModel.JitBlock]
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: JitAnalysisContext):
        """
        Construct the control flow model.
         
         
        
        Analysis is performed as part of constructing the model.
        
        :param JitAnalysisContext context: the analysis context
        """

    def dumpResult(self):
        """
        For diagnostics: Dump the results to stderr
        
        
        .. seealso::
        
            | :obj:`Diag.PRINT_CFM`
        """

    def getBlocks(self) -> java.util.Collection[JitControlFlowModel.JitBlock]:
        """
        Get the basic blocks
        
        :return: the collection of blocks
        :rtype: java.util.Collection[JitControlFlowModel.JitBlock]
        """

    @property
    def blocks(self) -> java.util.Collection[JitControlFlowModel.JitBlock]:
        ...


class JitVarScopeModel(java.lang.Object):
    """
    The variable scope analysis of JIT-accelerated emulation.
     
     
    
    This implements the Variable Scope Analysis phase of the :obj:`JitCompiler`. The result provides
    the set of in-scope (alive) varnodes for each basic block. The design of this analysis, and the
    shortcuts we take, are informed by the design of downstream phases. In particular, we do not
    intend to allocate each SSA variable. There are often many, many such variables, and attempting
    to allocate them to as few target resources, e.g., JVM locals, as possible is *probably* a
    complicated and expensive algorithm. I don't think we'd gain much from it either. Instead, we'll
    just allocate by varnode. To do that, though, we still have to consider that some varnodes
    overlap and otherwise alias others. If we are able to handle all that aliasing in place, then we
    need not generate code for the synthetic ops. One might ask, well then why do any of the Data
    Flow Analysis in the first place? 1) We still need data flow to inform the selection of JVM local
    types. We have not measured the run-time cost of the bitwise casts, but we do know the bytecode
    for each cast occupies space, counted against the 65,535-byte max. 2) We also need data flow to
    inform operation elimination, which removes many wasted flag computations.
     
     
    
    To handle the aliasing, we coalesce overlapping varnodes. For example, ``EAX`` will get
    coalesced with ``RAX``, but ``BH`` *will not* get coalesced with ``BL``,
    assuming no other part of ``RBX`` is accessed. The :obj:`JitDataFlowModel` records all
    varnodes accessed in the course of its intra-block analysis. Only those actually accessed are
    considered. We then compute scope in terms of these coalesced varnodes. For example, if both
    ``RAX`` and ``EAX`` are used by a passage, then an access of ``EAX`` causes
    ``RAX`` to remain in scope.
     
     
    
    The decision to compute scope on a block-by-block basis instead of op-by-op is for simplicity. We
    intend to birth and retire variables along block transitions by considering what variables are
    coming into or leaving scope on the flow edge. *Birthing* is just reading a variable's
    value from the run-time :obj:`state <JitBytesPcodeExecutorState>` into its allocated JVM local.
    Conversely, *retiring* is writing the value back out to the state. There's little to be
    gained by retiring a variable midway through a block as opposed to the end of the block. Perhaps
    if one giant block handles a series of variables in sequence, we could have used a single JVM
    local to allocate each, but we're already committed to allocating a JVM local per (coalesced)
    varnode. So, while that may ensure only one variable is alive at a time, the number of JVM locals
    required remains the same. Furthermore, the amount of bytecode emitted remains the same, but at
    different locations in the block. The case where this might be worth considering is a userop
    invocation, because all live variables must be forcefully retired.
    
     
    
    We then consider what common cases we want to ensure are optimized, when we're limited to a
    block-by-block analysis. One that comes to mind is a function with an early bail. Consider the
    following C source:
     
     
    int func(my_struct* ptr) {
    if (ptr == NULL) {
        return ERR;
    }
    // Do some serious work
    return ptr->v;
    }
     
     
     
    
    Often, the C compiler will group all the returns into one final basic block, so we might get the
    following p-code:
     
     
    1   RSP    = INT_SUB RSP, 0x20:8
    2   $U00:1 = INT_EQUAL RDI, 0:8     # RDI is ptr
    3            CBRANCH <err>, $U0:1
    
    4            # Do some serious work
    5   $U10:8 = INT_ADD RDI, 0xc:8     # Offset to field v
    6   EAX    = LOAD [ram] $U10:8
    7            BRANCH <exit>
    <err>
    8   EAX    = COPY 0xffffffff:4
    <exit>
    9   RSP    = INT_ADD RSP, 0x20:8
    10  RIP    = LOAD [ram] RSP
    11  RSP    = INT_ADD RSP, 8:8
    12           RETURN RIP
     
     
     
    
    Note that I've elided the actual x86 machine code and all of the noise generated by C compilation
    and p-code lifting, and I've presumed the decoded passage contains exactly the example function.
    The result is your typical if-else diamond. We'll place the error case on the left:
     
     
        +---------+
        |   1--3  |
        | CBRANCH |
        +-T-----F-+
        /       \
        /         \
    +--------+ +--------+
    |   8    | |  4--7  |
    | (fall) | | BRANCH |
    +--------+ +--------+
        \         /
        \       /
        +---------+
        |  9--12  |
        | RETURN  |
        +---------+
     
     
     
    
    Suppose the "serious work" on line 4 accesses several varnodes: RBX, RCX, RDX, and RSI. If
    execution follows the error path, we'd rather not birth any of those variables. Thus, we might
    like the result of the scope analysis to be:
     
     
    +-------+-------------------------------------------+
    | Block |                 Live Vars                 |
    +=======+===========================================+
    |1–3    |RDI, RSP, $U00:1                           |
    +-------+-------------------------------------------+
    |4–7    |EAX, RBX, RCX, RDI, RDX, RSI, RSP, $U10:8  |
    +-------+-------------------------------------------+
    |8      |EAX, RSP                                   |
    +-------+-------------------------------------------+
    |9–12   |RIP, RSP                                   |
    +-------+-------------------------------------------+
    
     
    This can be achieved rather simply: Define two sets for each block, the upward view and the
    downward view. The first corresponds to all varnodes that could be accessed before entering this
    block or while in it. The second corresponds to all varnodes that could be access while in this
    block or after leaving it. The upward view is computed by initializing each set to the varnodes
    accessed by its block. Then we "push" each set upward by adding its elements into the set for
    each block with flows into this one, until the sets converge. The downward sets are similarly
    computed, independently of the upward sets. The result is the intersection of these sets, per
    block. The algorithm is somewhat intuitive in that we accrue live variables as we move toward the
    "body" of the control flow graph, and they begin to drop off as we approach an exit. The accrual
    is captured by the downward set, and the drop off is captured by intersection with the upward
    set. This will also prevent retirement and rebirth of variables. Essentially, if we are between
    two accesses of a varnode, then that varnode is alive. Consider ``RSP`` from the example
    above. The algorithm considers it alive in blocks 4–7 and 8, despite the fact neither
    actually accesses it. Nevertheless, we'd rather generate one birth upon entering block 1–3,
    keep it alive in the body, and then generate one retirement upon leaving block 9–12.
     
     
    
    One notable effect of this algorithm is that all blocks in a loop will have the same variables in
    scope.... I think this is okay. We'll birth the relevant variables upon entering the loop, keep
    them all alive during loop execution, and then retire them (unless they're accessed downstream)
    upon leaving.
    
    
    .. admonition:: Implementation Note
    
        **TODO**: There's some nonsense to figure out with types. It would be nice if we
        could allow variables of different types to occupy the same location at different
        times. This can be the case, e.g., if a register is used as a temporary location for
        copying values around. If there are times when it's treated as an int and other times
        when it's treated as a float, we could avoid unnecessary Java type conversions.
        However, this would require us to track liveness with types, and at that granularity,
        it could get unwieldy. My inclination is to just consider location liveness and then
        have the allocator decide what type to assign the local variable for that location
        based on some voting system. This is not the best, because some access sites are
        executed more often than others, but it'll suffice.
    """

    @typing.type_check_only
    class Which(java.lang.Enum[JitVarScopeModel.Which]):
        """
        Encapsulates set movement when computing the upward and downward views.
        """

        class_: typing.ClassVar[java.lang.Class]
        UP: typing.Final[JitVarScopeModel.Which]
        """
        Set movement for the upward view
        """

        DOWN: typing.Final[JitVarScopeModel.Which]
        """
        Set movement for the downward view
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JitVarScopeModel.Which:
            ...

        @staticmethod
        def values() -> jpype.JArray[JitVarScopeModel.Which]:
            ...


    @typing.type_check_only
    class ScopeInfo(java.lang.Object):
        """
        Encapsulates the (intermediate) analytic result for each block
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, block: JitControlFlowModel.JitBlock):
            """
            Construct the result for the given block
            
            :param JitControlFlowModel.JitBlock block: the block
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cfm: JitControlFlowModel, dfm: JitDataFlowModel):
        """
        Construct the model
        
        :param JitControlFlowModel cfm: the control flow model
        :param JitDataFlowModel dfm: the data flow model
        """

    def coalescedVarnodes(self) -> java.lang.Iterable[ghidra.program.model.pcode.Varnode]:
        """
        Get the collection of all coalesced varnodes
        
        :return: the varnodes
        :rtype: java.lang.Iterable[ghidra.program.model.pcode.Varnode]
        """

    def dumpResult(self):
        """
        For diagnostics: Dump the analysis result to stderr
        
        
        .. seealso::
        
            | :obj:`Diag.PRINT_VSM`
        """

    def getCoalesced(self, part: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.pcode.Varnode:
        """
        Get the varnode into which the given varnode was coalesced
         
         
        
        In many cases, the result is the same varnode.
        
        :param ghidra.program.model.pcode.Varnode part: the varnode
        :return: the coalesced varnode
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def getLiveVars(self, block: JitControlFlowModel.JitBlock) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        """
        Get the set of live varnodes for the given block
        
        :param JitControlFlowModel.JitBlock block: the block
        :return: the live varnodes
        :rtype: java.util.Set[ghidra.program.model.pcode.Varnode]
        """

    @property
    def liveVars(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def coalesced(self) -> ghidra.program.model.pcode.Varnode:
        ...


class JitTypeBehavior(java.lang.Enum[JitTypeBehavior]):
    """
    The behavior/requirement for an operand's type.
    
    
    .. seealso::
    
        | :obj:`JitTypeModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    ANY: typing.Final[JitTypeBehavior]
    """
    No type requirement or interpretation.
    """

    INTEGER: typing.Final[JitTypeBehavior]
    """
    The bits are interpreted as an integer.
    """

    FLOAT: typing.Final[JitTypeBehavior]
    """
    The bits are interpreted as a floating-point value.
    """

    COPY: typing.Final[JitTypeBehavior]
    """
    For :obj:`JitCopyOp` and :obj:`JitPhiOp`: No type requirement or interpretation, but there
    is an implication that the output has the same interpretation as the inputs.
    """


    @staticmethod
    def compare(b1: JitTypeBehavior, b2: JitTypeBehavior) -> int:
        """
        Compare two behaviors by preference. The behavior with the smaller ordinal is preferred.
        
        :param JitTypeBehavior b1: the first behavior
        :param JitTypeBehavior b2: the second behavior
        :return: as in :meth:`Comparator.compare(Object, Object) <Comparator.compare>`
        :rtype: int
        """

    @staticmethod
    def forJavaType(cls: java.lang.Class[typing.Any]) -> JitTypeBehavior:
        """
        Derive the type behavior from a Java language type.
         
         
        
        This is used on userops declared with Java primitives for parameters. To work with the
        :obj:`JitTypeModel`, we need to specify the type behavior of each operand. We aim to select
        behaviors such that the model allocates JVM locals whose JVM types match the userop method's
        parameters. This optimizes type conversions during Direct invocation.
        
        :param java.lang.Class[typing.Any] cls: the primitive class (not boxed)
        :return: the p-code type behavior
        :rtype: JitTypeBehavior
        
        .. seealso::
        
            | :obj:`JitDataFlowUseropLibrary`
        """

    def resolve(self, varType: JitType) -> JitType:
        """
        Re-apply this behavior to an existing type
         
         
        
        For :obj:`.ANY` and :obj:`.COPY` the result is the given type.
        
        :param JitType varType: the type
        :return: the resulting type
        :rtype: JitType
        """

    def type(self, size: typing.Union[jpype.JInt, int]) -> JitType:
        """
        Apply this behavior to a value of the given size to determine its type
        
        :param jpype.JInt or int size: the size of the value in bytes
        :return: the resulting type
        :rtype: JitType
        :raises AssertionError: if the type is not applicable, and such an invocation was not expected
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> JitTypeBehavior:
        ...

    @staticmethod
    def values() -> jpype.JArray[JitTypeBehavior]:
        ...


class JitDataFlowUseropLibrary(ghidra.pcode.exec_.PcodeUseropLibrary[ghidra.pcode.emu.jit.var.JitVal]):
    """
    A wrapper around a userop library that places :obj:`callother <PcodeOp.CALLOTHER>` ops into the
    use-def graph
     
     
    
    This is the library provided to
    :meth:`JitDataFlowExecutor.execute(PcodeProgram, PcodeUseropLibrary) <JitDataFlowExecutor.execute>` to cooperate with in the
    population of the use-def graph. The Sleigh compiler is very permissive when it comes to userop
    invocations. Notably, there's no way to declare the "prototype" or "signature" of the userop.
    Invocations can have any number of input operands and an optional output operand. Because the
    use-def graph takes careful notice of variables and their definiting ops, there are two possible
    op nodes: :obj:`JitCallOtherOp` when no output operand is given and :obj:`JitCallOtherDefOp`
    when an output operand is given.
     
     
    
    We employ several different strategies to handle a p-code userop:
     
     
    * Standard: Invocation of the userop in the same fashion as the interpreted p-code
    emulator. Any live variables have to be written into the:obj:`state <JitBytesPcodeExecutorState>`
    before the invocation and the read back out afterward. If the userop accesses the state directly,
    we must use this strategy. Most userops whose implementations precede the introduction of JIT
    acceleration can be supported with this strategy, so long as they don't manipulate the
    emulator/executor directly is some unsupported way.
    * Inlining: The inclusion of the userop's p-code directly at its call site, replacing
    the:obj:`PcodeOp.CALLOTHER` op. This is implemented in the decoder by
    :obj:`DecoderUseropLibrary`. This strategy is only applicable to userops defined using Sleigh
    and/or p-code.
    * Direct: The direct invocation of the userop's defining Java method in the generated
    JVM bytecode. This is applicable when the method's parameters and return type are primitives that
    each map to a:obj:`JitTypeBehavior`. The input values can be passed directly in, which works
    well when the inputs are registers or uniques allocated in JVM locals. The return value can be
    handled similarly.
    
     
     
    
    The default strategy for all userops is Standard. Implementors should set the attributes of
    :obj:`PcodeUserop` and adjust the parameters of the userop's method accordingly. To allow
    inlining, set :meth:`canInline <PcodeUserop.canInline>`. To allow direct invocation, set
    :meth:`PcodeUserop.functional() <PcodeUserop.functional>` and ensure all the parameter types and return type are
    supported. Supported types include primitives other than ``char``. The return type may be
    ``void``. No matter the strategy, userops may be subject to removal by the
    :obj:`JitOpUseModel`. To permit removal, clear :meth:`PcodeUserop.hasSideEffects() <PcodeUserop.hasSideEffects>`. The default
    prevents removal. For the inline strategy, each op from the inlined userop is analyzed
    separately, so the userop could be partially culled. An inlined userop cannot have side effects,
    and so the attribute is ignored.
    """

    @typing.type_check_only
    class WrappedUseropDefinition(ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[ghidra.pcode.emu.jit.var.JitVal]):
        """
        The wrapper of a specific userop definition
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, decOp: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[java.lang.Object]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: JitAnalysisContext, dfm: JitDataFlowModel):
        """
        Construct a wrapper library
        
        :param JitAnalysisContext context: the context from which the decoder's userop wrapper library is retrieved
        :param JitDataFlowModel dfm: the data flow model whose use-def graph to populate.
        
        .. admonition:: Implementation Note
        
            Each time this is constructed, it has to traverse the wrapped userop library and
            create a wrapper for each individual userop. For a large library, this could get
            expensive, and it currently must happen for every passage compiled. Part of the
            cause for this requirement is the reference to the data flow mode used by each
            userop wrapper.
        """


class JitTypeModel(java.lang.Object):
    """
    The type analysis for JIT-accelerated emulation.
     
     
    
    This implements the Type Assignment phase of the :obj:`JitCompiler` using a very basic "voting"
    algorithm. The result is an assignment of type to each :obj:`JitVal`. To be clear, at this
    phase, we're assigning types to variables (and constants) in the use-def graph, not varnodes.
    Later we do another bit of "voting" to determine the type of each JVM local allocated to a
    varnode. Perhaps we could be more direct, but in anticipation of future optimizations, we keep
    this analysis at the per-variable level. This is partly an artifact of exploration before
    deciding to allocate by varnode instead of by variable.
     
     
    ***************************
    Types in P-code and the JVM
    ***************************
    
     
    
    P-code (and Sleigh) is a relatively type free language. Aside from size, variables have no type;
    they are just bit vectors. The operators are typed and cast the bits as required. This aligns
    well with most machine architectures. Registers are just bit vectors, and the instructions
    interpret them according to some type. In contrast, JVM variables have a type: ``int``,
    ``long``, ``float``, ``double``, or a reference. Conversions between JVM types must
    be explicit, so we must attend to certain aspects of p-code types when consuming operands
    allocated in JVM locals. There are three aspects to consider when translating p-code types to the
    JVM: behavior, size, and signedness.
     
     
    ===========================
    Behavior: Integer vs. Float
    ===========================
    
     
    
    The JVM has two integral types ``int`` and ``long`` of 4 and 8 bytes respectively. P-code
    has one integral type of no specified size. Or rather, it has as many integral types: 1-byte int,
    2-byte int, 3-byte int, and so on. We thus describe p-code operands as having a type
    :obj:`behavior <JitTypeBehavior>`: *integral* or *floating-point*. Note there are
    two ancillary behaviors *any* and *copy* to describe the operands of truly typeless
    operators, like :obj:`JitCopyOp`.
     
     
    ====
    Size
    ====
    
     
    
    When paired with a varnode's size, we have enough information to start mapping p-code types to
    JVM types. For float types, p-code only supports specific sizes defined by IEEE 754: 2-byte
    half-precision, 4-byte single-precision, 8-byte double-precision, 10-byte extended-precision,
    16-byte quadruple-precision, and 32-byte octuple-precision. Some p-code types map precisely to
    JVM counterparts: The 4- and 8-byte integer types map precisely to the JVM's ``int`` and
    ``long`` types. Similarly, the 4- and 8-byte float types map precisely to ``float`` and
    ``double``. **TODO**: The JIT translator does not currently support integral types greater
    than 8 bytes (64 bits) in size nor floating-point types other than 4 and 8 bytes (single and
    double precision) in size.
     
     
    ==========
    Signedness
    ==========
    
     
    
    All floating-point types are signed, whether in p-code or in the JVM, so there's little to
    consider in terms of mapping. Some p-code operators have signed operands, some have unsigned
    operands, and others have no signedness at all. In contrast, no JVM bytecodes are strictly
    unsigned. They are either signed or have no signedness. It was a choice of the Java language
    designers that all variables would be signed, and this is consequence of that choice. In time,
    "unsigned" operations were introduced in the form of static methods, e.g.,
    :meth:`Integer.compareUnsigned(int, int) <Integer.compareUnsigned>` and :meth:`Long.divideUnsigned(long, long) <Long.divideUnsigned>`. Note that
    at the bit level, unsigned multiplication is the same as signed, and so no "unsigned multiply"
    method was provided. This actually aligns well with p-code in that, for this aspect of
    signedness, the variables are all the same. Instead the operations apply the type interpretation.
    Thus, we need not consider signedness when allocating JVM locals.
     
     
    *********************
    Conversions and Casts
    *********************
    
     
    
    Conversions between JVM primitive types must be explicit in the emitted bytecode, even if the
    intent is just to re-cast the bits. This is not the case for p-code. Conversions in p-code need
    only be explicit when they mutate the actual bits. Consider the following p-code:
     
     
    $U00:4 = FLOAT_ADD r0, r1
    r2     = INT_2COMP $U00:4
     
     
     
    
    The native translation to bytecode:
     
     
    FLOAD  1 # r0
    FLOAD  2 # r1
    FADD
    FSTORE 3 # $U00:4
    LDC    0
    ILOAD  3 # $U00:4
    ISUB
    ISTORE 4 # r2
     
     
     
    
    Will cause an error when loading the class. This is because the local variable 3 must be one of
    ``int`` or ``float``, and the bytecode must declare which, so either the ``FSTORE 3``
    or the ``ILOAD 3`` will fail the JVM's type checker. To resolve this, we could assign the
    type ``float`` to local variable 3, and change the erroneous ``ILOAD 3`` to:
     
     
    FLOAD  3
    INVOKESTATIC :meth:`Float.floatToRawIntBits(float) <Float.floatToRawIntBits>`
     
     
     
    
    At this point, the bit-vector contents of ``$U00:4`` are on the stack, but for all the JVM
    cares, they are now an ``int``. We must assigned a JVM type to each local we allocate and
    place bitwise type casts wherever the generated bytecodes would cause type disagreement. We would
    like to assign JVM types in a way that reduces the number of ``INVOKESTATIC`` bytecodes
    emitted. One could argue that we should instead seek to reduce the number of ``INVOKESTATIC``
    bytecodes actually executed, but I pray the JVM's JIT compiler can recognize calls to
    :meth:`Float.floatToRawIntBits(float) <Float.floatToRawIntBits>` and similar and emit no native code for them, i.e., they
    ought to have zero run-time cost.
     
     
    
    Size conversions cause a similar need for explicit conversions, for two reasons: 1) Any
    conversion between JVM ``int`` and ``long`` still requires specific bytecodes. Neither
    platform supports implicit conversion between ``float`` and ``double``. 2) We allocate
    the smaller JVM integral type to accommodate each p-code integral type, so we must apply masks in
    some cases to assure values to do not exceed their p-code varnode size. Luckily, p-code also
    requires explicit conversions between sizes, e.g., using :obj:`zext <PcodeOp.INT_ZEXT>`. However,
    we often have to perform temporary conversions in order to meet the type/size requirements of JVM
    bytecodes.
     
     
    
    Consider ``r2 = INT_MULT r0, r1`` where the registers are all 5 bytes. Thus, the registers
    are allocated as JVM locals of type ``long``. We load ``r0`` and ``r1`` onto the
    stack, and then we emit an :obj:`Opcodes.LMUL`. Technically, the result is another JVM
    ``long``, which maps to an 8-byte p-code integer. Thus, we must apply a mask to "convert" the
    result to a 5-byte p-code integer before storing the result in ``r2``'s JVM local.
     
     
    ***************
    Type Assignment
    ***************
    
     
    
    Given that only behavior and size require any explicit conversions, we omit signedness from the
    formal definition of p-code :obj:`type <JitType>`. It is just the behavior applied to a size,
    e.g., :obj:`int3 <IntJitType.I3>`.
     
     
    
    We use a fairly straightforward voting algorithm that examines how each variable definition is
    used. The type of an operand is trivially determined by examining the behavior of each operand,
    as specified by the p-code opcode; and the size of the input varnode, specified by the specific
    p-code op instance. For example, the p-code op ``$U00:4 = FLOAT_ADD r0, r1`` has an output
    operand of :obj:`float4 <FloatJitType.F4>`. Thus, it casts a vote that ``$U00:4`` should be
    that type. However, the subsequent op ``r2 = INT_2COMP $U00`` casts a vote for
    :obj:`int4 <IntJitType.I4>`. We prefer an ``int`` when tied, so we assign ``$U00:4`` the
    type ``int4``.
     
     
    
    This become complicated in the face of typeless ops, namely :obj:`copy <JitCopyOp>` and
    :obj:`phi <JitPhiOp>`. Again, we'd like to reduce the number of casts we have to emit in the
    bytecode. Consider the op ``r1 = COPY r0``. This should emit a load followed immediately by a
    store, but The JVM will require both the source and destination locals to have the same type.
    Otherwise, a cast is necessary. The votes regarding ``r0`` will thus need to incorporate the
    votes regarding ``r1`` and vice versa.
     
     
    
    Our algorithm is a straightforward queued traversal of the use-def graph until convergence.
    First, we initialize a queue with all values (variables and constants) in the graph and
    initialize all type assignments to :obj:`any <JitTypeBehavior.ANY>`. We then process each value in
    the queue until it is empty. A value receives votes from its uses as required by each operand.
    :obj:`integer <JitTypeBehavior.INTEGER>` and :obj:`float <JitTypeBehavior>` behaviors count as 1
    vote for that behavior. The :obj:`any <JitTypeBehavior.ANY>` behavior contributes 0 votes. If the
    behavior is :obj:`copy <JitTypeBehavior.COPY>`, then we know the use is either a :obj:`copy <JitCopyOp>` or :obj:`phi <JitPhiOp>` op, so we fetch its output value. The op casts its vote for the
    tentative type of that output value. Similar is done for the value's defining op, if applicable.
    If it's a copy or phi, we start a sub contest where each input/option casts a vote for its
    tentative type. The defining op's vote is cast according to the winner of the sub contest. Ties
    favor :obj:`integer <JitTypeBehavior.INTEGER>`. The final winner is computed and the tentative
    type assignment is updated. If there are no votes, the tentative assignment is
    :obj:`JitTypeBehavior.ANY`.
     
     
    
    When an update changes the tentative type assignment of a value, then all its neighbors are added
    back to the queue. Neighbors are those values connected to this one via a copy or phi. When the
    queue is empty, the tentative type assignments are made final. Any assignment that remains
    :obj:`any <JitTypeBehavior.ANY>` is treated as if :obj:`int <JitTypeBehavior.INTEGER>`.
    **TODO**: Prove that this algorithm always terminates.
    
    
    .. admonition:: Implementation Note
    
        We do all the bookkeeping in terms of :obj:`JitTypeBehavior` and wait to resolve the
        actual type until the final assignment.
    """

    @typing.type_check_only
    class Contest(java.lang.Record):
        """
        A contest to determine a type assignment
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            """
            Start a new contest
            """

        @staticmethod
        def compareCandidateEntries(ent1: java.util.Map.Entry[JitTypeBehavior, java.lang.Integer], ent2: java.util.Map.Entry[JitTypeBehavior, java.lang.Integer]) -> int:
            """
            Compare the votes between two candidates, and select the winner
             
             
            
            The :meth:`winner() <.winner>` method seeks the "max" candidate, so the vote counts are compared
            in the usual fashion. We need to invert the comparison of the types, though.
            :obj:`JitTypeBehavior.INTEGER` has a lower ordinal than :obj:`JitTypeBehavior.FLOAT`,
            but we want to ensure int is preferred, so we reverse that comparison.
            
            :param java.util.Map.Entry[JitTypeBehavior, java.lang.Integer] ent1: the first candidate-vote entry
            :param java.util.Map.Entry[JitTypeBehavior, java.lang.Integer] ent2: the second candidate-vote entry
            :return: -1 if the *second* wins, 1 if the *first* wins. 0 should never
                    result, unless we're comparing a candidate with itself.
            :rtype: int
            """

        def counts(self) -> java.util.Map[JitTypeBehavior, java.lang.Integer]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def vote(self, candidate: JitTypeBehavior):
            """
            Cast a vote for the given candidate
            
            :param JitTypeBehavior candidate: the candidate type
            """

        def winner(self) -> JitTypeBehavior:
            """
            Compute the winner of the contest
            
            :return: the winner, or :obj:`JitTypeBehavior.ANY` if there are no entries
            :rtype: JitTypeBehavior
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dfm: JitDataFlowModel):
        """
        Construct the type model
        
        :param JitDataFlowModel dfm: the data flow model whose use-def graph to process
        """

    def typeOf(self, v: ghidra.pcode.emu.jit.var.JitVal) -> JitType:
        """
        Get the final type assignment for the given value
        
        :param ghidra.pcode.emu.jit.var.JitVal v: the value
        :return: the value's assigned type
        :rtype: JitType
        """



__all__ = ["JitDataFlowBlockAnalyzer", "JitAnalysisContext", "JitDataFlowState", "JitDataFlowArithmetic", "JitOpUpwardVisitor", "JitDataFlowModel", "JitAllocationModel", "JitOpVisitor", "JitDataFlowExecutor", "JitType", "JitOpUseModel", "JitControlFlowModel", "JitVarScopeModel", "JitTypeBehavior", "JitDataFlowUseropLibrary", "JitTypeModel"]
