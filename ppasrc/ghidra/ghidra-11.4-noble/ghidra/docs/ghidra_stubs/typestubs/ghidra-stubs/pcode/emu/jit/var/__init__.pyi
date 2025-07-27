from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.op
import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


class JitMissingVar(AbstractJitVarnodeVar):
    """
    A p-code variable whose definition could not be determined.
     
     
    
    This is only applicable to ``register`` and ``unique`` variables. It indicates the
    :obj:`JitDataFlowState` had not recorded a definition for the variable's varnode (or some
    portion of it) prior in the same block. These should never enter the use-def graph. Instead, each
    should be replaced by a :obj:`JitOutVar` defined by a :obj:`phi <JitPhiOp>` node. The phi node's
    options are determined later during :obj:`inter-block <JitDataFlowModel>` analysis.
    
    
    .. seealso::
    
        | :obj:`.generatePhi(JitDataFlowModel, JitBlock)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        """

    def generatePhi(self, dfm: ghidra.pcode.emu.jit.analysis.JitDataFlowModel, block: ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock) -> ghidra.pcode.emu.jit.op.JitPhiOp:
        """
        Create the :obj:`phi <JitPhiOp>` node for this missing variable.
         
        The resulting node and its :meth:`output <JitPhiOp.out>` are added to the use-def graph. Note
        that this missing variable never enters the use-def graph. The phi's output takes the place
        of this variable.
        
        :param ghidra.pcode.emu.jit.analysis.JitDataFlowModel dfm: the data flow model
        :param ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock block: the block containing the op that accessed the varnode
        :return: the generated phi op
        :rtype: ghidra.pcode.emu.jit.op.JitPhiOp
        
        .. seealso::
        
            | :obj:`JitDataFlowModel`Inter-block data flow analysis
        """


class JitLocalOutVar(AbstractJitOutVar):
    """
    A p-code register or unique variable with a defining p-code op.
     
     
    
    This represents an output operand located in a thread's "local" state, i.e., it is a
    ``register`` or ``unique`` variable. These can be used by downstream p-code ops in the
    use-def graph, because we wish to analyze this flow and optimize the generated code.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int], varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param jpype.JInt or int id: the unique id
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        
        .. seealso::
        
            | :obj:`JitDataFlowModel.generateOutVar(Varnode)`
        """


class AbstractJitVarnodeVar(AbstractJitVar, JitVarnodeVar):
    """
    An abstract implementation of :obj:`JitVarnodeVar`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int], varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param jpype.JInt or int id: the unique id
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        """


class JitConstVal(AbstractJitVal):
    """
    A p-code constant use-def node.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, size: typing.Union[jpype.JInt, int], value: java.math.BigInteger):
        """
        Construct a constant.
         
         
        
        Use :meth:`JitVal.constant(int, BigInteger) <JitVal.constant>` instead.
        
        :param jpype.JInt or int size: the size in bytes
        :param java.math.BigInteger value: the value
        """

    def value(self) -> java.math.BigInteger:
        """
        The value of this constant.
        
        :return: the value
        :rtype: java.math.BigInteger
        """


class AbstractJitVal(JitVal):
    """
    An abstract implementation of :obj:`JitVal`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, size: typing.Union[jpype.JInt, int]):
        """
        Construct a value of the given size.
        
        :param jpype.JInt or int size: the size in bytes
        """


class JitVal(java.lang.Object):
    """
    A p-code value use-def node.
     
     
    
    For a table of value/variable node classes and generators, see :obj:`ValGen`.
    """

    class ValUse(java.lang.Record):
        """
        The use of a value node by an operator node.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, op: ghidra.pcode.emu.jit.op.JitOp, position: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def op(self) -> ghidra.pcode.emu.jit.op.JitOp:
            ...

        def position(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> ghidra.pcode.emu.jit.analysis.JitTypeBehavior:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addUse(self, op: ghidra.pcode.emu.jit.op.JitOp, position: typing.Union[jpype.JInt, int]):
        """
        Add a use.
         
         
        
        In most cases, uses should be final, once this value node has been entered into the use-def
        graph. An exception deals with :obj:`phi <JitPhiOp>` nodes, as this analysis occurs after each
        intra-block portion of the graph has been constructed. During inter-block analysis,
        additional uses will get recorded. Even further uses may be recorded uding
        :obj:`op-use <JitOpUseModel>` analysis, since it may generate more :obj:`phi <JitPhiOp>` nodes.
        
        :param ghidra.pcode.emu.jit.op.JitOp op: the operator node using this one
        :param jpype.JInt or int position: the position of this value in the operator's input operands
        """

    @staticmethod
    def constant(size: typing.Union[jpype.JInt, int], value: java.math.BigInteger) -> JitConstVal:
        """
        Create a constant value.
        
        :param jpype.JInt or int size: the size in bytes
        :param java.math.BigInteger value: the value
        :return: the value node
        :rtype: JitConstVal
        """

    def removeUse(self, op: ghidra.pcode.emu.jit.op.JitOp, position: typing.Union[jpype.JInt, int]):
        """
        Remove a use.
        
        :param ghidra.pcode.emu.jit.op.JitOp op: as in :meth:`addUse(JitOp, int) <.addUse>`
        :param jpype.JInt or int position: as in :meth:`addUse(JitOp, int) <.addUse>`
        
        .. seealso::
        
            | :obj:`.addUse(JitOp, int)`
        """

    def size(self) -> int:
        """
        The size in bytes.
        
        :return: the size
        :rtype: int
        """

    def uses(self) -> java.util.List[JitVal.ValUse]:
        """
        The list of uses.
        
        :return: the uses
        :rtype: java.util.List[JitVal.ValUse]
        """


class JitVar(JitVal):
    """
    A p-code variable use-def node.
    """

    class_: typing.ClassVar[java.lang.Class]

    def id(self) -> int:
        """
        A unique id for this variable
        
        :return: the id
        :rtype: int
        """

    def space(self) -> ghidra.program.model.address.AddressSpace:
        """
        The address space of this variable.
        
        :return: the space
        :rtype: ghidra.program.model.address.AddressSpace
        """


class JitDirectMemoryVar(AbstractJitVarnodeVar, JitMemoryVar):
    """
    A p-code variable node with a fixed location in memory.
     
     
    
    This represents an input operand located in memory. Its value can be accessed directly from the
    :obj:`state <JitBytesPcodeExecutorState>` at run time.
    
    
    .. seealso::
    
        | :obj:`JitMemoryOutVar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int], varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param jpype.JInt or int id: the unique id
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        
        .. seealso::
        
            | :obj:`JitDataFlowModel.generateDirectMemoryVar(Varnode)`
        """


class AbstractJitVar(AbstractJitVal, JitVar):
    """
    An abstract implementation of :obj:`JitVar`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Construct a variable with the given id and size.
        
        :param jpype.JInt or int id: a unique id among all variables in the same use-def graph
        :param jpype.JInt or int size: the size in bytes
        """


class JitMemoryVar(JitVar):
    """
    A p-code variable located in memory.
     
     
    
    The offset could be fixed or variable. The variable is shared among all threads.
    """

    class_: typing.ClassVar[java.lang.Class]


class JitFailVal(java.lang.Enum[JitFailVal], JitVal):
    """
    A value that is forbidden from being translated
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[JitFailVal]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> JitFailVal:
        ...

    @staticmethod
    def values() -> jpype.JArray[JitFailVal]:
        ...


class JitOutVar(JitVarnodeVar):
    """
    A p-code variable node with a defining p-code op.
    """

    class_: typing.ClassVar[java.lang.Class]

    def definition(self) -> ghidra.pcode.emu.jit.op.JitDefOp:
        """
        The defining p-code operator node
         
         
        
        This should "never" be null. The only exception is the short interim between constructing the
        node and setting its definition. Once this variable has been entered into the use-def graph,
        the definition should be non-null and final.
        
        :return: the defining node
        :rtype: ghidra.pcode.emu.jit.op.JitDefOp
        """

    def setDefinition(self, definition: ghidra.pcode.emu.jit.op.JitDefOp):
        """
        Set the defining p-code operator node
        
        :param ghidra.pcode.emu.jit.op.JitDefOp definition: the defining node
        """


class JitInputVar(AbstractJitVarnodeVar):
    """
    A p-code variable that is an input to a passage, i.e., there are reads possible before writes.
     
     
    
    These only appear as options to a :obj:`phi <JitPhiOp>` node. They are very common, because any
    block that is also a valid passage entry (which is most of them) can have an option that is
    defined outside the passage. It may very well be the only option.
    
    
    .. admonition:: Implementation Note
    
        We delay creation of passage-input variables until inter-block analysis, because the
        variable must turn up missing (i.e., not be defined prior in the same block) before we
        can consider it might be a passage input. We thus create a :obj:`phi <JitPhiOp>` node
        for it and record the input as just one of many options. We had at one point
        "simplified" single-option phi nodes, which covered the case where the varnode is
        *certainly* a passage input, but we found it difficult in terms of bookkeeping.
        Also, because of our variable allocation strategy, such simplification offered no real
        value during code generation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        
        .. seealso::
        
            | :obj:`JitPhiOp.addInputOption()`
        """


class JitVarnodeVar(JitVar):
    """
    A p-code variable node with a fixed address (given by a :obj:`Varnode`).
    """

    class_: typing.ClassVar[java.lang.Class]

    def varnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        The location of the variable.
        
        :return: the varnode
        :rtype: ghidra.program.model.pcode.Varnode
        """


class JitIndirectMemoryVar(java.lang.Enum[JitIndirectMemoryVar], JitMemoryVar):
    """
    A dummy variable node representing an indirect memory access.
     
     
    
    These are caused by :obj:`PcodeOp.LOAD`, since that is the only manner in which the
    :obj:`JitDataFlowState` can be accessed with a non-constant offset. However, the node is
    immediately dropped on the floor by
    :meth:`JitDataFlowArithmetic.modAfterLoad(PcodeOp, AddressSpace, JitVal, JitVal) <JitDataFlowArithmetic.modAfterLoad>`, which instead
    places the :obj:`JitLoadOp` into the use-def graph. This just exists so we don't return
    ``null``.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[JitIndirectMemoryVar]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> JitIndirectMemoryVar:
        ...

    @staticmethod
    def values() -> jpype.JArray[JitIndirectMemoryVar]:
        ...


class AbstractJitOutVar(AbstractJitVarnodeVar, JitOutVar):
    """
    An abstract implementation of :obj:`JitOutVar`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int], varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param jpype.JInt or int id: the unique id
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        """


class JitMemoryOutVar(AbstractJitOutVar, JitMemoryVar):
    """
    A p-code variable node with a fixed location in memory and a defining p-code op.
     
     
    
    This represents an output operand located in memory. It can be addressed directly. In contrast to
    :obj:`JitLocalOutVar`, these *may not* be used by downstream p-code ops in the use-def
    graph, because the output is written to the :obj:`state <JitBytesPcodeExecutorState>` immediately.
    There's no benefit to further analysis. Instead, ops that use the same varnode will take a
    :obj:`JitDirectMemoryVar`, which indicate input immediately from the
    :obj:`state <JitBytesPcodeExecutorState>`.
    
    
    .. seealso::
    
        | :obj:`JitDirectMemoryVar`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JInt, int], varnode: ghidra.program.model.pcode.Varnode):
        """
        Construct a variable.
        
        :param jpype.JInt or int id: the unique id
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        
        .. seealso::
        
            | :obj:`JitDataFlowModel.generateOutVar(Varnode)`
        """



__all__ = ["JitMissingVar", "JitLocalOutVar", "AbstractJitVarnodeVar", "JitConstVal", "AbstractJitVal", "JitVal", "JitVar", "JitDirectMemoryVar", "AbstractJitVar", "JitMemoryVar", "JitFailVal", "JitOutVar", "JitInputVar", "JitVarnodeVar", "JitIndirectMemoryVar", "AbstractJitOutVar", "JitMemoryOutVar"]
