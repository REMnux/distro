from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore


class CodeBlockImpl(CodeBlock):
    """
    CodeBlockImpl is an implementation of a CodeBlock.
    These are produced by a particular CodeBlockModel and are associated
    with only that model.  Most methods simply delegate any work that
    is specific to a particular CodeBlockModel to that model.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlock`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: CodeBlockModel, starts: jpype.JArray[ghidra.program.model.address.Address], body: ghidra.program.model.address.AddressSetView):
        """
        Construct a multi-entry CodeBlock associated with a CodeBlockModel. The
        significance of the start Addresses is model dependent.
        
        :param CodeBlockModel model: the model instance which produced this block.
        :param jpype.JArray[ghidra.program.model.address.Address] starts: the entry points for the block. Any of these addresses may
        be used to identify this block within the model that produced it.
        :param ghidra.program.model.address.AddressSetView body: the address set which makes-up the body of this block.
        """


class SubroutineDestReferenceIterator(CodeBlockReferenceIterator):
    """
    SubroutineDestReferenceIterator is a unidirectional iterator over 
    the destination ``CodeBlockReference``s for a CodeBlock.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct an Iterator over Destination blocks for a CodeBlock.
        External references will be ignored.
        
        :param CodeBlock block: block to get destination blocks for.  This should be a
        subroutine obtained from PartitionCodeSubModel.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @staticmethod
    def getNumDestinations(block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of destination references flowing out of this subroutine (block).
        All Calls from this block, and all external FlowType block references
        from this block are counted.
        
        :param CodeBlock block: code block to get the number of destination references from.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.hasNext()`
        """

    def next(self) -> CodeBlockReference:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.next()`
        """


class SimpleSourceReferenceIterator(CodeBlockReferenceIterator):
    """
    SimpleSourceReferenceIterator is a unidirectional iterator over the ``CodeBlockReference``s
    for a CodeBlock.  It is **not** failfast, whenever ``hasNext()``
    are called it will find if there is a next ``CodeBlockReference`` and acquire
    a handle if there is one. If new code units are added to the listing after
    the iterator is created it will find them as it scans ahead.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, block: CodeBlock, followIndirectFlows: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct an Iterator over Source blocks for a CodeBlock.
        
        :param CodeBlock block: block to get destination blocks for.  This should be a
        block obtained from SimpleBlockModel.
        :param jpype.JBoolean or bool followIndirectFlows: indirect references will only be included if true
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @staticmethod
    @deprecated("this method should be avoided since it repeats the work of the iterator")
    def getNumSources(block: CodeBlock, followIndirectFlows: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of source references flowing from this subroutine (block).
        All Calls to this block, and all external FlowType block references
        to this block are counted.
        
        :param CodeBlock block: code block to get the number of source references to.
        :param jpype.JBoolean or bool followIndirectFlows: indirect references will only be included if true
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        
        .. deprecated::
        
        this method should be avoided since it repeats the work of the iterator
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.hasNext()`
        """

    def next(self) -> CodeBlockReference:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.next()`
        """


@typing.type_check_only
class EmptyCodeBlockReferenceIterator(CodeBlockReferenceIterator):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CodeBlock(ghidra.program.model.address.AddressSetView):
    """
    CodeBlock represents some group of Instructions/Data.  Each block
    has some set of source blocks that flow into it and some
    set of destination blocks that flow out of it.  A BlockModel
    is used to produce CodeBlocks.  Each model produces blocks
    based on its interpretation of Instruction/Data grouping and flow
    between those groups.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDestinations(self, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an Iterator over the CodeBlocks that are flowed to from this
        CodeBlock.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: An iterator over CodeBlocks referred to by this Block.
        :rtype: CodeBlockReferenceIterator
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFirstStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Return the first start address of the CodeBlock.
        Depending on the model used to generate the CodeBlock,
        there may be multiple entry points to the block.  This will
        return the first start address for the block.  It should
        always return the same address for a given block if there
        is more than one entry point.
        
        :return: the first start address of the block.
        :rtype: ghidra.program.model.address.Address
        """

    def getFlowType(self) -> ghidra.program.model.symbol.FlowType:
        """
        Return, in theory, how things flow out of this node.
        If there are any abnormal ways to flow out of this node,
        (ie: jump, call, etc...) then the flow type of the node
        takes on that type.
        If there are multiple unique ways out of the node, then we
        should return FlowType.UNKNOWN.
        Fallthrough is returned if that is the only way out.
        
        :return: flow type of this node
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getModel(self) -> CodeBlockModel:
        """
        Get the model instance which was used to generate this block.
        
        :return: the model used to build this CodeBlock
        :rtype: CodeBlockModel
        """

    def getName(self) -> str:
        """
        Return the name of the block.
        
        :return: name of block,
        normally the symbol at the starting address
        :rtype: str
        """

    def getNumDestinations(self, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get the number of CodeBlocks this block flows to.
        Note that this is almost as much work as getting the actual destination references.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: number of destination CodeBlocks.
        :rtype: int
        :raises CancelledException: if the monitor cancels the operation.
        
        .. seealso::
        
            | :obj:`.getDestinations(ghidra.util.task.TaskMonitor)`
        """

    def getNumSources(self, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get the number of CodeBlocks that flow into this CodeBlock.
        Note that this is almost as much work as getting the actual source references.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: number of source CodeBlocks.
        :rtype: int
        :raises CancelledException: if the monitor cancels the operation.
        
        .. seealso::
        
            | :obj:`.getSources(ghidra.util.task.TaskMonitor)`
        """

    def getSources(self, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an Iterator over the CodeBlocks that flow into this CodeBlock.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: An iterator over CodeBlocks referencing this Block.
        :rtype: CodeBlockReferenceIterator
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getStartAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Get all the entry points to this block.  Depending on the
        model, there may be more than one entry point.
        Entry points will be returned in natural sorted order.
        
        :return: an array of entry points to this block.
        a zero length array if there are no entry points.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @property
    def startAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def sources(self) -> CodeBlockReferenceIterator:
        ...

    @property
    def firstStartAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def numDestinations(self) -> jpype.JInt:
        ...

    @property
    def destinations(self) -> CodeBlockReferenceIterator:
        ...

    @property
    def numSources(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def model(self) -> CodeBlockModel:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class MultEntSubModel(SubroutineBlockModel):
    """
    ``MultEntSubModel`` (M-model) defines subroutines which do not share code with
    any other subroutine and may have one or more entry points. Each entry-
    points represent either a source or called entry-point.
     
    
    MODEL-M subroutines should be used to determine which subroutine(s) contains
    a particular instruction.
    Since model-M subroutines yield the largest subroutines, they should be particular useful
    in the process of program slicing -- the process of splitting the program into modules
    or subroutine cliques -- in order to begin to understand the structure and functionality
    of the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Multiple Entry"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct a ``MultEntSubModel`` for a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a ``MultEntSubModel`` for a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        :param jpype.JBoolean or bool includeExternals: external blocks will be included if true
        """

    def getAddressSet(self, block: CodeBlock) -> ghidra.program.model.address.AddressSetView:
        """
        Compute an address set that represents all the addresses contained
        in all instructions that are part of this block
        
        :param CodeBlock block: code block to compute address set for.
        """

    def getCodeBlockAt(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the code block that has an entry point at addr.
        
        :param ghidra.program.model.address.Address addr: one of the entry points for a Model-M subroutine
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: null if there is no subroutine with an entry at addr.
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getCodeBlocks(self, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over the code blocks in the entire program.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[CodeBlock]:
        """
        Returns the one code block contained by addr (only for
        a model that has shared subroutines would this method
        return more than one code block)
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A CodeBlock if any block contains the address.
                empty array otherwise.
        :rtype: jpype.JArray[CodeBlock]
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over CodeBlocks which overlap the specified address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: an address set within program
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFirstCodeBlockContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the MultEntSubModel Code Block that contains the address.
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A CodeBlock if any block contains the address.
                null otherwise.
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFlowType(self, block: CodeBlock) -> ghidra.program.model.symbol.FlowType:
        """
        Return in general how things flow out of this node.
        This method exists for the SIMPLEBLOCK model.
        
         
        
        Since it doesn't make a great deal of sense to ask for this method
        in the case of subroutines, we return FlowType.UNKNOWN
        as long as the block exists.
        
         
        
        If this block has no valid instructions, it can't flow,
        so FlowType.INVALID is returned.
        
        :return: flow type of this node
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getListing(self) -> ghidra.program.model.listing.Listing:
        """
        Returns the listing associated with this block model.
        
        :return: the listing associated with this block model.
        :rtype: ghidra.program.model.listing.Listing
        """

    def getNumDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of destination references flowing out of this subroutine (block).
        All Calls from this block, and all external FlowType block references
        from this block are counted.
        
        :param CodeBlock block: code block to get the number of destination references from.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @property
    def codeBlocks(self) -> CodeBlockIterator:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def listing(self) -> ghidra.program.model.listing.Listing:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


@typing.type_check_only
class PartitionCodeSubIterator(CodeBlockIterator):
    """
    ``PartitionCodeSubIterator`` is an implementation of
    ``CodeBlockIterator`` capable of iterating in
    the forward direction over "PartitionCodeSubModel code blocks".
    """

    class_: typing.ClassVar[java.lang.Class]


class CodeBlockModel(java.lang.Object):
    """
    An implementation of a CodeBlockModel will produce CodeBlocks
    based on some algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]
    emptyBlockArray: typing.Final[jpype.JArray[CodeBlock]]

    def allowsBlockOverlap(self) -> bool:
        """
        Return true if this model allows overlapping of address sets for
        the blocks it returns.
        
        :return: true if this model allows overlapping of address sets for
                the blocks it returns.
                This implies that getBlocksContaining() can return more than one block.
                false implies that getBlocksContaining() will return at most one block.
        :rtype: bool
        """

    def externalsIncluded(self) -> bool:
        """
        Returns true if externals are handled by the model,
        false if externals are ignored.  When handled, externals
        are represented by an ExtCodeBlockImpl.
        """

    def getBasicBlockModel(self) -> CodeBlockModel:
        """
        Get the basic block model used by this model.
        """

    def getCodeBlockAt(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the code block with a starting address (i.e., entry-point) of addr.
        
        :param ghidra.program.model.address.Address addr: starting address of a codeblock.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: null if there is no codeblock starting at the address.
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getCodeBlocks(self, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over the code blocks in the entire program.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[CodeBlock]:
        """
        Get all the code blocks containing the address.
        
        :param ghidra.program.model.address.Address addr: address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: an array of blocks that contains the address, null otherwise.
        :rtype: jpype.JArray[CodeBlock]
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over code blocks which overlap the specified address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: an address set within program
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an iterator over the destination flows out of the block.
        
        :param CodeBlock block: the block to get the destination flows for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFirstCodeBlockContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the first code block that contains the given address.
        
        :param ghidra.program.model.address.Address addr: address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: a block that contains the address, or null otherwise.
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFlowType(self, block: CodeBlock) -> ghidra.program.model.symbol.FlowType:
        """
        Return in general how things flow out of this node.
        If there are any abnormal ways to flow out of this node,
        (ie: jump, call, etc...) then the flow type of the node
        takes on that type.
        If there are multiple unique ways out of the node, then we
        should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
        Fallthrough is returned if that is the only way out.
        
        :return: flow type of this node
        :rtype: ghidra.program.model.symbol.FlowType
        """

    @typing.overload
    def getName(self) -> str:
        """
        Returns the model name.
        
        :return: the model name
        :rtype: str
        """

    @typing.overload
    def getName(self, block: CodeBlock) -> str:
        """
        Get a name for this block.
        
        :return: usually the label at the start address of the block
            however the model can choose any name it wants for its blocks.
        :rtype: str
        """

    def getNumDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get the number of destination flows out of the block.
        
        :param CodeBlock block: the code blocks to get the destination flows for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getNumSources(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get the number of source flows into the block.
        
        :param CodeBlock block: the code blocks to get the destination flows for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program object associated with this CodeBlockModel instance.
        
        :return: program associated with this CodeBlockModel.
        :rtype: ghidra.program.model.listing.Program
        """

    def getSources(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an iterator over the source flows into the block.
        
        :param CodeBlock block: the block to get the destination flows for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @property
    def codeBlocks(self) -> CodeBlockIterator:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def basicBlockModel(self) -> CodeBlockModel:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class SingleEntSubIterator(CodeBlockIterator):
    """
    ``SingleEntSubIterator`` is an implementation of
    ``CodeBlockIterator`` capable of iterating in
    the forward direction over subroutine code blocks.
    This iterator supports subroutine models which allow only one
    called/source entry point within a subroutine and may
    share code with other subroutines produced by the same model.
    All entry points must be accounted for within M-Model subroutines.
    
    NOTE: This iterator only supports OverlapCodeSubModel block models
    and extensions.
    
    NOTE: If the containing M-model subroutine has two entry points, say
    A and B, such that the code traversed from A is identical to the code traversed
    by B (due to a cycle), then this iterator will include it twice rather than
    skipping over the identical address set.  This is because the iterator works by
    iterating through M-model subroutines, and wherever M-model subroutines have
    n > 1 multiple entry points, the iterator produces an O-model subroutine
    for every one of the entry points.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: OverlapCodeSubModel, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new iterator that will iterate over the entire
        program starting from its current minimum address.
        
        :param OverlapCodeSubModel model: the BlockModel the iterator will use in its operations.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def __init__(self, model: OverlapCodeSubModel, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new iterator that will iterate over the
        program within a given address range set. All blocks which 
        overlap the address set will be returned.
        
        :param OverlapCodeSubModel model: the BlockModel the iterator will use in its operations.
        :param ghidra.program.model.address.AddressSetView set: the address range set which the iterator is to be
                    restricted to.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """


class SubroutineSourceReferenceIterator(CodeBlockReferenceIterator):
    """
    SubroutineSourceReferenceIterator is a unidirectional iterator over 
    the source ``CodeBlockReference``s for a CodeBlock.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct an Iterator over Source blocks for a CodeBlock.
        
        :param CodeBlock block: block to get destination blocks for.  This should be a
        subroutine obtained from SubroutineBlockModel.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @staticmethod
    def getNumSources(block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of source references flowing from this subroutine (block).
        All Calls to this block, and all external FlowType block references
        to this block are counted.
        
        :param CodeBlock block: code block to get the number of source references to.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.hasNext()`
        """

    def next(self) -> CodeBlockReference:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.next()`
        """


class IsolatedEntrySubModel(OverlapCodeSubModel):
    """
    ``IsolatedEntryCodeSubModel`` (S-model) defines subroutines with a
    unique entry point, which may share code with other subroutines. Each entry-
    point may either be a source or called entry-point and is identified using
    the MultEntSubModel. This model extends the OverlapCodeSubModel, redefining
    the set of addresses contained within each subroutine. Unlike the
    OverlapCodeSubModel, the address set of a IsolatedEntryCodeSubModel
    subroutine is permitted to span entry-points of other subroutines based upon
    the possible flows from its entry- point.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockModel`
    
        | :obj:`ghidra.program.model.block.OverlapCodeSubModel`
    
        | :obj:`ghidra.program.model.block.MultEntSubModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    ISOLATED_MODEL_NAME: typing.Final = "Isolated Entry"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct a ``IsolatedEntrySubModel`` subroutine on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a ``IsolatedEntrySubModel`` subroutine on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        """


class SimpleBlockIterator(CodeBlockIterator):
    """
    ``SimpleBlockIterator`` is an implementation of
    ``CodeBlockIterator`` capable of iterating in
    the forward direction over "simple blocks".
    
    
    .. seealso::
    
        | :obj:`SimpleBlockModel`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: SimpleBlockModel, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new iterator that will iterate over the entire
        program starting from its current minimum address.
        
        :param SimpleBlockModel model: the BlockModel the iterator will use in its operations.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def __init__(self, model: SimpleBlockModel, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new iterator that will iterate over the
        program within a given address range set. All blocks which 
        overlap the address set will be returned.
        
        :param SimpleBlockModel model: the BlockModel the iterator will use in its operations.
        :param ghidra.program.model.address.AddressSetView set: the address range set which the iterator is to be
                    restricted to.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """


class SubroutineBlockModel(CodeBlockModel):
    """
    Subroutine block model.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseSubroutineModel(self) -> SubroutineBlockModel:
        """
        Get the underlying base subroutine model.
        This is generally the MultEntSubModel (M-Model).
        
        :return: base subroutine model.  If there is no base model,
        this subroutine model is returned.
        :rtype: SubroutineBlockModel
        """

    @property
    def baseSubroutineModel(self) -> SubroutineBlockModel:
        ...


class ExtCodeBlockImpl(ghidra.program.model.address.AddressSet, CodeBlock):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: CodeBlockModel, extAddr: ghidra.program.model.address.Address):
        ...


class SimpleDestReferenceIterator(CodeBlockReferenceIterator):
    """
    This iterator is implemented by getting the flows from the instruction
    and iterating over those flows (plus the fallthrough).  This is probably
    not the most efficient method.  An linked-list of references has to be created each
    time we want to get the destinations from a block.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, block: CodeBlock, followIndirectFlows: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct an Iterator over Destination blocks for a CodeBlock.
        External references are ignored.
        
        :param CodeBlock block: block to get destination blocks for.  This should be a
        block obtained from SimpleBlockModel.
        :param jpype.JBoolean or bool followIndirectFlows: indirect references will only be included if true
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @staticmethod
    @deprecated("this method should be avoided since it repeats the work of the iterator")
    def getNumDestinations(block: CodeBlock, followIndirectFlows: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of destination references flowing out of this block.
        All Calls from this block, and all external FlowType block references
        from this block are ignored.
        
        :param CodeBlock block: code block to get the number of destination references from.
        :param jpype.JBoolean or bool followIndirectFlows: indirect references will only be included if true
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        
        .. deprecated::
        
        this method should be avoided since it repeats the work of the iterator
        """

    def hasNext(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.hasNext()`
        """

    def next(self) -> CodeBlockReference:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.block.CodeBlockReferenceIterator.next()`
        """


class OverlapCodeSubModel(SubroutineBlockModel):
    """
    ``OverlapCodeSubModel`` (O-model) defines subroutines with a
    unique entry point, which may share code with other subroutines. Each entry-
    point may either be a source or called entry-point and is identified using
    the MultEntSubModel.  This model defines the set of addresses contained
    within each subroutine based upon the possible flows from its entry- point.
    Flows which encounter another entry-point are terminated.
     
    
    NOTE: This differs from the original definition of an entry point, however,
    the intent of the O-Model is preserved.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockModel`
    
        | :obj:`ghidra.program.model.block.MultEntSubModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    OVERLAP_MODEL_NAME: typing.Final = "Overlapped Code"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct a ``OverlapCodeSubModel`` subroutine on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a ``OverlapCodeSubModel`` subroutine on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        :param jpype.JBoolean or bool includeExternals: external blocks will be included if true
        """

    def getCodeBlocksContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[CodeBlock]:
        """
        Get all the Code Blocks containing the address.
        Model-O is the only of the MOP models that allows for there to be more than one
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A CodeBlock array with one entry containing the subroutine that
                    contains the address empty array otherwise.
        :rtype: jpype.JArray[CodeBlock]
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFlowType(self, block: CodeBlock) -> ghidra.program.model.symbol.FlowType:
        """
        Return in general how things flow out of this node.
        This method exists for the SIMPLEBLOCK model.
        
         
        
        Since it doesn't make a great deal of sense to ask for this method
        in the case of subroutines, we return FlowType.UNKNOWN
        as long as the block exists.
        
         
        
        If this block has no valid instructions, it can't flow,
        so FlowType.INVALID is returned.
        
        :return: flow type of this node
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getListing(self) -> ghidra.program.model.listing.Listing:
        """
        Returns the listing associated with this block model.
        
        :return: the listing associated with this block model
        :rtype: ghidra.program.model.listing.Listing
        """

    @property
    def listing(self) -> ghidra.program.model.listing.Listing:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class CodeBlockReference(java.lang.Object):
    """
    A CodeBlockReference represents the flow from one CodeBlock to another. Flow
    consists of: 
     
    * The source and destination CodeBlocks
    * The Type of flow (JMP, CALL, Fallthrough, etc...
    * The referent - the instruction's address in the source block that causes
    the flow
    * The reference - the address in the destination block that is flowed to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDestinationAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the Destination Block address.
        The destination address should only occur in one block.
        
        :return: the Destination Block address
        :rtype: ghidra.program.model.address.Address
        """

    def getDestinationBlock(self) -> CodeBlock:
        """
        Returns the Destination CodeBlock.
        
        :return: the Destination CodeBlock
        :rtype: CodeBlock
        """

    def getFlowType(self) -> ghidra.program.model.symbol.FlowType:
        """
        Returns the type of flow from the Source to the Destination CodeBlock.
        
        :return: the type of flow
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getReference(self) -> ghidra.program.model.address.Address:
        """
        Returns the address in the Destination block that is referenced by the Source block.
        
        :return: the address in the Destination block that is referenced by the Source block
        :rtype: ghidra.program.model.address.Address
        """

    def getReferent(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the instruction in the Source Block that refers to the Destination block.
        
        :return: the address of the instruction in the Source Block that refers to the Destination block
        :rtype: ghidra.program.model.address.Address
        """

    def getSourceAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the Source Block address.
        The source address should only occur in one block.
        
        :return: the Source Block address
        :rtype: ghidra.program.model.address.Address
        """

    def getSourceBlock(self) -> CodeBlock:
        """
        Returns the Source CodeBlock.
        
        :return: the Source CodeBlock
        :rtype: CodeBlock
        """

    @property
    def reference(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def sourceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def destinationBlock(self) -> CodeBlock:
        ...

    @property
    def destinationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def referent(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def sourceBlock(self) -> CodeBlock:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class CodeBlockReferenceImpl(CodeBlockReference):
    """
    CodeBlockReferenceImpl implements a CodeBlockReference.
     
    
    A ``CodeBlockReference`` represents the flow from one source block
    to a destination block, including information about how
    flow occurs between the two blocks (JUMP, CALL, etc..).
     
    
    The ``reference`` is the address in the destination
    block that is actually flowed to by some instruction in the source block.
     
    
    The ``referent`` is the address of the instruction in
    the source block that flows to the destination block.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockReference`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: CodeBlock, destination: CodeBlock, flowType: ghidra.program.model.symbol.FlowType, reference: ghidra.program.model.address.Address, referent: ghidra.program.model.address.Address):
        """
        Constructor for a CodeBlockReferenceImpl
        
        :param CodeBlock source: source block for this flow
        :param CodeBlock destination: destination block for this flow
        :param ghidra.program.model.symbol.FlowType flowType: how we flow
        :param ghidra.program.model.address.Address reference: reference address in destination block
        :param ghidra.program.model.address.Address referent: address of instruction in source block that flows to destination block.
        """


@typing.type_check_only
class MultEntSubIterator(CodeBlockIterator):
    """
    ``MultEntSubIterator`` is an implementation of
    ``CodeBlockIterator`` capable of iterating in
    the forward direction over subroutine code blocks.
    The iterator supports subroutine models which allow one or
    more called/source entry points within a subroutine and do not
    share code with other subroutines produced by the same model.
    """

    class_: typing.ClassVar[java.lang.Class]


class CodeBlockIterator(java.lang.Iterable[CodeBlock]):
    """
    An iterator interface over CodeBlocks.
     
     
    Note: this iterator is also :obj:`Iterable`.  The :meth:`hasNext() <.hasNext>` and :meth:`next() <.next>`
    methods of this interface throw a :obj:`CancelledException` if the monitor is cancelled.  The
    iterator returned from :meth:`iterator() <.iterator>` does **not** throw a cancelled exception.  If 
    you need to know the cancelled state of this iterator, then you must check the cancelled state
    of the monitor passed into this iterator via the :obj:`CodeBlockModel`.  See 
    :meth:`TaskMonitor.isCancelled() <TaskMonitor.isCancelled>`.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlock`
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Return true if next() will return a CodeBlock.
        
        :return: true if next() will return a CodeBlock.
        :rtype: bool
        :raises CancelledException: thrown if the operation is cancelled.
        """

    def next(self) -> CodeBlock:
        """
        Return the next CodeBlock.
        
        :return: the next CodeBlock.
        :rtype: CodeBlock
        :raises CancelledException: thrown if the operation is cancelled.
        """


class CodeBlockReferenceIterator(java.lang.Object):
    """
    An iterator interface over CodeBlockReferences.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockReference`
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Return true if next() will return a CodeBlockReference.
        
        :raises CancelledException: thrown if the operation is cancelled.
        """

    def next(self) -> CodeBlockReference:
        """
        Return the next CodeBlockReference.
        
        :raises CancelledException: thrown if the operation is cancelled.
        """


@typing.type_check_only
class CodeBlockCache(ghidra.program.model.address.AddressObjectMap):
    """
    Provides a subroutine cache implementation.
    
     
    Created: February 28, 2002
    """

    class_: typing.ClassVar[java.lang.Class]


class SimpleBlockModel(CodeBlockModel):
    """
    This BlockModel implements the simple block model.
    
    Each Codeblock is made up of contiguous instructions in address order.
    
    Blocks satisfy the following:
    1. Any instruction with a label starts a block.
    2. Each instruction that could cause program control flow to change is the
    last instruction of a Codeblock.
    3. All other instructions are "NOP" fallthroughs, meaning
    after execution the program counter will be at
    the instruction immediately following.
    4. Any instruction that is unreachable and has no label is also considered the start
    of a block.
    
    So a CodeBlock in this model consists of contiguous code that has zero or
    more nonflow fallthrough instructions followed by a single flow instruction.
    Each block may or may not have a label at the first instruction, but may not
    have a label at any other instruction contained in the block.
     
    
    This model does not implement the pure simple block model
    because unreachable code is still considered a block.
     
    
    This model handles delay slot instructions with the following 
    assumptions:
     
    1. A delayed instruction is always corresponds to a change in
    flow and terminates a block.  The delay slot instructions
    following this instruction are always included with the
    block.  Therefore, delay slot instructions will always fall
    at the bottom of a simple block.
    2. The delay slot depth of the delayed instruction will always
    correspond to the number of delay slot instructions immediately
    following the instruction. The model may not behave properly if
    the disassembled code violates this assumption.
    
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Simple Block"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct a SimpleBlockModel on a program.
        Externals will be excluded.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a SimpleBlockModel on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        :param jpype.JBoolean or bool includeExternals: externals will be included if true
        """

    def getCodeBlockAt(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the code/data block starting at this address.
        
        :param ghidra.program.model.address.Address addr: 
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: null if there is no codeblock starting at the address
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getCodeBlocks(self, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over the code blocks in the entire program.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[CodeBlock]:
        """
        Get all the Code Blocks containing the address.
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A SimpleBlock if any block contains the address
                empty array otherwise.
        :rtype: jpype.JArray[CodeBlock]
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over CodeBlocks which overlap the specified address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: an address set within program
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an iterator over destination blocks flowing from this block.
        
        :param CodeBlock block: code block to get the destination block iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFirstCodeBlockContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the First Code Block that contains the address.
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A SimpleBlock if any block contains the address.
                null otherwise.
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFlowType(self, block: CodeBlock) -> ghidra.program.model.symbol.FlowType:
        """
        Return in general how things flow out of this node.
        If there are any abnormal ways to flow out of this node,
        (ie: jump, call, etc...) then the flow type of the node
        takes on that type.
        
        If there are multiple unique ways out of the node, then we
        should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
        
        Fallthrough is returned if that is the only way out.
        
        If this block really has no valid instructions, it can't flow,
        so FlowType.INVALID is returned.
        
        :return: flow type of this node
        :rtype: ghidra.program.model.symbol.FlowType
        """

    @deprecated("this method should be avoided since it repeats the work of the getDestinations iterator")
    def getNumDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of destination blocks flowing out of this block
        
        :param CodeBlock block: code block to get the destination block iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        
        .. deprecated::
        
        this method should be avoided since it repeats the work of the getDestinations iterator
        """

    @deprecated("this method should be avoided since it repeats the work of the getSources iterator")
    def getNumSources(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of source blocks flowing into this block
        
        :param CodeBlock block: code block to get the source iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        
        .. deprecated::
        
        this method should be avoided since it repeats the work of the getSources iterator
        """

    def getSources(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an iterator over source blocks flowing into this block.
        
        :param CodeBlock block: code block to get the source iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def isBlockStart(self, instruction: ghidra.program.model.listing.Instruction) -> bool:
        """
        Check if the instruction starts a Simple block.
        
        :param ghidra.program.model.listing.Instruction instruction: instruction to test if it starts a block
        :return: true if this instruction is the start of a simple block.
        :rtype: bool
        """

    @property
    def blockStart(self) -> jpype.JBoolean:
        ...

    @property
    def codeBlocks(self) -> CodeBlockIterator:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class FollowFlow(java.lang.Object):
    """
    FollowFlow follows the program's code flow either forward or backward from an initial
    address set. It adds the flow addresses to the initial address set by flowing "from" the 
    initial addresses in the forward direction or by flowing "to" the initial addresses when
    used in the backward direction.
    The flow can be limited by indicating the flow types (i.e. unconditional call, 
    computed jump, etc.) that we do NOT want to follow.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSetView, doNotFollow: jpype.JArray[ghidra.program.model.symbol.FlowType]):
        """
        Constructor
         
        Note: flow into existing functions will be included
        Note: flow into un-disassembled locations will be included
        
        :param ghidra.program.model.listing.Program program: the program whose flow we are following.
        :param ghidra.program.model.address.AddressSetView addressSet: the initial addresses that should be flowed from or flowed to.
        :param jpype.JArray[ghidra.program.model.symbol.FlowType] doNotFollow: array of flow types that are not to be followed.
        null or empty array indicates follow all flows. The following are valid
        flow types for the doNotFollow array:
         
        FlowType.COMPUTED_CALL
         
        FlowType.CONDITIONAL_CALL
         
        FlowType.UNCONDITIONAL_CALL
         
        FlowType.COMPUTED_JUMP
         
        FlowType.CONDITIONAL_JUMP
         
        FlowType.UNCONDITIONAL_JUMP
         
        FlowType.INDIRECTION
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSetView, doNotFollow: jpype.JArray[ghidra.program.model.symbol.FlowType], followIntoFunctions: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
         
        Note: flow into un-disassembled locations will be included
        
        :param ghidra.program.model.listing.Program program: the program whose flow we are following.
        :param ghidra.program.model.address.AddressSetView addressSet: the initial addresses that should be flowed from or flowed to.
        :param jpype.JArray[ghidra.program.model.symbol.FlowType] doNotFollow: array of flow types that are not to be followed.
        null or empty array indicates follow all flows. The following are valid
        flow types for the doNotFollow array:
         
        FlowType.COMPUTED_CALL
         
        FlowType.CONDITIONAL_CALL
         
        FlowType.UNCONDITIONAL_CALL
         
        FlowType.COMPUTED_JUMP
         
        FlowType.CONDITIONAL_JUMP
         
        FlowType.UNCONDITIONAL_JUMP
         
        FlowType.INDIRECTION
        :param jpype.JBoolean or bool followIntoFunctions: true if flows into (or back from) defined functions
        should be followed.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSet, doNotFollow: jpype.JArray[ghidra.program.model.symbol.FlowType], followIntoFunctions: typing.Union[jpype.JBoolean, bool], includeData: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program whose flow we are following.
        :param ghidra.program.model.address.AddressSet addressSet: the initial addresses that should be flowed from or flowed to.
        :param jpype.JArray[ghidra.program.model.symbol.FlowType] doNotFollow: array of flow types that are not to be followed.
        null or empty array indicates follow all flows. The following are valid
        flow types for the doNotFollow array:
         
        FlowType.COMPUTED_CALL
         
        FlowType.CONDITIONAL_CALL
         
        FlowType.UNCONDITIONAL_CALL
         
        FlowType.COMPUTED_JUMP
         
        FlowType.CONDITIONAL_JUMP
         
        FlowType.UNCONDITIONAL_JUMP
         
        FlowType.INDIRECTION
        :param jpype.JBoolean or bool followIntoFunctions: true if flows into (or back from) defined functions
        should be followed.
        :param jpype.JBoolean or bool includeData: true if instruction flows into un-disassembled data should be included
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, doNotFollow: jpype.JArray[ghidra.program.model.symbol.FlowType], followIntoFunctions: typing.Union[jpype.JBoolean, bool], includeData: typing.Union[jpype.JBoolean, bool], restrictSingleAddressSpace: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program whose flow we are following.
        :param ghidra.program.model.address.Address address: the initial address that should be flowed from or flowed to.
        :param jpype.JArray[ghidra.program.model.symbol.FlowType] doNotFollow: array of flow types that are not to be followed.
        :param jpype.JBoolean or bool restrictSingleAddressSpace: if true collected flows should be restricted to
        a single address space identified by ``address``.
        null or empty array indicates follow all flows. The following are valid
        flow types for the doNotFollow array:
         
        FlowType.COMPUTED_CALL
         
        FlowType.CONDITIONAL_CALL
         
        FlowType.UNCONDITIONAL_CALL
         
        FlowType.COMPUTED_JUMP
         
        FlowType.CONDITIONAL_JUMP
         
        FlowType.UNCONDITIONAL_JUMP
         
        FlowType.INDIRECTION
        :param jpype.JBoolean or bool followIntoFunctions: true if flows into (or back from) defined functions
        should be followed.
        :param jpype.JBoolean or bool includeData: true if instruction flows into un-disassembled data should be included
        """

    def getFlowAddressSet(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSet:
        """
        Determines the address set that flows from the addresses in this FollowFlow object's
        initialAddresses set. The address set is determined by what addresses were provided 
        when the FollowFlow was constructed and the type of flow requested.
        This method follows flows in the forward direction.
        
        :param ghidra.util.task.TaskMonitor monitor: a cancellable task monitor, may be null
        :return: code unit flow represented by an address set as determined by the flow options.
        An empty address set will be returned if cancelled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getFlowToAddressSet(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSet:
        """
        Determines the address set that flows to the addresses in this FollowFlow object's
        initialAddresses set. The address set is determined by what addresses were provided 
        when the FollowFlow was constructed and the type of flow requested. The constructor
        indicated the flow types not to be followed. All others will be traversed in the
        backwards direction to determine the addresses that are flowing to those in the initial
        set.
        
        :param ghidra.util.task.TaskMonitor monitor: a cancellable task monitor, may be null
        :return: code unit flow represented by an address set as determined by the flow options.
        An empty address set will be returned if cancelled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @property
    def flowToAddressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def flowAddressSet(self) -> ghidra.program.model.address.AddressSet:
        ...


class BasicBlockModel(SimpleBlockModel):
    """
    This BlockModel implements the Basic block model.
    
    Each Codeblock is made up of contiguous instructions in address order.
    
    Blocks satisfy the following:
    1. Any instruction with a label starts a block.
    2. Each instruction that could cause program control flow to change local to 
    the containing function (i.e., excludes calls) is the last instruction of a Codeblock.
    3. All other instructions are "NOP" fallthroughs, meaning
    after execution the program counter will be at
    the instruction immediately following.
    4. Any instruction that is unreachable and has no label is also considered the start
    of a block.
    
    So a CodeBlock in this model consists of contiguous code that has zero or
    more fallthrough or call instructions followed by a single flow instruction.
    Each block may or may not have a label at the first instruction, but may not
    have a label at any other instruction contained in the block.
     
    This model handles delay slot instructions with the following 
    assumptions:
     
    1. The delay slot depth of the delayed instruction will always
    correspond to the number of delay slot instructions immediately
    following the instruction. The model may not behave properly if
    the disassembled code violates this assumption.
    
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockModel`
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Basic Block"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]):
        ...


class PartitionCodeSubModel(SubroutineBlockModel):
    """
    ``PartitionCodeSubModel`` (Model-P) defines subroutines which do not share code with
    other subroutines and may have one or more entry points.
    Entry points represent anyone of a variety of flow entries, including a source, called, jump or
    fall-through entry point.
     
    
    MODEL-P is the answer to those who always want to be able to know what subroutine
    a given instruction is in, but also do not want the subroutine to have multiple
    entry points.  When a model-M subroutine has multiple entry points,
    that set of code will necessarily consist of several model-P subroutines.  When
    a model-M subroutine has a single entry point, it will consist of a single model-P subroutine
    which has the same address set and entry point.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockModel`Created February 7, 2002.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Partitioned Code"

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct a Model-P subroutine on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a Model-P subroutine on a program.
        
        :param ghidra.program.model.listing.Program program: program to create blocks from.
        :param jpype.JBoolean or bool includeExternals: externals included if true
        """

    @typing.overload
    def getCodeBlocksContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[CodeBlock]:
        """
        Get all the Code Blocks containing the address.
        For model-P, there is only one.
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A CodeBlock array with one entry containing the subroutine that
                    contains the address null otherwise.
        :rtype: jpype.JArray[CodeBlock]
        :raises CancelledException: if the monitor cancels the operation.
        """

    @typing.overload
    def getCodeBlocksContaining(self, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockIterator:
        """
        Get an iterator over CodeBlocks which overlap the specified address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: an address set within program
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        """

    def getDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an iterator over destination blocks flowing from this block.
        
        :param CodeBlock block: code block to get the destination block iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFirstCodeBlockContaining(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> CodeBlock:
        """
        Get the (first) Model-P subroutine that contains the address.
        This is equivalent to getCodeBlocksContaining(addr) except that
        it doesn't return an array since model-P subroutines don't share code.
        
        :param ghidra.program.model.address.Address addr: Address to find a containing block.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :return: A CodeBlock if any block contains the address.
                empty array otherwise.
        :rtype: CodeBlock
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getFlowType(self, block: CodeBlock) -> ghidra.program.model.symbol.FlowType:
        """
        Return in general how things flow out of this node.
        This method exists for the SIMPLEBLOCK model.
        
         
        
        Since it doesn't make a great deal of sense to ask for this method
        in the case of subroutines, we return FlowType.UNKNOWN
        as long as the block exists.
        
        
         
        
        If this block has no valid instructions, it can't flow,
        so FlowType.INVALID is returned.
        
        
        :return: flow type of this node
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getListing(self) -> ghidra.program.model.listing.Listing:
        """
        Returns the listing associated with this block model.
        
        :return: the listing associated with this block model
        :rtype: ghidra.program.model.listing.Listing
        """

    def getNumDestinations(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of destination references flowing out of this subroutine (block).
        All Calls from this block, and all external FlowType block references
        from this block are counted.
        
        :param CodeBlock block: code block to get the number of destination references from.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getNumSources(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Get number of block source references flowing into this block.
        
        :param CodeBlock block: code block to get the source iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    def getSources(self, block: CodeBlock, monitor: ghidra.util.task.TaskMonitor) -> CodeBlockReferenceIterator:
        """
        Get an iterator over source blocks flowing into this block.
        
        :param CodeBlock block: code block to get the source iterator for.
        :param ghidra.util.task.TaskMonitor monitor: task monitor which allows user to cancel operation.
        :raises CancelledException: if the monitor cancels the operation.
        """

    @property
    def listing(self) -> ghidra.program.model.listing.Listing:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...



__all__ = ["CodeBlockImpl", "SubroutineDestReferenceIterator", "SimpleSourceReferenceIterator", "EmptyCodeBlockReferenceIterator", "CodeBlock", "MultEntSubModel", "PartitionCodeSubIterator", "CodeBlockModel", "SingleEntSubIterator", "SubroutineSourceReferenceIterator", "IsolatedEntrySubModel", "SimpleBlockIterator", "SubroutineBlockModel", "ExtCodeBlockImpl", "SimpleDestReferenceIterator", "OverlapCodeSubModel", "CodeBlockReference", "CodeBlockReferenceImpl", "MultEntSubIterator", "CodeBlockIterator", "CodeBlockReferenceIterator", "CodeBlockCache", "SimpleBlockModel", "FollowFlow", "BasicBlockModel", "PartitionCodeSubModel"]
