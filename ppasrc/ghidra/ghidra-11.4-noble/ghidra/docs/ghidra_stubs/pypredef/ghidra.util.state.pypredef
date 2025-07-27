from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class FunctionAnalyzer(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dataReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], storageVarnode: ghidra.program.model.pcode.Varnode, refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        """
        Callback indicating that an absolute memory reference was encountered
        
        :param ghidra.program.model.pcode.PcodeOp op: pcode operation
        :param jpype.JInt or int instrOpIndex: opIndex associated with reference or -1 if it could not be determined
        :param ghidra.program.model.pcode.Varnode storageVarnode: absolute storage Varnode
        :param ghidra.program.model.symbol.RefType refType: read/write/data reference type
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if callback canceled by monitor
        """

    def indirectDataReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], offsetVarnode: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int], storageSpaceID: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        """
        Callback indicating that an indirect/computed memory reference was encountered using an indirect/computed offset
        
        :param ghidra.program.model.pcode.PcodeOp op: pcode operation
        :param jpype.JInt or int instrOpIndex: opIndex associated with reference or -1 if it could not be determined
        :param ghidra.program.model.pcode.Varnode offsetVarnode: indirect/computed offset
        :param jpype.JInt or int size: access size or -1 if not applicable
        :param jpype.JInt or int storageSpaceID: storage space ID
        :param ghidra.program.model.symbol.RefType refType: read/write/data reference type
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if callback canceled by monitor
        """

    def resolvedFlow(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], destAddr: ghidra.program.model.address.Address, currentState: ContextState, results: ResultsState, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Callback indicating that a call/branch destination was identified.  
        Analyzer should create reference if appropriate
        Keep in mind that there could be other unidentified destinations.
        
        :param ghidra.program.model.pcode.PcodeOp op: branch or call flow operation
        :param jpype.JInt or int instrOpIndex: opIndex associated with reference or -1 if it could not be determined
        :param ghidra.program.model.address.Address destAddr: destination address
        :param ResultsState results: contains previous states leading upto the currentState
        :param ContextState currentState: current state at the branch/call
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if destination should be disassembled if not already
        :rtype: bool
        :raises CancelledException: if callback canceled by monitor
        """

    @typing.overload
    def stackReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], storageSpaceID: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        """
        Callback indicating that an absolute stack reference was encountered.  A non-load/store
        operation will have a -1 for both storageSpaceId and size.
        
        :param ghidra.program.model.pcode.PcodeOp op: pcode operation
        :param jpype.JInt or int instrOpIndex: opIndex associated with reference or -1 if it could not be determined
        :param jpype.JInt or int stackOffset: stack offset
        :param jpype.JInt or int size: access size or -1 if not applicable
        :param jpype.JInt or int storageSpaceID: storage space ID or -1 if not applicable
        :param ghidra.program.model.symbol.RefType refType: read/write/data reference type
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if callback canceled by monitor
        """

    @typing.overload
    def stackReference(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], computedStackOffset: VarnodeOperation, size: typing.Union[jpype.JInt, int], storageSpaceID: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, monitor: ghidra.util.task.TaskMonitor):
        """
        Callback indicating that a computed stack reference was encountered.  A non-load/store
        operation will have a -1 for both storageSpaceId and size.
        
        :param ghidra.program.model.pcode.PcodeOp op: pcode operation
        :param jpype.JInt or int instrOpIndex: opIndex associated with reference or -1 if it could not be determined
        :param VarnodeOperation computedStackOffset: stack offset computation (i.e., VarnodeOperation w/ stack pointer)
        :param jpype.JInt or int size: access size or -1 if not applicable
        :param jpype.JInt or int storageSpaceID: storage space ID or -1 if not applicable
        :param ghidra.program.model.symbol.RefType refType: read/write/data reference type
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if callback canceled by monitor
        """

    def unresolvedIndirectFlow(self, op: ghidra.program.model.pcode.PcodeOp, instrOpIndex: typing.Union[jpype.JInt, int], destination: ghidra.program.model.pcode.Varnode, currentState: ContextState, results: ResultsState, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Callback indicating that a computed call/branch destination was not resolved.
        
        :param ghidra.program.model.pcode.PcodeOp op: indirect branch or call flow operation
        :param jpype.JInt or int instrOpIndex: opIndex associated with reference or -1 if it could not be determined
        :param ghidra.program.model.pcode.Varnode destination: destination identified as a Varnode (may be an expression represented by
        a :obj:`VarnodeOperation`
        :param ResultsState results: contains previous states leading upto the currentState
        :param ContextState currentState: current state at the branch/call
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: list of resolved destinations which should be used or null.  List of destination
        addresses will trigger disassembly where necessary.
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises CancelledException: if callback cancelled by monitor
        """


class VarnodeOperation(ghidra.program.model.pcode.Varnode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pcodeOp: ghidra.program.model.pcode.PcodeOp, inputValues: jpype.JArray[ghidra.program.model.pcode.Varnode]):
        ...

    def getInputValues(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    def getPCodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    def isSimplified(self) -> bool:
        ...

    def setSimplified(self, simplified: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def simplified(self) -> jpype.JBoolean:
        ...

    @simplified.setter
    def simplified(self, value: jpype.JBoolean):
        ...

    @property
    def pCodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
        ...

    @property
    def inputValues(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...


class ContextState(java.lang.Object):

    @typing.type_check_only
    class FrameNode(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MaskedVarnodeOperation(ghidra.program.model.pcode.Varnode):
        """
        MaskedVarnodeOperation provides a wrapper for VarnodeOperation objects
        to specify an affective mask/shift of a larger-than-byte operation.
        The object are not intended for internal use only and must not be used
        as a key value.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MemoryByteVarnode(ghidra.program.model.pcode.Varnode):
        """
        MemoryByteVarnode provides an indication that this
        constant varnode was speculatively loaded from program memory.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, val: typing.Union[jpype.JByte, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entryPt: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program):
        """
        Constructs an empty state.
        
        :param ghidra.program.model.address.Address entryPt: the entry point for the context state
        :param ghidra.program.model.listing.Program program: the program
        """

    @typing.overload
    def __init__(self, entryPt: ghidra.program.model.address.Address, programCtx: ghidra.program.model.listing.ProgramContext, program: ghidra.program.model.listing.Program):
        """
        Constructs an empty state.
        
        :param ghidra.program.model.address.Address entryPt: the entry point for the context state
        :param ghidra.program.model.listing.ProgramContext programCtx: initial program context or null
        :param ghidra.program.model.listing.Program program: the program
        """

    @typing.overload
    def __init__(self, pcodeEntry: ghidra.program.model.pcode.SequenceNumber, previousState: ContextState):
        """
        Derive a new context state from an initial state
        
        :param ghidra.program.model.pcode.SequenceNumber pcodeEntry: the pcode entry sequence number
        :param ContextState previousState: previous context state flowing into the specified pcode location
        """

    def branchState(self, pcodeEntry: ghidra.program.model.pcode.SequenceNumber) -> ContextState:
        """
        Branch the current state.  The current state should be associated with
        branch target, the returned state should be used for the fall-through flow.
        
        :return: 
        :rtype: ContextState
        """

    def clearUniqueState(self) -> java.util.HashMap[java.lang.Long, ghidra.program.model.pcode.Varnode]:
        """
        When done processing a particular instruction, this method should be invoked to 
        clear any unique Varnode state.
        
        :return: previous unique state
        :rtype: java.util.HashMap[java.lang.Long, ghidra.program.model.pcode.Varnode]
        """

    @typing.overload
    def get(self, spaceID: typing.Union[jpype.JInt, int], offsetValue: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        """
        Retrieve the value/operation stored within the specified space using an offset
        identified by a value/operation.
        
        :param jpype.JInt or int spaceID: 
        :param ghidra.program.model.pcode.Varnode offsetValue: 
        :param jpype.JInt or int size: 
        :return: stored value/operation or null or DUMMY_BYTE_VARNODE
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @typing.overload
    def get(self, spaceID: typing.Union[jpype.JInt, int], offsetValue: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.pcode.Varnode:
        """
        Retrieve the value/operation stored within the specified space using an offset
        identified by a value/operation.
        
        :param jpype.JInt or int spaceID: 
        :param ghidra.program.model.pcode.Varnode offsetValue: 
        :param jpype.JInt or int size: 
        :return: stored value/operation or null or DUMMY_BYTE_VARNODE
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @typing.overload
    def get(self, varnode: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.pcode.Varnode:
        """
        Retrieve the value/operation stored in the specified addressable location (address or register varnode).
        If varnode is a constant, the input argument will be returned.
        Unique varnodes not permitted once locked.
        
        :param ghidra.program.model.pcode.Varnode varnode: identifies constant or storage (constant, address, register or unique), if VarnodeOperation
        specified null will always be returned.
        :return: stored value/operation
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @typing.overload
    def get(self, varnode: ghidra.program.model.pcode.Varnode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.pcode.Varnode:
        """
        Retrieve the value/operation stored in the specified addressable location (address or register varnode).
        If varnode is a constant, the input argument will be returned.
        Unique varnodes not permitted once locked.
        
        :param ghidra.program.model.pcode.Varnode varnode: identifies constant or storage (constant, address, register or unique), if VarnodeOperation
        specified null will always be returned.
        :return: stored value/operation
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def getDifferingRegisters(self, other: ContextState) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    def getEntryPoint(self) -> ghidra.program.model.pcode.SequenceNumber:
        """
        Returns the point at which the state was instantiated.
        """

    def getExitPoint(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    def getFlowFroms(self) -> java.util.Set[ghidra.program.model.pcode.SequenceNumber]:
        ...

    def getPreviousContextState(self) -> ContextState:
        """
        Returns previous ContextState which flowed into this one.
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns program associated with this context state
        """

    def getSequenceRange(self) -> SequenceRange:
        ...

    def hasDifferingRegisters(self, other: ContextState) -> bool:
        ...

    def isFlowFrom(self, seq: ghidra.program.model.pcode.SequenceNumber) -> bool:
        ...

    def lock(self):
        """
        When no longer updating this state, this method should be invoked to
        cleanup resources no longer needed (e.g., uniqueState no longer 
        maintained).
        """

    def setDebugVarnod(self, varnode: ghidra.program.model.pcode.Varnode):
        """
        Set a varnode to be debugged.  This will be passed to any states 
        derived from this state.
        
        :param ghidra.program.model.pcode.Varnode varnode: varnode to be debugged
        """

    @typing.overload
    def store(self, spaceID: typing.Union[jpype.JInt, int], offsetValue: ghidra.program.model.pcode.Varnode, storedValue: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @typing.overload
    def store(self, addressVarnode: ghidra.program.model.pcode.Varnode, storedValue: ghidra.program.model.pcode.Varnode):
        """
        Store a value.  Unique varnodes not permitted once locked.
        
        :param ghidra.program.model.pcode.Varnode addressVarnode: identifies storage (address, register or unique)
        :param ghidra.program.model.pcode.Varnode storedValue: constant or OperationVarnode
        """

    @property
    def previousContextState(self) -> ContextState:
        ...

    @property
    def sequenceRange(self) -> SequenceRange:
        ...

    @property
    def differingRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def flowFrom(self) -> jpype.JBoolean:
        ...

    @property
    def exitPoint(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def entryPoint(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    @property
    def flowFroms(self) -> java.util.Set[ghidra.program.model.pcode.SequenceNumber]:
        ...


class SequenceRange(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: ghidra.program.model.pcode.SequenceNumber, end: ghidra.program.model.pcode.SequenceNumber):
        ...

    def contains(self, seq: ghidra.program.model.pcode.SequenceNumber) -> bool:
        ...

    def getEnd(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    def getStart(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    @property
    def start(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    @property
    def end(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...


class ResultsState(java.lang.Object):

    @typing.type_check_only
    class BranchDestination(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ContextStateSet(java.util.HashMap[ghidra.program.model.pcode.SequenceNumber, ContextState]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InlineCallException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, destAddr: ghidra.program.model.address.Address):
            ...

        def getInlineCallAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def inlineCallAddress(self) -> ghidra.program.model.address.Address:
            ...


    class FramePointerCandidate(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        register: typing.Final[ghidra.program.model.lang.Register]
        assignedAt: typing.Final[ghidra.program.model.pcode.SequenceNumber]
        value: typing.Final[ghidra.program.model.pcode.Varnode]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entryPt: ghidra.program.model.address.Address, analyzer: FunctionAnalyzer, program: ghidra.program.model.listing.Program, maintainInstructionResults: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor from a function entry point.  Program context is used to establish the entry context state.
        Analysis is performed during construction.
        
        :param ghidra.program.model.address.Address entryPt: function entry point
        :param FunctionAnalyzer analyzer: function analysis call-back handler
        :param ghidra.program.model.listing.Program program: program containing function
        :param jpype.JBoolean or bool maintainInstructionResults: true to maintain the instruction results
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException:
        """

    @typing.overload
    def __init__(self, flowList: java.util.LinkedList[ghidra.program.model.pcode.SequenceNumber], analyzer: FunctionAnalyzer, entryState: ContextState, maintainInstructionResults: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor for replaying over a specified set of context states indicated via a flowList.
        Analysis is performed during construction.
        
        :param java.util.LinkedList[ghidra.program.model.pcode.SequenceNumber] flowList: ordered list of context state entry points
        :param FunctionAnalyzer analyzer: function analysis call-back handler
        :param ContextState entryState: context state which feeds into the first point within the flowList
        :param jpype.JBoolean or bool maintainInstructionResults: 
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException:
        """

    def assume(self, register: ghidra.program.model.lang.Register, value: typing.Union[jpype.JLong, int]):
        """
        Set an assumed register value immediately following construction and prior to flow.
        
        :param ghidra.program.model.lang.Register register: (context register not permitted)
        :param jpype.JLong or int value:
        """

    def getContextStates(self, seq: ghidra.program.model.pcode.SequenceNumber) -> java.util.Iterator[ContextState]:
        ...

    def getEntryPoint(self) -> ghidra.program.model.pcode.SequenceNumber:
        """
        Returns entry point associated with this results state.
        """

    def getExaminedSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns set of addresses analyzed with function.
        (In-line functions not included)
        """

    def getFramePointerCandidates(self) -> java.util.Collection[ResultsState.FramePointerCandidate]:
        """
        Returns collection of frame pointer candidates.
        """

    def getInputRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Returns list of registers which are read before written.
        """

    def getModifiedRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Returns the set of registers which were modified
        """

    def getPreservedRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Returns the set of registers which were modified yet preserved.
        """

    def getReturnAddresses(self) -> java.util.Set[ghidra.program.model.pcode.SequenceNumber]:
        ...

    def getReturnValues(self, varnode: ghidra.program.model.pcode.Varnode) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @staticmethod
    def getSignedOffset(v: ghidra.program.model.pcode.Varnode) -> int:
        ...

    def getStackPointerVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        
        
        :return: Varnode that represents the stack pointer register
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @staticmethod
    def getUnsignedOffset(v: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def simplify(pcodeOp: ghidra.program.model.pcode.PcodeOp, values: jpype.JArray[ghidra.program.model.pcode.Varnode], addrFactory: ghidra.program.model.address.AddressFactory, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.pcode.Varnode:
        """
        Generate simplified operation
        
        :param ghidra.program.model.pcode.PcodeOp pcodeOp: pcode operation
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] values: values associated with pcodeOp inputs
        :return: operation output result or simplification of an operation.
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @property
    def returnValues(self) -> java.util.Set[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def modifiedRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def stackPointerVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def framePointerCandidates(self) -> java.util.Collection[ResultsState.FramePointerCandidate]:
        ...

    @property
    def contextStates(self) -> java.util.Iterator[ContextState]:
        ...

    @property
    def inputRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def examinedSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def entryPoint(self) -> ghidra.program.model.pcode.SequenceNumber:
        ...

    @property
    def returnAddresses(self) -> java.util.Set[ghidra.program.model.pcode.SequenceNumber]:
        ...

    @property
    def preservedRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...



__all__ = ["FunctionAnalyzer", "VarnodeOperation", "ContextState", "SequenceRange", "ResultsState"]
