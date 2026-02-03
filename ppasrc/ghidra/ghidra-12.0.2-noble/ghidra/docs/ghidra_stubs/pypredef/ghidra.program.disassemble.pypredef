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
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


@typing.type_check_only
class DisassemblerQueue(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DisassemblerContextImpl(ghidra.program.model.lang.DisassemblerContext):
    """
    Maintains processor state information during disassembly and analysis.  Tracks register state 
    associated with instruction flows.  Within this context, a flow is defined as a contiguous
    range of instructions.  Also, this context provides storage for context states at future flow
    addresses, which will be used when subsequent flowTo(Address) or flowStart(Address) calls 
    are made with those addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, programContext: ghidra.program.model.listing.ProgramContext):
        """
        Constructor for DisassemblerContext.
        
        :param ghidra.program.model.listing.ProgramContext programContext: contains the values for registers at specific addresses store in the program.
        """

    @typing.overload
    def copyToFutureFlowState(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Saves the current processor state for when this context flows to the given address.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.address.Address address: the address at which to save the current processor state.
        :return: context register value which was copied
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def copyToFutureFlowState(self, fromAddr: ghidra.program.model.address.Address, destAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Saves the current processor state flowing from the fromAddr, for when this context flows to the given address.
        
        :param ghidra.program.model.address.Address fromAddr: the address from which this flow originates.
        :param ghidra.program.model.address.Address destAddr: the address at which to save the current processor state.
        :return: context register value which was copied
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def flowAbort(self):
        """
        Terminate active flow while preserving any accumulated future context.
        Any context commits resulting from a flowToAddress or flowEnd will be 
        unaffected.
        """

    def flowEnd(self, maxAddress: ghidra.program.model.address.Address):
        """
        Ends the current flow.  Unsaved register values will be saved up to and including max address.
        
        :param ghidra.program.model.address.Address maxAddress: the maximum address of an instruction flow.  If maxAddress is null,
        or the current flow address has already advanced beyond maxAddress, then no save is performed.
        :raises IllegalStateException: if a flow has not been started.
        """

    @typing.overload
    def flowStart(self, address: ghidra.program.model.address.Address):
        """
        Starts a new flow. Initializes the current state for all registers using any future flow state
        that has been set.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.address.Address address: the starting address of a new instruction flow.
        :raises IllegalStateException: if a previous flow was not ended.
        """

    @typing.overload
    def flowStart(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address):
        """
        Starts a new flow from an address to the new start.
        Initializes the current state for all registers using any future flow state
        that has been set flowing from the fromAddr.
        
        :param ghidra.program.model.address.Address fromAddr: address that this flow is flowing from.
        :param ghidra.program.model.address.Address toAddr: the starting address of a new instruction flow.
        :raises IllegalStateException: if a previous flow was not ended.
        """

    @typing.overload
    def flowToAddress(self, address: ghidra.program.model.address.Address):
        """
        Continues the current flow at the given address.  Checks for register values that have been
        stored in the future flow state.  If any registers have saved future state, the current state
        for all registers is written to the program context upto the specified address(exclusive).
        The future flow state values are then loaded into the current context.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.address.Address address: the address to flow to.
        :raises IllegalStateException: if no flow was started.
        """

    @typing.overload
    def flowToAddress(self, fromAddr: ghidra.program.model.address.Address, destAddr: ghidra.program.model.address.Address):
        """
        Continues the current flow from an address to the given address.  Checks for register values that have been
        stored in the future flow state.  If any registers have saved future state, the current state
        for all registers is written to the program context upto the specified address(exclusive).
        The future flow state values are then loaded into the current context.
        
        :param ghidra.program.model.address.Address fromAddr: address that this flow is flowing from.
        :param ghidra.program.model.address.Address destAddr: the starting address of a new instruction flow.
        :raises IllegalStateException: if a previous flow was not ended.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the current flow address for this context.
        """

    @typing.overload
    def getFlowContextValue(self, destAddr: ghidra.program.model.address.Address, isFallThrough: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.lang.RegisterValue:
        """
        Get flowed context value at arbitrary destination address without affecting state.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.address.Address destAddr: 
        :param jpype.JBoolean or bool isFallThrough: 
        :return: the flowed context value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getFlowContextValue(self, fromAddr: ghidra.program.model.address.Address, destAddr: ghidra.program.model.address.Address, isFallThrough: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.lang.RegisterValue:
        """
        Get flowed context value at a destination address, that has been flowed from the fromAddr, without affecting state.
        
        :param ghidra.program.model.address.Address fromAddr: address that this flow is flowing from.
        :param ghidra.program.model.address.Address destAddr: the starting address of a new instruction flow.
        :raises IllegalStateException: if a previous flow was not ended.
        """

    def getKnownFlowToAddresses(self, toAddr: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Returns an array of locations that have values that will flow to this location
        
        :param ghidra.program.model.address.Address toAddr: address that is the target of a flow to
        :return: and array of known address flows to this location
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    def getProgramContext(self) -> ghidra.program.model.listing.ProgramContext:
        ...

    @typing.overload
    def getRegisterValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the future RegisterValue at the specified address.  If no future value is stored,
        it will return the value stored in the program. The value returned may not have a complete
        value for the requested register.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.lang.Register register: the register to get a value for.
        :param ghidra.program.model.address.Address address: the address at which to get a value.
        :return: a RegisterValue object if one has been stored in the future flow or the program.
        The RegisterValue object may have a "no value" state for the bits specified by the given register.
        Also, null may be returned if no value have been stored.
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getRegisterValue(self, register: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, destAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the future RegisterValue at the specified address that occurred because of a flow from
        the fromAddr.  If no future value is stored, it will return the value stored in the program.
        The value returned may not have a complete value for the requested register.
        
        :param ghidra.program.model.lang.Register register: the register to get a value for.
        :param ghidra.program.model.address.Address fromAddr: the address from which the flow originated
        :param ghidra.program.model.address.Address destAddr: the address at which to get a value.
        :return: a RegisterValue object if one has been stored in the future flow or the program.
        The RegisterValue object may have a "no value" state for the bits specified by the given register.
        Also, null may be returned if no value have been stored.
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address, signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Returns the future register value at the specified address.  If no future value is stored,
        it will return the value stored in the program.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.lang.Register register: the register to get a value for.
        :param ghidra.program.model.address.Address address: the address at which to get a value.
        :param jpype.JBoolean or bool signed: if true, interpret the value as signed.
        :return: the value of the register at the location, or null if a full value is not established.
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def getValue(self, register: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Returns the future register value at the specified address that occurred because of a flow
        from the fromAddr.  If no future value is stored, it will return the value stored in the program.
        
        :param ghidra.program.model.lang.Register register: the register to get a value for.
        :param ghidra.program.model.address.Address fromAddr: the address from which this flow originated.
        :param ghidra.program.model.address.Address toAddr: the future flow address to save the value.
        :param jpype.JBoolean or bool signed: if true, interpret the value as signed.
        :return: the value of the register at the location, or null if a full value is not established.
        :rtype: java.math.BigInteger
        """

    def isFlowActive(self) -> bool:
        """
        Returns true if a flow has been started and not yet ended.
        
        :return: true if a flow has been started and not yet ended.
        :rtype: bool
        """

    @typing.overload
    def mergeToFutureFlowState(self, address: ghidra.program.model.address.Address) -> java.util.ArrayList[ghidra.program.model.lang.RegisterValue]:
        """
        Saves the current processor state for when this context is later used at the given address.
        If the address already has a value, return the value on a collision list!
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.address.Address address: the address at which to save the current processor state.
        """

    @typing.overload
    def mergeToFutureFlowState(self, fromAddr: ghidra.program.model.address.Address, destAddr: ghidra.program.model.address.Address) -> java.util.ArrayList[ghidra.program.model.lang.RegisterValue]:
        """
        Saves the current processor state flowing from the fromAddr to the destAddr for when this context is later used.
        If the address already has a value, return the value on a collision list!
        
        :param ghidra.program.model.address.Address fromAddr: the address from which this flow originated
        :param ghidra.program.model.address.Address destAddr: the address at which to save the current processor state.
        """

    @typing.overload
    def setContextRegisterValue(self, value: ghidra.program.model.lang.RegisterValue, address: ghidra.program.model.address.Address):
        """
        Modify the current context register value at the specified address.  If current 
        disassembly flow address equals specified address the current disassembly context 
        will be changed, otherwise the future flow state will be changed. This differs from 
        :meth:`setValue(Register, Address, BigInteger) <.setValue>` in that is can affect the current 
        context state at the current address in a non-delayed fashion.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.lang.RegisterValue value: register value
        :param ghidra.program.model.address.Address address: disassembly address
        """

    @typing.overload
    def setContextRegisterValue(self, value: ghidra.program.model.lang.RegisterValue, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address):
        """
        Modify the current context register value at the specified address.  If current 
        disassembly toAddr address equals specified address the current disassembly context 
        will be changed, otherwise the future flow state flowing from the fromAddr will be changed.
        This differs from :meth:`setValue(Register, Address, BigInteger) <.setValue>` in that is can
        affect the current context state at the current address in a non-delayed fashion.
        
        :param ghidra.program.model.lang.RegisterValue value: register value
        :param ghidra.program.model.address.Address fromAddr: the address from which this flow originated
        :param ghidra.program.model.address.Address toAddr: the future flow address to save the value.
        """

    @typing.overload
    def setValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address, newValue: java.math.BigInteger):
        """
        Sets the value for the given register to be used when the flow advances to the given address
        using either the flowTo() or flowStart() methods.  The new value has precedence over any
        existing value.
         
        Use this method if keeping separate flows from different flow from addresses is not important.
        
        :param ghidra.program.model.lang.Register register: the register for which the value is to be saved.
        :param ghidra.program.model.address.Address address: the future flow address to save the value.
        :param java.math.BigInteger newValue: the value to save for future flow.
        """

    @typing.overload
    def setValue(self, register: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, newValue: java.math.BigInteger):
        """
        Sets the value for the given register to be used when the flow advances to the given address
        using either the flowTo() or flowStart() methods.  The new value has precedence over any
        existing value.
        
        :param ghidra.program.model.lang.Register register: the register for which the value is to be saved.
        :param ghidra.program.model.address.Address fromAddr: the address from which this flow originated
        :param ghidra.program.model.address.Address toAddr: the future flow address to save the value.
        :param java.math.BigInteger newValue: the value to save for future flow.
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def programContext(self) -> ghidra.program.model.listing.ProgramContext:
        ...

    @property
    def flowActive(self) -> jpype.JBoolean:
        ...

    @property
    def knownFlowToAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...


class ReDisassembler(java.lang.Object):
    """
    A class that re-disassembles where necessary
     
     
    
    Given a seed address, this will (re-)disassemble the instruction at that address. If it indicates
    any context changes, whether via ``globalset`` or fall-through, the affected addresses are
    considered for re-disassembly as well. If no instruction exists at the address, or an off-cut
    instruction exists at the address, the address is dropped, but the outgoing context is recorded.
    If one does exist, but its context is already the same, the address is dropped. Otherwise, it is
    queued up and the process repeats.
    """

    @typing.type_check_only
    class FlowType(java.lang.Enum[ReDisassembler.FlowType]):

        class_: typing.ClassVar[java.lang.Class]
        SEED: typing.Final[ReDisassembler.FlowType]
        FALLTHROUGH: typing.Final[ReDisassembler.FlowType]
        BRANCH: typing.Final[ReDisassembler.FlowType]
        GLOBALSET: typing.Final[ReDisassembler.FlowType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ReDisassembler.FlowType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ReDisassembler.FlowType]:
            ...


    @typing.type_check_only
    class Flow(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.address.Address:
            ...

        def hashCode(self) -> int:
            ...

        def to(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> ReDisassembler.FlowType:
            ...


    @typing.type_check_only
    class ReDisState(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, monitor: ghidra.util.task.TaskMonitor):
            ...

        def writeContext(self):
            ...


    @typing.type_check_only
    class ReDisBlock(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, state: ReDisassembler.ReDisState, entry: ReDisassembler.Flow):
            ...


    @typing.type_check_only
    class ReDisassemblerContext(ghidra.program.model.lang.DisassemblerContextAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, state: ReDisassembler.ReDisState, flow: ReDisassembler.Flow):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def disasemble(self, seed: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        ...


class Disassembler(DisassemblerConflictHandler):
    """
    Class to perform disassembly.  Contains the logic to follow instruction
    flows to continue the disassembly.
    17-Nov-2008: moved to ghidra.program.disassemble package since this is now used during 
                            language upgrades which may occur during construction of ProgramDB.
    12-Dec-2012: major refactor of disassembly to perform bulk add of instructions to 
    program to avoid context related conflicts
    """

    @typing.type_check_only
    class DisassemblerProgramContext(ghidra.program.util.AbstractProgramContext):
        """
        ``DisassemblerProgramContext`` is used as a proxy program context due to the 
        delayed nature of laying down instructions and their associated context state.
        This is used to track context not yet committed for use by the DisassemblerContext 
        in place of the true program context.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InstructionContext(ghidra.program.model.lang.ProcessorContext):
        """
        InstructionContext is an immutable context for use when minting pseudo instructions.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MARK_BAD_INSTRUCTION_PROPERTY: typing.Final = "Mark Bad Disassembly"
    """
    ``MARK_BAD_INSTRUCTION_PROPERTY`` Program Disassembler property 
    enables marking of instruction disassembly errors.  Boolean property is defined
    within the Disassembler property list, see :obj:`Program.DISASSEMBLER_PROPERTIES`.
    """

    MARK_UNIMPL_PCODE_PROPERTY: typing.Final = "Mark Unimplemented Pcode"
    """
    ``MARK_UNIMPL_PCODE_PROPERTY`` Program Disassembler property 
    enables marking of instructions which are missing their pcode implementation.  
    Boolean property is defined within the Disassembler property list, see 
    :obj:`Program.DISASSEMBLER_PROPERTIES`.
    """

    RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY: typing.Final = "Restrict Disassembly to Executable Memory"
    """
    ``RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY`` Program Disassembler property 
    restricts disassembly to executable memory only.  
    Boolean property is defined within the Disassembler property list, see 
    :obj:`Program.DISASSEMBLER_PROPERTIES`.
    """

    ERROR_BOOKMARK_CATEGORY: typing.Final = "Bad Instruction"
    UNIMPL_BOOKMARK_CATEGORY: typing.Final = "Unimplemented Pcode"
    MAX_REPEAT_PATTERN_LENGTH: typing.Final = 16

    @staticmethod
    def clearBadInstructionErrors(program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Clear all bookmarks which indicate Bad Instruction within the specified address set.
        
        :param ghidra.program.model.listing.Program program: program to clear bookmarks
        :param ghidra.program.model.address.AddressSetView addressSet: restricted address set or null for entire program
        :param ghidra.util.task.TaskMonitor monitor: allow canceling
        :raises CancelledException: if monitor canceled
        """

    @staticmethod
    def clearUnimplementedPcodeWarnings(program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Clear all bookmarks which indicate unimplemented pcode within the specified address set.
        
        :param ghidra.program.model.listing.Program program: program to clear bookmarks
        :param ghidra.program.model.address.AddressSetView addressSet: restricted address set or null for entire program
        :param ghidra.util.task.TaskMonitor monitor: allow canceling
        :raises CancelledException: if monitor canceled
        """

    @typing.overload
    def disassemble(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, doFollowFlow: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSet:
        """
        Attempt disassembly of all undefined code units within the specified set of addresses.
        NOTE: A single instance of this Disassembler does not support concurrent
        invocations of the various disassemble methods.
        Disassembler must be instantiated with a Program object.
        
        :param ghidra.program.model.address.AddressSetView startSet: the minimum set of addresses to disassemble
        :param ghidra.program.model.address.AddressSetView restrictedSet: the set of addresses that disassembling is restricted to (may be null)
        :param jpype.JBoolean or bool doFollowFlow: flag to follow references while disassembling.
        :return: the set of addresses that were disassembled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def disassemble(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, initialContextValue: ghidra.program.model.lang.RegisterValue, doFollowFlow: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSet:
        """
        Attempt disassembly of all undefined code units within the specified set of addresses.
        NOTE: A single instance of this Disassembler does not support concurrent
        invocations of the various disassemble methods.
        Disassembler must be instantiated with a Program object.
        
        :param ghidra.program.model.address.AddressSetView startSet: the minimum set of addresses to disassemble
        :param ghidra.program.model.address.AddressSetView restrictedSet: the set of addresses that disassembling is restricted to (may be null)
        :param ghidra.program.model.lang.RegisterValue initialContextValue: initial context value to be applied at the
        startAddr.  If not null this value will take precedence when combined with
        any seed value or program context.
        :param jpype.JBoolean or bool doFollowFlow: flag to follow references while disassembling.
        :return: the set of addresses that were disassembled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def disassemble(self, startAddr: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet:
        """
        Disassembles code starting at startAddr and restricted to addrSet.
        NOTE: A single instance of this Disassembler does not support concurrent
        invocations of the various disassemble methods.
        Disassembler must be instantiated with a Program object.
        
        :param ghidra.program.model.address.Address startAddr: the address to begin disassembling.
        :param ghidra.program.model.address.AddressSetView restrictedSet: the set of addresses that disassembling is restricted to.
        :return: AddressSet the set of addresses that were disassembled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def disassemble(self, startAddr: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, doFollowFlow: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSet:
        """
        Disassembles code starting at startAddr and restricted to addrSet.
        NOTE: A single instance of this Disassembler does not support concurrent
        invocations of the various disassemble methods. 
        Disassembler must be instantiated with a Program object.
        
        :param ghidra.program.model.address.Address startAddr: the address to begin disassembling.
        :param ghidra.program.model.address.AddressSetView restrictedSet: the set of addresses that disassembling is restricted to.
        :param jpype.JBoolean or bool doFollowFlow: flag to follow references while disassembling.
        :return: AddressSet the set of addresses that were disassembled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def disassemble(self, startAddr: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, initialContextValue: ghidra.program.model.lang.RegisterValue, doFollowFlow: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSet:
        """
        Disassembles code starting at startAddr and restricted to addrSet.
        NOTE: A single instance of this Disassembler does not support concurrent
        invocations of the various disassemble methods.  
        Disassembler must be instantiated with a Program object.
        
        :param ghidra.program.model.address.Address startAddr: the address to begin disassembling.
        :param ghidra.program.model.address.AddressSetView restrictedSet: the set of addresses that disassembling is restricted to.
        :param ghidra.program.model.lang.RegisterValue initialContextValue: initial context value to be applied at the
        startAddr.  If not null this value will take precedence when combined with
        any seed value or program context.
        :param jpype.JBoolean or bool doFollowFlow: flag to follow references while disassembling.
        :return: AddressSet the set of addresses that were disassembled.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    @typing.overload
    def getDisassembler(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, listener: DisassemblerMessageListener) -> Disassembler:
        """
        Get a suitable disassembler instance. 
        The following Program options are used during disassbly:
         
        * :obj:`.MARK_BAD_INSTRUCTION_PROPERTY`
        * :obj:`.MARK_UNIMPL_PCODE_PROPERTY`
        * :obj:`.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY`
        
        
        :param ghidra.program.model.listing.Program program: the program to be disassembled.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :param DisassemblerMessageListener listener: object to notify of disassembly messages.
        :return: a disassembler ready to disassemble
        :rtype: Disassembler
        """

    @staticmethod
    @typing.overload
    def getDisassembler(language: ghidra.program.model.lang.Language, addrFactory: ghidra.program.model.address.AddressFactory, monitor: ghidra.util.task.TaskMonitor, listener: DisassemblerMessageListener) -> Disassembler:
        """
        Get a suitable disassembler instance.
        Intended for block pseudo-disassembly use only when the method 
        :meth:`Disassembler.pseudoDisassembleBlock(MemBuffer, RegisterValue, int) <Disassembler.pseudoDisassembleBlock>`
        is used.
        NOTE: Executable memory restriction is not provided but should possibly be considered
        by any use of the resulting instance.
        
        :param ghidra.program.model.lang.Language language: processor language
        :param ghidra.program.model.address.AddressFactory addrFactory: address factory
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :param DisassemblerMessageListener listener: object to notify of disassembly messages.
        :return: a disassembler ready to disassemble
        :rtype: Disassembler
        """

    @staticmethod
    @typing.overload
    def getDisassembler(program: ghidra.program.model.listing.Program, markBadInstructions: typing.Union[jpype.JBoolean, bool], markUnimplementedPcode: typing.Union[jpype.JBoolean, bool], restrictToExecuteMemory: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor, listener: DisassemblerMessageListener) -> Disassembler:
        """
        Get a suitable disassembler instance.
        
        :param ghidra.program.model.listing.Program program: the program to be disassembled.
        :param jpype.JBoolean or bool markBadInstructions: if true bad instructions will be marked
        :param jpype.JBoolean or bool markUnimplementedPcode: if true instructions with unimplemented pcode will be marked
        :param jpype.JBoolean or bool restrictToExecuteMemory: if true disassembly will only be permitted with executable memory blocks
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :param DisassemblerMessageListener listener: object to notify of disassembly messages.
        :return: a disassembler ready to disassemble
        :rtype: Disassembler
        """

    @staticmethod
    def isMarkBadDisassemblyOptionEnabled(program: ghidra.program.model.listing.Program) -> bool:
        """
        
        
        :param ghidra.program.model.listing.Program program: the program to check
        :return: true if program MARK_BAD_INSTRUCTION_PROPERTY has been enabled
        :rtype: bool
        """

    @staticmethod
    def isMarkUnimplementedPcodeOptionEnabled(program: ghidra.program.model.listing.Program) -> bool:
        """
        
        
        :param ghidra.program.model.listing.Program program: the program to check
        :return: true if program MARK_UNIMPL_PCODE_PROPERTY has been enabled
        :rtype: bool
        """

    @staticmethod
    def isRestrictToExecuteMemory(program: ghidra.program.model.listing.Program) -> bool:
        """
        
        
        :param ghidra.program.model.listing.Program program: the program to check
        :return: true if program RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY has been enabled
        :rtype: bool
        """

    @staticmethod
    def markUnimplementedPcode(program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Mark all instructions with unimplemented pcode over the specified address set
        
        :param ghidra.program.model.listing.Program program: to mark unimplemented in
        :param ghidra.program.model.address.AddressSetView addressSet: restricted address set or null for entire program
        :param ghidra.util.task.TaskMonitor monitor: allow canceling
        :raises CancelledException: if monitor canceled
        """

    @typing.overload
    def pseudoDisassembleBlock(self, addr: ghidra.program.model.address.Address, defaultContextValue: ghidra.program.model.lang.RegisterValue, limit: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.InstructionBlock:
        """
        Perform a pseudo-disassembly of an single instruction block only following fall-throughs.
        WARNING! This method should not be used in conjunction with other disassembly methods
        on the this Disassembler instance.  Disassembler must be instantiated with a Program object.
        
        :param ghidra.program.model.address.Address addr: start of block
        :param ghidra.program.model.lang.RegisterValue defaultContextValue: starting context to use if no context has previously been established
        for the specified startAddr
        :param jpype.JInt or int limit: maximum number of instructions to disassemble
        :return: instruction block of pseudo-instructions
        :rtype: ghidra.program.model.lang.InstructionBlock
        """

    @typing.overload
    def pseudoDisassembleBlock(self, blockMemBuffer: ghidra.program.model.mem.MemBuffer, defaultContextValue: ghidra.program.model.lang.RegisterValue, limit: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.InstructionBlock:
        """
        Perform a pseudo-disassembly of an single instruction block only following fall-throughs.
        WARNING! This method should not be used in conjunction with other disassembly methods
        on the this Disassembler instance.
        
        :param ghidra.program.model.mem.MemBuffer blockMemBuffer: block memory buffer
        :param ghidra.program.model.lang.RegisterValue defaultContextValue: starting context to use if no context has previously been established
        for the specified startAddr
        :param jpype.JInt or int limit: maximum number of instructions to disassemble
        :return: instruction block of pseudo-instructions or null if minimum address of blockMemBuffer 
        is not properly aligned for instruction parsing.
        :rtype: ghidra.program.model.lang.InstructionBlock
        """

    def resetDisassemblerContext(self):
        """
        Clear any retained context state which may have been accumulated.
        Use of this method is only needed when using the pseudoDisassembleBlock 
        method over an extended code range to avoid excessive in-memory state accumulation.
        """

    def setRepeatPatternLimit(self, maxInstructions: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of instructions in a single run which contain the same byte values.
        Disassembly flow will stop and be flagged when this threshold is encountered.
        This check is set to MAX_REPEAT_PATTERN_LENGTH by default, and can be disabled by setting a value of -1
        NOTE: This restriction will only work for those cases where a given repeated byte 
        results in an instruction which has a fall-through.
        
        :param jpype.JInt or int maxInstructions: limit on the number of consecutive instructions with the same 
        byte values
        """

    def setRepeatPatternLimitIgnored(self, set: ghidra.program.model.address.AddressSetView):
        """
        Set the region over which the repeat pattern limit will be ignored.
        This allows areas which have been explicitly disassembled to be 
        free of bad bookmarks caused by the repeat pattern limit being exceeded.
        
        :param ghidra.program.model.address.AddressSetView set: region over which the repeat pattern limit will be ignored
        """

    def setSeedContext(self, seedContext: DisassemblerContextImpl):
        """
        Set seed context which will be used to establish initial context at starting points
        which are not arrived at via a natural disassembly flow.  A null value will disable
        use of any previously set seed context
        
        :param DisassemblerContextImpl seedContext: initial context for disassembly
        """


class DisassemblerConflictHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def markInstructionError(self, conflict: ghidra.program.model.lang.InstructionError):
        ...


class DisassemblerMessageListener(java.lang.Object):
    """
    Interface for reporting disassembly messages
    """

    class_: typing.ClassVar[java.lang.Class]
    IGNORE: typing.Final[DisassemblerMessageListener]
    """
    Ignores all messages from the disassembler.
    """

    CONSOLE: typing.Final[DisassemblerMessageListener]
    """
    Writes all messages from disassembler to the console.
    """


    def disassembleMessageReported(self, msg: typing.Union[java.lang.String, str]):
        """
        Method called to display disassembly progress messasges
        
        :param java.lang.String or str msg: the message to display.
        """



__all__ = ["DisassemblerQueue", "DisassemblerContextImpl", "ReDisassembler", "Disassembler", "DisassemblerConflictHandler", "DisassemblerMessageListener"]
