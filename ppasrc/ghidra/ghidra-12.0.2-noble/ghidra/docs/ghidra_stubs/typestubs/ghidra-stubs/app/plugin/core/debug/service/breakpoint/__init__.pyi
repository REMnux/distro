from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.debug.api.breakpoint
import ghidra.debug.api.modules
import ghidra.debug.api.target
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


class EnableEmuBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def loc(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def snap(self) -> int:
        ...

    def toString(self) -> str:
        ...


class DisableTargetBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, target: ghidra.debug.api.target.Target, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def loc(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def target(self) -> ghidra.debug.api.target.Target:
        ...

    def toString(self) -> str:
        ...


class TrackedTooSoonException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BreakpointActionSet(java.util.LinkedHashSet[BreakpointActionItem]):
    """
    A de-duplicated collection of breakpoint action items necessary to implement a logical breakpoint
    action.
     
     
    
    This will de-duplicate action items, but it does not check them for sanity. For example, deleting
    a breakpoint then enabling it. Typically, all the items are the same type, so such sanity checks
    are not necessary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def execute(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Carry out the actions in the order they were added
        
        :return: a future which completes when the actions have all completed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def planDeleteEmu(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]) -> DeleteEmuBreakpointActionItem:
        """
        Add an item to delete an emulated breakpoint
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the trace breakpoint
        :param jpype.JLong or int snap: the snap
        :return: the added item
        :rtype: DeleteEmuBreakpointActionItem
        """

    def planDeleteTarget(self, target: ghidra.debug.api.target.Target, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> DeleteTargetBreakpointActionItem:
        """
        Add an item to delete a target breakpoint
        
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the target breakpoint
        :return: the added item
        :rtype: DeleteTargetBreakpointActionItem
        """

    def planDisableEmu(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]) -> DisableEmuBreakpointActionItem:
        """
        Add an item to disable an emulated breakpoint
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the trace breakpoint
        :param jpype.JLong or int snap: the snap
        :return: the added item
        :rtype: DisableEmuBreakpointActionItem
        """

    def planDisableTarget(self, target: ghidra.debug.api.target.Target, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> DisableTargetBreakpointActionItem:
        """
        Add an item to disable a target breakpoint
        
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the target breakpoint
        :return: the added item
        :rtype: DisableTargetBreakpointActionItem
        """

    def planEnableEmu(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]) -> EnableEmuBreakpointActionItem:
        """
        Add an item to enable an emulated breakpoint
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the trace breakpoint
        :param jpype.JLong or int snap: the snap
        :return: the added item
        :rtype: EnableEmuBreakpointActionItem
        """

    def planEnableTarget(self, target: ghidra.debug.api.target.Target, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> EnableTargetBreakpointActionItem:
        """
        Add an item to enable a target breakpoint
        
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the target breakpoint
        :return: the added item
        :rtype: EnableTargetBreakpointActionItem
        """


class EnableTargetBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, target: ghidra.debug.api.target.Target, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def loc(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def target(self) -> ghidra.debug.api.target.Target:
        ...

    def toString(self) -> str:
        ...


class DeleteTargetBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, target: ghidra.debug.api.target.Target, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def loc(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def target(self) -> ghidra.debug.api.target.Target:
        ...

    def toString(self) -> str:
        ...


@typing.type_check_only
class TraceBreakpointSet(java.lang.Object):
    """
    The trace side of a logical breakpoint
     
     
    
    If the logical breakpoint is a mapped, it will have one of these sets for each trace where the
    breakpoint has (or could have) a location. For a lone logical breakpoint, it will have just one
    of these for the one trace where its located.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, address: ghidra.program.model.address.Address):
        """
        Create a set of breakpoint locations for a given trace
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool for the UI
        :param ghidra.trace.model.Trace trace: the trace whose locations this set collects
        :param ghidra.program.model.address.Address address: the dynamic address where the breakpoint is (or would be) located
        """

    def add(self, bpt: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> bool:
        """
        Add a breakpoint to this set
         
         
        
        The caller should first call :meth:`canMerge(TraceBreakpointLocation) <.canMerge>` to check if the breakpoint
        "fits."
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation bpt: the breakpoint
        :return: true if the set actually changed as a result
        :rtype: bool
        """

    def canMerge(self, bpt: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> bool:
        """
        Check if the given trace breakpoint "fits" in this set
         
         
        
        The breakpoint fits if it's dynamic location matches that expected in this set
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation bpt: the breakpoint
        :return: true if it fits
        :rtype: bool
        """

    def computeEmuMode(self, bpt: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode:
        """
        Compute the mode of the given breakpoint for the emulator
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation bpt: the breakpoint
        :return: the mode
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode
        """

    @typing.overload
    def computeMode(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode:
        """
        Compute the mode (enablement) of this set
         
         
        
        In most cases, there is 0 or 1 trace breakpoints that "fit" the logical breakpoint. The mode
        is derived from one of :meth:`TraceBreakpointLocation.isEnabled(long) <TraceBreakpointLocation.isEnabled>` or
        :meth:`TraceBreakpointLocation.isEmuEnabled(long) <TraceBreakpointLocation.isEmuEnabled>`, depending on the UI's control mode for this
        trace.
        
        :return: the mode
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode
        """

    @typing.overload
    def computeMode(self, bpt: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode:
        """
        Compute the mode (enablement) of the given breakpoint
         
         
        
        The mode is derived from one of :meth:`TraceBreakpointLocation.isEnabled(long) <TraceBreakpointLocation.isEnabled>` or
        :meth:`TraceBreakpointLocation.isEmuEnabled(long) <TraceBreakpointLocation.isEmuEnabled>`, depending on the UI's control mode for this
        trace.
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation bpt: the breakpoint
        :return: the mode
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode
        """

    def computeSleigh(self) -> str:
        """
        If all breakpoints agree on sleigh injection, get that injection
        
        :return: the injection, or null if there's disagreement.
        :rtype: str
        """

    def computeTargetMode(self, bpt: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode:
        """
        Compute the mode of the given breakpoint for the target
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation bpt: the breakpoint
        :return: the mode
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint.TraceMode
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the dynamic address where the breakpoint is (or would be) located in this trace
        
        :return: the dynamic address
        :rtype: ghidra.program.model.address.Address
        """

    def getBreakpoints(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        """
        Get the breakpoints in this set
        
        :return: the breakpoints
        :rtype: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isEmpty(self) -> bool:
        """
        Check if this set actually contains any trace breakpoints
        
        :return: true if empty, false otherwise
        :rtype: bool
        """

    def planDelete(self, actions: BreakpointActionSet, length: typing.Union[jpype.JLong, int], kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]):
        """
        Plan to delete the logical breakpoint in this trace
        
        :param BreakpointActionSet actions: the action set to populate
        :param jpype.JLong or int length: the length in bytes of the breakpoint
        :param java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind] kinds: the kinds of breakpoint
        """

    def planDisable(self, actions: BreakpointActionSet, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence):
        """
        Plan to disable the logical breakpoint in this trace
        
        :param BreakpointActionSet actions: the action set to populate
        :param jpype.JLong or int length: the length in bytes of the breakpoint
        :param collections.abc.Sequence kinds: the kinds of breakpoint
        """

    def planEnable(self, actions: BreakpointActionSet, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence):
        """
        Plan to enable the logical breakpoint within this trace
         
         
        
        This method prefers to use the existing breakpoint specifications which result in breakpoints
        at this address. In other words, it favors what the user has already done to effect a
        breakpoint at this logical breakpoint's address. If there is no such existing specification,
        then it attempts to place a new breakpoint via the target's breakpoint container, usually
        resulting in a new spec, which should effect exactly the one specified address. If the
        control mode indicates emulated breakpoints, then this simply writes the breakpoint to the
        trace database.
         
         
        
        This method may convert applicable addresses to the target space. If the address cannot be
        mapped, it's usually because this logical breakpoint does not apply to the given trace's
        target. E.g., the trace may not have a live target, or the logical breakpoint may be in a
        module not loaded by the trace.
        
        :param BreakpointActionSet actions: the action set to populate
        :param jpype.JLong or int length: the length in bytes of the breakpoint
        :param collections.abc.Sequence kinds: the kinds of breakpoint
        """

    def remove(self, bpt: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> bool:
        """
        Remove a breakpoint from this set
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation bpt: the breakpoint
        :return: true if the set actually changes as a result
        :rtype: bool
        """

    def setEmuSleigh(self, emuSleigh: typing.Union[java.lang.String, str]):
        """
        Set the sleigh injection for all breakpoints in this set
        
        :param java.lang.String or str emuSleigh: the sleigh injection
        """

    def setTarget(self, target: ghidra.debug.api.target.Target):
        """
        Set the target when the trace is associated to a live target
        
        :param ghidra.debug.api.target.Target target: the target
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def breakpoints(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DisableEmuBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def loc(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def snap(self) -> int:
        ...

    def toString(self) -> str:
        ...


class DeleteEmuBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def loc(self) -> ghidra.trace.model.breakpoint.TraceBreakpointLocation:
        ...

    def snap(self) -> int:
        ...

    def toString(self) -> str:
        ...


class LoneLogicalBreakpoint(LogicalBreakpointInternal):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence):
        ...


class PlaceEmuBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind], emuSleigh: typing.Union[java.lang.String, str]):
        ...

    def address(self) -> ghidra.program.model.address.Address:
        ...

    @staticmethod
    def createName(address: ghidra.program.model.address.Address) -> str:
        ...

    def emuSleigh(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def kinds(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        ...

    def length(self) -> int:
        ...

    def snap(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def trace(self) -> ghidra.trace.model.Trace:
        ...


class BreakpointActionItem(java.lang.Object):
    """
    An invocation is planning an action on a breakpoint
    
    
    .. seealso::
    
        | :obj:`BreakpointActionSet`
    """

    class_: typing.ClassVar[java.lang.Class]

    def execute(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Perform the action
        
        :return: the future for the action. Synchronous invocations can just return
                :obj:`AsyncUtils.NIL`.
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @staticmethod
    def range(address: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
        """
        Compute a range from an address and length
        
        :param ghidra.program.model.address.Address address: the min address
        :param jpype.JLong or int length: the length
        :return: the range
        :rtype: ghidra.program.model.address.AddressRange
        """


class ProgramBreakpoint(java.lang.Object):
    """
    The static side of a mapped logical breakpoint
     
     
    
    Programs don't have a built-in concept of breakpoints, so we store them as breakpoints with a
    specific type for each state. We also encode other intrinsic properties (length and kinds) to the
    category. Extrinsic properties (name and sleigh) are encoded in the comment. Because traces are
    fairly ephemeral, the program bookmarks are the primary means a user has to save and manage a
    breakpoint set.
    """

    @typing.type_check_only
    class BreakpointProperties(java.lang.Object):
        """
        A class for (de)serializing breakoint properties in the bookmark's comments
        """

        class_: typing.ClassVar[java.lang.Class]
        name: java.lang.String
        sleigh: java.lang.String

        def __init__(self, name: typing.Union[java.lang.String, str], sleigh: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]):
        """
        Construct a program breakpoint
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address address: the static address of the breakpoint (even if a bookmark is not present there)
        :param jpype.JLong or int length: the length of the breakpoint in bytes
        :param java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind] kinds: the kinds of the breakpoint
        """

    def add(self, bookmark: ghidra.program.model.listing.Bookmark) -> bool:
        """
        Fill the static side of this breakpoint with the given bookmark
         
         
        
        The caller should first use :meth:`canMerge(Program, Bookmark) <.canMerge>` to ensure the bookmark can
        actually represent this breakpoint.
        
        :param ghidra.program.model.listing.Bookmark bookmark: the bookmark
        :return: true if this changed the breakpoint state
        :rtype: bool
        """

    def canMerge(self, candProgram: ghidra.program.model.listing.Program, candBookmark: ghidra.program.model.listing.Bookmark) -> bool:
        """
        Check if the given bookmark can fill the static side of this breakpoint
        
        :param ghidra.program.model.listing.Program candProgram: the program containing the bookmark
        :param ghidra.program.model.listing.Bookmark candBookmark: the bookmark
        :return: true if the bookmark can represent this breakpoint, false otherwise
        :rtype: bool
        """

    def computeCategory(self) -> str:
        """
        Compute the category for a new bookmark representing this breakpoint
        
        :return: the category
        :rtype: str
        """

    def computeMode(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.ProgramMode:
        """
        Compute the mode of this breakpoint
         
         
        
        In order to ensure at least the saved state (enablement) can be rendered in the marker margin
        in the absence of the breakpoint marker plugin, we use one type of bookmark for disabled
        breakpoints, and another for enabled breakpoints. As the state is changing, it's possible for
        a brief moment that both bookmarks are present. We thus have a variable for each bookmark and
        prefer the "enabled" state. We can determine are state by examining which variable is
        non-null. If both are null, the breakpoint is not actually saved to the program, yet. We
        cannot return :obj:`ProgramMode.NONE`, because that would imply there is no static location.
        
        :return: the state
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint.ProgramMode
        """

    def deleteFromProgram(self):
        """
        Remove the bookmark
         
         
        
        Note this does not necessarily destroy the breakpoint, since it may still exist in one or
        more traces.
        """

    def disable(self):
        """
        Disable this breakpoint
        
        
        .. seealso::
        
            | :obj:`.toggleWithComment(boolean, String)`
        """

    def enable(self):
        """
        Enable this breakpoint
        
        
        .. seealso::
        
            | :obj:`.toggleWithComment(boolean, String)`
        """

    def getBookmark(self) -> ghidra.program.model.listing.Bookmark:
        """
        Get the bookmark representing this breakpoint, if present
        
        :return: the bookmark or null
        :rtype: ghidra.program.model.listing.Bookmark
        """

    def getEmuSleigh(self) -> str:
        """
        Get the sleigh injection for this breakpoint
        
        :return: the sleigh injection
        :rtype: str
        """

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Get the breakpoint's static program location
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getName(self) -> str:
        """
        Get the user-defined name of the breakpoint
        
        :return: the name
        :rtype: str
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program where this breakpoint is located
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    def isDisabled(self) -> bool:
        """
        Check if the bookmark represents a disabled breakpoint
        
        :return: true if disabled, false if anything else
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Check if either bookmark is present
        
        :return: true if both are absent, false if either or both is present
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        Check if the bookmark represents an enabled breakpoint
        
        :return: true if enabled, false if anything else
        :rtype: bool
        """

    @staticmethod
    def kindsFromBookmark(mark: ghidra.program.model.listing.Bookmark) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        """
        Get the kinds of a breakpoint from its bookmark
        
        :param ghidra.program.model.listing.Bookmark mark: the bookmark representing a breakpoint
        :return: the kinds
        :rtype: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]
        """

    @staticmethod
    def lengthFromBookmark(mark: ghidra.program.model.listing.Bookmark) -> int:
        """
        Get the length of a breakpoint from its bookmark
        
        :param ghidra.program.model.listing.Bookmark mark: the bookmark representing a breakpoint
        :return: the length in bytes
        :rtype: int
        """

    def remove(self, bookmark: ghidra.program.model.listing.Bookmark) -> bool:
        """
        Remove a bookmark from the static side of this breakpoint
        
        :param ghidra.program.model.listing.Bookmark bookmark: the bookmark
        :return: true if this changed the breakpoint state
        :rtype: bool
        """

    def setEmuSleigh(self, sleigh: typing.Union[java.lang.String, str]):
        """
        Set the sleigh injection for this breakpoint
        
        :param java.lang.String or str sleigh: the sleigh injection
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name of the breakpoint
        
        :param java.lang.String or str name: the name
        """

    def toggleWithComment(self, enabled: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]):
        """
        Change the state of this breakpoint by manipulating bookmarks
         
         
        
        If the breakpoint is already in the desired state, no change is made. Otherwise, this will
        delete the existing bookmark, if present, and create a new bookmark whose type indicates the
        desired state. Thus, some event processing may need to take place before this breakpoint's
        state is actually updated accordingly.
        
        :param jpype.JBoolean or bool enabled: the desired state, true for :obj:`ProgramMode.ENABLED`, false for
                    :obj:`ProgramMode.DISABLED`.
        :param java.lang.String or str comment: the comment to give the breakpoint, almost always from :meth:`getComment() <.getComment>`.
        """

    @property
    def bookmark(self) -> ghidra.program.model.listing.Bookmark:
        ...

    @property
    def emuSleigh(self) -> java.lang.String:
        ...

    @emuSleigh.setter
    def emuSleigh(self, value: java.lang.String):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def disabled(self) -> jpype.JBoolean:
        ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class LogicalBreakpointInternal(ghidra.debug.api.breakpoint.LogicalBreakpoint):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def canMerge(self, program: ghidra.program.model.listing.Program, bookmark: ghidra.program.model.listing.Bookmark) -> bool:
        ...

    @typing.overload
    def canMerge(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if this logical breakpoint can subsume the given candidate trace breakpoint
         
         
        
        Note that logical breakpoints only include trace breakpoints for traces being actively
        recorded. All statuses regarding trace breakpoints are derived from the target breakpoints,
        i.e., they show the present status, regardless of the view's current time. A separate
        breakpoint history provider handles displaying records from the past, including dead traces.
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation breakpoint: the trace breakpoint to check
        :param jpype.JLong or int snap: the snap
        :return: true if it can be aggregated.
        :rtype: bool
        :raises TrackedTooSoonException: if the containing trace is still being added to the manager
        """

    def planDelete(self, actions: BreakpointActionSet, trace: ghidra.trace.model.Trace):
        """
        Collect actions to delete a logical breakpoint.
        
        :param BreakpointActionSet actions: the destination action set (plan)
        :param ghidra.trace.model.Trace trace: a trace, if actions should be limited to the given trace
        """

    def planDisable(self, actions: BreakpointActionSet, trace: ghidra.trace.model.Trace):
        """
        Collect actions to disable a logical breakpoint.
        
        :param BreakpointActionSet actions: the destination action set (plan)
        :param ghidra.trace.model.Trace trace: a trace, if actions should be limited to the given trace
        """

    def planEnable(self, actions: BreakpointActionSet, trace: ghidra.trace.model.Trace):
        """
        Collect actions to enable a logical breakpoint.
        
        :param BreakpointActionSet actions: the destination action set (plan)
        :param ghidra.trace.model.Trace trace: a trace, if actions should be limited to the given trace
        """

    def removeTrace(self, trace: ghidra.trace.model.Trace):
        """
        Remove the given trace from this set
         
         
        
        This happens when a trace's recorder stops or when a trace is closed.
        
        :param ghidra.trace.model.Trace trace: the trace no longer participating
        """

    def setTarget(self, trace: ghidra.trace.model.Trace, target: ghidra.debug.api.target.Target):
        ...

    def setTraceAddress(self, trace: ghidra.trace.model.Trace, address: ghidra.program.model.address.Address):
        """
        Set the expected address for trace breakpoints in the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.program.model.address.Address address: the address of this logical breakpoint in the given trace
        """

    @typing.overload
    def trackBreakpoint(self, bookmark: ghidra.program.model.listing.Bookmark) -> bool:
        ...

    @typing.overload
    def trackBreakpoint(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> bool:
        ...

    @typing.overload
    def untrackBreakpoint(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> bool:
        ...

    @typing.overload
    def untrackBreakpoint(self, program: ghidra.program.model.listing.Program, bookmark: ghidra.program.model.listing.Bookmark) -> bool:
        ...


class DebuggerLogicalBreakpointServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerLogicalBreakpointService):

    @typing.type_check_only
    class AddCollector(java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, l: ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener, updated: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]):
            ...


    @typing.type_check_only
    class RemoveCollector(java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, l: ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener, updated: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]):
            ...


    @typing.type_check_only
    class ChangeCollector(java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, l: ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener):
            ...


    @typing.type_check_only
    class TrackTargetsListener(ghidra.debug.api.target.TargetPublicationListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TrackMappingsListener(ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TrackModesListener(ghidra.app.services.DebuggerControlService.ControlModeChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TraceBreakpointsListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, info: DebuggerLogicalBreakpointServicePlugin.InfoPerTrace):
            ...


    @typing.type_check_only
    class ProgramBreakpointsListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, info: DebuggerLogicalBreakpointServicePlugin.InfoPerProgram):
            ...


    @typing.type_check_only
    class AbstractInfo(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class InfoPerTrace(DebuggerLogicalBreakpointServicePlugin.AbstractInfo):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...

        def toDynamicLocation(self, loc: ghidra.program.util.ProgramLocation) -> ghidra.trace.model.TraceLocation:
            ...


    @typing.type_check_only
    class InfoPerProgram(DebuggerLogicalBreakpointServicePlugin.AbstractInfo):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program):
            ...


    @typing.type_check_only
    class TargetBreakpointConsumer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, actions: BreakpointActionSet, target: ghidra.debug.api.target.Target, tb: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
            ...


    @typing.type_check_only
    class EmuBreakpointConsumer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, actions: BreakpointActionSet, tb: ghidra.trace.model.breakpoint.TraceBreakpointLocation, snap: typing.Union[jpype.JLong, int]):
            ...


    @typing.type_check_only
    class ProgramBreakpointConsumer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, lb: ghidra.debug.api.breakpoint.LogicalBreakpoint):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class MappedLogicalBreakpoint(LogicalBreakpointInternal):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def appliesTo(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    @typing.overload
    def appliesTo(self, trace: ghidra.trace.model.Trace) -> bool:
        ...

    def enableForProgramWithName(self, name: typing.Union[java.lang.String, str]):
        """
        Place the program's bookmark with a comment specifying a desired name
         
         
        
        **WARNING:** Use only when this breakpoint was just placed, otherwise, this will reset
        other extrinsic properties, such as the sleigh injection.
        
        :param java.lang.String or str name: the desired name
        """

    def enableForTraces(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        ...

    def enableWithName(self, name: typing.Union[java.lang.String, str]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        ...


class PlaceTargetBreakpointActionItem(java.lang.Record, BreakpointActionItem):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, target: ghidra.debug.api.target.Target, range: ghidra.program.model.address.AddressRange, kinds: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, target: ghidra.debug.api.target.Target, range: ghidra.program.model.address.AddressRange, kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def kinds(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        ...

    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    def target(self) -> ghidra.debug.api.target.Target:
        ...

    def toString(self) -> str:
        ...



__all__ = ["EnableEmuBreakpointActionItem", "DisableTargetBreakpointActionItem", "TrackedTooSoonException", "BreakpointActionSet", "EnableTargetBreakpointActionItem", "DeleteTargetBreakpointActionItem", "TraceBreakpointSet", "DisableEmuBreakpointActionItem", "DeleteEmuBreakpointActionItem", "LoneLogicalBreakpoint", "PlaceEmuBreakpointActionItem", "BreakpointActionItem", "ProgramBreakpoint", "LogicalBreakpointInternal", "DebuggerLogicalBreakpointServicePlugin", "MappedLogicalBreakpoint", "PlaceTargetBreakpointActionItem"]
