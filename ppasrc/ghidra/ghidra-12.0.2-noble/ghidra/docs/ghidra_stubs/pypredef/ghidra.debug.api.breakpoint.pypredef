from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore


class LogicalBreakpoint(java.lang.Object):
    """
    A logical breakpoint
    
     
    
    This is a collection of at most one program breakpoint, which is actually a bookmark with a
    special type, and any number of trace breakpoints. The program breakpoint represents the logical
    breakpoint, as this is the most stable anchor for keeping the user's breakpoint set. All
    breakpoints in the set correspond to the same address when considering the module map (or other
    source of static-to-dynamic mapping), which may involve relocation. They also share the same
    kinds and length, since these are more or less intrinsic to the breakpoints specification. Thus,
    more than one logical breakpoint may occupy the same address. A logical breakpoints having a
    program bookmark (or that at least has a static address) is called a "mapped" breakpoint. This is
    the ideal, ordinary case. A breakpoint that cannot be mapped to a static address (and thus cannot
    have a program bookmark) is called a "lone" breakpoint.
     
     
    
    **WARNING:** The lifecycle of a logical breakpoint is fairly volatile. It is generally not
    safe to "hold onto" a logical breakpoint, since with any event, the logical breakpoint service
    may discard and re-create the object, even if it's composed of the same program and trace
    breakpoints. If it is truly necessary to hold onto logical breakpoints, consider using
    :meth:`DebuggerLogicalBreakpointService.addChangeListener(LogicalBreakpointsChangeListener) <DebuggerLogicalBreakpointService.addChangeListener>`. A
    logical breakpoint is valid until the service invokes
    :meth:`LogicalBreakpointsChangeListener.breakpointRemoved(LogicalBreakpoint) <LogicalBreakpointsChangeListener.breakpointRemoved>`.
    """

    class ProgramMode(java.lang.Enum[LogicalBreakpoint.ProgramMode]):
        """
        The state of a logical breakpoint's program bookmark
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[LogicalBreakpoint.ProgramMode]
        """
        A placeholder state when the program bookmark state is not applicable
        """

        MISSING: typing.Final[LogicalBreakpoint.ProgramMode]
        """
        The state when the program location applies, but no breakpoint is present there
         
         
        
        This can happen when a breakpoint is placed directly in the debugger at a mapped address,
        but that breakpoint is not (yet) bookmarked in the mapped program.
        """

        ENABLED: typing.Final[LogicalBreakpoint.ProgramMode]
        """
        The breakpoint's program bookmark is enabled
        """

        DISABLED: typing.Final[LogicalBreakpoint.ProgramMode]
        """
        The breakpoint's program bookmark is disabled
        """


        def combineTrace(self, traceMode: LogicalBreakpoint.TraceMode, perspective: LogicalBreakpoint.Perspective) -> LogicalBreakpoint.State:
            """
            Compose the logical breakpoint state from the perspective of the program, given the
            composed state of its locations
             
             
            
            This state is generally considered the state of the logical breakpoint. In other words,
            the program's perspective is the default.
            
            :param LogicalBreakpoint.TraceMode traceMode: the mode of its locations
            :param LogicalBreakpoint.Perspective perspective: the perspective
            :return: the logical state
            :rtype: LogicalBreakpoint.State
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LogicalBreakpoint.ProgramMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[LogicalBreakpoint.ProgramMode]:
            ...


    class Perspective(java.lang.Enum[LogicalBreakpoint.Perspective]):

        class_: typing.ClassVar[java.lang.Class]
        LOGICAL: typing.Final[LogicalBreakpoint.Perspective]
        TRACE: typing.Final[LogicalBreakpoint.Perspective]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LogicalBreakpoint.Perspective:
            ...

        @staticmethod
        def values() -> jpype.JArray[LogicalBreakpoint.Perspective]:
            ...


    class TraceMode(java.lang.Enum[LogicalBreakpoint.TraceMode]):
        """
        The state of a logical breakpoint's trace/target locations
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[LogicalBreakpoint.TraceMode]
        """
        A placeholder mode when no traces are involved
        """

        MISSING: typing.Final[LogicalBreakpoint.TraceMode]
        """
        The mode when the breakpoint is missing from one or more of its mapped locations
        """

        ENABLED: typing.Final[LogicalBreakpoint.TraceMode]
        """
        The mode when all mapped locations are placed and enabled
        """

        DISABLED: typing.Final[LogicalBreakpoint.TraceMode]
        """
        The mode when all mapped locations are placed and disabled
        """

        MIXED: typing.Final[LogicalBreakpoint.TraceMode]
        """
        The mode when all mapped locations are placed, but some are enabled, and some are
        disabled
        """


        def combine(self, that: LogicalBreakpoint.TraceMode) -> LogicalBreakpoint.TraceMode:
            """
            For locations of the same logical breakpoint, compose the mode
            
            :param LogicalBreakpoint.TraceMode that: the other state
            :return: the composed state
            :rtype: LogicalBreakpoint.TraceMode
            """

        @staticmethod
        def fromBool(enabled: typing.Union[jpype.JBoolean, bool]) -> LogicalBreakpoint.TraceMode:
            """
            Convert a boolean to trace breakpoint mode
            
            :param jpype.JBoolean or bool enabled: true for :obj:`.ENABLED`, false for :obj:`.DISABLED`
            :return: the state
            :rtype: LogicalBreakpoint.TraceMode
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LogicalBreakpoint.TraceMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[LogicalBreakpoint.TraceMode]:
            ...


    class Mode(java.lang.Enum[LogicalBreakpoint.Mode]):
        """
        The mode of a logical breakpoint
         
         
        
        Depending on context this may describe the mode from the perspective of a program, where
        breakpoints are saved from session to session; or this may describe the mode from the
        perspective of one or more traces/targets:
         
         
        
        If the breakpoint is a lone breakpoint, meaning Ghidra cannot determine to what program it
        belongs, then this describes the mode of that trace breakpoint.
         
         
        
        If the breakpoint is mapped, meaning Ghidra can determine to what program it belongs and at
        what address, but it is not bookmarked, then for the static context, this describes the mode
        of the participating trace breakpoints. If the breakpoint is bookmarked, then for the static
        context, this describes the mode of that bookmark. For the dynamic context, this describes
        the mode of the trace's breakpoint, ignoring the presence or state of the bookmark. Note that
        the bookmark and trace modes may disagree. The displayed mode is still determined by context,
        but it will be marked as inconsistent. See :obj:`Consistency`.
        """

        class_: typing.ClassVar[java.lang.Class]
        ENABLED: typing.Final[LogicalBreakpoint.Mode]
        """
        All locations are enabled
        """

        DISABLED: typing.Final[LogicalBreakpoint.Mode]
        """
        All locations are disabled
        """

        MIXED: typing.Final[LogicalBreakpoint.Mode]
        """
        Has both enabled and disabled trace locations
        """


        def sameAddress(self, that: LogicalBreakpoint.Mode) -> LogicalBreakpoint.Mode:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LogicalBreakpoint.Mode:
            ...

        @staticmethod
        def values() -> jpype.JArray[LogicalBreakpoint.Mode]:
            ...


    class Consistency(java.lang.Enum[LogicalBreakpoint.Consistency]):
        """
        The consistency of a logical breakpoint
         
         
        
        When operating as designed, all breakpoints should be in the :obj:`.NORMAL` state. This
        indicates that the breakpoint's bookmark and all trace locations agree on the mode.
        Exceptions do happen, and they should be indicated to the user:
         
         
        
        If the breakpoint is a lone breakpoint, meaning Ghidra cannot determine to what program it
        belongs, then the breakpoint is always :obj:`.INCONSISTENT`, because Ghidra uses program
        bookmarks to save breakpoints.
         
         
        
        If the breakpoint is mapped, meaning Ghidra can determine to what program it belongs and at
        what address, but it is not bookmarked, then the breakpoint is :obj:`.INCONSISTENT`. If it
        is bookmarked, but the bookmark disagrees, then the breakpoint is :obj:`.INCONSISTENT`. A
        breakpoint that is bookmarked but has no trace locations, or is missing from any
        participating trace, is :obj:`.INEFFECTIVE`.
        
        
        .. admonition:: Implementation Note
        
            These are ordered by priority, highest last.
        """

        class_: typing.ClassVar[java.lang.Class]
        NORMAL: typing.Final[LogicalBreakpoint.Consistency]
        """
        the bookmark and locations all agree
        """

        INEFFECTIVE: typing.Final[LogicalBreakpoint.Consistency]
        """
        has a bookmark but one or more trace locations is missing
        """

        INCONSISTENT: typing.Final[LogicalBreakpoint.Consistency]
        """
        has a trace location but is not bookmarked, or the bookmark disagrees
        """


        def sameAddress(self, that: LogicalBreakpoint.Consistency) -> LogicalBreakpoint.Consistency:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LogicalBreakpoint.Consistency:
            ...

        @staticmethod
        def values() -> jpype.JArray[LogicalBreakpoint.Consistency]:
            ...


    class State(java.lang.Enum[LogicalBreakpoint.State]):
        """
        The state of a logical breakpoint
         
         
        
        Because a breakpoint is comprised of possibly many locations on target or among several
        targets, as well as a saved bookmark in a program, the "state" can get fairly complex. This
        is an attempt to enumerate these states while preserving enough information about the
        breakpoint to display it in various contexts, hopefully informing more than confusing.
         
         
        
        In essence, this is the cross product of :obj:`Mode` and :obj:`Consistency` with an
        additional :obj:`.NONE` option.
         
         
        
        A breakpoint is simply :obj:`.ENABLED` or :obj:`.DISABLED` if it is maped and all its
        locations and bookmark agree. Ideally, all breakpoints would be in one of these two states.
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[LogicalBreakpoint.State]
        """
        A placeholder state, usually indicating the logical breakpoint should not exist
         
         
        
        This state should not ever be assigned to any actual breakpoint, except if that
        breakpoint is ephemeral and about to be removed. This value may appear during
        computations and is a suitable default placeholder for editors and renderers.
        """

        ENABLED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is enabled, and all locations and its bookmark agree
        """

        DISABLED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is disabled, and all locations and its bookmark agree
        """

        MIXED: typing.Final[LogicalBreakpoint.State]
        """
        There are multiple logical breakpoints at this address, and they are all saved and
        effective, but some are enabled, and some are disabled.
        """

        INEFFECTIVE_ENABLED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is saved as enabled, but one or more trace locations are absent.
        """

        INEFFECTIVE_DISABLED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is saved as disabled, and one or more trace locations are absent.
        """

        INEFFECTIVE_MIXED: typing.Final[LogicalBreakpoint.State]
        """
        There are multiple logical breakpoints at this address, and they are all saved, but at
        least one is ineffective; furthermore, some are enabled, and some are disabled.
        """

        INCONSISTENT_ENABLED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is enabled, and all locations agree, but the bookmark is absent or
        disagrees.
        """

        INCONSISTENT_DISABLED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is disabled, and all locations agree, but the bookmark is absent or
        disagrees.
        """

        INCONSISTENT_MIXED: typing.Final[LogicalBreakpoint.State]
        """
        The breakpoint is terribly inconsistent: its locations disagree, and the bookmark may be
        absent.
        """

        VALUES: typing.Final[java.util.List[LogicalBreakpoint.State]]
        mode: typing.Final[LogicalBreakpoint.Mode]
        consistency: typing.Final[LogicalBreakpoint.Consistency]
        display: typing.Final[java.lang.String]
        icon: typing.Final[javax.swing.Icon]

        @staticmethod
        def fromFields(mode: LogicalBreakpoint.Mode, consistency: LogicalBreakpoint.Consistency) -> LogicalBreakpoint.State:
            ...

        def getToggled(self, mapped: typing.Union[jpype.JBoolean, bool]) -> LogicalBreakpoint.State:
            """
            Get the desired state were the logical breakpoint to be toggled
             
             
            
            The expected "action" when toggling a breakpoint may vary depending on whether or not the
            breakpoint is mapped, and the notion of "mapped" may vary depending on other settings. In
            general, if the breakpoint is not in a consistent, enabled, and effective state, but it
            could be, then toggling it should attempt to make it so. If it is consistent, enabled,
            and effective, then toggling it should make it consistent, disabled, and effective. If it
            is not mapped, the state should toggle between enabled and disabled, but ineffective.
             
             
            
            This will always return one of :obj:`.ENABLED` or :obj:`.DISABLED`, indicating what
            action should be taken on the logical breakpoint. A breakpoint that is ineffective,
            because it is not mapped, will remain ineffective.
            
            :param jpype.JBoolean or bool mapped: true if the breakpoint is mapped, as interpreted by the action context
            :return: the resulting state
            :rtype: LogicalBreakpoint.State
            """

        def isEffective(self) -> bool:
            ...

        def isEnabled(self) -> bool:
            ...

        def isIneffective(self) -> bool:
            ...

        def isNormal(self) -> bool:
            ...

        def sameAdddress(self, that: LogicalBreakpoint.State) -> LogicalBreakpoint.State:
            """
            For logical breakpoints which appear at the same address, compose their state
             
             
            
            This can happen when two logical breakpoints, having different attributes (size, kinds,
            etc.) coincide at the same address. This should be used only when deciding how to mark or
            choose actions for the address.
            
            :param LogicalBreakpoint.State that: the other state.
            :return: the composed state
            :rtype: LogicalBreakpoint.State
            """

        @staticmethod
        def sameAddress(col: collections.abc.Sequence) -> LogicalBreakpoint.State:
            """
            For logical breakpoints which appear at the same address, compose their state
            
            :param collections.abc.Sequence col: a collection of states derived from logical breakpoints at the same address
            :return: the composed state
            :rtype: LogicalBreakpoint.State
            
            .. seealso::
            
                | :obj:`.sameAdddress(State)`
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LogicalBreakpoint.State:
            ...

        @staticmethod
        def values() -> jpype.JArray[LogicalBreakpoint.State]:
            ...

        @property
        def ineffective(self) -> jpype.JBoolean:
            ...

        @property
        def normal(self) -> jpype.JBoolean:
            ...

        @property
        def effective(self) -> jpype.JBoolean:
            ...

        @property
        def toggled(self) -> LogicalBreakpoint.State:
            ...

        @property
        def enabled(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ENABLED_BOOKMARK_TYPE: typing.Final = "BreakpointEnabled"
    DISABLED_BOOKMARK_TYPE: typing.Final = "BreakpointDisabled"
    NAME_MARKER_ENABLED: typing.Final = "Enabled Breakpoint"
    NAME_MARKER_DISABLED: typing.Final = "Disabled Breakpoint"
    NAME_MARKER_MIXED: typing.Final = "Mixed Breakpoint"
    NAME_MARKER_INEFF_EN: typing.Final = "Ineffective Enabled Breakpoint"
    NAME_MARKER_INEFF_DIS: typing.Final = "Ineffective Disabled Breakpoint"
    NAME_MARKER_INEFF_MIX: typing.Final = "Ineffective Mixed Breakpoint"
    NAME_MARKER_INCON_EN: typing.Final = "Inconsistent Enabled Breakpoint"
    NAME_MARKER_INCON_DIS: typing.Final = "Inconsistent Disabled Breakpoint"
    NAME_MARKER_INCON_MIX: typing.Final = "Inconsistent Mixed Breakpoint"
    ICON_OVERLAY_INCONSISTENT: typing.Final[javax.swing.Icon]
    ICON_MARKER_ENABLED: typing.Final[javax.swing.Icon]
    ICON_MARKER_DISABLED: typing.Final[javax.swing.Icon]
    ICON_MARKER_MIXED: typing.Final[javax.swing.Icon]
    ICON_MARKER_INEFF_EN: typing.Final[javax.swing.Icon]
    ICON_MARKER_INEFF_DIS: typing.Final[javax.swing.Icon]
    ICON_MARKER_INEFF_MIX: typing.Final[javax.swing.Icon]
    ICON_MARKER_INCON_EN: typing.Final[javax.swing.Icon]
    ICON_MARKER_INCON_DIS: typing.Final[javax.swing.Icon]
    ICON_MARKER_INCON_MIX: typing.Final[javax.swing.Icon]

    def computeState(self) -> LogicalBreakpoint.State:
        """
        Compute the state for all involved traces and program.
        
        :return: the state
        :rtype: LogicalBreakpoint.State
        """

    def computeStateForLocation(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> LogicalBreakpoint.State:
        """
        Compute the state for the given location.
         
         
        
        This is just the location's mode combined with that of the static bookmark.
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the location
        :return: the state
        :rtype: LogicalBreakpoint.State
        """

    def computeStateForProgram(self, program: ghidra.program.model.listing.Program) -> LogicalBreakpoint.State:
        """
        Compute the state for the given program.
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the state
        :rtype: LogicalBreakpoint.State
        """

    def computeStateForTrace(self, trace: ghidra.trace.model.Trace) -> LogicalBreakpoint.State:
        """
        Compute the state for the given trace.
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the state
        :rtype: LogicalBreakpoint.State
        """

    def delete(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Delete this breakpoint everywhere in the tool.
         
         
        
        This presumes the breakpoint's specifications are deletable. This affects the mapped program,
        if applicable, and all open and live traces. Note, depending on the debugging model, the
        deleted breakpoints may be removed from other targets.
         
         
        
        This simply issues the command. The logical breakpoint is updated only when the resulting
        events are processed.
        
        :return: a future which completes when the breakpoint is deleted
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def deleteForProgram(self):
        """
        Delete any "breakpoint" bookmark in the mapped program, if applicable.
        """

    def deleteForTrace(self, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Delete this breakpoint in the given target.
         
         
        
        This presumes the breakpoint's specifications are deletable. Note that if the logical
        breakpoint is still mappable into this trace, a marker may be displayed, even though no
        breakpoint is actually present. Note, depending on the debugging model, the deleted
        breakpoint may be removed from other targets.
         
        This simply issues the command. The logical breakpoint is updated only when the resulting
        events are processed.
        
        :param ghidra.trace.model.Trace trace: the trace for the given target
        :return: a future which completes when the breakpoint is deleted
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def disable(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Disable this breakpoint everywhere in the tool.
         
         
        
        This affects the mapped program, if applicable, and all open and live traces. Note, depending
        on the debugging model, the disabled breakpoints may affect other targets.
         
         
        
        This simply issues the command. The logical breakpoint is updated only when the resulting
        events are processed.
        
        :return: a future which completes when the breakpoint is disabled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def disableForProgram(self):
        """
        Place a "disabled breakpoint" bookmark in the mapped program, if applicable.
        """

    def disableForTrace(self, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Disable this breakpoint in the given target.
         
         
        
        Note this will not create any new breakpoints. It will disable all breakpoints of the same
        kind at the mapped address. Note, depending on the debugging model, the disabled breakpoint
        may affect other targets.
         
         
        
        This simply issues the command. The logical breakpoint is updated only when the resulting
        events are processed.
        
        :param ghidra.trace.model.Trace trace: the trace for the given target
        :return: a future which completes when the breakpoint is disabled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def enable(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Enable (or create) this breakpoint everywhere in the tool.
         
         
        
        This affects the mapped program, if applicable, and all open and live traces. Note, depending
        on the debugging model, the enabled or created breakpoints may affect other targets.
         
         
        
        This simply issues the command. The logical breakpoint is updated only when the resulting
        events are processed.
        
        :return: a future which completes when the breakpoint is enabled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def enableForProgram(self):
        """
        Place an "enabled breakpoint" bookmark in the mapped program, if applicable.
        """

    def enableForTrace(self, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Enable (or create) this breakpoint in the given target.
         
         
        
        If the breakpoint already exists, it is enabled. If it's already enabled, this has no effect.
        If not, and the breakpoint is mappable to the given trace, the breakpoint is created. Note,
        depending on the debugging model, the enabled or created breakpoint may affect other targets.
        If the breakpoint is not mappable to the given trace, this has no effect.
         
         
        
        This simply issues the command(s). The logical breakpoint is updated only when the resulting
        events are processed.
        
        :param ghidra.trace.model.Trace trace: the trace for the given target
        :return: a future which completes when the breakpoint is enabled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def generateStatusEnable(self, trace: ghidra.trace.model.Trace) -> str:
        """
        Generate a status message for enabling this breakpoint
         
         
        
        If this breakpoint has no locations in the given trace, then the status message should
        explain that it cannot actually enable the breakpoint.
        
        :param ghidra.trace.model.Trace trace: optional to limit scope of message to locations in the given trace
        :return: the status message, or null
        :rtype: str
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address within the domain object that best locates this breakpoint
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getDomainObject(self) -> ghidra.framework.model.DomainObject:
        """
        Get the best representative domain object for this breakpoint's location
        
        :return: the domain object (program or trace)
        :rtype: ghidra.framework.model.DomainObject
        """

    def getEmuSleigh(self) -> str:
        """
        Get the sleigh injection when emulating this breakpoint
        
        :return: the sleigh injection
        :rtype: str
        
        .. seealso::
        
            | :obj:`TraceBreakpointLocation.getEmuSleigh(long)`
        """

    def getKinds(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        """
        Get the kinds of this logical breakpoint.
        
        :return: the kinds
        :rtype: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]
        """

    def getLength(self) -> int:
        """
        Get the (requested) length of this breakpoint
         
         
        
        Each debugger may choose whether or not to heed this, and it may depend on the breakpoint
        kinds. To know the actual length given by the debugger, inspect each contained breakpoint
        individually.
        
        :return: the requested length
        :rtype: int
        """

    def getMappedTraces(self) -> java.util.Set[ghidra.trace.model.Trace]:
        """
        Get the traces for which this logical breakpoint has an address.
         
         
        
        Note, this does not necessarily indicate that a :obj:`TraceBreakpointLocation` is present
        for each trace, but rather that for each returned trace, the logical breakpoint can be mapped
        to an address in that trace. See :meth:`getParticipatingTraces() <.getParticipatingTraces>`.
        
        :return: a copy of the set of traces
        :rtype: java.util.Set[ghidra.trace.model.Trace]
        """

    def getName(self) -> str:
        """
        If the logical breakpoint is present in a program, get its name.
        
        :return: the name, or the empty string
        :rtype: str
        """

    def getParticipatingTraces(self) -> java.util.Set[ghidra.trace.model.Trace]:
        """
        Get the traces for which this logical breakpoint has a trace breakpoint.
         
         
        
        Note, unlike :meth:`getMappedTraces() <.getMappedTraces>`, this does indicate that a
        :obj:`TraceBreakpointLocation` is present for each trace.
        
        :return: the set of traces
        :rtype: java.util.Set[ghidra.trace.model.Trace]
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        If the logical breakpoint has a mapped program location, get that program.
        
        :return: the program if mapped, or ``null``
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgramBookmark(self) -> ghidra.program.model.listing.Bookmark:
        """
        If the logical breakpoint is present in a program, get its bookmark.
         
         
        
        Note it is possible for a logical breakpoint to have a mapped program location, even though
        that location is not bookmarked, i.e., the breakpoint may not be present in the program.
        
        :return: the bookmark, or ``null``
        :rtype: ghidra.program.model.listing.Bookmark
        """

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        If the logical breakpoint has a mapped program location, get that location.
        
        :return: the location if mapped, or ``null``
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getTraceAddress(self, trace: ghidra.trace.model.Trace) -> ghidra.program.model.address.Address:
        """
        If the logical breakpoint has a mapped location for the given trace, get the address.
        
        :param ghidra.trace.model.Trace trace: the desired trace
        :return: the address if mapped, or ``null``.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getTraceBreakpoints(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        """
        Get all trace breakpoints which map to this logical breakpoint.
         
         
        
        Note that not all traces for which this logical breakpoint has an address will have a
        corresponding trace breakpoint, i.e., the breakpoint may not be present in every mappable
        trace.
        
        :return: the set of trace breakpoints
        :rtype: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]
        """

    @typing.overload
    def getTraceBreakpoints(self, trace: ghidra.trace.model.Trace) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        """
        Get all trace breakpoints for the given trace which map to this logical breakpoint.
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the set of trace breakpoints
        :rtype: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]
        """

    def isEmpty(self) -> bool:
        """
        True if there is neither a program bookmark nor any trace breakpoints aggregated.
        
        :return: true if empty
        :rtype: bool
        """

    def setEmuSleigh(self, sleigh: typing.Union[java.lang.String, str]):
        """
        Set the sleigh injection when emulating this breakpoint
        
        :param java.lang.String or str sleigh: the sleigh injection
        
        .. seealso::
        
            | :obj:`TraceBreakpointLocation.setEmuSleigh(long,String)`
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        If the logical breakpoint is present in a program, set its name.
        
        :param java.lang.String or str name: the name
        :raises IllegalStateException: if the breakpoint is not present in a program
        """

    @property
    def traceBreakpoints(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointLocation]:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def programBookmark(self) -> ghidra.program.model.listing.Bookmark:
        ...

    @property
    def traceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def kinds(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def mappedTraces(self) -> java.util.Set[ghidra.trace.model.Trace]:
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
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def participatingTraces(self) -> java.util.Set[ghidra.trace.model.Trace]:
        ...


class LogicalBreakpointsChangeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def breakpointAdded(self, added: LogicalBreakpoint):
        ...

    def breakpointRemoved(self, removed: LogicalBreakpoint):
        ...

    def breakpointUpdated(self, updated: LogicalBreakpoint):
        ...

    def breakpointsAdded(self, added: collections.abc.Sequence):
        ...

    def breakpointsRemoved(self, removed: collections.abc.Sequence):
        ...

    def breakpointsUpdated(self, updated: collections.abc.Sequence):
        ...

    def locationAdded(self, added: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...

    def locationRemoved(self, removed: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...

    def locationUpdated(self, updated: ghidra.trace.model.breakpoint.TraceBreakpointLocation):
        ...



__all__ = ["LogicalBreakpoint", "LogicalBreakpointsChangeListener"]
