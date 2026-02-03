from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.debug.api.tracemgr
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import ghidra.trace.model.guest
import ghidra.trace.model.stack
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore


class Target(java.lang.Object):
    """
    The interface between the front-end UI and the back-end connector.
     
     
    
    Anything the UI might command a target to do must be defined as a method here. Each
    implementation can then sort out, using context from the UI as appropriate, how best to effect
    the command using the protocol and resources available on the back-end.
    """

    class ActionEntry(java.lang.Object):
        """
        A description of a UI action provided by this target.
         
         
        
        In most cases, this will generate a menu entry or a toolbar button, but in some cases, it's
        just invoked implicitly. Often, the two suppliers are implemented using lambda functions, and
        those functions will keep whatever some means of querying UI and/or target context in their
        closures.
        """

        class_: typing.ClassVar[java.lang.Class]

        def details(self) -> str:
            """
            Get the text providing more details, usually displayed in a tool tip
            
            :return: the details
            :rtype: str
            """

        def display(self) -> str:
            """
            Get the text to display on UI actions associated with this entry
            
            :return: the display
            :rtype: str
            """

        def get(self, prompt: typing.Union[jpype.JBoolean, bool]) -> java.lang.Object:
            """
            Invoke the action synchronously, getting its result
            
            :param jpype.JBoolean or bool prompt: whether or not to prompt the user for arguments
            :return: the resulting value, if applicable
            :rtype: java.lang.Object
            """

        def getShow(self) -> ActionName.Show:
            """
            Check if this action's name is built in
            
            :return: true if built in.
            :rtype: ActionName.Show
            """

        def icon(self) -> javax.swing.Icon:
            """
            Get the icon to display in menus and dialogs
            
            :return: the icon
            :rtype: javax.swing.Icon
            """

        def invokeAsync(self, prompt: typing.Union[jpype.JBoolean, bool]) -> java.util.concurrent.CompletableFuture[typing.Any]:
            """
            Invoke the action asynchronously, prompting if desired
             
             
            
            Note this will impose a timeout of :const:`Target.TIMEOUT_MILLIS` milliseconds.
            
            :param jpype.JBoolean or bool prompt: whether or not to prompt the user for arguments
            :return: the future result, often :obj:`Void`
            :rtype: java.util.concurrent.CompletableFuture[typing.Any]
            """

        def invokeAsyncWithoutTimeout(self, prompt: typing.Union[jpype.JBoolean, bool]) -> java.util.concurrent.CompletableFuture[typing.Any]:
            """
            Invoke the action asynchronously, prompting if desired.
             
             
            
            The implementation is not required to provide a timeout; however, downstream components
            may.
            
            :param jpype.JBoolean or bool prompt: whether or not to prompt the user for arguments
            :return: the future result, often :obj:`Void`
            :rtype: java.util.concurrent.CompletableFuture[typing.Any]
            """

        def isEnabled(self) -> bool:
            """
            Check if this action is currently enabled
            
            :return: true if enabled
            :rtype: bool
            """

        def name(self) -> ActionName:
            """
            Get the name of a common debugger command this action implements
            
            :return: the name
            :rtype: ActionName
            """

        def requiresPrompt(self) -> bool:
            """
            Check whether invoking the action requires further user interaction
            
            :return: true if prompting is required
            :rtype: bool
            """

        def run(self, prompt: typing.Union[jpype.JBoolean, bool]):
            """
            Invoke the action synchronously
             
             
            
            To avoid blocking the Swing thread on a remote socket, this method cannot be called on
            the Swing thread.
            
            :param jpype.JBoolean or bool prompt: whether or not to prompt the user for arguments
            """

        def specificity(self) -> int:
            """
            Get a relative score of specificity.
             
             
            
            These are only meaningful when compared among entries returned in the same collection.
            
            :return: the specificity
            :rtype: int
            """

        @property
        def show(self) -> ActionName.Show:
            ...

        @property
        def enabled(self) -> jpype.JBoolean:
            ...


    class ObjectArgumentPolicy(java.lang.Enum[Target.ObjectArgumentPolicy]):
        """
        Specifies how object arguments are derived
        """

        class_: typing.ClassVar[java.lang.Class]
        CONTEXT_ONLY: typing.Final[Target.ObjectArgumentPolicy]
        """
        The object should be taken exactly from the action context, if applicable, present, and
        matching in schema.
        """

        CURRENT_AND_RELATED: typing.Final[Target.ObjectArgumentPolicy]
        """
        The object should be taken from the current (active) object in the tool, or a suitable
        relative having the correct schema.
        """

        EITHER_AND_RELATED: typing.Final[Target.ObjectArgumentPolicy]
        """
        The object can be taken from the given context, or the current (active) object in the
        tool, or a suitable relative having the correct schema.
        """


        def allowContextObject(self) -> bool:
            ...

        def allowCoordsObject(self) -> bool:
            ...

        def allowSuitableRelative(self) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Target.ObjectArgumentPolicy:
            ...

        @staticmethod
        def values() -> jpype.JArray[Target.ObjectArgumentPolicy]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    TIMEOUT_MILLIS: typing.Final = 10000

    def activate(self, prev: ghidra.debug.api.tracemgr.DebuggerCoordinates, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        """
        Request that the back end's focus be set to the same as the front end's (Ghidra's) GUI.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates prev: the GUI's immediately previous coordinates
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coords: the GUI's current coordinates
        """

    def activateAsync(self, prev: ghidra.debug.api.tracemgr.DebuggerCoordinates, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.activate(DebuggerCoordinates, DebuggerCoordinates)`
        """

    def collectActions(self, name: ActionName, context: docking.ActionContext, policy: Target.ObjectArgumentPolicy) -> java.util.Map[java.lang.String, Target.ActionEntry]:
        """
        Collect all actions that implement the given common debugger command
         
         
        
        Note that if the context provides a program location (i.e., address), the object policy is
        ignored. It will use current and related objects.
        
        :param ActionName name: the action name
        :param docking.ActionContext context: applicable context from the UI
        :param Target.ObjectArgumentPolicy policy: determines how objects may be found
        :return: the collected actions
        :rtype: java.util.Map[java.lang.String, Target.ActionEntry]
        """

    def deleteBreakpoint(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointCommon):
        """
        Delete the given breakpoint from the target
         
         
        
        If successful, this method must cause the breakpoint removal to be recorded in the trace.
        Otherwise, it should throw an exception.
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointCommon breakpoint: the breakpoint to delete
        """

    def deleteBreakpointAsync(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointCommon) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.deleteBreakpoint(TraceBreakpointCommon)`
        """

    def describe(self) -> str:
        """
        Describe the target for display in the UI
        
        :return: the description
        :rtype: str
        """

    def disconnect(self):
        """
        Terminate the target and its connection
         
         
        
        **WARNING:** This terminates the connection, even if there are other live targets still
        using it. One example where this might happen is if the target process launches a child, and
        the debugger is configured to remain attached to both. Whether this is expected or acceptable
        behavior has not been decided.
         
         
        
        **NOTE:** This method cannot be invoked on the Swing thread, because it may block on I/O.
        
        
        .. seealso::
        
            | :obj:`.disconnectAsync()`
        """

    def disconnectAsync(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.disconnect()`
        """

    def execute(self, command: typing.Union[java.lang.String, str], toString: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Execute a command as if in the CLI
        
        :param java.lang.String or str command: the command
        :param jpype.JBoolean or bool toString: true to capture the output and return it, false to print to the terminal
        :return: the captured output, or null if ``toString`` is false
        :rtype: str
        """

    def executeAsync(self, command: typing.Union[java.lang.String, str], toString: typing.Union[jpype.JBoolean, bool]) -> java.util.concurrent.CompletableFuture[java.lang.String]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.execute(String, boolean)`
        """

    def forceTerminate(self):
        """
        Forcefully terminate the target
         
         
        
        This will first attempt to kill the target gracefully. In addition, and whether or not the
        target is successfully terminated, the target will be dissociated from its trace, and the
        target will be invalidated. To attempt only a graceful termination, check
        :meth:`collectActions(ActionName, ActionContext, ObjectArgumentPolicy) <.collectActions>` with
        :obj:`ActionName.KILL`.
        """

    def forceTerminateAsync(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.forceTerminate()`
        """

    def forciblyCloseTransactions(self):
        """
        Forcibly commit all of the back-ends transactions on this target's trace.
         
         
        
        This is generally not a recommended course of action, except that sometimes the back-end
        crashes and fails to close a transaction. It should only be invoked by a relatively hidden
        menu option, and mediated by a warning of some sort. Closing a transaction prematurely, when
        the back-end actually *does* still need it may cause a host of other problems.
        """

    def getFocus(self) -> ghidra.trace.model.target.path.KeyPath:
        """
        Get the object that currently has focus on the back end's UI
        
        :return: the focused object's path, or null
        :rtype: ghidra.trace.model.target.path.KeyPath
        """

    def getSnap(self) -> int:
        """
        Get the current snapshot key for the target
         
         
        
        For most targets, this is the most recently created snapshot. For time-traveling targets, if
        may not be. If this returns a negative number, then it refers to a scratch snapshot and
        almost certainly indicates time travel with instruction steps. Use :meth:`getTime() <.getTime>` in that
        case to get a more precise schedule.
        
        :return: the snapshot
        :rtype: int
        """

    def getStackFrameForSuccessor(self, path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.stack.TraceStackFrame:
        """
        Get the trace stack frame that contains the given object
        
        :param ghidra.trace.model.target.path.KeyPath path: the path of the object
        :return: the stack frame, or null
        :rtype: ghidra.trace.model.stack.TraceStackFrame
        """

    def getSupportedBreakpointKinds(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        """
        Get the kinds of breakpoints supported by the target.
        
        :return: the set of kinds
        :rtype: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]
        """

    def getSupportedTimeForm(self, obj: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.time.schedule.TraceSchedule.ScheduleForm:
        """
        Get the form of schedules supported by "activate" on the back end
         
         
        
        A non-null return value indicates the back end supports time travel. If it does, the return
        value indicates the form of schedules that can be activated, (i.e., via some "go to time"
        command). NOTE: Switching threads is considered an event by every time-traveling back end
        that we know of. Events are usually mapped to a Ghidra trace's snapshots, and so most back
        ends are constrained to schedules of the form :obj:`ScheduleForm.SNAP_EVT_STEPS`. A back-end
        based on emulation may support thread switching. To support p-code op stepping, the back-end
        will certainly have to be based on p-code emulation, and it must be using the same Sleigh
        language as Ghidra.
        
        :param ghidra.trace.model.target.TraceObject obj: the object (or an ancestor) that may support time travel
        :param jpype.JLong or int snap: the *destination* snapshot
        :return: the form
        :rtype: ghidra.trace.model.time.schedule.TraceSchedule.ScheduleForm
        """

    def getThreadExecutionState(self, thread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.TraceExecutionState:
        """
        Get the execution state of the given thread
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :return: the state
        :rtype: ghidra.trace.model.TraceExecutionState
        """

    def getThreadForSuccessor(self, path: ghidra.trace.model.target.path.KeyPath) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the trace thread that contains the given object
        
        :param ghidra.trace.model.target.path.KeyPath path: the path of the object
        :return: the thread, or null
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getTime(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        """
        Get the current time
        
        :return: the current time
        :rtype: ghidra.trace.model.time.schedule.TraceSchedule
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace into which this target is recorded
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def invalidateMemoryCaches(self):
        """
        Invalidate any caches on the target's back end or on the client side of the connection.
         
         
        
        In general, back ends should avoid doing any caching. Instead, the front-end will assume
        anything marked :obj:`TraceMemoryState.KNOWN` is up to date. I.e., the trace database acts
        as the client-side cache for a live target.
         
         
        
        **NOTE:** This method exists for invalidating model-based target caches. It may be
        deprecated and removed, unless it turns out we need this for Trace RMI, too.
        """

    def invalidateMemoryCachesAsync(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.invalidateMemoryCaches()`
        """

    def isBreakpointValid(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> bool:
        """
        Check if the given breakpoint (location) is still valid on target
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation breakpoint: the breakpoint
        :return: true if valid
        :rtype: bool
        """

    def isBusy(self) -> bool:
        """
        Check if the target is busy updating the trace
         
         
        
        This generally means the connection has an open transaction. If *does not* indicate
        the execution state of the target/debuggee.
        
        :return: true if busy
        :rtype: bool
        """

    def isSupportsFocus(self) -> bool:
        """
        Check if the target supports synchronizing focus
        
        :return: true if supported
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Check if the target is still valid
        
        :return: true if valid
        :rtype: bool
        """

    def isVariableExists(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check if a given variable (register or memory) exists on target
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the registers
        :param ghidra.trace.model.thread.TraceThread thread: if a register, the thread whose registers to examine
        :param jpype.JInt or int frame: the frame level, usually 0.
        :param ghidra.program.model.address.Address address: the address of the variable
        :param jpype.JInt or int length: the size of the variable. Ignored for memory
        :return: true if the variable can be mapped to the target
        :rtype: bool
        """

    def placeBreakpoint(self, range: ghidra.program.model.address.AddressRange, kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind], condition: typing.Union[java.lang.String, str], commands: typing.Union[java.lang.String, str]):
        """
        Place a new breakpoint of the given kind(s) over the given range
         
         
        
        If successful, this method must cause the breakpoint to be recorded into the trace.
        Otherwise, it should throw an exception.
        
        :param ghidra.program.model.address.AddressRange range: the range. NOTE: The target is only required to support length-1 execution
                    breakpoints.
        :param java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind] kinds: the kind(s) of the breakpoint.
        :param java.lang.String or str condition: optionally, a condition for the breakpoint, expressed in the back-end's
                    language. NOTE: May be silently ignored by the implementation, if not supported.
        :param java.lang.String or str commands: optionally, a command to execute upon hitting the breakpoint, expressed in
                    the back-end's language. NOTE: May be silently ignored by the implementation, if
                    not supported.
        """

    def placeBreakpointAsync(self, range: ghidra.program.model.address.AddressRange, kinds: java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind], condition: typing.Union[java.lang.String, str], commands: typing.Union[java.lang.String, str]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.placeBreakpoint(AddressRange, Set, String, String)`
        """

    def readMemory(self, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Read and capture several ranges of target memory
         
         
        
        The target may read more than the requested memory, usually because it will read all pages
        containing any portion of the requested set. The target should attempt to read at least the
        given memory. To the extent it is successful, it must cause the values to be recorded into
        the trace *before* this method returns. Only if the request is *entirely*
        unsuccessful should this method throw an exception. Otherwise, the failed portions, if any,
        should be logged without throwing an exception.
        
        :param ghidra.program.model.address.AddressSetView set: the addresses to capture
        :param ghidra.util.task.TaskMonitor monitor: a monitor for displaying task steps
        :raises CancelledException: if the operation is cancelled
        """

    def readMemoryAsync(self, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.readMemory(AddressSetView, TaskMonitor)`
        """

    @typing.overload
    def readRegisters(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], registers: java.util.Set[ghidra.program.model.lang.Register]):
        """
        Read and capture the named target registers for the given platform, thread, and frame.
         
         
        
        Target target should read the registers and, to the extent it is successful, cause the values
        to be recorded into the trace *before* this method returns. Only if the request is
        *entirely* unsuccessful should this method throw an exception. Otherwise, the failed
        registers, if any, should be logged without throwing an exception.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform defining the registers
        :param ghidra.trace.model.thread.TraceThread thread: the thread whose context contains the register values
        :param jpype.JInt or int frame: the frame, if applicable, for saved register values. 0 for current values.
        :param java.util.Set[ghidra.program.model.lang.Register] registers: the registers to read
        """

    @typing.overload
    def readRegisters(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], guestSet: ghidra.program.model.address.AddressSetView):
        """
        Read and capture the target registers in the given address set.
         
         
        
        Aside from how registers are named, this works equivalently to
        :meth:`readRegisters(TracePlatform, TraceThread, int, Set) <.readRegisters>`.
        """

    @typing.overload
    def readRegistersAsync(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], registers: java.util.Set[ghidra.program.model.lang.Register]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.readRegisters(TracePlatform, TraceThread, int, Set)`
        """

    @typing.overload
    def readRegistersAsync(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], guestSet: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.readRegistersAsync(TracePlatform, TraceThread, int, AddressSetView)`
        """

    def toggleBreakpoint(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointCommon, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Toggle the given breakpoint on the target
         
         
        
        If successful, this method must cause the breakpoint toggle to be recorded in the trace. If
        the state is already as desired, this method may have no effect. If unsuccessful, this method
        should throw an exception.
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointCommon breakpoint: the breakpoint to toggle
        :param jpype.JBoolean or bool enabled: true to enable, false to disable
        """

    def toggleBreakpointAsync(self, breakpoint: ghidra.trace.model.breakpoint.TraceBreakpointCommon, enabled: typing.Union[jpype.JBoolean, bool]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.toggleBreakpoint(TraceBreakpointLocation, boolean)`
        """

    def writeMemory(self, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]):
        """
        Write data to the target's memory
         
         
        
        The target should attempt to write the memory. To the extent it is successful, it must cause
        the effects to be recorded into the trace *before* this method returns. Only if the
        request is *entirely* unsuccessful should this method throw an exception. Otherwise,
        the failed portions, if any, should be logged without throwing an exception.
        
        :param ghidra.program.model.address.Address address: the starting address
        :param jpype.JArray[jpype.JByte] data: the bytes to write
        """

    def writeMemoryAsync(self, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.readMemory(AddressSetView, TaskMonitor)`
        """

    @typing.overload
    def writeRegister(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], value: ghidra.program.model.lang.RegisterValue):
        """
        Write a value to a target register for the given platform, thread, and frame
         
         
        
        The target should attempt to write the register. If successful, it must cause the effects to
        be recorded into the trace *before* this method returns. If the request is
        unsuccessful, this method throw an exception.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the registers
        :param ghidra.trace.model.thread.TraceThread thread: the thread whose register to write
        :param jpype.JInt or int frame: the frame level, usually 0.
        :param ghidra.program.model.lang.RegisterValue value: the register and value to write
        """

    @typing.overload
    def writeRegister(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]):
        """
        Write a value to a target register by its address
         
         
        
        Aside from how the register is named, this works equivalently to
        :meth:`writeRegister(TracePlatform, TraceThread, int, RegisterValue) <.writeRegister>`. The address is the
        one defined by Ghidra.
        """

    @typing.overload
    def writeRegisterAsync(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], value: ghidra.program.model.lang.RegisterValue) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.writeRegister(TracePlatform, TraceThread, int, RegisterValue)`
        """

    @typing.overload
    def writeRegisterAsync(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.writeRegister(TracePlatform, TraceThread, int, Address, byte[])`
        """

    def writeVariable(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]):
        """
        Write a variable (memory or register) of the given thread or the process
         
         
        
        This is a convenience for writing target memory or registers, based on address. If the given
        address represents a register, this will attempt to map it to a register and write it in the
        given thread and frame. If the address is in memory, it will simply delegate to
        :meth:`writeMemory(Address, byte[]) <.writeMemory>`.
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread. Ignored (may be null) if address is in memory
        :param jpype.JInt or int frame: the frame, usually 0. Ignored if address is in memory
        :param ghidra.program.model.address.Address address: the starting address
        :param jpype.JArray[jpype.JByte] data: the value to write
        """

    def writeVariableAsync(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.writeVariable(TracePlatform, TraceThread, int, Address, byte[])`
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def threadForSuccessor(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def breakpointValid(self) -> jpype.JBoolean:
        ...

    @property
    def stackFrameForSuccessor(self) -> ghidra.trace.model.stack.TraceStackFrame:
        ...

    @property
    def supportsFocus(self) -> jpype.JBoolean:
        ...

    @property
    def threadExecutionState(self) -> ghidra.trace.model.TraceExecutionState:
        ...

    @property
    def supportedBreakpointKinds(self) -> java.util.Set[ghidra.trace.model.breakpoint.TraceBreakpointKind]:
        ...

    @property
    def focus(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    @property
    def time(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class ActionName(java.lang.Record):
    """
    A name for a commonly-recognized target action.
     
     
    
    Many common commands/actions have varying names across different back-end debuggers. We'd like to
    present common idioms for these common actions, but allow them to keep the names used by the
    back-end, because those names are probably better known to users of that back-end than Ghidra's
    action names are known. The action hints will affect the icon and placement of the action in the
    UI, but the display name will still reflect the name given by the back-end. Note that the "stock"
    action names are not a fixed enumeration. These are just the ones that might get special
    treatment from Ghidra. All methods should appear somewhere (at least, e.g., in context menus for
    applicable objects), even if the action name is unspecified or does not match a stock name. This
    list may change over time, but that shouldn't matter much. Each back-end should make its best
    effort to match its methods to these stock actions where applicable, but ultimately, it is up to
    the UI to decide what is presented where.
    """

    class Show(java.lang.Enum[ActionName.Show]):
        """
        Specifies when an action should appear in the menus. For diagnostics, a user may override
        this by holding SHIFT when right-clicking, causing all applicable general actions to appear.
        """

        class_: typing.ClassVar[java.lang.Class]
        BUILTIN: typing.Final[ActionName.Show]
        """
        Don't show general actions. The tool has built-in actions that already know how to invoke
        this.
        """

        ADDRESS: typing.Final[ActionName.Show]
        """
        Only show general actions in address-based context, e.g., when right-clicking in the
        listing.
        """

        EXTENDED: typing.Final[ActionName.Show]
        """
        Show in all contexts. This is the default.
        """


        def isShowing(self, context: docking.ActionContext) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ActionName.Show:
            ...

        @staticmethod
        def values() -> jpype.JArray[ActionName.Show]:
            ...

        @property
        def showing(self) -> jpype.JBoolean:
            ...


    class Enabler(java.lang.Enum[ActionName.Enabler]):

        class_: typing.ClassVar[java.lang.Class]
        ALWAYS: typing.Final[ActionName.Enabler]
        NOT_RUNNING: typing.Final[ActionName.Enabler]
        NOT_STOPPED: typing.Final[ActionName.Enabler]
        NOT_DEAD: typing.Final[ActionName.Enabler]

        def isEnabled(self, obj: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ActionName.Enabler:
            ...

        @staticmethod
        def values() -> jpype.JArray[ActionName.Enabler]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    REFRESH: typing.Final[ActionName]
    ACTIVATE: typing.Final[ActionName]
    """
    Activate a given object and optionally a time
     
     
    
    Forms: (focus:Object), (focus:Object, snap:LONG), (focus:Object, time:STR)
    """

    FOCUS: typing.Final[ActionName]
    """
    A weaker form of activate.
     
     
    
    The user has expressed interest in an object, but has not activated it yet. This is often
    used to communicate selection (i.e., highlight) of the object. Whereas, double-clicking or
    pressing enter would more likely invoke 'activate.'
    """

    TOGGLE: typing.Final[ActionName]
    DELETE: typing.Final[ActionName]
    EXECUTE: typing.Final[ActionName]
    """
    Execute a CLI command
     
     
    
    Forms: (cmd:STRING):STRING; Optional arguments: capture:BOOL
    """

    CONNECT: typing.Final[ActionName]
    """
    Connect the back-end to a (usually remote) target
     
     
    
    Forms: (spec:STRING)
    """

    ATTACH: typing.Final[ActionName]
    """
    Forms: (target:Attachable), (pid:INT), (spec:STRING)
    """

    DETACH: typing.Final[ActionName]
    LAUNCH: typing.Final[ActionName]
    """
    Forms: (command_line:STRING), (file:STRING,args:STRING), (file:STRING,args:STRING_ARRAY),
    (ANY*)
    """

    KILL: typing.Final[ActionName]
    RESUME: typing.Final[ActionName]
    INTERRUPT: typing.Final[ActionName]
    STEP_INTO: typing.Final[ActionName]
    """
    All of these will show in the "step" portion of the control toolbar, if present. The
    difference in each "step_x" is minor. The icon will indicate which form, and the positions
    will be shifted so they appear in a consistent order. The display name is determined by the
    method name, not the action name. For stepping actions that don't fit the standards, use
    :obj:`.STEP_EXT`. There should be at most one of each standard applicable for any given
    context. (Multiple will appear, but may confuse the user.) You can have as many extended step
    actions as you like. They will be ordered lexicographically by name.
    """

    STEP_OVER: typing.Final[ActionName]
    STEP_OUT: typing.Final[ActionName]
    STEP_SKIP: typing.Final[ActionName]
    """
    Skip is not typically available, except in emulators. If the back-end debugger does not have
    a command for this action out-of-the-box, we do not recommend trying to implement it
    yourself. The purpose of these actions just to expose/map each command to the UI, not to
    invent new features for the back-end debugger.
    """

    STEP_BACK: typing.Final[ActionName]
    """
    Step back is not typically available, except in emulators and timeless (or time-travel)
    debuggers.
    """

    STEP_EXT: typing.Final[ActionName]
    """
    The action for steps that don't fit one of the common stepping actions.
    """

    BREAK_SW_EXECUTE: typing.Final[ActionName]
    """
    Forms: (addr:ADDRESS), R/W(rng:RANGE), (expr:STRING)
     
     
    
    Optional arguments: condition:STRING, commands:STRING
     
     
    
    The client may pass either null or "" for condition and/or commands to indicate omissions of
    those arguments.
    """

    BREAK_HW_EXECUTE: typing.Final[ActionName]
    BREAK_READ: typing.Final[ActionName]
    BREAK_WRITE: typing.Final[ActionName]
    BREAK_ACCESS: typing.Final[ActionName]
    BREAK_EXT: typing.Final[ActionName]
    READ_MEM: typing.Final[ActionName]
    """
    Forms: (rng:RANGE)
    """

    WRITE_MEM: typing.Final[ActionName]
    """
    Forms: (addr:ADDRESS,data:BYTES)
    """

    WRITE_REG: typing.Final[ActionName]
    """
    Forms: (frame:Frame,name:STRING,value:BYTES), (register:Register,value:BYTES)
    """


    def __init__(self, name: typing.Union[java.lang.String, str], show: ActionName.Show, enabler: ActionName.Enabler, display: typing.Union[java.lang.String, str], icon: javax.swing.Icon, okText: typing.Union[java.lang.String, str]):
        ...

    def display(self) -> str:
        ...

    def enabler(self) -> ActionName.Enabler:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def icon(self) -> javax.swing.Icon:
        ...

    @staticmethod
    @typing.overload
    def name(name: typing.Union[java.lang.String, str]) -> ActionName:
        ...

    @typing.overload
    def name(self) -> str:
        ...

    def okText(self) -> str:
        ...

    def show(self) -> ActionName.Show:
        ...

    def toString(self) -> str:
        ...


class TargetPublicationListener(java.lang.Object):
    """
    A listener for changes to the set of published targets
    """

    class_: typing.ClassVar[java.lang.Class]

    def targetPublished(self, target: Target):
        """
        The given target was published
        
        :param Target target: the published target
        """

    def targetWithdrawn(self, target: Target):
        """
        The given target was withdrawn, usually because it's no longer valid
        
        :param Target target: the withdrawn target
        """



__all__ = ["Target", "ActionName", "TargetPublicationListener"]
