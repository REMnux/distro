from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.script
import ghidra.app.services
import ghidra.debug.api.breakpoint
import ghidra.debug.api.control
import ghidra.debug.api.target
import ghidra.debug.api.tracemgr
import ghidra.debug.api.tracermi
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.program
import ghidra.trace.model.target
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import ghidra.util.task
import java.lang # type: ignore
import java.math # type: ignore
import java.nio # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


T = typing.TypeVar("T")


class FlatDebuggerRmiAPI(FlatDebuggerAPI):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getLaunchOffers(self, program: ghidra.program.model.listing.Program) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Get offers for launching the given program
        
        :param ghidra.program.model.listing.Program program: the program, or null for no image
        :return: the offers
        :rtype: java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    @typing.overload
    def getLaunchOffers(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Get offers for launching the current program
        
        :return: the offers
        :rtype: java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    @typing.overload
    def getSavedLaunchOffers(self, program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Get saved offers for launching the given program, ordered by most-recently-saved
        
        :param ghidra.program.model.listing.Program program: the program, or null for no image
        :return: the offers
        :rtype: java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    @typing.overload
    def getSavedLaunchOffers(self) -> java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Get saved offers for launching the current program, ordered by most-recently-saved
        
        :return: the offers
        :rtype: java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    def getTraceRmiLauncherService(self) -> ghidra.app.services.TraceRmiLauncherService:
        """
        Get the trace-rmi launcher service
        
        :return: the service
        :rtype: ghidra.app.services.TraceRmiLauncherService
        """

    @typing.overload
    def launch(self, offer: ghidra.debug.api.tracermi.TraceRmiLaunchOffer, overrideArgs: collections.abc.Mapping, monitor: ghidra.util.task.TaskMonitor) -> ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult:
        """
        Launch the given offer with the default, saved, and/or overridden arguments
         
         
        
        If the offer has saved arguments, those will be loaded. Otherwise, the default arguments will
        be used. If given, specific arguments can be overridden by the caller. The caller may need to
        examine the offer's parameters before overriding any arguments. Conventionally, the argument
        displayed as "Image" gives the path to the executable, and "Args" gives the command-line
        arguments to pass to the target.
        
        :param ghidra.debug.api.tracermi.TraceRmiLaunchOffer offer: the offer to launch
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the launch stages
        :param collections.abc.Mapping overrideArgs: overridden arguments, which may be empty
        :return: the launch result, which may indicate errors
        :rtype: ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult
        """

    @typing.overload
    def launch(self, offer: ghidra.debug.api.tracermi.TraceRmiLaunchOffer, monitor: ghidra.util.task.TaskMonitor) -> ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult:
        """
        Launch the given offer with the default or saved arguments
        
        :param ghidra.debug.api.tracermi.TraceRmiLaunchOffer offer: the offer to launch
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the launch stages
        :return: the launch result, which may indicate errors
        :rtype: ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult
        """

    @typing.overload
    def launch(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult:
        """
        Launch the given program with the most-recently-saved offer
        
        :param ghidra.program.model.listing.Program program: the program to launch
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the launch stages
        :return: the launch result, which may indicate errors
        :rtype: ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult
        """

    @typing.overload
    def launch(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult:
        """
        Launch the current program with the most-recently-saved offer
        
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the launch stages
        :return: the launch result, which may indicate errors
        :rtype: ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult
        """

    @typing.overload
    def requireLastLaunchOffer(self, program: ghidra.program.model.listing.Program) -> ghidra.debug.api.tracermi.TraceRmiLaunchOffer:
        """
        Get the most-recently-saved launch offer for the given program
        
        :param ghidra.program.model.listing.Program program: the program, or null for no image
        :return: the offer
        :rtype: ghidra.debug.api.tracermi.TraceRmiLaunchOffer
        :raises NoSuchElementException: if no offer's configuration has been saved
        """

    @typing.overload
    def requireLastLaunchOffer(self) -> ghidra.debug.api.tracermi.TraceRmiLaunchOffer:
        """
        Get the most-recently-saved launch offer for the current program
        
        :return: the offer
        :rtype: ghidra.debug.api.tracermi.TraceRmiLaunchOffer
        :raises NoSuchElementException: if no offer's configuration has been saved
        """

    @property
    def launchOffers(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        ...

    @property
    def traceRmiLauncherService(self) -> ghidra.app.services.TraceRmiLauncherService:
        ...

    @property
    def savedLaunchOffers(self) -> java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        ...


class FlatDebuggerAPI(java.lang.Object):
    """
    This interface is a flattened version of the Debugger and Trace APIs.
     
     
    
    To use this "mix-in" interface, extend :obj:`GhidraScript` as you normally would for your
    script, but also add this interface to the ``implements`` clause of your script, e.g.,
    ``class MyDebuggerScript extends GhidraScript implements FlatDebuggerAPI``.
    """

    class ExpectingBreakpointChanges(java.lang.AutoCloseable):
        """
        Class that implements :meth:`FlatDebuggerAPI.expectBreakpointChanges() <FlatDebuggerAPI.expectBreakpointChanges>`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, flat: FlatDebuggerAPI, service: ghidra.app.services.DebuggerLogicalBreakpointService):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def activateFrame(self, frame: typing.Union[jpype.JInt, int]):
        """
        Make the given frame the active frame
        
        :param jpype.JInt or int frame: the frame level, 0 being the innermost
        """

    def activateSnap(self, snap: typing.Union[jpype.JLong, int]):
        """
        Make the given snapshot the active snapshot
         
         
        
        Activating negative snapshot keys is not recommended. The trace manager uses negative keys
        for emulation scratch space and will activate them indirectly as needed.
        
        :param jpype.JLong or int snap: the snapshot key
        """

    def activateThread(self, thread: ghidra.trace.model.thread.TraceThread):
        """
        Make the given thread the active thread
         
         
        
        if the trace is not already open in the tool, it will be opened automatically
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        """

    def activateTrace(self, trace: ghidra.trace.model.Trace):
        """
        Make the given trace the active trace
         
         
        
        If the trace is not already open in the tool, it will be opened automatically
        
        :param ghidra.trace.model.Trace trace: the trace
        """

    def breakpointSet(self, location: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JLong, int], kinds: ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet, name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Set a breakpoint at the given location
         
         
        
        **NOTE:** Many asynchronous events take place when creating a breakpoint, esp., among
        several live targets. Furthermore, some targets may adjust the breakpoint specification just
        slightly. This method does its best to identify the resulting breakpoint(s) once things have
        settled. Namely, it retrieves breakpoints at the specific location having the specified name
        and assumes those are the result. It is possible this command succeeds, but this method fails
        to identify the result. In that case, the returned result will be the empty set.
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :param jpype.JLong or int length: the length, for "access breakpoints" or "watchpoints"
        :param ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet kinds: the kinds, not all combinations are reasonable
        :param java.lang.String or str name: a user-defined name
        :return: the resulting breakpoint(s), or null if failed
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointSetAccess(self, location: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Set an access breakpoint at the given location
         
         
        
        This might also be called a "watchpoint."
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :param jpype.JInt or int length: the length
        :param java.lang.String or str name: a user-defined name
        :return: true if successful
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointSetHardwareExecute(self, location: ghidra.program.util.ProgramLocation, name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Set a hardware breakpoint at the given location
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :param java.lang.String or str name: a user-defined name
        :return: true if successful
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointSetRead(self, location: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Set a read breakpoint at the given location
         
         
        
        This might also be called a "read watchpoint" or a "read access breakpoint."
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :param jpype.JInt or int length: the length
        :param java.lang.String or str name: a user-defined name
        :return: true if successful
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointSetSoftwareExecute(self, location: ghidra.program.util.ProgramLocation, name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Set a software breakpoint at the given location
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :param java.lang.String or str name: a user-defined name
        :return: true if successful
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointSetWrite(self, location: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Set a write breakpoint at the given location
         
         
        
        This might also be called a "write watchpoint" or a "write access breakpoint."
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :param jpype.JInt or int length: the length
        :param java.lang.String or str name: a user-defined name
        :return: true if successful
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointsClear(self, location: ghidra.program.util.ProgramLocation) -> bool:
        """
        Clear the breakpoints at a given location
        
        :param ghidra.program.util.ProgramLocation location: the location, can be static or dynamic
        :return: true if successful, false otherwise
        :rtype: bool
        """

    def breakpointsDisable(self, location: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Disable the breakpoints at a given location
        
        :param ghidra.program.util.ProgramLocation location: the location, can be static or dynamic
        :return: the (possibly empty) set of breakpoints at that location, or null if failed
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointsEnable(self, location: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Enable the breakpoints at a given location
        
        :param ghidra.program.util.ProgramLocation location: the location, can be static or dynamic
        :return: the (possibly empty) set of breakpoints at that location, or null if failed
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def breakpointsToggle(self, location: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Toggle the breakpoints at a given location
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :return: the (possibly empty) set of breakpoints at that location, or null if failed
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def closeTrace(self, trace: ghidra.trace.model.Trace):
        """
        Close the given trace in the UI
        
        :param ghidra.trace.model.Trace trace: the trace
        """

    @typing.overload
    def createContext(self, object: ghidra.trace.model.target.TraceObject) -> docking.ActionContext:
        ...

    @typing.overload
    def createContext(self, thread: ghidra.trace.model.thread.TraceThread) -> docking.ActionContext:
        ...

    @typing.overload
    def createContext(self, trace: ghidra.trace.model.Trace) -> docking.ActionContext:
        ...

    @typing.overload
    def createStateEditor(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.app.services.DebuggerControlService.StateEditor:
        """
        Create a state editor for the given context, adhering to its current control mode
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the context
        :return: the editor
        :rtype: ghidra.app.services.DebuggerControlService.StateEditor
        """

    @typing.overload
    def createStateEditor(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> ghidra.app.services.DebuggerControlService.StateEditor:
        """
        Create a state editor suitable for memory edits for the given context
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :return: the editor
        :rtype: ghidra.app.services.DebuggerControlService.StateEditor
        """

    @typing.overload
    def createStateEditor(self, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int]) -> ghidra.app.services.DebuggerControlService.StateEditor:
        """
        Create a state editor suitable for register or memory edits for the given context
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JInt or int frame: the frame
        :param jpype.JLong or int snap: the snap
        :return: the editor
        :rtype: ghidra.app.services.DebuggerControlService.StateEditor
        """

    @typing.overload
    def createStateEditor(self) -> ghidra.app.services.DebuggerControlService.StateEditor:
        """
        Create a state editor for the current context, adhering to the current control mode
        
        :return: the editor
        :rtype: ghidra.app.services.DebuggerControlService.StateEditor
        """

    def doAction(self, target: ghidra.debug.api.target.Target, name: ghidra.debug.api.target.ActionName, context: docking.ActionContext) -> java.lang.Object:
        ...

    def doThreadAction(self, thread: ghidra.trace.model.thread.TraceThread, name: ghidra.debug.api.target.ActionName) -> bool:
        ...

    def doTraceAction(self, trace: ghidra.trace.model.Trace, name: ghidra.debug.api.target.ActionName) -> bool:
        ...

    @typing.overload
    def dynamicLocation(self, view: ghidra.trace.model.program.TraceProgramView, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the given view
        
        :param ghidra.trace.model.program.TraceProgramView view: the (dynamic) trace view
        :param ghidra.program.model.address.Address address: the address
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, view: ghidra.trace.model.program.TraceProgramView, addrString: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the given view
        
        :param ghidra.trace.model.program.TraceProgramView view: the (dynamic) trace view
        :param java.lang.String or str addrString: the address string
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the current trace and snap
        
        :param ghidra.program.model.address.Address address: the address
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, addrString: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the current trace and snap
        
        :param java.lang.String or str addrString: the address string
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, trace: ghidra.trace.model.Trace, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the given trace's primary view
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.program.model.address.Address address: the address
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, trace: ghidra.trace.model.Trace, addrString: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the given trace's primary view
        
        :param ghidra.trace.model.Trace trace: the trace
        :param java.lang.String or str addrString: the address string
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the given trace at the given snap
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address address: the address
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def dynamicLocation(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], addrString: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        """
        Create a dynamic location at the given address in the given trace at the given snap
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str addrString: the address string
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def emulate(self, platform: ghidra.trace.model.guest.TracePlatform, time: ghidra.trace.model.time.schedule.TraceSchedule, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Emulate the given trace platform as specified in the given schedule and display the result in
        the UI
        
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the schedule of steps
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        """

    @typing.overload
    def emulate(self, trace: ghidra.trace.model.Trace, time: ghidra.trace.model.time.schedule.TraceSchedule, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Emulate the given trace as specified in the given schedule and display the result in the UI
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the schedule of steps
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        """

    @typing.overload
    def emulate(self, time: ghidra.trace.model.time.schedule.TraceSchedule, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Emulate the current trace as specified and display the result
        
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the schedule of steps
        :param ghidra.util.task.TaskMonitor monitor: the monitor for the emulation
        :return: true if successful
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        :raises IllegalStateException: if there is no current trace
        """

    @typing.overload
    def emulateLaunch(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.trace.model.Trace:
        """
        Load the given program into a trace suitable for emulation in the UI, starting at the given
        address
         
         
        
        Note that the program bytes are not actually loaded into the trace. Rather a static mapping
        is generated, allowing the emulator to load bytes from the target program lazily. The trace
        is automatically loaded into the UI (trace manager).
        
        :param ghidra.program.model.listing.Program program: the target program
        :param ghidra.program.model.address.Address address: the initial program counter
        :return: the resulting trace
        :rtype: ghidra.trace.model.Trace
        :raises IOException: if the trace cannot be created
        """

    @typing.overload
    def emulateLaunch(self, address: ghidra.program.model.address.Address) -> ghidra.trace.model.Trace:
        """
        Does the same as :meth:`emulateLaunch(Program, Address) <.emulateLaunch>`, for the current program
        
        :param ghidra.program.model.address.Address address: the initial program counter
        :return: the resulting trace
        :rtype: ghidra.trace.model.Trace
        :raises IOException: if the trace cannot be created
        """

    @typing.overload
    def evaluate(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, expression: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        """
        Evaluate a Sleigh expression in the given context
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the context
        :param java.lang.String or str expression: the Sleigh expression
        :return: the value
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def evaluate(self, expression: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        """
        Evaluate a Sleigh expression in the current context
        
        :param java.lang.String or str expression: the Sleigh expression
        :return: the value
        :rtype: java.math.BigInteger
        """

    @typing.overload
    def execute(self, trace: ghidra.trace.model.Trace, command: typing.Union[java.lang.String, str]) -> bool:
        """
        Execute a command on the live debugger for the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :param java.lang.String or str command: the command
        :return: true if successful
        :rtype: bool
        """

    @typing.overload
    def execute(self, command: typing.Union[java.lang.String, str]) -> bool:
        """
        Execute a command on the live debugger for the current trace
        
        :param java.lang.String or str command: the command
        :return: true if successful
        :rtype: bool
        :raises IllegalStateException: if there is no current trace
        """

    @typing.overload
    def executeCapture(self, trace: ghidra.trace.model.Trace, command: typing.Union[java.lang.String, str]) -> str:
        """
        Execute a command on the live debugger for the given trace, capturing the output
        
        :param ghidra.trace.model.Trace trace: the trace
        :param java.lang.String or str command: the command
        :return: the output, or null if there is no live interpreter
        :rtype: str
        """

    @typing.overload
    def executeCapture(self, command: typing.Union[java.lang.String, str]) -> str:
        """
        Execute a command on the live debugger for the current trace, capturing the output
        
        :param java.lang.String or str command: the command
        :return: the output, or null if there is no live interpreter
        :rtype: str
        :raises IllegalStateException: if there is no current trace
        """

    def expectBreakpointChanges(self) -> FlatDebuggerAPI.ExpectingBreakpointChanges:
        """
        Perform some operations expected to cause changes, and then wait for those changes to settle
         
         
        
        Use this via a try-with-resources block containing the operations causing changes.
        
        :return: a closable object for a try-with-resources block
        :rtype: FlatDebuggerAPI.ExpectingBreakpointChanges
        """

    def findAction(self, target: ghidra.debug.api.target.Target, action: ghidra.debug.api.target.ActionName, context: docking.ActionContext) -> ghidra.debug.api.target.Target.ActionEntry:
        ...

    def flushAsyncPipelines(self, trace: ghidra.trace.model.Trace) -> bool:
        """
        Flush each stage of the asynchronous processing pipelines from end to end
         
         
        
        This method includes as many components as its author knows to flush. It flushes the trace's
        event queue. Then, it waits for various services' changes to settle, in dependency order.
        Currently, that is the static mapping service followed by the logical breakpoint service.
        Note that some stages use timeouts. It's also possible the target had not generated all the
        expected events by the time this method began flushing its queue. Thus, callers should still
        check that some expected condition is met and possibly repeat the flush before proceeding.
         
         
        
        There are additional dependents in the GUI; however, scripts should not depend on them, so we
        do not wait on them.
        
        :param ghidra.trace.model.Trace trace: the trace whose events need to be completely processed before continuing.
        :return: true if all stages were flushed, false if there were errors
        :rtype: bool
        """

    def getAllBreakpoints(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get all the breakpoints
         
         
        
        This returns all logical breakpoints among all open programs and traces (targets)
        
        :return: the breakpoints
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def getBreakpointService(self) -> ghidra.app.services.DebuggerLogicalBreakpointService:
        """
        Get the breakpoint service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerLogicalBreakpointService
        """

    @typing.overload
    def getBreakpoints(self, program: ghidra.program.model.listing.Program) -> java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        """
        Get the breakpoints in the given program, indexed by address
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the address-breakpoint-set map
        :rtype: java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]
        """

    @typing.overload
    def getBreakpoints(self, trace: ghidra.trace.model.Trace) -> java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        """
        Get the breakpoints in the given trace, indexed by (dynamic) address
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the address-breakpoint-set map
        :rtype: java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]
        """

    def getBreakpointsAt(self, location: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get the breakpoints at a given location
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`staticLocation(String) <.staticLocation>` and
                    :meth:`dynamicLocation(String) <.dynamicLocation>`.
        :return: the (possibly empty) set of breakpoints at that location
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def getBreakpointsNamed(self, name: typing.Union[java.lang.String, str]) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get the breakpoints having the given name (from any open program or trace)
        
        :param java.lang.String or str name: the name
        :return: the breakpoints
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def getControlService(self) -> ghidra.app.services.DebuggerControlService:
        """
        Get the control service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerControlService
        """

    def getCurrentDebuggerAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the current dynamic address
        
        :return: the dynamic address
        :rtype: ghidra.program.model.address.Address
        """

    def getCurrentDebuggerCoordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Get the current "coordinates", i.e., trace, thread, frame, snap, etc., usually for the active
        target.
        
        :return: the coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        """

    def getCurrentDebuggerProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Get the current trace program view and address
         
         
        
        This constitutes a portion of the debugger coordinates plus the current dynamic address. The
        program given by :meth:`ProgramLocation.getProgram() <ProgramLocation.getProgram>` can be safely cast to
        :obj:`TraceProgramView`, which should give the same result as :meth:`getCurrentView() <.getCurrentView>`.
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getCurrentEmulationSchedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        """
        Get the current emulation schedule
         
         
        
        This constitutes the current snapshot and an optional schedule of emulation steps. If there
        is a schedule, then the view's snap will be the destination scratch snap rather than the
        current snap.
        
        :return: the emulation schedule
        :rtype: ghidra.trace.model.time.schedule.TraceSchedule
        """

    def getCurrentFrame(self) -> int:
        """
        Get the current frame, 0 being the innermost
         
         
        
        If the target doesn't support frames, this will return 0
        
        :return: the frame
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getCurrentDebuggerCoordinates()`
        """

    def getCurrentPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        """
        Get the current trace platform
        
        :return: the trace platform, or null
        :rtype: ghidra.trace.model.guest.TracePlatform
        """

    def getCurrentProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the current program
         
         
        
        This is implemented by virtue of extending :obj:`FlatProgramAPI`, which is inherited via
        :obj:`GhidraScript`.
        
        :return: the current program
        :rtype: ghidra.program.model.listing.Program
        """

    def getCurrentSnap(self) -> int:
        """
        Get the current snap, i.e., snapshot key
         
         
        
        Snaps are the trace's notion of time. Positive keys should be monotonic with respect to time:
        a higher value implies a later point in time. Negative keys do not; they are used as scratch
        space, usually for displaying emulated machine states. This value defaults to 0, so it is
        only meaningful if there is a current trace.
        
        :return: the snap
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getCurrentDebuggerCoordinates()`
        """

    def getCurrentThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the current thread
         
         
        
        While uncommon, it is possible for there to be a current trace, but no current thread.
        
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        
        .. seealso::
        
            | :obj:`.getCurrentDebuggerCoordinates()`
        """

    def getCurrentTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the current trace
        
        :return: the trace, or null
        :rtype: ghidra.trace.model.Trace
        
        .. seealso::
        
            | :obj:`.getCurrentDebuggerCoordinates()`
        """

    def getCurrentView(self) -> ghidra.trace.model.program.TraceProgramView:
        """
        Get the current trace program view
         
         
        
        The view is an adapter for traces that allows them to be used as a :obj:`Program`. However,
        it only works for a chosen snapshot. Typically, :meth:`TraceProgramView.getSnap() <TraceProgramView.getSnap>` for this
        view will give the same result as :meth:`getCurrentSnap() <.getCurrentSnap>`. The exception is when the UI is
        displaying emulated (scratch) machine state. In that case, :meth:`getCurrentSnap() <.getCurrentSnap>` will
        give the "source" snapshot of the emulated state, and :meth:`TraceProgramView.getSnap() <TraceProgramView.getSnap>` will
        give the "destination" scratch snapshot. See :meth:`getCurrentEmulationSchedule() <.getCurrentEmulationSchedule>`.
        
        :return: the view
        :rtype: ghidra.trace.model.program.TraceProgramView
        
        .. seealso::
        
            | :obj:`.getCurrentDebuggerCoordinates()`
        """

    def getDebuggerListing(self) -> ghidra.app.services.DebuggerListingService:
        """
        Get the dynamic listing service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerListingService
        """

    def getEmulationService(self) -> ghidra.app.services.DebuggerEmulationService:
        """
        Get the emulation service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerEmulationService
        """

    @typing.overload
    def getExecutionState(self, trace: ghidra.trace.model.Trace) -> ghidra.trace.model.TraceExecutionState:
        """
        Get the current state of the given trace
         
         
        
        If the trace does not have a live target, it is considered
        :obj:`TraceExecutionState.TERMINATED` (even if the trace *never* technically had a
        live target.) Otherwise, this gets the state of that live target. **NOTE:** This does not
        consider the current snap. It only considers a live target in the present.
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the trace's execution state
        :rtype: ghidra.trace.model.TraceExecutionState
        """

    @typing.overload
    def getExecutionState(self, thread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.TraceExecutionState:
        """
        Get the current state of the given thread
         
         
        
        If the thread does not have a corresponding live target thread, it is considered
        :obj:`TraceExecutionState.TERMINATED` (even if the thread *never* technically had a
        live target thread.) Otherwise, this gets the state of that live target thread. **NOTE:**
        This does not consider the current snap. It only considers a live target thread in the
        present. In other words, if the user rewinds trace history to a point where the thread was
        alive, this method still considers that thread terminated. To compute state with respect to
        trace history, use :meth:`TraceThread.isValid(long) <TraceThread.isValid>`.
        
        :param ghidra.trace.model.thread.TraceThread thread: 
        :return: the thread's execution state
        :rtype: ghidra.trace.model.TraceExecutionState
        """

    def getMappingService(self) -> ghidra.app.services.DebuggerStaticMappingService:
        """
        Get the static mapping service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerStaticMappingService
        """

    @typing.overload
    def getProgramCounter(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.program.model.address.Address:
        """
        Get the program counter for the given context
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the context
        :return: the program counter, or null if not known
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getProgramCounter(self) -> ghidra.program.model.address.Address:
        """
        Get the program counter for the current context
        
        :return: the program counter, or null if not known
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getStackPointer(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.program.model.address.Address:
        """
        Get the stack pointer for the given context
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the context
        :return: the stack pointer, or null if not known
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getStackPointer(self) -> ghidra.program.model.address.Address:
        """
        Get the stack pointer for the current context
        
        :return: the stack pointer, or null if not known
        :rtype: ghidra.program.model.address.Address
        """

    def getState(self) -> ghidra.app.script.GhidraState:
        """
        Get the script state
         
         
        
        This is required to get various debugger services. It should be implemented by virtue of
        extending :obj:`GhidraScript`.
        
        :return: the state
        :rtype: ghidra.app.script.GhidraState
        """

    def getTargetService(self) -> ghidra.app.services.DebuggerTargetService:
        """
        The target service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerTargetService
        """

    def getTrace(self, location: ghidra.program.util.ProgramLocation) -> ghidra.trace.model.Trace:
        """
        If the location is dynamic, get its trace
        
        :param ghidra.program.util.ProgramLocation location: the location
        :return: the trace, or null if a static location
        :rtype: ghidra.trace.model.Trace
        """

    def getTraceManager(self) -> ghidra.app.services.DebuggerTraceManagerService:
        """
        Get the trace manager service
        
        :return: the service
        :rtype: ghidra.app.services.DebuggerTraceManagerService
        """

    @typing.overload
    def goToDynamic(self, location: ghidra.program.util.ProgramLocation) -> bool:
        """
        Go to the given dynamic location in the dynamic listing
         
         
        
        To "go to" a point in time, use :meth:`activateSnap(long) <.activateSnap>` or
        :meth:`emulate(Trace, TraceSchedule, TaskMonitor) <.emulate>`.
        
        :param ghidra.program.util.ProgramLocation location: the location, e.g., from :meth:`dynamicLocation(String) <.dynamicLocation>`
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def goToDynamic(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Go to the given dynamic address in the dynamic listing
        
        :param ghidra.program.model.address.Address address: the destination address
        :return: true if successful, false otherwise
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.goToDynamic(ProgramLocation)`
        """

    @typing.overload
    def goToDynamic(self, addrString: typing.Union[java.lang.String, str]) -> bool:
        """
        Go to the given dynamic address in the dynamic listing
        
        :param java.lang.String or str addrString: the destination address, as a string
        :return: true if successful, false otherwise
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.goToDynamic(ProgramLocation)`
        """

    @typing.overload
    def interrupt(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Interrupt execution of the live target for the given trace thread
         
         
        
        This is commonly called "pause" or "break," as well, but not "stop."
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to interrupt (may interrupt the whole target)
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def interrupt(self, trace: ghidra.trace.model.Trace) -> bool:
        """
        Interrupt execution of the live target for the given trace
         
         
        
        This is commonly called "pause" or "break," as well, but not "stop."
        
        :param ghidra.trace.model.Trace trace: the trace whose target to interrupt
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def interrupt(self) -> bool:
        """
        Interrupt execution of the current thread or trace
        
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def isTargetAlive(self, trace: ghidra.trace.model.Trace) -> bool:
        """
        Check if the given trace's target is alive
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: true if alive
        :rtype: bool
        """

    @typing.overload
    def isTargetAlive(self) -> bool:
        """
        Check if the current target is alive
         
         
        
        **NOTE:** To be "current," the target must be recorded, and its trace must be the current
        trace.
        
        :return: true if alive
        :rtype: bool
        """

    @typing.overload
    def isThreadAlive(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Check if the given trace thread's target is alive
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :return: true if alive
        :rtype: bool
        """

    @typing.overload
    def isThreadAlive(self) -> bool:
        """
        Check if the current target thread is alive
         
         
        
        **NOTE:** To be the "current" target thread, the target must be recorded, and its trace
        thread must be the current thread.
        
        :return: true if alive
        :rtype: bool
        """

    @typing.overload
    def kill(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Terminate execution of the live target for the given trace thread
         
         
        
        This is commonly called "stop" as well.
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to kill (may kill the whole target)
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def kill(self, trace: ghidra.trace.model.Trace) -> bool:
        """
        Terminate execution of the live target for the given trace
         
         
        
        This is commonly called "stop" as well.
        
        :param ghidra.trace.model.Trace trace: the trace whose target to kill
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def kill(self) -> bool:
        """
        Terminate execution of the current thread or trace
        
        :return: true if successful, false otherwise
        :rtype: bool
        """

    def openTrace(self, trace: ghidra.trace.model.Trace):
        """
        Open the given trace in the UI
        
        :param ghidra.trace.model.Trace trace: the trace
        """

    def patchEmu(self, sleigh: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Apply the given Sleigh patch to the emulator
        
        :param java.lang.String or str sleigh: the Sleigh source, without terminating semicolon
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful, false otherwise
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        """

    @typing.overload
    def readMemory(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, buffer: jpype.JArray[jpype.JByte], monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Read memory into the given buffer, refreshing from target if needed
        
        :param ghidra.trace.model.Trace trace: the source trace
        :param jpype.JLong or int snap: the source snap
        :param ghidra.program.model.address.Address start: the source starting address
        :param jpype.JArray[jpype.JByte] buffer: the destination buffer
        :param ghidra.util.task.TaskMonitor monitor: a monitor for live read progress
        :return: the number of bytes read
        :rtype: int
        :raises CancelledException: if the operation was cancelled
        """

    @typing.overload
    def readMemory(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[jpype.JByte]:
        """
        Read memory, refreshing from target if needed
        
        :param ghidra.trace.model.Trace trace: the source trace
        :param jpype.JLong or int snap: the source snap
        :param ghidra.program.model.address.Address start: the source starting address
        :param jpype.JInt or int length: the desired number of bytes
        :param ghidra.util.task.TaskMonitor monitor: a monitor for live read progress
        :return: the array of bytes read, can be shorter than desired
        :rtype: jpype.JArray[jpype.JByte]
        :raises CancelledException: if the operation was cancelled
        """

    @typing.overload
    def readMemory(self, start: ghidra.program.model.address.Address, buffer: jpype.JArray[jpype.JByte], monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Read memory from the current trace view into the given buffer, refreshing from target if
        needed
        
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JArray[jpype.JByte] buffer: the destination buffer
        :param ghidra.util.task.TaskMonitor monitor: a monitor for live read progress
        :return: the number of bytes read
        :rtype: int
        :raises CancelledException: if the operation was cancelled
        """

    @typing.overload
    def readMemory(self, start: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[jpype.JByte]:
        """
        Read memory for the current trace view, refreshing from target if needed
        
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JInt or int length: the desired number of bytes
        :param ghidra.util.task.TaskMonitor monitor: a monitor for live read progress
        :return: the array of bytes read, can be shorter than desired
        :rtype: jpype.JArray[jpype.JByte]
        :raises CancelledException: if the operation was cancelled
        """

    @typing.overload
    def readRegister(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Read a register
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the registers
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread
        :param jpype.JInt or int frame: the source frame level, 0 being the innermost
        :param jpype.JLong or int snap: the source snap
        :param ghidra.program.model.lang.Register register: the source register
        :return: the register's value, or null on error
        :rtype: ghidra.program.model.lang.RegisterValue
        
        .. seealso::
        
            | :obj:`.readRegisters(TracePlatform, TraceThread, int, long, Collection)`
        """

    @typing.overload
    def readRegister(self, platform: ghidra.trace.model.guest.TracePlatform, register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Read a register from the current context, refreshing from the target if needed
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param ghidra.program.model.lang.Register register: the register
        :return: the value, or null on error
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def readRegister(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Read a register from the current context, refreshing from the target if needed
        
        :param ghidra.program.model.lang.Register register: the register
        :return: the value, or null on error
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def readRegister(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.RegisterValue:
        """
        Read a register from the current context, refreshing from the target if needed
        
        :param java.lang.String or str name: the register name
        :return: the value, or null on error
        :rtype: ghidra.program.model.lang.RegisterValue
        :raises IllegalArgumentException: if the name is invalid
        
        .. seealso::
        
            | :obj:`.readRegister(Register)`
        """

    @typing.overload
    def readRegisters(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], registers: collections.abc.Sequence) -> java.util.List[ghidra.program.model.lang.RegisterValue]:
        """
        Read several registers from the given context, refreshing from target if needed
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the registers
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread
        :param jpype.JInt or int frame: the source frame level, 0 being the innermost
        :param jpype.JLong or int snap: the source snap
        :param collections.abc.Sequence registers: the source registers
        :return: the list of register values, or null on error
        :rtype: java.util.List[ghidra.program.model.lang.RegisterValue]
        """

    @typing.overload
    def readRegisters(self, registers: collections.abc.Sequence) -> java.util.List[ghidra.program.model.lang.RegisterValue]:
        """
        Read several registers from the current context, refreshing from the target if needed
        
        :param collections.abc.Sequence registers: the source registers
        :return: the list of register values, or null on error
        :rtype: java.util.List[ghidra.program.model.lang.RegisterValue]
        
        .. seealso::
        
            | :obj:`.readRegisters(TracePlatform, TraceThread, int, long, Collection)`
        """

    def readRegistersNamed(self, names: collections.abc.Sequence) -> java.util.List[ghidra.program.model.lang.RegisterValue]:
        """
        Read several registers from the current context, refreshing from the target if needed
        
        :param collections.abc.Sequence names: the source register names
        :return: the list of register values, or null on error
        :rtype: java.util.List[ghidra.program.model.lang.RegisterValue]
        :raises IllegalArgumentException: if any name is invalid
        
        .. seealso::
        
            | :obj:`.readRegisters(TracePlatform, TraceThread, int, long, Collection)`
        """

    def refreshMemoryIfLive(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Copy memory from target to trace, if applicable and not already cached
        
        :param ghidra.trace.model.Trace trace: the trace to update
        :param jpype.JLong or int snap: the snap the snap, to determine whether target bytes are applicable
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JInt or int length: the number of bytes to make fresh
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress
        :raises CancelledException: if the operation was cancelled
        """

    def refreshRegistersIfLive(self, platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], registers: collections.abc.Sequence):
        """
        Copy registers from target to trace, if applicable and not already cached
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the registers
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread to update
        :param jpype.JInt or int frame: the frame level, 0 being the innermost
        :param jpype.JLong or int snap: the snap, to determine whether target values are applicable
        :param collections.abc.Sequence registers: the registers to make fresh
        """

    def requireCurrentPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        """
        Get the current trace platform, throwing an exception if there isn't one
        
        :return: the trace platform
        :rtype: ghidra.trace.model.guest.TracePlatform
        :raises IllegalStateException: if there is no current trace platform
        """

    def requireCurrentProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the current program, throwing an exception if there isn't one.
        
        :return: the current program
        :rtype: ghidra.program.model.listing.Program
        :raises IllegalStateException: if there is no current program
        """

    def requireCurrentThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the current thread, throwing an exception if there isn't one
        
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        :raises IllegalStateException: if there is no current thread
        """

    def requireCurrentTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the current trace, throwing an exception if there isn't one
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        :raises IllegalStateException: if there is no current trace
        """

    def requireCurrentView(self) -> ghidra.trace.model.program.TraceProgramView:
        """
        Get the current trace view, throwing an exception if there isn't one
        
        :return: the trace view
        :rtype: ghidra.trace.model.program.TraceProgramView
        :raises IllegalStateException: if there is no current trace view
        """

    def requirePlatform(self, platform: ghidra.trace.model.guest.TracePlatform) -> ghidra.trace.model.guest.TracePlatform:
        """
        Require that the given platform is not null
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :return: the platform
        :rtype: ghidra.trace.model.guest.TracePlatform
        :raises IllegalStateException: if the platform is null
        """

    def requireService(self, cls: java.lang.Class[T]) -> T:
        """
        Require a service from the tool
         
         
        
        If the service is missing, an exception is thrown directing the user to run the script from
        the Debugger tool.
        
        :param T: the type of the service:param java.lang.Class[T] cls: the class of the service
        :return: the service
        :rtype: T
        :raises IllegalStateException: if the service is missing
        """

    def requireThread(self, thread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.thread.TraceThread:
        """
        Require that the given thread is not null
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        :raises IllegalStateException: if the thread is null
        """

    def requireTrace(self, trace: ghidra.trace.model.Trace) -> ghidra.trace.model.Trace:
        """
        Require that the given trace is not null
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        :raises IllegalStateException: if the trace is null
        """

    @typing.overload
    def resume(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Resume execution of the live target for the given trace thread
         
         
        
        This is commonly called "continue" or "go," as well.
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def resume(self, trace: ghidra.trace.model.Trace) -> bool:
        """
        Resume execution of the live target for the given trace
         
         
        
        This is commonly called "continue" or "go," as well.
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def resume(self) -> bool:
        """
        Resume execution of the current thread or trace
        
        :return: true if successful, false otherwise
        :rtype: bool
        """

    def safeRange(self, start: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.AddressRange:
        """
        Create an address range, avoiding address overflow by truncating
         
         
        
        If the length would cause address overflow, it is adjusted such that the range's maximum
        address is the space's maximum address.
        
        :param ghidra.program.model.address.Address start: the minimum address
        :param jpype.JInt or int length: the desired length
        :return: the range
        :rtype: ghidra.program.model.address.AddressRange
        """

    @typing.overload
    def searchMemory(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, data: java.nio.ByteBuffer, mask: java.nio.ByteBuffer, forward: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Search trace memory for a given masked byte sequence
         
         
        
        **NOTE:** This searches the trace only. It will not interrogate the live target. There are
        two mechanisms for searching a live target's full memory: 1) Capture the full memory (or the
        subset to search) -- using, e.g.,
        :meth:`refreshMemoryIfLive(Trace, long, Address, int, TaskMonitor) <.refreshMemoryIfLive>` -- then search the
        trace. 2) If possible, invoke the target debugger's search functions -- using, e.g.,
        :meth:`executeCapture(String) <.executeCapture>`.
         
         
        
        This delegates to
        :meth:`TraceMemoryOperations.findBytes(long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor) <TraceMemoryOperations.findBytes>`.
        It culls out ranges that have never been recorded, effectively excluding default ``00``s.
        This can only search a single snapshot per invocation, but it does include stale bytes, i.e.,
        those from a previous snapshot without a more up-to-date record. In particular, a stale
        ``00`` is matched as usual, as is any stale byte. Only those ranges which have
        *never* been recorded are culled. While not required, memory is conventionally read
        and recorded in pages, so culling tends to occur at page boundaries.
         
         
        
        Be wary of leading or trailing wildcards, i.e., masked-out bytes. The full data array must
        fit within the given range after culling. For example, suppose the byte ``12`` is
        recorded at ``ram:00400000``. The full page is recorded, but the preceding page has never
        been recorded. Thus, the byte at ``ram:003fffff`` is a default ``00``. Searching for
        the pattern ``?? 12`` in the range ``ram:00400000:00400fff`` will not find the match.
        This much is intuitive, because the match starts at ``ram:003fffff``, which is outside
        the specified range. However, this rule also affects trailing wildcards. Furthermore, because
        the preceding page was never recorded, even if the specified range were
        ``ram:003ff000:00400fff``, the range would be culled, and the match would still be
        excluded. Nothing -- not even a wildcard -- can match a default ``00``.
        
        :param ghidra.trace.model.Trace trace: the trace to search
        :param jpype.JLong or int snap: the snapshot of the trace to search
        :param ghidra.program.model.address.AddressRange range: the range within to search
        :param java.nio.ByteBuffer data: the bytes to search for
        :param java.nio.ByteBuffer mask: a mask on the bits to search, or null to match exactly.
        :param jpype.JBoolean or bool forward: true to start at the min address going forward, false to start at the max
                    address going backward
        :param ghidra.util.task.TaskMonitor monitor: a monitor for search progress
        :return: the minimum address of the matched bytes, or null if not found
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def searchMemory(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, data: jpype.JArray[jpype.JByte], mask: jpype.JArray[jpype.JByte], forward: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        
        
        :param ghidra.trace.model.Trace trace: the trace to search
        :param jpype.JLong or int snap: the snapshot of the trace to search
        :param ghidra.program.model.address.AddressRange range: the range within to search
        :param jpype.JArray[jpype.JByte] data: the bytes to search for
        :param jpype.JArray[jpype.JByte] mask: a mask on the bits to search, or null to match exactly.
        :param jpype.JBoolean or bool forward: true to start at the min address going forward, false to start at the max
                    address going backward
        :param ghidra.util.task.TaskMonitor monitor: a monitor for search progress
        :return: the minimum address of the matched bytes, or null if not found
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.searchMemory(Trace, long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)`
        """

    @typing.overload
    def setControlMode(self, trace: ghidra.trace.model.Trace, mode: ghidra.debug.api.control.ControlMode):
        """
        Set the control mode of the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.debug.api.control.ControlMode mode: the mode
        """

    @typing.overload
    def setControlMode(self, mode: ghidra.debug.api.control.ControlMode):
        """
        Set the control mode of the current trace
        
        :param ghidra.debug.api.control.ControlMode mode: the mode
        """

    def skipEmuInstruction(self, count: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Step the current trace count skipped instructions via emulation
         
         
        
        Note there's no such thing as "skipping in reverse." If a negative count is given, this will
        behave the same as :meth:`stepEmuInstruction(long, TaskMonitor) <.stepEmuInstruction>`.
        
        :param jpype.JLong or int count: the number of instructions to skip, negative to step in reverse
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful, false otherwise
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        """

    def skipEmuPcodeOp(self, count: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Step the current trace count skipped p-code operations via emulation
         
         
        
        Note there's no such thing as "skipping in reverse." If a negative count is given, this will
        behave the same as :meth:`stepEmuPcodeOp(int, TaskMonitor) <.stepEmuPcodeOp>`.
        
        :param jpype.JInt or int count: the number of operations to skip, negative to step in reverse
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful, false otherwise
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        """

    @typing.overload
    def staticLocation(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        """
        Create a static location at the given address in the current program
        
        :param ghidra.program.model.listing.Program program: the (static) program
        :param ghidra.program.model.address.Address address: the address
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def staticLocation(self, program: ghidra.program.model.listing.Program, addrString: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        """
        Create a static location at the given address in the current program
        
        :param ghidra.program.model.listing.Program program: the (static) program
        :param java.lang.String or str addrString: the address string
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def staticLocation(self, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        """
        Create a static location at the given address in the current program
        
        :param ghidra.program.model.address.Address address: the address
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def staticLocation(self, addrString: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        """
        Create a static location at the given address in the current program
        
        :param java.lang.String or str addrString: the address string
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def stepEmuInstruction(self, count: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Step the current trace count instructions via emulation
        
        :param jpype.JLong or int count: the number of instructions to step, negative to step in reverse
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful, false otherwise
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        :raises IllegalStateException: if there is no current trace or thread
        """

    def stepEmuPcodeOp(self, count: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Step the current trace count p-code operations via emulation
        
        :param jpype.JInt or int count: the number of operations to step, negative to step in reverse
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the emulation
        :return: true if successful, false otherwise
        :rtype: bool
        :raises CancelledException: if the user cancelled via the given monitor
        """

    @typing.overload
    def stepInto(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Step the given thread, stepping into subroutines
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def stepInto(self) -> bool:
        """
        Step the current thread, stepping into subroutines
        
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def stepOut(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Step the given thread, until it returns from the current subroutine
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def stepOut(self) -> bool:
        """
        Step the current thread, until it returns from the current subroutine
        
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def stepOver(self, thread: ghidra.trace.model.thread.TraceThread) -> bool:
        """
        Step the given thread, stepping over subroutines
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def stepOver(self) -> bool:
        """
        Step the current thread, stepping over subroutines
        
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def translateDynamicToStatic(self, location: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation:
        """
        Translate the given dynamic location to the corresponding static location
         
         
        
        This does the opposite of :meth:`translateStaticToDynamic(ProgramLocation) <.translateStaticToDynamic>`. The resulting
        static location could be for any open program, not just the current one, since a target may
        load several images. For example, a single user-space process typically has several modules:
        the executable image and several libraries.
        
        :param ghidra.program.util.ProgramLocation location: the dynamic location, e.g., from :meth:`dynamicLocation(String) <.dynamicLocation>`
        :return: the static location, or null if not translated
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def translateDynamicToStatic(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate the given dynamic address to the corresponding static address
         
         
        
        This does the same as :meth:`translateDynamicToStatic(ProgramLocation) <.translateDynamicToStatic>`, but assumes the
        address is for the current trace view. The returned address is for the current program. If
        there is not current view or program, or if the address cannot be translated to the current
        program, null is returned.
        
        :param ghidra.program.model.address.Address address: the dynamic address
        :return: the static address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def translateStaticToDynamic(self, location: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation:
        """
        Translate the given static location to the corresponding dynamic location
         
         
        
        This uses the trace's static mappings (see :meth:`Trace.getStaticMappingManager() <Trace.getStaticMappingManager>` and
        :obj:`DebuggerStaticMappingService`) to translate a static location to the corresponding
        dynamic location in the current trace. If there is no current trace or the location cannot be
        translated to the current trace, the result is null. This accommodates link-load-time
        relocation, particularly from address-space layout randomization (ASLR).
        
        :param ghidra.program.util.ProgramLocation location: the static location, e.g., from :meth:`staticLocation(String) <.staticLocation>`
        :return: the dynamic location, or null if not translated
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def translateStaticToDynamic(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate the given static address to the corresponding dynamic address
         
         
        
        This does the same as :meth:`translateStaticToDynamic(ProgramLocation) <.translateStaticToDynamic>`, but assumes the
        address is for the current program. The returned address is for the current trace view.
        
        :param ghidra.program.model.address.Address address: the static address
        :return: the dynamic address, or null if not translated
        :rtype: ghidra.program.model.address.Address
        """

    def validateRegisterName(self, language: ghidra.program.model.lang.Language, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.Register:
        """
        Validate and retrieve the name register
        
        :param ghidra.program.model.lang.Language language: the language defining the register
        :param java.lang.String or str name: the name
        :return: the register
        :rtype: ghidra.program.model.lang.Register
        :raises IllegalArgumentException: if the name is invalid
        """

    def validateRegisterNames(self, language: ghidra.program.model.lang.Language, names: collections.abc.Sequence) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Validate and retrieve the named registers
        
        :param ghidra.program.model.lang.Language language: the language defining the registers
        :param collections.abc.Sequence names: the names
        :return: the registers, in the same order
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        :raises IllegalArgumentException: if any name is invalid
        """

    @typing.overload
    def waitForBreak(self, trace: ghidra.trace.model.Trace, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit):
        """
        Wait for the trace's target to break
         
         
        
        If the trace has no target, this method returns immediately, i.e., it assumes the target has
        terminated.
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int timeout: the maximum amount of time to wait
        :param java.util.concurrent.TimeUnit unit: the units for time
        :raises TimeoutException: if the timeout expires
        """

    @typing.overload
    def waitForBreak(self, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit):
        """
        Wait for the current target to break
        
        :param jpype.JLong or int timeout: the maximum
        :param java.util.concurrent.TimeUnit unit: the units for time
        :raises TimeoutException: if the timeout expires
        :raises IllegalStateException: if there is no current trace
        
        .. seealso::
        
            | :obj:`.waitForBreak(Trace, long, TimeUnit)`
        """

    def waitOn(self, cf: java.util.concurrent.CompletableFuture[T]) -> T:
        """
        The method used to wait on futures.
         
         
        
        By default, this waits at most 1 minute.
        
        :param T: the type of the result:param java.util.concurrent.CompletableFuture[T] cf: the future
        :return: the result
        :rtype: T
        :raises java.lang.InterruptedException: if execution is interrupted
        :raises ExecutionException: if an error occurs
        :raises TimeoutException: if the future does not complete in time
        """

    @typing.overload
    def writeMemory(self, editor: ghidra.app.services.DebuggerControlService.StateEditor, start: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> bool:
        """
        Patch memory using the given editor
         
         
        
        The success or failure of this method depends on a few factors. First is the user-selected
        control mode for the trace. See :meth:`setControlMode(ControlMode) <.setControlMode>`. In read-only mode, this
        will always fail. When editing traces, a write almost always succeeds. Exceptions would
        probably indicate I/O errors. When editing via emulation, a write should almost always
        succeed. Second, when editing the target, the state of the target matters. If the trace has
        no target, this will always fail. If the target is not accepting commands, e.g., because the
        target or debugger is busy, this may fail or be delayed. If the target doesn't support
        editing the given space, this will fail. Some debuggers may also deny modification due to
        permissions.
        
        :param ghidra.app.services.DebuggerControlService.StateEditor editor: the editor
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JArray[jpype.JByte] data: the bytes to write
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def writeMemory(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> bool:
        """
        Patch memory of the given target, according to its current control mode
         
         
        
        If you intend to apply several patches, consider using :meth:`createStateEditor(Trace,long) <.createStateEditor>`
        and :meth:`writeMemory(StateEditor, Address, byte[]) <.writeMemory>`
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snapshot
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JArray[jpype.JByte] data: the bytes to write
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def writeMemory(self, start: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> bool:
        """
        Patch memory of the current target, according to the current control mode
         
         
        
        If you intend to apply several patches, consider using :meth:`createStateEditor() <.createStateEditor>` and
        :meth:`writeMemory(StateEditor, Address, byte[]) <.writeMemory>`
        
        :param ghidra.program.model.address.Address start: the starting address
        :param jpype.JArray[jpype.JByte] data: the bytes to write
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def writeRegister(self, editor: ghidra.app.services.DebuggerControlService.StateEditor, rv: ghidra.program.model.lang.RegisterValue) -> bool:
        """
        Patch a register using the given editor
         
         
        
        The success or failure of this methods depends on a few factors. First is the user-selected
        control mode for the trace. See :meth:`setControlMode(ControlMode) <.setControlMode>`. In read-only mode, this
        will always fail. When editing traces, a write almost always succeeds. Exceptions would
        probably indicate I/O errors. When editing via emulation, a write should only fail if the
        register is not accessible to Sleigh, e.g., the context register. Second, when editing the
        target, the state of the target matters. If the trace has no target, this will always fail.
        If the target is not accepting commands, e.g., because the target or debugger is busy, this
        may fail or be delayed. If the target doesn't support editing the given register, this will
        fail.
        
        :param ghidra.app.services.DebuggerControlService.StateEditor editor: the editor
        :param ghidra.program.model.lang.RegisterValue rv: the register value
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def writeRegister(self, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], rv: ghidra.program.model.lang.RegisterValue) -> bool:
        """
        Patch a register of the given context, according to its current control mode
         
         
        
        If you intend to apply several patches, consider using
        :meth:`createStateEditor(TraceThread,int,long) <.createStateEditor>` and
        :meth:`writeRegister(StateEditor, RegisterValue) <.writeRegister>`.
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JInt or int frame: the frame
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.RegisterValue rv: the register value
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def writeRegister(self, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str], value: java.math.BigInteger) -> bool:
        """
        Patch a register of the given context, according to its current control mode
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JInt or int frame: the frame
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str name: the register name
        :param java.math.BigInteger value: the value
        :return: true if successful, false otherwise
        :rtype: bool
        :raises IllegalArgumentException: if the register name is invalid
        
        .. seealso::
        
            | :obj:`.writeRegister(TraceThread, int, long, RegisterValue)`
        """

    @typing.overload
    def writeRegister(self, rv: ghidra.program.model.lang.RegisterValue) -> bool:
        """
        Patch a register of the current thread, according to the current control mode
         
         
        
        If you intend to apply several patches, consider using :meth:`createStateEditor() <.createStateEditor>` and
        :meth:`writeRegister(StateEditor, RegisterValue) <.writeRegister>`.
        
        :param ghidra.program.model.lang.RegisterValue rv: the register value
        :return: true if successful, false otherwise
        :rtype: bool
        """

    @typing.overload
    def writeRegister(self, name: typing.Union[java.lang.String, str], value: java.math.BigInteger) -> bool:
        """
        Patch a register of the current thread, according to the current control mode
        
        :param java.lang.String or str name: the register name
        :param java.math.BigInteger value: the value
        :return: true if successful, false otherwise
        :rtype: bool
        :raises IllegalArgumentException: if the register name is invalid
        
        .. seealso::
        
            | :obj:`.writeRegister(RegisterValue)`
        """

    @property
    def currentProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def breakpointsAt(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...

    @property
    def currentPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...

    @property
    def breakpointsNamed(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...

    @property
    def breakpointService(self) -> ghidra.app.services.DebuggerLogicalBreakpointService:
        ...

    @property
    def threadAlive(self) -> jpype.JBoolean:
        ...

    @property
    def currentDebuggerProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def traceManager(self) -> ghidra.app.services.DebuggerTraceManagerService:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def debuggerListing(self) -> ghidra.app.services.DebuggerListingService:
        ...

    @property
    def currentFrame(self) -> jpype.JInt:
        ...

    @property
    def state(self) -> ghidra.app.script.GhidraState:
        ...

    @property
    def breakpoints(self) -> java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        ...

    @property
    def currentEmulationSchedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    @property
    def currentThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def allBreakpoints(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...

    @property
    def programCounter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def currentDebuggerAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def currentDebuggerCoordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def executionState(self) -> ghidra.trace.model.TraceExecutionState:
        ...

    @property
    def targetAlive(self) -> jpype.JBoolean:
        ...

    @property
    def emulationService(self) -> ghidra.app.services.DebuggerEmulationService:
        ...

    @property
    def currentView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    @property
    def mappingService(self) -> ghidra.app.services.DebuggerStaticMappingService:
        ...

    @property
    def targetService(self) -> ghidra.app.services.DebuggerTargetService:
        ...

    @property
    def currentSnap(self) -> jpype.JLong:
        ...

    @property
    def stackPointer(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def currentTrace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def controlService(self) -> ghidra.app.services.DebuggerControlService:
        ...



__all__ = ["FlatDebuggerRmiAPI", "FlatDebuggerAPI"]
