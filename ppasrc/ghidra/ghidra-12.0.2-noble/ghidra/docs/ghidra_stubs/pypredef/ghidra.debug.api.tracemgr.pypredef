from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.debug.api.target
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.program
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import java.lang # type: ignore


class DebuggerCoordinates(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    NOWHERE: typing.Final[DebuggerCoordinates]
    """
    Coordinates that indicate no trace is active in the Debugger UI.
     
    
    Typically, that only happens when no trace is open. Telling the trace manager to activate
    ``NOWHERE`` will cause it to instead activate the most recently active trace, which may
    very well be the current trace, resulting in no change. Internally, the trace manager will
    activate ``NOWHERE`` whenever the current trace is closed, effectively activating the
    most recent trace other than the one just closed.
    """


    def differsOnlyByPatch(self, that: DebuggerCoordinates) -> bool:
        """
        Checks if the given coordinates are the same as this but with an extra or differing patch.
        
        :param DebuggerCoordinates that: the other coordinates
        :return: true if the difference is only in the final patch step
        :rtype: bool
        """

    @staticmethod
    def equalsIgnoreTargetAndView(a: DebuggerCoordinates, b: DebuggerCoordinates) -> bool:
        ...

    @typing.overload
    def frame(self, newFrame: typing.Union[jpype.JInt, int]) -> DebuggerCoordinates:
        ...

    @typing.overload
    def frame(self, newFrame: typing.Union[java.lang.Integer, int]) -> DebuggerCoordinates:
        ...

    def getFrame(self) -> int:
        ...

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getObject(self) -> ghidra.trace.model.target.TraceObject:
        ...

    def getPath(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    def getPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...

    def getRegisterContainer(self) -> ghidra.trace.model.target.TraceObject:
        ...

    def getSnap(self) -> int:
        ...

    def getTarget(self) -> ghidra.debug.api.target.Target:
        ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    def getTime(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def getView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    def getViewSnap(self) -> int:
        ...

    @staticmethod
    @typing.overload
    def isAlive(target: ghidra.debug.api.target.Target) -> bool:
        ...

    @typing.overload
    def isAlive(self) -> bool:
        ...

    @staticmethod
    @typing.overload
    def isAliveAndPresent(view: ghidra.trace.model.program.TraceProgramView, target: ghidra.debug.api.target.Target) -> bool:
        ...

    @typing.overload
    def isAliveAndPresent(self) -> bool:
        ...

    def isAliveAndReadsPresent(self) -> bool:
        ...

    def isDeadOrPresent(self) -> bool:
        ...

    def isRegisterSpace(self, space: ghidra.program.model.address.AddressSpace) -> bool:
        ...

    def object(self, newObject: ghidra.trace.model.target.TraceObject) -> DebuggerCoordinates:
        ...

    def path(self, newPath: ghidra.trace.model.target.path.KeyPath) -> DebuggerCoordinates:
        ...

    def pathNonCanonical(self, newPath: ghidra.trace.model.target.path.KeyPath) -> DebuggerCoordinates:
        ...

    def platform(self, newPlatform: ghidra.trace.model.guest.TracePlatform) -> DebuggerCoordinates:
        ...

    def reFindThread(self) -> DebuggerCoordinates:
        ...

    @staticmethod
    def readDataState(tool: ghidra.framework.plugintool.PluginTool, saveState: ghidra.framework.options.SaveState, key: typing.Union[java.lang.String, str]) -> DebuggerCoordinates:
        ...

    def snap(self, snap: typing.Union[jpype.JLong, int]) -> DebuggerCoordinates:
        """
        Get these same coordinates with time replaced by the given snap-only schedule
        
        :param jpype.JLong or int snap: the new snap
        :return: the new coordinates
        :rtype: DebuggerCoordinates
        """

    def snapNoResolve(self, snap: typing.Union[jpype.JLong, int]) -> DebuggerCoordinates:
        """
        Get these same coordinates with time replace by the given snap-only schedule, and DO NOT
        resolve or adjust anything else
        
        :param jpype.JLong or int snap: the new snap
        :return: exactly these same coordinates with the snap/time changed
        :rtype: DebuggerCoordinates
        """

    def target(self, newTarget: ghidra.debug.api.target.Target) -> DebuggerCoordinates:
        ...

    def thread(self, newThread: ghidra.trace.model.thread.TraceThread) -> DebuggerCoordinates:
        ...

    def time(self, newTime: ghidra.trace.model.time.schedule.TraceSchedule) -> DebuggerCoordinates:
        """
        Get these same coordinates with time replaced by the given schedule
        
        :param ghidra.trace.model.time.schedule.TraceSchedule newTime: the new schedule
        :return: the new coordinates
        :rtype: DebuggerCoordinates
        """

    def trace(self, newTrace: ghidra.trace.model.Trace) -> DebuggerCoordinates:
        ...

    def view(self, newView: ghidra.trace.model.program.TraceProgramView) -> DebuggerCoordinates:
        ...

    def writeDataState(self, tool: ghidra.framework.plugintool.PluginTool, saveState: ghidra.framework.options.SaveState, key: typing.Union[java.lang.String, str]):
        ...

    @property
    def aliveAndPresent(self) -> jpype.JBoolean:
        ...

    @property
    def aliveAndReadsPresent(self) -> jpype.JBoolean:
        ...

    @property
    def alive(self) -> jpype.JBoolean:
        ...

    @property
    def viewSnap(self) -> jpype.JLong:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def registerContainer(self) -> ghidra.trace.model.target.TraceObject:
        ...

    @property
    def deadOrPresent(self) -> jpype.JBoolean:
        ...

    @property
    def registerSpace(self) -> jpype.JBoolean:
        ...



__all__ = ["DebuggerCoordinates"]
