from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.thread
import java.lang # type: ignore


class TraceProgramViewRegisterListing(TraceProgramViewListing):

    class_: typing.ClassVar[java.lang.Class]

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...


class TraceVariableSnapProgramView(TraceProgramView):

    class_: typing.ClassVar[java.lang.Class]

    def seekLatest(self):
        """
        Seek to the latest snap
        """

    def setPlatform(self, platform: ghidra.trace.model.guest.TracePlatform):
        """
        Set the current platform, so that actions have context
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        """

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        """
        Seek to a particular snap
        
        :param jpype.JLong or int snap: the snap
        """


@typing.type_check_only
class SnapSpecificTraceView(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getSnap(self) -> int:
        """
        Get the snap this view presents
        
        :return: the snap
        :rtype: int
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace this view presents
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class TraceProgramViewListing(ghidra.program.model.listing.Listing, SnapSpecificTraceView):

    class_: typing.ClassVar[java.lang.Class]

    def getProgram(self) -> TraceProgramView:
        ...

    @property
    def program(self) -> TraceProgramView:
        ...


class TraceProgramView(ghidra.program.model.listing.Program):
    """
    View of a trace at a particular time, as a program
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMaxSnap(self) -> int:
        """
        Get the trace's latest snap
        
        :return: the maximum snap
        :rtype: int
        """

    def getSnap(self) -> int:
        """
        Get the current snap
        
        :return: the snap
        :rtype: int
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace this view presents
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def getViewport(self) -> ghidra.trace.model.TraceTimeViewport:
        """
        Get the viewport this view is using for forked queries
        
        :return: the viewport
        :rtype: ghidra.trace.model.TraceTimeViewport
        """

    @property
    def maxSnap(self) -> jpype.JLong:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def viewport(self) -> ghidra.trace.model.TraceTimeViewport:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class TraceProgramViewBookmarkManager(ghidra.program.model.listing.BookmarkManager, SnapSpecificTraceView):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TraceProgramViewMemory(ghidra.program.model.mem.Memory, SnapSpecificTraceView):

    class_: typing.ClassVar[java.lang.Class]

    def isForceFullView(self) -> bool:
        ...

    def setForceFullView(self, forceFullView: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def forceFullView(self) -> jpype.JBoolean:
        ...

    @forceFullView.setter
    def forceFullView(self, value: jpype.JBoolean):
        ...



__all__ = ["TraceProgramViewRegisterListing", "TraceVariableSnapProgramView", "SnapSpecificTraceView", "TraceProgramViewListing", "TraceProgramView", "TraceProgramViewBookmarkManager", "TraceProgramViewMemory"]
