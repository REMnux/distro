from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui.action
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.trace.model.time.schedule
import java.lang # type: ignore
import java.util.concurrent # type: ignore
import javax.swing.event # type: ignore


class DebuggerTraceViewDiffPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    @typing.type_check_only
    class ListingCoordinationListener(ghidra.app.services.CoordinatedListingPanelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ForAltListingTrackingTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerTrackLocationTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SyncAltListingTrackingSpecChangeListener(ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MarkerSetChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def blockFor(blockSize: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        ...

    def endComparison(self) -> bool:
        ...

    def getDiffs(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getNextDiff(self) -> ghidra.program.model.address.Address:
        ...

    def getPrevDiff(self) -> ghidra.program.model.address.Address:
        ...

    def gotoNextDiff(self) -> bool:
        ...

    def gotoPrevDiff(self) -> bool:
        ...

    def hasNextDiff(self) -> bool:
        ...

    def hasPrevDiff(self) -> bool:
        ...

    @staticmethod
    def lenRemainsBlock(blockSize: typing.Union[jpype.JInt, int], off: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def maxOfBlock(blockSize: typing.Union[jpype.JInt, int], off: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def maxOfBlock(blockSize: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    @staticmethod
    def minOfBlock(blockSize: typing.Union[jpype.JInt, int], off: typing.Union[jpype.JLong, int]) -> int:
        ...

    def startComparison(self, time: ghidra.trace.model.time.schedule.TraceSchedule) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Begin a snapshot/time comparison session
         
         
        
        NOTE: This method handles asynchronous errors by popping an error dialog. Callers need not
        handle exceptional completion.
        
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the alternative time
        :return: a future which completes when the alternative listing and difference is presented
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @property
    def nextDiff(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def prevDiff(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def diffs(self) -> ghidra.program.model.address.AddressSetView:
        ...



__all__ = ["DebuggerTraceViewDiffPlugin"]
