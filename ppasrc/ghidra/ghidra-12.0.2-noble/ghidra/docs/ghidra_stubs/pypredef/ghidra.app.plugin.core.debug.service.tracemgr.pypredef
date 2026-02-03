from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.debug.api.target
import ghidra.debug.api.tracemgr
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.trace.model
import java.lang # type: ignore
import java.util.concurrent # type: ignore


class DebuggerTraceManagerServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerTraceManagerService):

    @typing.type_check_only
    class ListenerForTraceChanges(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...


    @typing.type_check_only
    class TransactionEndFuture(java.util.concurrent.CompletableFuture[java.lang.Void], ghidra.framework.model.TransactionListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...


    @typing.type_check_only
    class ForTargetsListener(ghidra.debug.api.target.TargetPublicationListener):

        class_: typing.ClassVar[java.lang.Class]

        def waitUnlockedDebounced(self, target: ghidra.debug.api.target.Target) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
            ...


    @typing.type_check_only
    class ForFollowPresentListener(ghidra.app.services.DebuggerControlService.ControlModeChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LastCoords(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]
        NEVER: typing.Final[DebuggerTraceManagerServicePlugin.LastCoords]

        def __init__(self, coords: ghidra.debug.api.tracemgr.DebuggerCoordinates):
            ...

        def coords(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def keepTime(self, adjusted: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> DebuggerTraceManagerServicePlugin.LastCoords:
            ...

        def time(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NEW_TRACES_FOLDER_NAME: typing.Final = "New Traces"

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        ...

    def askTrace(self, trace: ghidra.trace.model.Trace) -> ghidra.framework.model.DomainFile:
        ...

    @staticmethod
    def createOrGetFolder(tool: ghidra.framework.plugintool.PluginTool, operation: typing.Union[java.lang.String, str], parent: ghidra.framework.model.DomainFolder, name: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFolder:
        ...

    @staticmethod
    @typing.overload
    def saveTrace(tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, force: typing.Union[jpype.JBoolean, bool]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        ...

    @typing.overload
    def saveTrace(self, trace: ghidra.trace.model.Trace, force: typing.Union[jpype.JBoolean, bool]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        ...



__all__ = ["DebuggerTraceManagerServicePlugin"]
