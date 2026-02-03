from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug
import ghidra.app.services
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.trace.model
import ghidra.trace.model.program
import java.lang # type: ignore


class DebuggerControlServicePlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin, ghidra.app.services.DebuggerControlService):

    @typing.type_check_only
    class AbstractStateEditor(ghidra.app.services.DebuggerControlService.StateEditor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultStateEditor(DebuggerControlServicePlugin.AbstractStateEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
            ...


    @typing.type_check_only
    class FollowsManagerStateEditor(DebuggerControlServicePlugin.AbstractStateEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...


    class FollowsViewStateEditor(DebuggerControlServicePlugin.AbstractStateEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, view: ghidra.trace.model.program.TraceProgramView):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["DebuggerControlServicePlugin"]
