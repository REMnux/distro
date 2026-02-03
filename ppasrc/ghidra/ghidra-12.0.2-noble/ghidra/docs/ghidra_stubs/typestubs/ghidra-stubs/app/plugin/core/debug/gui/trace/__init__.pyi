from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.tab
import ghidra.app.plugin.core.debug.gui.thread
import ghidra.app.services
import ghidra.debug.api.target
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import java.awt.event # type: ignore
import java.lang # type: ignore


class DebuggerTraceTabPanel(docking.widgets.tab.GTabPanel[ghidra.trace.model.Trace], ghidra.framework.plugintool.util.PluginEventListener, ghidra.framework.model.DomainObjectListener):

    @typing.type_check_only
    class TargetsChangeListener(ghidra.debug.api.target.TargetPublicationListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...

    def getActionContext(self, e: java.awt.event.MouseEvent) -> ghidra.app.plugin.core.debug.gui.thread.DebuggerTraceFileActionContext:
        ...

    def setTargetService(self, targetService: ghidra.app.services.DebuggerTargetService):
        ...

    @property
    def actionContext(self) -> ghidra.app.plugin.core.debug.gui.thread.DebuggerTraceFileActionContext:
        ...



__all__ = ["DebuggerTraceTabPanel"]
