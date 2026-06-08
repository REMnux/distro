from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.plugin.core.debug
import ghidra.framework.plugintool
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import java.lang # type: ignore
import javax.swing # type: ignore


class BreakpointTimelinePlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


@typing.type_check_only
class BreakpointTimelinePanel(javax.swing.JPanel):

    @typing.type_check_only
    class CachedIndex(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BreakpointTimelineProvider(docking.ComponentProvider):

    @typing.type_check_only
    class BreakpointHitEvent(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def breakType(self) -> ghidra.trace.model.breakpoint.TraceBreakpointKind:
            ...

        def breakpointName(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def snap(self) -> int:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class BreakpointTimeOverviewEventListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...


    @typing.type_check_only
    class CloseAllZoomWindowsAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SmallestCellSizeAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleGridAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleGridOrColumnAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ZoomInAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ZoomOutAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["BreakpointTimelinePlugin", "BreakpointTimelinePanel", "BreakpointTimelineProvider"]
