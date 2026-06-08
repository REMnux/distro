from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.plugin.core.debug.gui.memview


class ZoomInTAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.memview.MemviewProvider) -> None:
        ...


class ZoomOutTAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.memview.MemviewProvider) -> None:
        ...


class ZoomOutAAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.memview.MemviewProvider) -> None:
        ...


class ZoomInAAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.memview.MemviewProvider) -> None:
        ...



__all__ = ["ZoomInTAction", "ZoomOutTAction", "ZoomOutAAction", "ZoomInAAction"]
