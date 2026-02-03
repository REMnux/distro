from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.debug.api.target
import ghidra.framework.plugintool
import java.lang # type: ignore


class AbstractTarget(ghidra.debug.api.target.Target):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...


class DebuggerTargetServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerTargetService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["AbstractTarget", "DebuggerTargetServicePlugin"]
