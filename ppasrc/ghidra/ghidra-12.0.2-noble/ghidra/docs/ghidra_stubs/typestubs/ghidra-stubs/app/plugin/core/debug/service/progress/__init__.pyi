from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.debug.api.progress
import ghidra.framework.plugintool
import java.lang # type: ignore


class DefaultCloseableTaskMonitor(ghidra.debug.api.progress.CloseableTaskMonitor):

    @typing.type_check_only
    class State(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgressServicePlugin):
        ...


class ProgressServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.ProgressService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DefaultMonitorReceiver(ghidra.debug.api.progress.MonitorReceiver):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ProgressServicePlugin):
        ...

    def clean(self):
        ...

    def close(self):
        ...



__all__ = ["DefaultCloseableTaskMonitor", "ProgressServicePlugin", "DefaultMonitorReceiver"]
