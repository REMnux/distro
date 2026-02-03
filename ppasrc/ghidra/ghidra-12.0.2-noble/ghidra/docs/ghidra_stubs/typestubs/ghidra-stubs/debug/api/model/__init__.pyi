from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import java.awt # type: ignore
import java.util # type: ignore


class DebuggerSingleObjectPathActionContext(docking.DefaultActionContext):
    """
    Really just used by scripts to get a path into an action context
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: ghidra.trace.model.target.path.KeyPath):
        ...

    def getPath(self) -> ghidra.trace.model.target.path.KeyPath:
        ...

    @property
    def path(self) -> ghidra.trace.model.target.path.KeyPath:
        ...


class DebuggerObjectActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, objectValues: collections.abc.Sequence, provider: docking.ComponentProvider, sourceComponent: java.awt.Component, snap: typing.Union[jpype.JLong, int]):
        ...

    def getObjectValues(self) -> java.util.List[ghidra.trace.model.target.TraceObjectValue]:
        ...

    def getSnap(self) -> int:
        ...

    @property
    def objectValues(self) -> java.util.List[ghidra.trace.model.target.TraceObjectValue]:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...



__all__ = ["DebuggerSingleObjectPathActionContext", "DebuggerObjectActionContext"]
