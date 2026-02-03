from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.tree
import ghidra.app.plugin.core.debug.gui.tracermi.connection
import ghidra.debug.api.target
import ghidra.debug.api.tracemgr
import ghidra.debug.api.tracermi
import java.lang # type: ignore


class TraceRmiTargetNode(AbstractTraceRmiManagerNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider, connectionNode: TraceRmiConnectionNode, target: ghidra.debug.api.target.Target):
        ...

    def getConnectionNode(self) -> TraceRmiConnectionNode:
        ...

    def getTarget(self) -> ghidra.debug.api.target.Target:
        ...

    @property
    def connectionNode(self) -> TraceRmiConnectionNode:
        ...

    @property
    def target(self) -> ghidra.debug.api.target.Target:
        ...


class TraceRmiManagerNode(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AbstractTraceRmiManagerNode(docking.widgets.tree.GTreeNode, TraceRmiManagerNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider, name: typing.Union[java.lang.String, str]):
        ...


class TraceRmiConnectionNode(AbstractTraceRmiManagerNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider, connection: ghidra.debug.api.tracermi.TraceRmiConnection):
        ...

    def getConnection(self) -> ghidra.debug.api.tracermi.TraceRmiConnection:
        ...

    def targetPublished(self, target: ghidra.debug.api.target.Target) -> TraceRmiTargetNode:
        ...

    def targetWithdrawn(self, target: ghidra.debug.api.target.Target):
        ...

    @property
    def connection(self) -> ghidra.debug.api.tracermi.TraceRmiConnection:
        ...


class TraceRmiServiceNode(AbstractTraceRmiManagerNode, ghidra.debug.api.tracermi.TraceRmiServiceListener, ghidra.debug.api.target.TargetPublicationListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider):
        ...

    def coordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...


class TraceRmiAcceptorNode(AbstractTraceRmiManagerNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider, acceptor: ghidra.debug.api.tracermi.TraceRmiAcceptor):
        ...

    def getAcceptor(self) -> ghidra.debug.api.tracermi.TraceRmiAcceptor:
        ...

    @property
    def acceptor(self) -> ghidra.debug.api.tracermi.TraceRmiAcceptor:
        ...


class TraceRmiServerNode(AbstractTraceRmiManagerNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider):
        ...



__all__ = ["TraceRmiTargetNode", "TraceRmiManagerNode", "AbstractTraceRmiManagerNode", "TraceRmiConnectionNode", "TraceRmiServiceNode", "TraceRmiAcceptorNode", "TraceRmiServerNode"]
