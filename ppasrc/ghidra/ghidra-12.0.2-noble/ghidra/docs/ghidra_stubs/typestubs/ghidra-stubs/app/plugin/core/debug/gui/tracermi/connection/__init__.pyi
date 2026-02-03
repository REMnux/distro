from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action.builder
import docking.widgets.tree
import ghidra.app.plugin.core.debug.gui.tracermi.connection.tree
import ghidra.app.plugin.core.debug.gui.tracermi.launcher
import ghidra.app.services
import ghidra.debug.api
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.util
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.tree # type: ignore


class TraceRmiConnectDialog(ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLaunchDialog):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], buttonText: typing.Union[java.lang.String, str]):
        ...

    def promptArguments(self) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
        ...


class TraceRmiManagerActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: TraceRmiConnectionManagerProvider, path: javax.swing.tree.TreePath, tree: docking.widgets.tree.GTree):
        ...

    def getSelectedNode(self) -> ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.TraceRmiManagerNode:
        ...

    @property
    def selectedNode(self) -> ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.TraceRmiManagerNode:
        ...


class TraceRmiConnectionManagerProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class StartServerAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Start Server"
        DESCRIPTION: typing.Final = "Start a TCP server for incoming connections (indefinitely)"
        GROUP: typing.Final = "2. Server"
        HELP_ANCHOR: typing.Final = "start_server"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class StopServerAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Stop Server"
        DESCRIPTION: typing.Final = "Close the TCP server"
        GROUP: typing.Final = "2. Server"
        HELP_ANCHOR: typing.Final = "stop_server"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ConnectAcceptAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Connect by Accept"
        DESCRIPTION: typing.Final = "Accept a single inbound TCP connection"
        GROUP: typing.Final = "1. Connect"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "connect_accept"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ConnectOutboundAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Connect Outbound"
        DESCRIPTION: typing.Final = "Connect to a listening agent/plugin by TCP"
        GROUP: typing.Final = "1. Connect"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "connect_outbound"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class CloseConnectionAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Close"
        DESCRIPTION: typing.Final = "Close a connection or server"
        GROUP: typing.Final = "3. Maintenance"
        HELP_ANCHOR: typing.Final = "close"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class CloseAllAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Close All"
        DESCRIPTION: typing.Final = "Close all connections and the server"
        GROUP: typing.Final = "3. Maintenance"
        HELP_ANCHOR: typing.Final = "close_all"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ForceCloseTransactionsActions(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Forcibly Close Transactions"
        DESCRIPTION: typing.Final = "Forcibly commit all remote transactions on the trace"
        GROUP: typing.Final = "3. Maintenance"
        HELP_ANCHOR: typing.Final = "forcibly_close_txes"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class InjectableGTree(docking.widgets.tree.GTree):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, root: docking.widgets.tree.GTreeNode):
            ...


    class_: typing.ClassVar[java.lang.Class]
    TITLE: typing.Final = "Connections"
    ICON: typing.Final[javax.swing.Icon]
    HELP: typing.Final[ghidra.util.HelpLocation]

    def __init__(self, plugin: TraceRmiConnectionManagerPlugin):
        ...

    def coordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        """
        Coordinates, whether active or inactive, for a trace changed
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates
        """

    def getTraceRmiService(self) -> ghidra.app.services.TraceRmiService:
        ...

    @property
    def traceRmiService(self) -> ghidra.app.services.TraceRmiService:
        ...


class TraceRmiConnectionManagerPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["TraceRmiConnectDialog", "TraceRmiManagerActionContext", "TraceRmiConnectionManagerProvider", "TraceRmiConnectionManagerPlugin"]
