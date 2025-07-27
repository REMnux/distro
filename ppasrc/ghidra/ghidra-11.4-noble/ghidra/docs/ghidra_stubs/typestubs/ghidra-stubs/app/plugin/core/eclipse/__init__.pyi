from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.main
import ghidra.framework.plugintool
import ghidra.util.task
import java.lang # type: ignore
import java.net # type: ignore


class EclipseConnection(java.lang.Object):
    """
    A class that represents a connection to Eclipse.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new Eclipse connection object that represents no connection.
        """

    @typing.overload
    def __init__(self, process: java.lang.Process, socket: java.net.Socket):
        """
        Creates a new Eclipse connection object.
        
        :param java.lang.Process process: The Eclipse process that we launched (could be null).
        :param java.net.Socket socket: The socket connected to Eclipse (could be null).
        """

    def getProcess(self) -> java.lang.Process:
        """
        Gets the Eclipse process that we launched.
        
        :return: The Eclipse process that we launched.  Could be null if we didn't need to 
        launch an Eclipse to establish a connection, or if we failed to launch Eclipse.
        :rtype: java.lang.Process
        """

    def getSocket(self) -> java.net.Socket:
        """
        Gets the socket connection to Eclipse.
        
        :return: The socket connection to Eclipse.  Could be null if a connection was 
        never established.
        :rtype: java.net.Socket
        """

    @property
    def process(self) -> java.lang.Process:
        ...

    @property
    def socket(self) -> java.net.Socket:
        ...


class EclipseIntegrationOptionsPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin):
    """
    Plugin responsible for registering Eclipse-related options.
    """

    class_: typing.ClassVar[java.lang.Class]
    PLUGIN_OPTIONS_NAME: typing.Final = "Eclipse Integration"
    ECLIPSE_INSTALL_DIR_OPTION: typing.Final = "Eclipse Installation Directory"
    ECLIPSE_WORKSPACE_DIR_OPTION: typing.Final = "Eclipse Workspace Directory (optional)"
    SCRIPT_EDITOR_PORT_OPTION: typing.Final = "Script Editor Port"
    SYMBOL_LOOKUP_PORT_OPTION: typing.Final = "Symbol Lookup Port"
    AUTO_GHIDRADEV_INSTALL_OPTION: typing.Final = "Automatically install GhidraDev"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class EclipseConnectorTask(ghidra.util.task.Task):
    """
    A :obj:`Task` to launch Eclipse.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eclipseService: ghidra.app.services.EclipseIntegrationService, port: typing.Union[jpype.JInt, int]):
        """
        Constructs a new Eclipse connector task.
        
        :param ghidra.app.services.EclipseIntegrationService eclipseService: The Eclipse integration service.
        :param jpype.JInt or int port: The port to connect to Eclipse on.
        """

    def getConnection(self) -> EclipseConnection:
        """
        Gets the Eclipse connection.
        
        :return: The Eclipse connection.
        :rtype: EclipseConnection
        """

    @property
    def connection(self) -> EclipseConnection:
        ...


class EclipseIntegrationPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.services.EclipseIntegrationService):
    """
    Plugin responsible for providing Eclipse-related services to other Ghidra plugins.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["EclipseConnection", "EclipseIntegrationOptionsPlugin", "EclipseConnectorTask", "EclipseIntegrationPlugin"]
