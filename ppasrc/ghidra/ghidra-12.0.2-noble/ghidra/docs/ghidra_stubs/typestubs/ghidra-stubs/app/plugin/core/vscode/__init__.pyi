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
import java.io # type: ignore
import java.lang # type: ignore


class VSCodeIntegrationOptionsPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin):
    """
    :obj:`Plugin` responsible for registering Visual Studio Code-related options
    """

    class_: typing.ClassVar[java.lang.Class]
    PLUGIN_OPTIONS_NAME: typing.Final = "Visual Studio Code Integration"
    VSCODE_EXE_PATH_OPTION: typing.Final = "Visual Studio Code Executable Path"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class VSCodeLauncherTask(ghidra.util.task.Task):
    """
    A :obj:`Task` to launch Visual Studio Code
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vscodeService: ghidra.app.services.VSCodeIntegrationService, file: jpype.protocol.SupportsPath):
        """
        Constructs a new Visual Studio Code launcher task
        
        :param ghidra.app.services.VSCodeIntegrationService vscodeService: The Visual Studio Code integration service
        :param jpype.protocol.SupportsPath file: The file to open in Visual Studio Code
        """


class VSCodeIntegrationPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.services.VSCodeIntegrationService):
    """
    :obj:`Plugin` responsible integrating Ghidra with Visual Studio Code
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Create a new :obj:`VSCodeIntegrationPlugin`
        
        :param ghidra.framework.plugintool.PluginTool tool: The associated :obj:`tool <PluginTool>`
        """



__all__ = ["VSCodeIntegrationOptionsPlugin", "VSCodeLauncherTask", "VSCodeIntegrationPlugin"]
