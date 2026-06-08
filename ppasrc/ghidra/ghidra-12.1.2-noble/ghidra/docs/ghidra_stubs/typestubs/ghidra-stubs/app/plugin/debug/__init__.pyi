from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import docking
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import javax.swing # type: ignore


class DbViewerPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class DomainEventDisplayPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.model.DomainObjectListener):
    """
    Debug Plugin to show domain object change events.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class DbViewerProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin) -> None:
        ...


class DomainFolderChangesDisplayPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin, ghidra.framework.model.ProjectListener, ghidra.framework.model.DomainFolderChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


@typing.type_check_only
class DbViewerComponent(javax.swing.JPanel):

    @typing.type_check_only
    class TableItem(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InternalDBListener(db.DBListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class JavaHelpPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelPlugin):
    """
    Generate a file of all components and actions in the
    """

    @typing.type_check_only
    class WriterTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HelpInfoObject(java.lang.Comparable[JavaHelpPlugin.HelpInfoObject]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class DomainFolderChangesDisplayComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]) -> None:
        ...

    def addText(self, text: typing.Union[java.lang.String, str]) -> None:
        ...


class GenerateOldLanguagePlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelPlugin):

    @typing.type_check_only
    class GenerateOldLanguageDialog(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GenerateTranslatorDialog(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DummyLanguageTranslator(ghidra.program.util.LanguageTranslatorAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DeprecatedLanguageService(ghidra.program.model.lang.VersionedLanguageService):
        """
        Language service which includes all languages, including old and deprecated
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class ComponentInfoPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to display information about components in the application
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class EventDisplayComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]) -> None:
        ...

    def processEvent(self, event: ghidra.framework.plugintool.PluginEvent) -> None:
        ...


class DomainEventComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]) -> None:
        ...


class EventDisplayPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to demonstrate handling of Program within a plugin and how to
    set up the list of consumed plugin events.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        """
        Constructor
        """

    def processEvent(self, event: ghidra.framework.plugintool.PluginEvent) -> None:
        """
        Put event processing code here.
        """



__all__ = ["DbViewerPlugin", "DomainEventDisplayPlugin", "DbViewerProvider", "DomainFolderChangesDisplayPlugin", "DbViewerComponent", "JavaHelpPlugin", "DomainFolderChangesDisplayComponentProvider", "GenerateOldLanguagePlugin", "ComponentInfoPlugin", "EventDisplayComponentProvider", "DomainEventComponentProvider", "EventDisplayPlugin"]
