from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util.worker
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore


class FontAdjustPlugin(ghidra.framework.plugintool.Plugin):
    """
    Manages the markers to display areas where changes have occurred
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class RegisterField(javax.swing.JTextField):

    @typing.type_check_only
    class MyDocFilter(javax.swing.text.DocumentFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bitSize: typing.Union[jpype.JInt, int], initialValue: typing.Union[java.lang.Long, int]):
        ...

    @typing.overload
    def __init__(self, bitSize: typing.Union[jpype.JInt, int], initialValue: typing.Union[java.lang.Long, int], useNoValue: typing.Union[jpype.JBoolean, bool]):
        ...

    def getBitSize(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    def getValueColor(self) -> java.awt.Color:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def setBitSize(self, bitSize: typing.Union[jpype.JInt, int]):
        ...

    def setChangeListener(self, listener: javax.swing.event.ChangeListener):
        ...

    def setNoValueColor(self, c: java.awt.Color):
        ...

    def setValue(self, value: typing.Union[java.lang.Long, int]):
        ...

    def setValueColor(self, c: java.awt.Color):
        ...

    @property
    def bitSize(self) -> jpype.JInt:
        ...

    @bitSize.setter
    def bitSize(self, value: jpype.JInt):
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @value.setter
    def value(self, value: jpype.JLong):
        ...

    @property
    def valueColor(self) -> java.awt.Color:
        ...

    @valueColor.setter
    def valueColor(self, value: java.awt.Color):
        ...


class MyProgramChangesDisplayPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    Manages the markers to display areas where changes have occurred
    """

    @typing.type_check_only
    class ProgramTransactionListener(ghidra.framework.model.TransactionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProgramFolderListener(ghidra.framework.model.DomainFolderListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateChangeSetJob(ghidra.util.worker.Job):
        """
        A job to grab program changes from the server
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def isTrackingServerChanges(self) -> bool:
        ...

    @property
    def trackingServerChanges(self) -> jpype.JBoolean:
        ...


class RecoverySnapshotMgrPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin, ghidra.framework.options.OptionsChangeListener, ghidra.framework.model.ProjectListener):

    @typing.type_check_only
    class SnapshotTask(java.lang.Runnable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor - Setup the plugin
        """

    def dispose(self):
        """
        Tells a plugin that it is no longer needed.  The plugin should remove itself
        from anything that it is registered to and release any resources.  Also,
        any plugin that overrides this method should call super.dispose().
        """



__all__ = ["FontAdjustPlugin", "RegisterField", "MyProgramChangesDisplayPlugin", "RecoverySnapshotMgrPlugin"]
