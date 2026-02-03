from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.formats.gfilesystem
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.util.task
import java.lang # type: ignore


class ArchivePlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin, ghidra.framework.model.ProjectListener):
    """
    The archive plugin provides menu action from the front end allowing the
    user to archive a project or restore an archived project.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        The archive plugin provides menu action from the front end allowing the
        user to archive a project or restore an archived project.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool that contains this plugin. The actions will only
        appear if the tool is the Ghidra front end tool.
        """


class ArchiveDialog(docking.ReusableDialogComponentProvider):
    """
    Dialog to prompt the user for the project to archive and the file to archive it to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getArchivePathName(self) -> str:
        """
        Returns the path name of the user specified archive file.
        
        :return: the archive file path name.
        :rtype: str
        """

    def showDialog(self, pProjectLocator: ghidra.framework.model.ProjectLocator, pArchivePathName: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool) -> bool:
        """
        Display this dialog.
        
        :param ghidra.framework.model.ProjectLocator pProjectLocator: the project URL to display when the dialog pops up.
        :param java.lang.String or str pArchivePathName: the archive file name to display when the dialog pops up.
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :return: true if the user submitted valid values for the project and
        archive file, false if user cancelled.
        :rtype: bool
        """

    @property
    def archivePathName(self) -> java.lang.String:
        ...


class RestoreDialog(docking.ReusableDialogComponentProvider):
    """
    Dialog to prompt the user for the archive file to restore
    and where to restore it to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ArchivePlugin):
        ...

    def getArchivePathName(self) -> str:
        """
        Returns the path name of the user specified archive file.
        """

    def showDialog(self, pathName: typing.Union[java.lang.String, str], projectLocator: ghidra.framework.model.ProjectLocator) -> bool:
        """
        Display this dialog.
        
        :param java.lang.String or str pathName: The pathname of the archive file containing the data to restore.
        :param ghidra.framework.model.ProjectLocator projectLocator: The project URL of the location to which the restore archive will be
                extracted.
        :return: true if the user submitted a valid value, false if user cancelled.
        :rtype: bool
        """

    @property
    def archivePathName(self) -> java.lang.String:
        ...


@typing.type_check_only
class ArchiveTask(ghidra.util.task.Task):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RestoreTask(ghidra.formats.gfilesystem.AbstractFileExtractorTask):
    """
    Task that restores a Ghidra Project Archive file (a zip file with a .gar extension)
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ArchivePlugin", "ArchiveDialog", "RestoreDialog", "ArchiveTask", "RestoreTask"]
