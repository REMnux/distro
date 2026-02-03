from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.plugin.core.datamgr
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.plugin.core.datamgr.tree
import ghidra.program.model.data
import ghidra.util.task
import java.lang # type: ignore


class RevertAction(SyncAction):

    class_: typing.ClassVar[java.lang.Class]
    MENU_NAME: typing.Final = "Revert Data Types From"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, dataTypeManagerHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dtm: ghidra.program.model.data.DataTypeManager, archiveNode: ghidra.app.plugin.core.datamgr.tree.ArchiveNode, sourceArchive: ghidra.program.model.data.SourceArchive, isEnabled: typing.Union[jpype.JBoolean, bool]):
        ...


class RevertDataTypeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...


class CommitAction(SyncAction):

    class_: typing.ClassVar[java.lang.Class]
    MENU_NAME: typing.Final = "Commit Data Types To"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, dataTypeManagerHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dtm: ghidra.program.model.data.DataTypeManager, archiveNode: ghidra.app.plugin.core.datamgr.tree.ArchiveNode, sourceArchive: ghidra.program.model.data.SourceArchive, isEnabled: typing.Union[jpype.JBoolean, bool]):
        ...


class CommitSingleDataTypeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...


class DisassociateDataTypeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...


class AssociateDataTypeAction(docking.action.DockingAction):
    """
    Allows the user to associate the selected action with a source archive.  An associate data type
    allows users to push changes to the source archive and to pull updates from the source archive.
    """

    @typing.type_check_only
    class ChooseArchiveDialog(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...


class SyncAction(docking.action.DockingAction, java.lang.Comparable[SyncAction]):

    @typing.type_check_only
    class SyncTask(ghidra.util.task.Task):
        """
        Task for off-loading long-running Sync operation
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, synchronizer: ghidra.app.plugin.core.datamgr.DataTypeSynchronizer):
            ...


    class_: typing.ClassVar[java.lang.Class]


class UpdateSingleDataTypeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        ...


class UpdateAction(SyncAction):

    class_: typing.ClassVar[java.lang.Class]
    MENU_NAME: typing.Final = "Update Data Types From"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, dataTypeManagerHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dtm: ghidra.program.model.data.DataTypeManager, archiveNode: ghidra.app.plugin.core.datamgr.tree.ArchiveNode, sourceArchive: ghidra.program.model.data.SourceArchive, isEnabled: typing.Union[jpype.JBoolean, bool]):
        ...


class DisassociateAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    MENU_NAME: typing.Final = "Disassociate Data Types From"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, handler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dtm: ghidra.program.model.data.DataTypeManager, archiveNode: ghidra.app.plugin.core.datamgr.tree.ArchiveNode, sourceArchive: ghidra.program.model.data.SourceArchive):
        ...


class SyncRefreshAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    MENU_NAME: typing.Final = "Refresh Sync Indicators For"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, dataTypeManagerHandler: ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler, dtm: ghidra.program.model.data.DataTypeManager, archiveNode: ghidra.app.plugin.core.datamgr.tree.ArchiveNode, sourceArchive: ghidra.program.model.data.SourceArchive, isEnabled: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["RevertAction", "RevertDataTypeAction", "CommitAction", "CommitSingleDataTypeAction", "DisassociateDataTypeAction", "AssociateDataTypeAction", "SyncAction", "UpdateSingleDataTypeAction", "UpdateAction", "DisassociateAction", "SyncRefreshAction"]
