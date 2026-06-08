from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.menu
import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.app.actions
import ghidra.app.plugin.core.datamgr
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.util.datatype
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.service.graph
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class RecentlyOpenedArchiveAction(docking.action.DockingAction):
    """
    Class for action to open a recently opened data type archive.
    """

    @typing.type_check_only
    class OpenArchiveTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, archivePath: typing.Union[java.lang.String, str], menuGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class CreateTypeDefAction(AbstractTypeDefAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class RemoveInvalidArchiveFromProgramAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateTypeDefDialog(docking.DialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CollapseAllArchivesAction(docking.action.DockingAction):
    """
    This action handles recursively collapsing nodes in the dataTypes tree.  If invoked from the
    local toolbar icon, it collapses all nodes in the tree.  If invoked from the popup, it only
    collapses the selected nodes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class EditAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class PasteAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CopyAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindReferencesToDataTypeAction(ghidra.app.actions.AbstractFindReferencesDataTypeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


@typing.type_check_only
class DerivativeDataTypeInfo(java.lang.Object):
    """
    A class to 1) hold related data for creating a new data type and 2) to validate the given 
    data when the requested info is based upon the a disallowed condition (e.g., creating a data
    type in the built-in archive).
    """

    class_: typing.ClassVar[java.lang.Class]


class PreviewWindowAction(docking.action.ToggleDockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, provider: ghidra.app.plugin.core.datamgr.DataTypesProvider) -> None:
        ...


class SetFavoriteDataTypeAction(docking.action.ToggleDockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


@typing.type_check_only
class AnnotationHandlerDialog(docking.DialogComponentProvider):
    """
    A simple dialog to select the language export type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getHandler(self) -> ghidra.program.model.data.AnnotationHandler:
        ...

    def wasSuccessful(self) -> bool:
        ...

    @property
    def handler(self) -> ghidra.program.model.data.AnnotationHandler:
        ...


class AbstractUndoRedoArchiveTransactionAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, actionName: typing.Union[java.lang.String, str], plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        """
        Construct Undo/Redo action
        
        :param java.lang.String or str actionName: "Undo" or "Redo" action name
        :param ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin plugin: :obj:`DataTypeManagerPlugin`
        """


class FindDataTypesBySizeAction(docking.action.DockingAction):

    @typing.type_check_only
    class SizeGTreeFilter(docking.widgets.tree.support.GTreeFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find Data Types by Size"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, menuSubGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class CreateEnumFromSelectionAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ApplyEnumsAsLabelsAction(docking.action.DockingAction):

    @typing.type_check_only
    class ApplySelectedEnumsTask(ghidra.util.task.Task):

        @typing.type_check_only
        class CreateLabelResult(java.lang.Object):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class DisplayTypeAsGraphAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class TypeGraphTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]
    COMPOSITE: typing.Final = "Composite"
    REFERENCE: typing.Final = "Reference"

    def __init__(self, type: ghidra.program.model.data.DataType, graphService: ghidra.service.graph.GraphDisplayProvider) -> None:
        ...


class CreateUnionAction(CreateDataTypeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CloseArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class RenameAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class SetArchiveArchitectureAction(docking.action.DockingAction):

    @typing.type_check_only
    class SetProgramArchitectureTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.Archive, dtm: ghidra.program.model.data.StandAloneDataTypeManager, language: ghidra.program.model.lang.Language, compilerSpecId: ghidra.program.model.lang.CompilerSpecID) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class SecondaryTreeFilterProvider(docking.widgets.tree.DefaultGTreeFilterProvider):
    """
    A filter that allows for an additional second filter.
    """

    class_: typing.ClassVar[java.lang.Class]


class ClearArchiveArchitectureAction(docking.action.DockingAction):

    @typing.type_check_only
    class ClearProgramArchitectureTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, archive: ghidra.app.plugin.core.datamgr.archive.Archive, dtm: ghidra.program.model.data.StandAloneDataTypeManager) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindReferencesToFieldByNameOrOffsetAction(AbstractFindReferencesToFieldAction):
    """
    An action that can be used on a :obj:`Composite` or :obj:`Enum` to find references to a field
    by name or offset.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin) -> None:
        ...


class CreateFunctionDefinitionAction(CreateDataTypeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ClearCutAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class OpenArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ReplaceDataTypeAction(docking.action.DockingAction):
    """
    Replace the selected data type with the chosen data type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateProjectArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateTypeDefFromDialogAction(AbstractTypeDefAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class SaveAsAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class OpenProjectArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class IncludeDataTypesInFilterAction(docking.action.ToggleDockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, provider: ghidra.app.plugin.core.datamgr.DataTypesProvider, menuSubGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class CreatePointerAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindStructuresByOffsetAction(docking.action.DockingAction):
    """
    Allows the user to supply one or more offsets that are used to search for structures that have
    any of those offsets.
    """

    @typing.type_check_only
    class OffsetGTreeFilter(docking.widgets.tree.support.GTreeFilter):

        @typing.type_check_only
        class OffsetIterator(java.util.Iterator[java.lang.Integer]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find Structures by Offset"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, menuSubGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class EditArchivePathAction(docking.action.DockingAction):

    @typing.type_check_only
    class PathManagerDialog(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ExportToHeaderAction(docking.action.DockingAction):

    @typing.type_check_only
    class DataTypeWriterTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateStructureAction(CreateDataTypeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class DataTypeMergeErrorDialog(AbstractDataTypeMergeDialog):
    """
    Dialog for showing datatype merge errors. The dialog shows the error message and a display
    of the two datatypes that couldn't be merged.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeTo: ghidra.program.model.data.DataType, mergeFrom: ghidra.program.model.data.DataType, error: typing.Union[java.lang.String, str]) -> None:
        ...


class DeleteAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class AbstractFindReferencesToFieldAction(docking.action.DockingAction):

    class DataTypeAndFields(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dataType: ghidra.program.model.data.DataType, fieldNames: jpype.JArray[java.lang.String]) -> None:
            ...

        def dataType(self) -> ghidra.program.model.data.DataType:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def fieldNames(self) -> jpype.JArray[java.lang.String]:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    BASE_ACTION_NAME: typing.Final = "Find Uses of"

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin) -> None:
        ...


class UnlockArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Unlock Archive"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class RedoArchiveTransactionAction(AbstractUndoRedoArchiveTransactionAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ApplyFunctionDataTypesAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ExpandAllAction(docking.action.DockingAction):
    """
    This action handles recursively expanding the selected nodes in the dataTypes tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class UndoArchiveTransactionAction(AbstractUndoRedoArchiveTransactionAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindBaseDataTypeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateDataTypeAction(docking.action.DockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AbstractDataTypeMergeDialog(docking.DialogComponentProvider):
    """
    Base class for both the datatype merge confirmation dialog and the datatype merge error dialog
    """

    @typing.type_check_only
    class PreviewPanel(javax.swing.JPanel, javax.swing.Scrollable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], result: ghidra.program.model.data.DataType, mergeTo: ghidra.program.model.data.DataType, mergeFrom: ghidra.program.model.data.DataType, message: typing.Union[java.lang.String, str]) -> None:
        ...


class CaptureFunctionDataTypesAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateEnumAction(CreateDataTypeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class DtFilterAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class LockArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Lock Archive"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindEnumsByValueAction(docking.action.DockingAction):
    """
    Finds enum data types by matching user supplied enum values or ranges.
    """

    @typing.type_check_only
    class OffsetGTreeFilter(docking.widgets.tree.support.GTreeFilter):

        @typing.type_check_only
        class OffsetIterator(java.util.Iterator[java.lang.Long]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find Enums by Value"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, menuSubGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class CutAction(docking.action.DockingAction):

    @typing.type_check_only
    class DataTypeTreeNodeTransferable(docking.widgets.tree.support.GTreeNodeTransferable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: docking.widgets.tree.support.GTreeTransferHandler, selectedData: java.util.List[docking.widgets.tree.GTreeNode]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindDataTypesByNameAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find Data Types by Name"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, menuSubGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class DataTypeMergeConfirmationDialog(AbstractDataTypeMergeDialog):
    """
    Confirmation dialog for merging two datatypes. The dialog displays the resulting datatype along
    with the two being merged in a side by side view. Also displays any warning messages associated
    with the merge.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, result: ghidra.program.model.data.DataType, mergeTo: ghidra.program.model.data.DataType, mergeFrom: ghidra.program.model.data.DataType, warnings: java.util.List[java.lang.String]) -> None:
        ...

    def wasCancelled(self) -> bool:
        ...


class DeleteArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class ConflictHandlerModesAction(docking.menu.MultiStateDockingAction[ghidra.program.model.data.DataTypeConflictHandler.ConflictResolutionPolicy]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class CreateCategoryAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


@typing.type_check_only
class AbstractTypeDefAction(docking.action.DockingAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CreateArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class SaveArchiveAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class MergeDataTypeAction(docking.action.DockingAction):
    """
    Replace the selected data type with the chosen data type
    """

    @typing.type_check_only
    class DataTypeMergeSelectionDialog(ghidra.app.util.datatype.DataTypeSelectionDialog):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin) -> None:
        ...


class FindStructuresBySizeAction(FindDataTypesBySizeAction):
    """
    Allows the user to supply one or more sizes that are used to search for structures that have
    that size.
    """

    @typing.type_check_only
    class StructureSizeGTreeFilter(docking.widgets.tree.support.GTreeFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find Structures by Size"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, menuSubGroup: typing.Union[java.lang.String, str]) -> None:
        ...


class UpdateSourceArchiveNamesAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Update Source Archive Names"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, dtm: ghidra.program.model.data.DataTypeManager) -> None:
        ...



__all__ = ["RecentlyOpenedArchiveAction", "CreateTypeDefAction", "RemoveInvalidArchiveFromProgramAction", "CreateTypeDefDialog", "CollapseAllArchivesAction", "EditAction", "PasteAction", "CopyAction", "FindReferencesToDataTypeAction", "DerivativeDataTypeInfo", "PreviewWindowAction", "SetFavoriteDataTypeAction", "AnnotationHandlerDialog", "AbstractUndoRedoArchiveTransactionAction", "FindDataTypesBySizeAction", "CreateEnumFromSelectionAction", "ApplyEnumsAsLabelsAction", "DisplayTypeAsGraphAction", "TypeGraphTask", "CreateUnionAction", "CloseArchiveAction", "RenameAction", "SetArchiveArchitectureAction", "SecondaryTreeFilterProvider", "ClearArchiveArchitectureAction", "FindReferencesToFieldByNameOrOffsetAction", "CreateFunctionDefinitionAction", "ClearCutAction", "OpenArchiveAction", "ReplaceDataTypeAction", "CreateProjectArchiveAction", "CreateTypeDefFromDialogAction", "SaveAsAction", "OpenProjectArchiveAction", "IncludeDataTypesInFilterAction", "CreatePointerAction", "FindStructuresByOffsetAction", "EditArchivePathAction", "ExportToHeaderAction", "CreateStructureAction", "DataTypeMergeErrorDialog", "DeleteAction", "AbstractFindReferencesToFieldAction", "UnlockArchiveAction", "RedoArchiveTransactionAction", "ApplyFunctionDataTypesAction", "ExpandAllAction", "UndoArchiveTransactionAction", "FindBaseDataTypeAction", "CreateDataTypeAction", "AbstractDataTypeMergeDialog", "CaptureFunctionDataTypesAction", "CreateEnumAction", "DtFilterAction", "LockArchiveAction", "FindEnumsByValueAction", "CutAction", "FindDataTypesByNameAction", "DataTypeMergeConfirmationDialog", "DeleteArchiveAction", "ConflictHandlerModesAction", "CreateCategoryAction", "AbstractTypeDefAction", "CreateArchiveAction", "SaveArchiveAction", "MergeDataTypeAction", "FindStructuresBySizeAction", "UpdateSourceArchiveNamesAction"]
