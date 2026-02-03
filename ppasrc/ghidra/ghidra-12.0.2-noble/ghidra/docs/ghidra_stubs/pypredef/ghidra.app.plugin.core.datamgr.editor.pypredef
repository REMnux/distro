from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.actions
import docking.widgets.table
import ghidra.app.plugin.core.compositeeditor
import ghidra.app.plugin.core.datamgr
import ghidra.app.plugin.core.datamgr.actions
import ghidra.app.plugin.core.function
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.util
import ghidra.util.table
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class DataTypeEditorManager(ghidra.app.plugin.core.compositeeditor.EditorListener):
    """
    Manages program and archive data type editors.
    """

    @typing.type_check_only
    class DTMEditFunctionSignatureDialog(ghidra.app.plugin.core.function.AbstractEditFunctionSignatureDialog):
        """
        ``DTMEditFunctionSignatureDialog`` provides the ability to edit the
        function signature associated with a specific :obj:`FunctionDefinition`.
        Use of this editor requires the presence of the tool-based datatype manager service.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DtSharedActionPlaceholder(docking.actions.SharedDockingActionPlaceholder):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin):
        """
        Constructs a manager for data type editors.
        
        :param ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin plugin: the plugin that owns this editor manager
        """

    def checkEditors(self, dtMgr: ghidra.program.model.data.DataTypeManager, allowCancel: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check for data types being edited for the given data type manager and prompt the user to
        save any unsaved changes.
        If dtMgr is null then all editors will be checked.
        
        :param ghidra.program.model.data.DataTypeManager dtMgr: the data type manager whose editors are to be checked for changes.
        If null, then check all editors for save.
        :param jpype.JBoolean or bool allowCancel: true indicates that the user can cancel the editor close when prompted
        for whether to save changes or not.
        :return: true if all editors were resolved and can close now; return
        false if the user canceled when prompted to save changes.
        :rtype: bool
        """

    def closed(self, editor: ghidra.app.plugin.core.compositeeditor.EditorProvider):
        """
        EditorListener method that gets called whenever an editor is closed.
        
        :param ghidra.app.plugin.core.compositeeditor.EditorProvider editor: the data type editor that closed
        """

    def createNewEnum(self, category: ghidra.program.model.data.Category):
        ...

    def createNewFunctionDefinition(self, cat: ghidra.program.model.data.Category):
        ...

    def createNewStructure(self, category: ghidra.program.model.data.Category, isPacked: typing.Union[jpype.JBoolean, bool]):
        ...

    def createNewUnion(self, category: ghidra.program.model.data.Category, isPacked: typing.Union[jpype.JBoolean, bool]):
        ...

    def dismissEditors(self, dtMgr: ghidra.program.model.data.DataTypeManager):
        """
        Check for any data types being edited for the given data
        type manager and closes those editors. An editor is associated with a data type
        manager based on the data type manager for the category where the edits will be saved.
        If dtMgr is null then all editors will be dismissed.
        
        :param ghidra.program.model.data.DataTypeManager dtMgr: the data type manager whose editors are to be dismissed.
        If null, then dismiss all editors.
        """

    def dispose(self):
        """
        Dismisses all open editors without prompting to save any changes.
        Performs any other cleanup necessary for this manager.
        """

    @typing.overload
    def edit(self, dataType: ghidra.program.model.data.DataType):
        """
        Displays a data type editor for editing the indicated data type. If the data type is
        is already being edited then it is brought to the front. Otherwise, a new editor is created
        and displayed.
        
        :param ghidra.program.model.data.DataType dataType: the data type to edit.
        """

    @typing.overload
    def edit(self, composite: ghidra.program.model.data.Composite, fieldName: typing.Union[java.lang.String, str]):
        """
        Displays a data type editor for editing the given Structure. If the structure is already 
        being edited then it is brought to the front. Otherwise, a new editor is created and 
        displayed.
        
        :param ghidra.program.model.data.Composite composite: the structure.
        :param java.lang.String or str fieldName: the optional name of the field to select in the editor.
        """

    def editFunctionSignature(self, functionDefinition: ghidra.program.model.data.FunctionDefinition):
        ...

    def getEditedDataTypeCategory(self, dataTypePath: ghidra.program.model.data.DataTypePath) -> ghidra.program.model.data.Category:
        """
        Get the category for the data type being edited; the data type
        may be new and not yet added to the category
        
        :param ghidra.program.model.data.DataTypePath dataTypePath: the full path name of the data type that is being
        edited if it were written to the category for this editor.
        :return: category associated with the data type or null.
        :rtype: ghidra.program.model.data.Category
        """

    def getEditor(self, dataType: ghidra.program.model.data.DataType) -> ghidra.app.plugin.core.compositeeditor.EditorProvider:
        """
        If the specified data type is being edited for the indicated category, this gets that editor.
        
        :param ghidra.program.model.data.DataType dataType: the data type
        :return: the editor or null.
        :rtype: ghidra.app.plugin.core.compositeeditor.EditorProvider
        """

    def getEditorHelpLocation(self, dataType: ghidra.program.model.data.DataType) -> ghidra.util.HelpLocation:
        """
        Gets the location of the help for editing the specified data type.
        
        :param ghidra.program.model.data.DataType dataType: the data type to be edited.
        :return: the help location for editing the data type.
        :rtype: ghidra.util.HelpLocation
        """

    def getEditsInProgress(self) -> java.util.List[ghidra.program.model.data.DataTypePath]:
        """
        Get a list of data type path names for data types that are currently being edited
        
        :return: a list of data type path names for data types that are currently being edited.
        :rtype: java.util.List[ghidra.program.model.data.DataTypePath]
        """

    def isEditInProgress(self) -> bool:
        """
        Determines whether this manager has any data type editor sessions in progress.
        
        :return: true if there are any data type editors.
        :rtype: bool
        """

    def isEditable(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if the indicated data type can be edited
        (i.e. it has an editor that this service knows how to invoke).
        
        :param ghidra.program.model.data.DataType dt: data type to be edited
        :return: true if this service can invoke an editor for changing the data type.
        :rtype: bool
        """

    def nameExists(self, dtm: ghidra.program.model.data.DataTypeManager, dtName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determines if a data type, indicated by the path name, already exists in a data type manager.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager
        :param java.lang.String or str dtName: data type path name
        :return: true if the named data type exists.
        :rtype: bool
        """

    def showStructureNumbersInHex(self) -> bool:
        ...

    def showUnionNumbersInHex(self) -> bool:
        ...

    @property
    def editorHelpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def editor(self) -> ghidra.app.plugin.core.compositeeditor.EditorProvider:
        ...

    @property
    def editedDataTypeCategory(self) -> ghidra.program.model.data.Category:
        ...

    @property
    def editable(self) -> jpype.JBoolean:
        ...

    @property
    def editInProgress(self) -> jpype.JBoolean:
        ...

    @property
    def editsInProgress(self) -> java.util.List[ghidra.program.model.data.DataTypePath]:
        ...


@typing.type_check_only
class EnumEditorPanel(javax.swing.JPanel):

    @typing.type_check_only
    class EnumTable(ghidra.util.table.GhidraTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class RangeValidator(docking.widgets.textfield.GValidatedTextField.LongField.LongValidator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def setOriginalValue(self, originalLong: typing.Union[jpype.JLong, int]):
            ...


    class StatusBarValidationMessageListener(docking.widgets.textfield.GValidatedTextField.ValidationMessageListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EnumCellEditor(docking.widgets.table.GTableTextCellEditor):

        @typing.type_check_only
        class CellEditRequest(java.lang.Record, java.lang.Runnable):

            class_: typing.ClassVar[java.lang.Class]

            def e(self) -> java.awt.event.KeyEvent:
                ...

            def editCol(self) -> int:
                ...

            def editedEntry(self) -> EnumEntry:
                ...

            def editorPanel(self) -> EnumEditorPanel:
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, textField: javax.swing.JTextField):
            ...


    @typing.type_check_only
    class EnumStringCellEditor(EnumEditorPanel.EnumCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EnumLongCellEditor(EnumEditorPanel.EnumCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class EnumValueRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class FindReferencesToEnumFieldAction(ghidra.app.plugin.core.datamgr.actions.AbstractFindReferencesToFieldAction):
    """
    Finds references to a member of an enum.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...


class EnumEntry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str]):
        ...

    def getComment(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getValue(self) -> int:
        ...

    def setComment(self, newComment: typing.Union[java.lang.String, str]):
        ...

    def setName(self, newName: typing.Union[java.lang.String, str]):
        ...

    def setValue(self, newValue: typing.Union[java.lang.Long, int]):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @value.setter
    def value(self, value: jpype.JLong):
        ...


@typing.type_check_only
class EnumTableModel(docking.widgets.table.AbstractSortedTableModel[EnumEntry]):
    """
    Model for the enum editor table.
    """

    @typing.type_check_only
    class EnumNameComparator(java.util.Comparator[EnumEntry]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnumValueComparator(java.util.Comparator[EnumEntry]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnumCommentComparator(java.util.Comparator[EnumEntry]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def setLength(self, length: typing.Union[jpype.JInt, int]):
        ...


class EnumEditorProvider(ghidra.framework.plugintool.ComponentProviderAdapter, javax.swing.event.ChangeListener, ghidra.app.plugin.core.compositeeditor.EditorProvider):
    """
    Editor for an Enum data type.
    """

    @typing.type_check_only
    class MyDataTypeManagerChangeListener(ghidra.program.model.data.DataTypeManagerChangeListenerAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnumPluginAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME_ADD: typing.Final = "Add Enum Value"
    ACTION_NAME_APPLY: typing.Final = "Apply Enum Changes"
    ACTION_NAME_DELETE: typing.Final = "Delete Enum Value"

    def __init__(self, plugin: ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin, enumDT: ghidra.program.model.data.Enum):
        """
        Construct a new enum editor provider.
        
        :param ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin plugin: owner of this provider
        :param ghidra.program.model.data.Enum enumDT: enum data type
        """

    def hasChanges(self) -> bool:
        ...


class EditorOptionManager(ghidra.framework.options.OptionsChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin):
        ...

    def dispose(self):
        ...

    def showStructureNumbersInHex(self) -> bool:
        ...

    def showUnionNumbersInHex(self) -> bool:
        ...



__all__ = ["DataTypeEditorManager", "EnumEditorPanel", "FindReferencesToEnumFieldAction", "EnumEntry", "EnumTableModel", "EnumEditorProvider", "EditorOptionManager"]
