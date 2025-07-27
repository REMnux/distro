from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.combobox
import docking.widgets.table
import ghidra.app.context
import ghidra.app.services
import ghidra.app.util.datatype
import ghidra.framework.cmd
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table
import ghidra.util.task
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore


class EditDataFieldDialog(docking.DialogComponentProvider):
    """
    Dialog for editing the name, comment, and datatype for a structure or union field.
    """

    @typing.type_check_only
    class UpdateDataComponentCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, dtmService: ghidra.app.services.DataTypeManagerService, composite: ghidra.program.model.data.Composite, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, ordinal: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: The tool hosting this dialog
        :param ghidra.app.services.DataTypeManagerService dtmService: the DataTypeManagerService used for choosing datatypes
        :param ghidra.program.model.data.Composite composite: the composite being edited
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address address: the address of the data type component
        :param jpype.JInt or int ordinal: the ordinal of the data type component inside of the composite
        """

    def getCommentText(self) -> str:
        """
        Returns the text currently in the text field for the field comment.
        
        :return: the text currently in the text field  for the field comment
        :rtype: str
        """

    def getDataTypeEditor(self) -> ghidra.app.util.datatype.DataTypeSelectionEditor:
        ...

    def getDataTypeText(self) -> str:
        ...

    def getNameText(self) -> str:
        """
        Returns the text currently in the text field  for the field name.
        
        :return: the text currently in the text field  for the field name
        :rtype: str
        """

    def getNewDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the pending new datatype to change to.
        
        :return: the pending new datatype to change to
        :rtype: ghidra.program.model.data.DataType
        """

    def setCommentText(self, newComment: typing.Union[java.lang.String, str]):
        """
        Sets the dialog's comment text field to the given text.
        
        :param java.lang.String or str newComment: the text to put into the comment text field
        """

    def setDataType(self, dataType: ghidra.program.model.data.DataType):
        """
        Sets the pending new datatype and updates the datatype text field to the name of that
        datatype.
        
        :param ghidra.program.model.data.DataType dataType: the new pending datatype
        """

    def setNameText(self, newName: typing.Union[java.lang.String, str]):
        """
        Sets the dialog's name text field to the given text.
        
        :param java.lang.String or str newName: the text to put into the name text field
        """

    @property
    def dataTypeEditor(self) -> ghidra.app.util.datatype.DataTypeSelectionEditor:
        ...

    @property
    def nameText(self) -> java.lang.String:
        ...

    @nameText.setter
    def nameText(self, value: java.lang.String):
        ...

    @property
    def dataTypeText(self) -> java.lang.String:
        ...

    @property
    def commentText(self) -> java.lang.String:
        ...

    @commentText.setter
    def commentText(self, value: java.lang.String):
        ...

    @property
    def newDataType(self) -> ghidra.program.model.data.DataType:
        ...


class CycleGroupAction(ghidra.app.context.ListingContextAction):
    """
    ``CycleGroupAction`` cycles data through a series of data types
    defined by a ``CycleGroup``.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeSettingsDialog(AbstractSettingsDialog):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataType: ghidra.program.model.data.DataType, settingsDefinitions: jpype.JArray[ghidra.docking.settings.SettingsDefinition]):
        """
        Construct for data type default settings
        
        :param ghidra.program.model.data.DataType dataType: data type (must be resolved to program)
        :param jpype.JArray[ghidra.docking.settings.SettingsDefinition] settingsDefinitions: settings definitions to be displayed (may be a restricted set)
        """


@typing.type_check_only
class DataAction(ghidra.app.context.ListingContextAction):
    """
    Base class for actions to create data types
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, plugin: DataPlugin):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, plugin: DataPlugin):
        """
        Constructor
        
        :param java.lang.String or str name: action name
        :param java.lang.String or str group: the action's group
        :param ghidra.program.model.data.DataType dataType: the data type used by this action
        :param DataPlugin plugin: the plugin that owns this action
        """


class ChooseDataTypeAction(ghidra.app.context.ListingContextAction):
    """
    An action that allows the user to change or select a data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataPlugin):
        ...


class DataPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DataService):
    """
    This plugin provides a generic method for: Applying installed data types to
    create data for a program Changing an existing Data item's properties.
    
    Currently any DataTypeProvider registered in the ServiceRegistry is displayed
    in the MouseRight Pop-up menu over an undefined data item. Once a Data item
    is defined, the properties associated with the data item that can be set are
    displayed in the MouseRight Pop-up menu.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class PointerDataAction(DataAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataPlugin):
        ...


@typing.type_check_only
class CreateStructureAction(ghidra.app.context.ListingContextAction):
    """
    Action class to create structures
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataPlugin):
        ...

    def actionPerformed(self, programActionContext: ghidra.app.context.ListingActionContext):
        """
        Method called when the action is invoked.
        """


class CreateStructureDialog(docking.ReusableDialogComponentProvider):
    """
    A dialog that allows the user to create a new structure based upon providing
    a new name or by using the name of an existing structure.
    """

    @typing.type_check_only
    class StructureTableModel(docking.widgets.table.AbstractSortedTableModel[CreateStructureDialog.StructureWrapper]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StructureWrapper(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StructureCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a new dialog with the given parent.
        
        :param ghidra.framework.plugintool.PluginTool tool: The current tool that this dialog needs to access services.
        """

    def showCreateStructureDialog(self, program: ghidra.program.model.listing.Program, structure: ghidra.program.model.data.Structure) -> ghidra.program.model.data.Structure:
        """
        Shows a dialog that allows the user to create a new structure.
         
        
        This method expects that ``program`` and ``structure`` be
        non-null.
        
        :param ghidra.program.model.listing.Program program: The current program which will be used to obtain current
                structures in the system.
        :param ghidra.program.model.data.Structure structure: The new structure shell that will be used to find
                matching structures in memory.
        :return: The new structure that will be added to memory.  This will be
                a new structure with a new name, or an existing structure.
        :rtype: ghidra.program.model.data.Structure
        :raises java.lang.NullPointerException: if either of the parameters are null.
        """


class AbstractSettingsDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class SettingsTable(ghidra.util.table.GhidraTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, settingsTableModel: AbstractSettingsDialog.SettingsTableModel):
            ...


    @typing.type_check_only
    class SettingsRowObject(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getName(self) -> str:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class SettingsTableModel(docking.widgets.table.AbstractSortedTableModel[AbstractSettingsDialog.SettingsRowObject]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SettingsRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NumberWrapper(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringWrapper(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringSettingsComboBox(docking.widgets.combobox.GComboBox[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SettingsEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RenameDataFieldDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def setDataComponent(self, program: ghidra.program.model.listing.Program, component: ghidra.program.model.data.DataTypeComponent, name: typing.Union[java.lang.String, str]):
        ...


class DataSettingsDialog(AbstractSettingsDialog):

    @typing.type_check_only
    class CommonSettingsAccumulatorTask(ghidra.util.task.Task):
        """
        Build an array of SettingsDefinitions which are shared across
        all defined data constrained by an address set.
        
        The presence of an instruction will result in the selectionContainsInstruction
        flag being set.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ApplyCommonSettingsTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, sel: ghidra.program.util.ProgramSelection):
        """
        Construct for data instance settings based upon selection
        
        :param ghidra.program.model.listing.Program program: program which contains data selection
        :param ghidra.program.util.ProgramSelection sel: data selection
        :raises CancelledException: if operation cancelled
        """

    @typing.overload
    def __init__(self, data: ghidra.program.model.listing.Data):
        """
        Construct for data instance settings (includes component instance) within a Program
        
        :param ghidra.program.model.listing.Data data: data whose instance settings are to be modified
        """


@typing.type_check_only
class CreateArrayAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataPlugin):
        ...


class RecentlyUsedAction(DataAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DataPlugin):
        ...


class ProgramProviderContext(ghidra.program.model.lang.DataTypeProviderContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        ...


class ProgramStructureProviderContext(ghidra.program.model.lang.DataTypeProviderContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, loc: ghidra.program.util.ProgramLocation):
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, struct: ghidra.program.model.data.Structure, myOffset: typing.Union[jpype.JInt, int]):
        ...

    def getDataTypeComponents(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.data.DataTypeComponent]:
        """
        Get an array of CodePrototypes that begin at or after start up to end.
        Prototypes that exist before start are not returned
        Prototypes that exist before end, but terminate after end ARE returned
        The prototypes must be contiguous from start to end
        
        :param jpype.JInt or int start: start offset
        :param jpype.JInt or int end: end offset
        :return: array of CodePrototypes that exist between start and end.
        :rtype: jpype.JArray[ghidra.program.model.data.DataTypeComponent]
        """



__all__ = ["EditDataFieldDialog", "CycleGroupAction", "DataTypeSettingsDialog", "DataAction", "ChooseDataTypeAction", "DataPlugin", "PointerDataAction", "CreateStructureAction", "CreateStructureDialog", "AbstractSettingsDialog", "RenameDataFieldDialog", "DataSettingsDialog", "CreateArrayAction", "RecentlyUsedAction", "ProgramProviderContext", "ProgramStructureProviderContext"]
