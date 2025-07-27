from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.app.context
import ghidra.app.plugin
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.util.table
import ghidra.util.task
import java.lang # type: ignore


class ConvertToUnsignedHexAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Convert To Unsigned Hex"

    def __init__(self, plugin: EquatePlugin):
        ...


class AbstractConvertAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: EquatePlugin, actionName: typing.Union[java.lang.String, str], isSigned: typing.Union[jpype.JBoolean, bool]):
        ...


class EquatePlugin(ghidra.framework.plugintool.Plugin):
    """
    Class to handle setting, removing, and renaming equates in a program.
    """

    @typing.type_check_only
    class InitializeDialogTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program, scalar: ghidra.program.model.scalar.Scalar):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ConvertToFloatAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: EquatePlugin):
        ...


class ConvertToCharAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Convert To Char"

    def __init__(self, plugin: EquatePlugin):
        ...


class EquateTablePlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ConvertToUnsignedDecimalAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: EquatePlugin):
        ...


class EquateTableProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RenameEquatesCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for moving all references to an equate to some other equate. If an equate
    for the new name does not exist, it will be created and all references will be moved
    to it before deleting the original equate.  If an equate already exists with that
    name (it better have the correct value or we shouldn't have gotten this far!), its
    references will be merged with the original equate references.  The undo method
    will restore everything back to where it was when this object was created.  The
    redo method will repeat the rename operation.
    """

    class_: typing.ClassVar[java.lang.Class]


class CreateEnumEquateCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addresses: ghidra.program.model.address.AddressSetView, enoom: ghidra.program.model.data.Enum, shouldDoOnSubOps: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param program: The program to use:param ghidra.program.model.address.AddressSetView addresses: The addresses to apply an enum to
        :param ghidra.program.model.data.Enum enoom: The enum to apply equates with
        :param jpype.JBoolean or bool shouldDoOnSubOps: true if the enum should also be applied to the sub-operands.
        """


class ConvertToBinaryAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: EquatePlugin):
        ...


@typing.type_check_only
class RemoveEquateCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for removing all references to an equate.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        """
        The name of the edit action.
        """

    @property
    def name(self) -> java.lang.String:
        ...


class ConvertToSignedDecimalAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Convert To Signed Decimal"

    def __init__(self, plugin: EquatePlugin):
        ...


@typing.type_check_only
class EquateTableModel(docking.widgets.table.GDynamicColumnTableModel[ghidra.program.model.symbol.Equate, java.lang.Object]):

    @typing.type_check_only
    class EquateNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.symbol.Equate, java.lang.String, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Name"


    @typing.type_check_only
    class EquateValueColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.symbol.Equate, java.lang.Long, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Value"


    @typing.type_check_only
    class EquateReferenceCountColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.symbol.Equate, java.lang.Integer, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "# Refs"


    @typing.type_check_only
    class IsEnumBasedEquateColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.symbol.Equate, java.lang.Boolean, java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Is Enum-Based"


    class_: typing.ClassVar[java.lang.Class]

    def getEquate(self, rowIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Equate:
        ...

    def update(self):
        ...

    @property
    def equate(self) -> ghidra.program.model.symbol.Equate:
        ...


class ConvertToSignedHexAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Convert To Signed Hex"

    def __init__(self, plugin: EquatePlugin):
        ...


@typing.type_check_only
class RenameEquateCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Renames an equate at a location to a new name.  It will create a new equate if
    one doesn't already exist with the new name.  If one already exists, it will just
    add the current location to its list of references.  The old equate will have this
    reference location removed and will be deleted if it was the last reference.
    """

    class_: typing.ClassVar[java.lang.Class]


class CreateEquateCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Class to handle creating new equates for a selection or the whole program
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, scalar: ghidra.program.model.scalar.Scalar, iter: ghidra.program.model.listing.CodeUnitIterator, equateName: typing.Union[java.lang.String, str], overwriteExisting: typing.Union[jpype.JBoolean, bool], context: ghidra.app.context.ListingActionContext):
        """
        
        
        :param ghidra.program.model.scalar.Scalar scalar: user defined scalar to search for in program
        :param ghidra.program.model.listing.CodeUnitIterator iter: the range of code units for which to maybe create equates
        :param java.lang.String or str equateName: user defined name for the new equate to be set
        :param jpype.JBoolean or bool overwriteExisting: true to rename existing equates
        :param ghidra.app.context.ListingActionContext context: the action context
        """

    @typing.overload
    def __init__(self, scalar: ghidra.program.model.scalar.Scalar, iter: ghidra.program.model.listing.CodeUnitIterator, enoom: ghidra.program.model.data.Enum, overwriteExisting: typing.Union[jpype.JBoolean, bool], context: ghidra.app.context.ListingActionContext):
        """
        
        
        :param ghidra.program.model.scalar.Scalar scalar: user defined scalar to search for in program
        :param ghidra.program.model.listing.CodeUnitIterator iter: the range of code units for which to maybe create equates
        :param ghidra.program.model.data.Enum enoom: the enum to use for formatting the equate name
        :param jpype.JBoolean or bool overwriteExisting: true to rename existing equates
        :param ghidra.app.context.ListingActionContext context: the action context
        """


class ConvertCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, action: AbstractConvertAction, context: ghidra.app.context.ListingActionContext):
        """
        Constructor for the command to convert scalars and data to the user chosen format. The
        command will work at a single address or over a selection in the case where the current
        location refers to an instruction.  
         
        
        Data convert only supports signed/unsigned and defined FormatSettingsDefinitions
        on data whose data type is based upon the AbstractIntegerDataType.
        
        :param AbstractConvertAction action: The action to pull information from
        :param ghidra.app.context.ListingActionContext context: The action context
        """


@typing.type_check_only
class EquateReferenceTableModel(docking.widgets.table.GDynamicColumnTableModel[ghidra.program.model.symbol.EquateReference, java.lang.Object], ghidra.util.table.ProgramTableModel):

    @typing.type_check_only
    class EquateReferenceAddressColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.symbol.EquateReference, ghidra.program.model.address.Address, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EquateOperandIndexColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.symbol.EquateReference, java.lang.Short, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ConvertToDoubleAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: EquatePlugin):
        ...


class ConvertToOctalAction(AbstractConvertAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Convert To Unsigned Octal"

    def __init__(self, plugin: EquatePlugin):
        ...



__all__ = ["ConvertToUnsignedHexAction", "AbstractConvertAction", "EquatePlugin", "ConvertToFloatAction", "ConvertToCharAction", "EquateTablePlugin", "ConvertToUnsignedDecimalAction", "EquateTableProvider", "RenameEquatesCmd", "CreateEnumEquateCommand", "ConvertToBinaryAction", "RemoveEquateCmd", "ConvertToSignedDecimalAction", "EquateTableModel", "ConvertToSignedHexAction", "RenameEquateCmd", "CreateEquateCmd", "ConvertCommand", "EquateReferenceTableModel", "ConvertToDoubleAction", "ConvertToOctalAction"]
