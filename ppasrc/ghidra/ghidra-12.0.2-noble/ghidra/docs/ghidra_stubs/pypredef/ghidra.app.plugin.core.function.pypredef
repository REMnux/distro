from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets
import generic.theme
import ghidra.app.context
import ghidra.app.services
import ghidra.app.util.importer
import ghidra.app.util.viewer.field
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class X86FunctionPurgeAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CycleGroupAction(ghidra.app.context.ListingContextAction):
    """
    ``CycleGroupAction`` cycles data through a series
    of data types defined by a ``CycleGroup``.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VariableDeleteAction(ghidra.app.context.ListingContextAction):
    """
    ``VariableDeleteAction`` allows the user to delete a function 
    variable.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DataService):
    """
    The FunctionPlugin allows creation of a function from the current selection.
    """

    class_: typing.ClassVar[java.lang.Class]
    FUNCTION_MENU_SUBGROUP: typing.Final = "Function"
    THUNK_FUNCTION_MENU_SUBGROUP: typing.Final = "FunctionThunk"
    FUNCTION_MENU_PULLRIGHT: typing.Final = "Function"
    VARIABLE_MENU_SUBGROUP: typing.Final = "FunctionVariable"
    VARIABLE_MENU_PULLRIGHT: typing.Final = "Function Variables"
    FUNCTION_SUBGROUP_BEGINNING: typing.Final = "A_Beginning"
    FUNCTION_SUBGROUP_MIDDLE: typing.Final = "M_Middle"
    SET_DATA_TYPE_PULLRIGHT: typing.Final = "Set Data Type"
    STACK_MENU_SUBGROUP: typing.Final = "Stack"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getDataTypeManagerService(self) -> ghidra.app.services.DataTypeManagerService:
        ...

    def getFunctions(self, context: ghidra.app.context.ListingActionContext) -> java.util.Iterator[ghidra.program.model.listing.Function]:
        """
        Get an iterator over all functions overlapping the current selection.
        If there is no selection any functions overlapping the current location.
        
        :param ghidra.app.context.ListingActionContext context: the context
        :return: Iterator over functions
        :rtype: java.util.Iterator[ghidra.program.model.listing.Function]
        """

    def getVariableCommentDialog(self) -> VariableCommentDialog:
        ...

    def isCreateFunctionAllowed(self, context: ghidra.app.context.ListingActionContext, allowExisting: typing.Union[jpype.JBoolean, bool], createThunk: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    @property
    def functions(self) -> java.util.Iterator[ghidra.program.model.listing.Function]:
        ...

    @property
    def dataTypeManagerService(self) -> ghidra.app.services.DataTypeManagerService:
        ...

    @property
    def variableCommentDialog(self) -> VariableCommentDialog:
        ...


@typing.type_check_only
class ClearFunctionAction(ghidra.app.context.ListingContextAction):
    """
    ``ClearFunctionAction`` allows the user to perform a clear of function data 
    at the entry point of the function.
     
    
    The actual work performed by this action depends upon the location of the cursor in the 
    code browser.  Further, multiple instances of this action are created to handel different 
    pieces of the function, like the signature, parameters, etc.
    """

    class_: typing.ClassVar[java.lang.Class]


class AddVarArgsAction(ghidra.app.context.ListingContextAction):
    """
    Action that changes a Function so that it has VarArgs (a variable argument list).
    """

    class_: typing.ClassVar[java.lang.Class]


class StackDepthChangeListener(java.util.EventListener):

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, e: StackDepthChangeEvent):
        """
        Invoked when an action occurs.
        """


@typing.type_check_only
class EditThunkFunctionAction(ghidra.app.context.ProgramContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        """
        Create a new action, to edit a thunk function at the current location
        
        :param FunctionPlugin plugin: does checking for this action
        """


@typing.type_check_only
class CommentDialog(docking.ReusableDialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DataAction(ghidra.app.context.ListingContextAction):
    """
    Base class for actions to create data types
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, plugin: FunctionPlugin):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, plugin: FunctionPlugin):
        ...


@typing.type_check_only
class DeleteFunctionAction(ghidra.app.context.ListingContextAction):
    """
    ``DeleteFunctionAction`` allows the user to Delete a function at
    the entry point of the function.
    """

    class_: typing.ClassVar[java.lang.Class]


class ChooseDataTypeAction(docking.action.DockingAction):
    """
    An action that allows the user to change or select a data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


@typing.type_check_only
class VariableCommentAction(ghidra.app.context.ListingContextAction):
    """
    ``CreateFunctionAction`` allows the user to create a function from
    a selection in the browser. The AddressSet indicates the function body and
    the minimum address is used as the entry point to the function.
    
    Action in FunctionPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def added(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Following the creation of instructions this analyzer searches for direct
        call references and creates functions at the called locations.
        """


class CreateThunkAnalyzer(FunctionAnalyzer):
    """
    This analyzer creates only functions that are thunks early in the analysis pipeline.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class AnalyzeStackRefsAction(ghidra.app.context.ListingContextAction):
    """
    ``AnalyzeStackRefsAction`` reanalyze functions stack references.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VariableCommentDialog(CommentDialog):
    """
    Dialog for setting the comments for a CodeUnit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


@typing.type_check_only
class CreateFunctionDefinitionAction(ghidra.app.context.ListingContextAction):
    """
    ``CreateFunctionDefinitionAction`` allows the user to create a 
    function definition data type from a function's signature.
    """

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: ghidra.app.context.ListingActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


class EditFunctionSignatureDialog(AbstractEditFunctionSignatureDialog):
    """
    ``EditFunctionSignatureDialog`` provides the ability to edit the
    function signature associated with a specific :obj:`Function`.  
    Use of this editor requires the presence of the tool-based datatype manager service.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], function: ghidra.program.model.listing.Function):
        """
        Edit function signature for a specified Function
        
        :param ghidra.framework.plugintool.PluginTool tool: A reference to the active tool.
        :param java.lang.String or str title: The title of the dialog.
        :param ghidra.program.model.listing.Function function: the function which is having its signature edited.
        """


@typing.type_check_only
class CreateFunctionAction(ghidra.app.context.ListingContextAction):
    """
    ``CreateFunctionAction`` allows the user to create a function from
    a selection in the browser. The AddressSet indicates the function body and
    the minimum address is used as the entry point to the function.
    
    Action in FunctionPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], plugin: FunctionPlugin, allowExisting: typing.Union[jpype.JBoolean, bool], createThunk: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new action, to create a function at the current location with a selection
        
        :param string: name of the action:param functionPlugin: does checking for this action:param jpype.JBoolean or bool allowExisting: allow an existing function at this location
        :param jpype.JBoolean or bool createThunk: if true thunk will be created
        """

    def actionPerformed(self, context: ghidra.app.context.ListingActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


class PointerDataAction(DataAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


class ExternalEntryFunctionAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def added(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Called when a function has been added.
        Looks at address for call reference
        """

    @staticmethod
    def isGoodFunctionStart(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if address is a good function start.
        Instruction exists at the location.
        No instruction falls through to this one.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address addr: address to check if is a good function start
        :return: true if would be a good function start, false otherwise
        :rtype: bool
        """


class EditFunctionPurgeAction(ghidra.app.context.ListingContextAction):
    """
    An action to set the stack purge of the function at the current 
    location.
    
    
    .. versionadded:: Tracker Id 548
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


class DeleteVarArgsAction(ghidra.app.context.ListingContextAction):
    """
    Action that changes a Function so that it has VarArgs (a variable argument list).
    """

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: ghidra.app.context.ListingActionContext):
        """
        Method called when the action is invoked.
        
        :param ev: details regarding the invocation of this action
        """


class EditFunctionAction(ghidra.app.context.ProgramContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: ghidra.app.context.ProgramActionContext):
        """
        Method called when the action is invoked.
        
        :param ev: details regarding the invocation of this action
        """


class CreateExternalFunctionAction(ghidra.app.context.ProgramContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], plugin: FunctionPlugin):
        ...


@typing.type_check_only
class RevertThunkFunctionAction(ghidra.app.context.ProgramContextAction):
    """
    ``RevertThunkFunctionAction`` allows the user to modify the function
    referenced by this function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        """
        Create a new action, to revert a thunk function at the current location
        to a normal function
        
        :param functionPlugin:
        """

    def actionPerformed(self, context: ghidra.app.context.ProgramActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


@typing.type_check_only
class CreateArrayAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


class StackVariableAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class EditStructureAction(ghidra.app.context.ListingContextAction):
    """
    ``EditStructureAction`` allows the user to edit a structure.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SetStackDepthChangeAction(ghidra.app.context.ListingContextAction):
    """
    ``SetStackDepthChangeAction`` allows the user to set a stack depth change value 
    at the current address.
    """

    @typing.type_check_only
    class StackChangeOptionDialog(docking.widgets.OptionDialog):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class AbstractEditFunctionSignatureDialog(docking.DialogComponentProvider):
    """
    ``EditFunctionSignatureDialog`` provides an abstract implementation 
    a function signature editor.  Use of this editor requires the presence of the tool-based
    datatype manager service.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], allowInLine: typing.Union[jpype.JBoolean, bool], allowNoReturn: typing.Union[jpype.JBoolean, bool], allowCallFixup: typing.Union[jpype.JBoolean, bool]):
        """
        Abstract function signature editor
        
        :param ghidra.framework.plugintool.PluginTool tool: A reference to the active tool.
        :param java.lang.String or str title: The title of the dialog.
        :param jpype.JBoolean or bool allowInLine: true if in-line attribute control should be included
        :param jpype.JBoolean or bool allowNoReturn: true if no-return attribute control should be added
        :param jpype.JBoolean or bool allowCallFixup: true if call-fixup choice should be added
        """


class ThunkReferenceAddressDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: reference memory address
        :rtype: ghidra.program.model.address.Address
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        :return: reference symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def showDialog(self, p: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address, referencedFunctionAddr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def showDialog(self, p: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address, symbol: ghidra.program.model.symbol.Symbol):
        ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class SharedReturnAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Identifies functions to which Jump references exist and converts the
    associated branching instruction flow to a CALL-RETURN
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], analyzerType: ghidra.app.services.AnalyzerType):
        ...


@typing.type_check_only
class EditNameAction(ghidra.app.context.ListingContextAction):
    """
    ``EditNameAction`` allows the user to rename a function.
    Action in FunctionPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]


class RecentlyUsedAction(DataAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


@typing.type_check_only
class VariableCommentDeleteAction(ghidra.app.context.ListingContextAction):
    """
    ``VariableCommentDeleteAction`` allows the user to delete a function variable comment.
    """

    class_: typing.ClassVar[java.lang.Class]


class SharedReturnJumpAnalyzer(SharedReturnAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def added(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Called when code has been added.
        Looks instructions for jumps to functions that are shared returns.
        
        :raises CancelledException:
        """


@typing.type_check_only
class EditOperandNameAction(ghidra.app.context.ListingContextAction):
    """
    ``EditNameAction`` allows the user to rename a function.
    Action in FunctionPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RemoveStackDepthChangeAction(ghidra.app.context.ListingContextAction):
    """
    ``RemoveStackDepthChangeAction`` allows the user to delete a stack depth change value 
    at the current address.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CreateMultipleFunctionsAction(ghidra.app.context.ListingContextAction):
    """
    ``CreateMultipleFunctionsAction`` allows the user to create functions from the 
    selection in the browser. This tries to create functions by working from the minimum address 
    to the maximum address in the selection. Any addresses in the selection that are already in 
    existing functions are discarded. Every time a function is created, all the other addresses 
    for that function are also discarded.
    
    Action in FunctionPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]


class VoidDataAction(DataAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: FunctionPlugin):
        ...


@typing.type_check_only
class StackDepthChangeEvent(java.awt.event.ActionEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: java.lang.Object, id: typing.Union[jpype.JInt, int], command: typing.Union[java.lang.String, str], stackDepthChange: typing.Union[jpype.JInt, int]):
        ...


class StackDepthFieldFactory(ghidra.app.util.viewer.field.FieldFactory):

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Stack Depth"
    COLOR: typing.Final[generic.theme.GColor]

    def __init__(self):
        ...



__all__ = ["X86FunctionPurgeAnalyzer", "CycleGroupAction", "VariableDeleteAction", "FunctionPlugin", "ClearFunctionAction", "AddVarArgsAction", "StackDepthChangeListener", "EditThunkFunctionAction", "CommentDialog", "DataAction", "DeleteFunctionAction", "ChooseDataTypeAction", "VariableCommentAction", "FunctionAnalyzer", "CreateThunkAnalyzer", "AnalyzeStackRefsAction", "VariableCommentDialog", "CreateFunctionDefinitionAction", "EditFunctionSignatureDialog", "CreateFunctionAction", "PointerDataAction", "ExternalEntryFunctionAnalyzer", "EditFunctionPurgeAction", "DeleteVarArgsAction", "EditFunctionAction", "CreateExternalFunctionAction", "RevertThunkFunctionAction", "CreateArrayAction", "StackVariableAnalyzer", "EditStructureAction", "SetStackDepthChangeAction", "AbstractEditFunctionSignatureDialog", "ThunkReferenceAddressDialog", "SharedReturnAnalyzer", "EditNameAction", "RecentlyUsedAction", "VariableCommentDeleteAction", "SharedReturnJumpAnalyzer", "EditOperandNameAction", "RemoveStackDepthChangeAction", "CreateMultipleFunctionsAction", "VoidDataAction", "StackDepthChangeEvent", "StackDepthFieldFactory"]
