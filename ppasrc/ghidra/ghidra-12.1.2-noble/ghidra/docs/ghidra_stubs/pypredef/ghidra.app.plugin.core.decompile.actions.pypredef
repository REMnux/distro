from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets
import docking.widgets.fieldpanel.support
import docking.widgets.search
import ghidra.app.actions
import ghidra.app.decompiler
import ghidra.app.decompiler.component
import ghidra.app.plugin.core.decompile
import ghidra.app.plugin.core.function
import ghidra.app.plugin.core.graph
import ghidra.app.services
import ghidra.app.util.datatype
import ghidra.framework.plugintool
import ghidra.graph
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.service.graph
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import utility.function


class PCodeCfgAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ConvertDecAction(ConvertConstantAction):
    """
    Convert a selected constant in the decompiler to a decimal representation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class DecompilerStructureVariableAction(CreateStructureVariableAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool, controller: ghidra.app.decompiler.component.DecompilerController) -> None:
        ...


@typing.type_check_only
class PCodeDfgDisplayListener(ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener):
    """
    GraphDisplayListener for a PCode data flow graph
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, display: ghidra.service.graph.GraphDisplay, high: ghidra.program.model.pcode.HighFunction, program: ghidra.program.model.listing.Program) -> None:
        ...


class PCodeCfgGraphType(ghidra.graph.ProgramGraphType):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DebugDecompilerAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, controller: ghidra.app.decompiler.component.DecompilerController) -> None:
        ...


class FindReferencesToDataTypeAction(ghidra.app.actions.AbstractFindReferencesDataTypeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool, controller: ghidra.app.decompiler.component.DecompilerController) -> None:
        ...


class EditFieldAction(AbstractDecompilerAction):
    """
    Performs a quick edit of a given field using the :obj:`EditDataFieldDialog`.   This action is
    similar to the same named action available in the Listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class PCodeCfgDisplayListener(ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener):
    """
    Listener for when an AST graph's nodes are selected.
    """

    class_: typing.ClassVar[java.lang.Class]


class RenameLocalAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to rename a local variable.
    If a matching variable in the database already exists, it is simply renamed. Otherwise
    a new variable is added to the database. In this case the new variable is assigned
    an "undefined" datatype, which leaves it un-typelocked, and the decompiler will take
    the name but lets the data-type continue to "float" and can speculatively merge the
    variable with others.
     
    If the selected variable is an input parameter, other input parameters within the decompiler
    model will need to be committed, if they do not already exist in the database, as any parameters
    committed to the database are forcing on the decompiler. Any new parameters committed this way
    inherit their name from the decompiler model, but the parameters will not be type-locked, allowing
    their data-type to "float".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ConvertOctAction(ConvertConstantAction):
    """
    Convert a selected constant in the decompiler to an octal representation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class RenameLabelAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RemoveEquateAction(AbstractDecompilerAction):
    """
    Remove a selected conversion or other equate set on a constant
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ListingStructureVariableAction(CreateStructureVariableAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool, controller: ghidra.app.decompiler.component.DecompilerController) -> None:
        ...


class ConvertDoubleAction(ConvertConstantAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class RemoveAllSecondaryHighlightsAction(AbstractDecompilerAction):
    """
    Removes all secondary highlights for the current function
    
    
    .. seealso::
    
        | :obj:`ClangHighlightController`
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Remove All Secondary Highlights"

    def __init__(self) -> None:
        ...


class RemoveLabelAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class EditPropertiesAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class RetypeFieldAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to change the data-type of
    a field within a structure data-type. The field must already exist, except in the case of a
    completely undefined structure. The data-type of the field is changed according to the user
    selection.  If the size of the selected data-type is bigger, this can trigger other fields in
    the structure to be removed and may change the size of the structure.  The modified data-type
    is permanently committed to the program's database.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ConvertHexAction(ConvertConstantAction):
    """
    Convert a selected constant in the decompiler to a hexadecimal representation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class RenameFunctionAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class DecompilerCursorPosition(docking.widgets.CursorPosition):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SelectAllAction(docking.action.DockingAction):
    """
    Action for adding all fields to the current format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.decompiler.component.DecompilerPanel) -> None:
        ...


class RenameStructBitFieldTask(RenameTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangBitFieldToken) -> None:
        ...


class RenameUnionFieldTask(RenameTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, composite: ghidra.program.model.data.Composite, ordinal: typing.Union[jpype.JInt, int]) -> None:
        ...


class PCodeDfgAction(AbstractDecompilerAction):
    """
    Action to create a PCode control data graph based on decompiler output
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RenameStructFieldTask(RenameTask):

    class_: typing.ClassVar[java.lang.Class]
    offset: jpype.JInt

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, structure: ghidra.program.model.data.Structure, offset: typing.Union[jpype.JInt, int]) -> None:
        ...


class RenameVariableTask(RenameTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, sym: ghidra.program.model.pcode.HighSymbol, st: ghidra.program.model.symbol.SourceType) -> None:
        ...


class SetEquateAction(ConvertConstantAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class EditDataTypeAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ForwardSliceToPCodeOpsAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ConvertConstantEquateTask(utility.function.Callback):
    """
    Create an equate in the table for the specific Address and hash value.
    The equate is not assumed to be attached to a particular instruction operand and
    uses the dynamic hash value to identify the particular constant (within p-code) to label.
    
    If altAddress is non-null and the other alt* fields are filled in, the task attempts
    to set the equation on the altAddress first to get the representation of the p-code
    constant at convertAddress to change.  After the decompilation finishes, the representation
    is checked, and if it did not change, the alt* equate is removed and an equate is created
    directly for the convertAddress;
    """

    @typing.type_check_only
    class ScalarMatch(java.lang.Object):
        """
        A helper class describing a (matching) scalar operand
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, addr: ghidra.program.model.address.Address, value: ghidra.program.model.scalar.Scalar, index: typing.Union[jpype.JInt, int]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: ghidra.app.plugin.core.decompile.DecompilerActionContext, name: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, scalar: ghidra.program.model.scalar.Scalar, hash: typing.Union[jpype.JLong, int], index: typing.Union[jpype.JInt, int]) -> None:
        """
        Construct a primary Equate task
        
        :param ghidra.app.plugin.core.decompile.DecompilerActionContext context: is the action context for the task
        :param java.lang.String or str name: is the primary Equate name
        :param ghidra.program.model.address.Address addr: is the primary address of the Equate
        :param ghidra.program.model.scalar.Scalar scalar: is the equate constant
        :param jpype.JLong or int hash: is the dynamic hash
        :param jpype.JInt or int index: is the operand index if the Equate is known to label an instruction operand
        """

    def call(self) -> None:
        """
        Callback executed after the alternative equate is placed and the DecompilerProvider has updated its window.
        We check to see if the equate reached the desired constant in the decompiler.
        If not, we remove the alternate equate and place a direct equate
        """

    def runTask(self) -> None:
        """
        Run the convert task.  If the task is given an alternate equate, this is placed, otherwise
        the primary equate is placed.  If an alternate is placed, a thread is scheduled to check if
        the alternate equate reached the constant Varnode.  If not the alternate equate reference is
        removed, and the task falls back and places the primary equate.
        """

    def setAlternate(self, name: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, index: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]) -> None:
        """
        Establish an alternate Equate to try before falling back on the primary Equate
        
        :param java.lang.String or str name: is the alternate name of the Equate
        :param ghidra.program.model.address.Address addr: is the alternate address
        :param jpype.JInt or int index: is the operand index
        :param jpype.JLong or int value: is the alternate constant value to equate
        """


class IsolateVariableAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RetypeReturnAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to change the return type of
    the function. The user selected data-type is permanently set as the return type. As the
    return type is part of the function prototype and is forcing on the decompiler,
    this action may trigger input parameters to be committed to the database as well. This situation
    currently triggers a confirmation dialog.  If new input parameters need to be committed, their
    name and data-type are taken from the decompiler model.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RenameGlobalAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to rename a global variable.
    The variable is associated with an address. There may already be a symbol in the database
    there, in which case the symbol is simply renamed. Otherwise a new symbol is added.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ConvertBinaryAction(ConvertConstantAction):
    """
    Convert a selected constant in the decompiler to a binary representation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class RemoveSecondaryHighlightAction(AbstractDecompilerAction):
    """
    Removes the selected token's secondary highlight
    
    
    .. seealso::
    
        | :obj:`ClangHighlightController`
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Remove Secondary Highlight"

    def __init__(self) -> None:
        ...


class FindAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class GoToPreviousBraceAction(AbstractDecompilerAction):
    """
    Go to the previous enclosing opening brace in the backward direction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class HighlightDefinedUseAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class SetSecondaryHighlightAction(AbstractSetSecondaryHighlightAction):
    """
    Sets the secondary highlight on the selected token
    
    
    .. seealso::
    
        | :obj:`ClangHighlightController`
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.ClassVar[java.lang.String]

    def __init__(self) -> None:
        ...


class CloneDecompilerAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class PCodeCombinedGraphTask(PCodeDfgGraphTask):
    """
    Task to create a combined PCode control flow and data flow graph based on decompiler output
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, graphService: ghidra.app.services.GraphDisplayBroker, hfunction: ghidra.program.model.pcode.HighFunction) -> None:
        ...


class ForwardSliceAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class DecompilerSearcher(docking.widgets.search.FindDialogSearcher):
    """
    A :obj:`FindDialogSearcher` for searching the text of the decompiler window.
    """

    @typing.type_check_only
    class SearchMatch(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldLineLocation(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def column(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def fieldNumber(self) -> int:
            ...

        def hashCode(self) -> int:
            ...

        def lineNumber(self) -> int:
            ...

        def row(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, decompilerPanel: ghidra.app.decompiler.component.DecompilerPanel) -> None:
        """
        Constructor
        
        :param ghidra.app.decompiler.component.DecompilerPanel decompilerPanel: decompiler panel
        """


class CreateStructureVariableAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool, controller: ghidra.app.decompiler.component.DecompilerController) -> None:
        ...


class PCodeDfgGraphTask(ghidra.util.task.Task):
    """
    Task for creating PCode data flow graphs from decompiler output
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, graphService: ghidra.app.services.GraphDisplayBroker, hfunction: ghidra.program.model.pcode.HighFunction) -> None:
        ...


class SliceHighlightColorProvider(ghidra.app.decompiler.component.ColorProvider):
    """
    A class to provider a color for highlight a variable using one of the 'slice' actions
    
    
    .. seealso::
    
        | :obj:`ForwardSliceAction`
    
        | :obj:`BackwardsSliceAction`
    """

    class_: typing.ClassVar[java.lang.Class]


class PreviousHighlightedTokenAction(AbstractDecompilerAction):
    """
    An action to navigate to the previous token highlighted by the user via the middle-mouse.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RenameBitFieldAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class PCodeDfgDisplayOptions(ghidra.service.graph.GraphDisplayOptions):
    """
    :obj:`GraphDisplayOptions` for :obj:`PCodeDfgGraphType`
    """

    class_: typing.ClassVar[java.lang.Class]
    SHAPE_ATTRIBUTE: typing.Final = "Shape"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        """
        constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: if non-null, will load values from tool options
        """


class DecompilerSearchLocation(docking.widgets.SearchLocation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation, startIndexInclusive: typing.Union[jpype.JInt, int], endIndexInclusive: typing.Union[jpype.JInt, int], text: typing.Union[java.lang.String, str], forwardDirection: typing.Union[jpype.JBoolean, bool], textLine: typing.Union[java.lang.String, str], lineNumber: typing.Union[jpype.JInt, int], context: docking.widgets.search.SearchLocationContext) -> None:
        ...

    def contains(self, other: docking.widgets.fieldpanel.support.FieldLocation) -> bool:
        ...

    def getFieldLocation(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    def getTextLine(self) -> str:
        ...

    @property
    def fieldLocation(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    @property
    def textLine(self) -> java.lang.String:
        ...


class PCodeCfgGraphTask(ghidra.util.task.Task):
    """
    Task to create a PCode control flow graph based on decompiler output
    """

    class PcodeGraphSubType(java.lang.Enum[PCodeCfgGraphTask.PcodeGraphSubType]):

        class_: typing.ClassVar[java.lang.Class]
        CONTROL_FLOW_GRAPH: typing.Final[PCodeCfgGraphTask.PcodeGraphSubType]
        DATA_FLOW_GRAPH: typing.Final[PCodeCfgGraphTask.PcodeGraphSubType]

        def getName(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PCodeCfgGraphTask.PcodeGraphSubType:
            ...

        @staticmethod
        def values() -> jpype.JArray[PCodeCfgGraphTask.PcodeGraphSubType]:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, graphService: ghidra.app.services.GraphDisplayBroker, newGraph: typing.Union[jpype.JBoolean, bool], codeLimitPerBlock: typing.Union[jpype.JInt, int], location: ghidra.program.model.address.Address, hfunction: ghidra.program.model.pcode.HighFunction, graphType: PCodeCfgGraphTask.PcodeGraphSubType) -> None:
        ...


class RenameTask(java.lang.Object):
    """
    Class for renaming symbols within the decompiler window
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, old: typing.Union[java.lang.String, str]) -> None:
        ...

    def commit(self) -> None:
        ...

    def getNewName(self) -> str:
        ...

    def getTransactionName(self) -> str:
        ...

    @staticmethod
    def isSymbolInFunction(function: ghidra.program.model.listing.Function, name: typing.Union[java.lang.String, str]) -> bool:
        ...

    def isValid(self, newNm: typing.Union[java.lang.String, str]) -> bool:
        ...

    def runTask(self, oldNameIsCancel: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Perform the task of selecting a new name and committing it to the database
        
        :param jpype.JBoolean or bool oldNameIsCancel: is true if the user entering/keeping the old name is considered a cancel
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def newName(self) -> java.lang.String:
        ...

    @property
    def transactionName(self) -> java.lang.String:
        ...


class ForceUnionAction(AbstractDecompilerAction):
    """
    An action to force the use of a particular field on the access of a union.
    The user selects particular field name token in the decompiler window and is presented
    with a list of other possible fields the access can be changed to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ExportToCAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RetypeStructFieldTask(RetypeFieldTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, composite: ghidra.program.model.data.Composite) -> None:
        ...


class CommitParamsAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class CommitLocalsAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class SelectedPCodeDfgGraphTask(PCodeDfgGraphTask):
    """
    Task for creating a PCode data flow graph from a selected address
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, graphService: ghidra.app.services.GraphDisplayBroker, hfunction: ghidra.program.model.pcode.HighFunction, address: ghidra.program.model.address.Address) -> None:
        ...


class ConvertCharAction(ConvertConstantAction):
    """
    Convert a selected constant in the decompiler window to a character representation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class CreatePointerRelative(RetypeLocalAction):

    class RelativePointerDialog(ghidra.app.util.datatype.DataTypeSelectionDialog):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, pluginTool: ghidra.framework.plugintool.PluginTool, prog: ghidra.program.model.listing.Program) -> None:
            ...

        def setInitialName(self, nm: typing.Union[java.lang.String, str]) -> None:
            ...

        def setInitialOffset(self, off: typing.Union[jpype.JInt, int]) -> None:
            ...


    @typing.type_check_only
    class TreeSearch(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        op: ghidra.program.model.pcode.PcodeOp
        slot: jpype.JInt
        offset: jpype.JInt
        iterForward: java.util.Iterator[ghidra.program.model.pcode.PcodeOp]
        dataType: ghidra.program.model.data.DataType

        @typing.overload
        def __init__(self, o: ghidra.program.model.pcode.PcodeOp, s: typing.Union[jpype.JInt, int], off: typing.Union[jpype.JInt, int]) -> None:
            ...

        @typing.overload
        def __init__(self, vn: ghidra.program.model.pcode.Varnode, off: typing.Union[jpype.JInt, int]) -> None:
            ...

        @staticmethod
        def getValidDataType(vn: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.data.DataType:
            ...

        def isDoneBackward(self, origType: ghidra.program.model.data.DataType) -> bool:
            ...

        def isDoneForward(self, origType: ghidra.program.model.data.DataType) -> bool:
            ...

        def nextVarnode(self) -> ghidra.program.model.pcode.Varnode:
            ...

        @staticmethod
        def searchBackward(vn: ghidra.program.model.pcode.Varnode, depth: typing.Union[jpype.JInt, int]) -> CreatePointerRelative.TreeSearch:
            ...

        @staticmethod
        def searchForward(vn: ghidra.program.model.pcode.Varnode, depth: typing.Union[jpype.JInt, int]) -> CreatePointerRelative.TreeSearch:
            ...

        def stripTypeDef(self) -> None:
            ...

        @property
        def doneBackward(self) -> jpype.JBoolean:
            ...

        @property
        def doneForward(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    @staticmethod
    def buildDefaultName(dt: ghidra.program.model.data.DataType, off: typing.Union[jpype.JInt, int]) -> str:
        """
        Build a default name for a relative pointer, given the base data-type and offset
        
        :param ghidra.program.model.data.DataType dt: is the given base data-type
        :param jpype.JInt or int off: is the given offset
        :return: the name
        :rtype: str
        """


class IsolateVariableTask(RenameTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, sym: ghidra.program.model.pcode.HighSymbol, st: ghidra.program.model.symbol.SourceType) -> None:
        ...


class BackwardsSliceAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Highlight Backward Slice"

    def __init__(self) -> None:
        ...


class DeletePrototypeOverrideAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class GoToNextBraceAction(AbstractDecompilerAction):
    """
    Go to the next enclosing closing brace in the forward direction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class BackwardsSliceToPCodeOpsAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class NextHighlightedTokenAction(AbstractDecompilerAction):
    """
    An action to navigate to the next token highlighted by the user via the middle-mouse.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class OverridePrototypeAction(AbstractDecompilerAction):

    @typing.type_check_only
    class ProtoOverrideDialog(ghidra.app.plugin.core.function.EditFunctionSignatureDialog):
        """
        ``ProtoOverrideDialog`` provides the ability to edit the
        function signature associated with a specific function definition override
        at a sub-function callsite.  
        Use of this editor requires the presence of the tool-based datatype manager service.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, func: ghidra.program.model.listing.Function, signature: typing.Union[java.lang.String, str], conv: typing.Union[java.lang.String, str]) -> None:
            """
            Construct signature override for called function
            
            :param ghidra.framework.plugintool.PluginTool tool: active tool
            :param ghidra.program.model.listing.Function func: function from which program access is achieved and supply of preferred 
            datatypes when parsing signature
            :param java.lang.String or str signature: initial prototype signature to be used
            :param java.lang.String or str conv: initial calling convention
            """

        def getFunctionDefinition(self) -> ghidra.program.model.data.FunctionDefinition:
            ...

        @property
        def functionDefinition(self) -> ghidra.program.model.data.FunctionDefinition:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class FindReferencesToAddressAction(ghidra.app.actions.AbstractFindReferencesToAddressAction):
    """
    An action to show all references to the given address
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]) -> None:
        ...


class SpecifyCPrototypeAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RenameFieldAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to rename a field within
    a structure data-type. If the field already exists within the specific structure, it is
    simply renamed. Otherwise, if the decompiler has discovered an undefined structure offset, a new
    field is added to the structure with this offset and the user selected name. In either case,
    the altered structure is committed permanently to the program's database.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RetypeFieldTask(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, composite: ghidra.program.model.data.Composite) -> None:
        ...

    def commit(self) -> None:
        """
        Assuming the transaction is started, do the work of changing the data-type.
        
        :raises java.lang.IllegalArgumentException: if there is a final error committing the data-type
        """

    def getTransactionName(self) -> str:
        """
        
        
        :return: the name to associate with the data-base transaction that actually changes the data-type
        :rtype: str
        """

    def isValidAfter(self) -> bool:
        """
        Given a new data-type chosen by the user, check if the retype can proceed.
        If there is a problem, the errorMsg is populated and false is returned.
        
        :return: true if the retype can proceed
        :rtype: bool
        """

    def isValidBefore(self) -> bool:
        """
        Check if the selected field is valid for retyping.
        If there is a problem, the errorMsg is populated and false is returned.
        
        :return: true if the field is valid
        :rtype: bool
        """

    def runTask(self) -> None:
        ...

    @property
    def transactionName(self) -> java.lang.String:
        ...

    @property
    def validBefore(self) -> jpype.JBoolean:
        ...

    @property
    def validAfter(self) -> jpype.JBoolean:
        ...


class AbstractDecompilerAction(docking.action.DockingAction):
    """
    A base class for :obj:`DecompilePlugin` actions that handles checking whether the
    decompiler is busy.   Each action is responsible for deciding its enablement via
    :meth:`isEnabledForDecompilerContext(DecompilerActionContext) <.isEnabledForDecompilerContext>`.  Each action must implement
    :meth:`decompilerActionPerformed(DecompilerActionContext) <.decompilerActionPerformed>` to complete its work.
     
     
    This parent class uses the :obj:`DecompilerActionContext` to check for the decompiler's
    busy status.  If the decompiler is busy, then the action will report that it is enabled.  We
    do this so that any keybindings registered for this action will get consumed and not passed up
    to the global context.   Then, if the action is executed, this class does not call the child
    class, but will instead show an information message indicating that the decompiler is busy.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getCompositeDataType(tok: ghidra.app.decompiler.ClangToken) -> ghidra.program.model.data.Composite:
        """
        Get the structure/union associated with a field token
        
        :param ghidra.app.decompiler.ClangToken tok: is the token representing a field
        :return: the structure/union which contains this field
        :rtype: ghidra.program.model.data.Composite
        """


class SetSecondaryHighlightColorChooserAction(AbstractSetSecondaryHighlightAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.ClassVar[java.lang.String]

    def __init__(self) -> None:
        ...


class FindReferencesToHighSymbolAction(AbstractDecompilerAction):
    """
    An action to show all references to the :obj:`HighSymbol` under the cursor in the Decompiler.
    A HighSymbol is a symbol recovered by the decompiler during decompilation and is generally 
    distinct from a :obj:`Symbol` stored in the Ghidra database (for more details see the
    "HighSymbol" entry in the "Decompiler Concepts" section of the Ghidra help).  For this action
    to be enabled, the HighSymbol must represent a function or global variable (not a local variable 
    or a parameter)
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find References to Symbol"

    def __init__(self) -> None:
        ...


class RetypeUnionFieldTask(RetypeFieldTask):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, provider: ghidra.app.plugin.core.decompile.DecompilerProvider, token: ghidra.app.decompiler.ClangToken, composite: ghidra.program.model.data.Composite) -> None:
        ...


class RetypeGlobalAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to change the data-type
    associated with a global variable. If the variable does not already exist in the program database,
    it will be created using storage address the decompiler has assigned to the variable within its model.
    In either case, there is a preexisting notion of variable storage. This action may allow the newly
    selected data-type to be of a different size relative to this preexisting storage, constrained by
    other global variables that might already consume storage.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class DecompilerSearchResults(docking.widgets.search.SearchResults):

    @typing.type_check_only
    class ActivateFunctionJob(docking.widgets.search.SearchResults.ActivationJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LinePosition(java.lang.Record, java.lang.Comparable[DecompilerSearchResults.LinePosition]):

        class_: typing.ClassVar[java.lang.Class]

        def col(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def line(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def decompilerUpdated(self) -> None:
        ...

    def getContainingLocation(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation, searchForward: typing.Union[jpype.JBoolean, bool]) -> DecompilerSearchLocation:
        ...

    def getLocationsByLine(self) -> java.util.Map[java.lang.Integer, java.util.List[DecompilerSearchLocation]]:
        ...

    @property
    def locationsByLine(self) -> java.util.Map[java.lang.Integer, java.util.List[DecompilerSearchLocation]]:
        ...


class RetypeLocalAction(AbstractDecompilerAction):
    """
    Action triggered from a specific token in the decompiler window to change the data-type
    associated with a variable in the local scope of the function. This can be an input parameter,
    a stack variable, a variable associated with a register, or a "dynamic" variable. If the
    variable does not already exist in the program database, it will be created using storage the
    decompiler has assigned to the variable within its model. In either case, there is a preexisting
    notion of variable storage. This action may allow the newly selected data-type to be of a
    different size relative to this preexisting storage, constrained by other variables that might
    already consume storage.
     
    If the selected variable is an input parameter, other input parameters within the decompiler
    model will need to be committed, if they do not already exist in the database, as any parameters
    committed to the database are forcing on the decompiler. Any new parameters committed this way
    inherit their name from the decompiler model, but the parameters will not be type-locked, allowing
    their data-type to "float".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ConvertFloatAction(ConvertConstantAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin) -> None:
        ...


class ConvertConstantAction(AbstractDecompilerAction):
    """
    Abstract pop-up menu convert action for the decompiler. If triggered, it lays down
    a new EquateReference that forces the selected constant to be displayed using
    the desired integer format.
    """

    class NearMatchValues(java.lang.Object):
        """
        Helper class for identifying integer values that are "near" a given value.
        "Near" can mean off by 1, negated, or inverted.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> None:
            ...

        @typing.overload
        def __init__(self, scalar: ghidra.program.model.scalar.Scalar) -> None:
            ...

        def isMatch(self, value: typing.Union[jpype.JLong, int]) -> bool:
            """
            
            
            :param jpype.JLong or int value: is the value to match
            :return: true if the value matches
            :rtype: bool
            """

        @property
        def match(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompile.DecompilePlugin, name: typing.Union[java.lang.String, str], convertType: typing.Union[jpype.JInt, int]) -> None:
        ...

    def getEquateName(self, scalar: ghidra.program.model.scalar.Scalar, program: ghidra.program.model.listing.Program) -> str:
        """
        Construct the name of the Equate, either absolutely for a conversion or
        by preventing the user with a dialog to select a name.
        
        :param ghidra.program.model.scalar.Scalar scalar: is the constant being converted
        :param ghidra.program.model.listing.Program program: is the current Program
        :return: the equate name
        :rtype: str
        """

    def getMenuDisplay(self, scalar: ghidra.program.model.scalar.Scalar, program: ghidra.program.model.listing.Program) -> str:
        """
        The menu option for this kind of action is intended to look like:
            Hexadecimal: 0x2408
        This method constructs the final part of this string, after the colon by
        formatting the actual value that is to be converted.
        
        :param ghidra.program.model.scalar.Scalar scalar: is the constant being converted
        :param ghidra.program.model.listing.Program program: the program
        :return: the formatted String
        :rtype: str
        """

    def getMenuPrefix(self) -> str:
        """
        The menu option for this kind of action is intended to look like:
            Hexadecimal: 0x2408
        This method establishes the first part of this string, up to the colon.
        
        :return: the menu prefix
        :rtype: str
        """

    @property
    def menuPrefix(self) -> java.lang.String:
        ...


class AbstractSetSecondaryHighlightAction(AbstractDecompilerAction):
    ...
    class_: typing.ClassVar[java.lang.Class]


class PCodeDfgGraphType(ghidra.service.graph.GraphType):
    """
    GraphType for a PCode data flow graph
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_VERTEX: typing.Final[java.lang.String]
    CONSTANT: typing.Final[java.lang.String]
    REGISTER: typing.Final[java.lang.String]
    UNIQUE: typing.Final[java.lang.String]
    PERSISTENT: typing.Final[java.lang.String]
    ADDRESS_TIED: typing.Final[java.lang.String]
    OP: typing.Final[java.lang.String]
    DEFAULT_EDGE: typing.Final[java.lang.String]
    WITHIN_BLOCK: typing.Final[java.lang.String]
    BETWEEN_BLOCKS: typing.Final[java.lang.String]

    def __init__(self) -> None:
        ...


class EditPrototypeOverrideAction(AbstractDecompilerAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...



__all__ = ["PCodeCfgAction", "ConvertDecAction", "DecompilerStructureVariableAction", "PCodeDfgDisplayListener", "PCodeCfgGraphType", "DebugDecompilerAction", "FindReferencesToDataTypeAction", "EditFieldAction", "PCodeCfgDisplayListener", "RenameLocalAction", "ConvertOctAction", "RenameLabelAction", "RemoveEquateAction", "ListingStructureVariableAction", "ConvertDoubleAction", "RemoveAllSecondaryHighlightsAction", "RemoveLabelAction", "EditPropertiesAction", "RetypeFieldAction", "ConvertHexAction", "RenameFunctionAction", "DecompilerCursorPosition", "SelectAllAction", "RenameStructBitFieldTask", "RenameUnionFieldTask", "PCodeDfgAction", "RenameStructFieldTask", "RenameVariableTask", "SetEquateAction", "EditDataTypeAction", "ForwardSliceToPCodeOpsAction", "ConvertConstantEquateTask", "IsolateVariableAction", "RetypeReturnAction", "RenameGlobalAction", "ConvertBinaryAction", "RemoveSecondaryHighlightAction", "FindAction", "GoToPreviousBraceAction", "HighlightDefinedUseAction", "SetSecondaryHighlightAction", "CloneDecompilerAction", "PCodeCombinedGraphTask", "ForwardSliceAction", "DecompilerSearcher", "CreateStructureVariableAction", "PCodeDfgGraphTask", "SliceHighlightColorProvider", "PreviousHighlightedTokenAction", "RenameBitFieldAction", "PCodeDfgDisplayOptions", "DecompilerSearchLocation", "PCodeCfgGraphTask", "RenameTask", "ForceUnionAction", "ExportToCAction", "RetypeStructFieldTask", "CommitParamsAction", "CommitLocalsAction", "SelectedPCodeDfgGraphTask", "ConvertCharAction", "CreatePointerRelative", "IsolateVariableTask", "BackwardsSliceAction", "DeletePrototypeOverrideAction", "GoToNextBraceAction", "BackwardsSliceToPCodeOpsAction", "NextHighlightedTokenAction", "OverridePrototypeAction", "FindReferencesToAddressAction", "SpecifyCPrototypeAction", "RenameFieldAction", "RetypeFieldTask", "AbstractDecompilerAction", "SetSecondaryHighlightColorChooserAction", "FindReferencesToHighSymbolAction", "RetypeUnionFieldTask", "RetypeGlobalAction", "DecompilerSearchResults", "RetypeLocalAction", "ConvertFloatAction", "ConvertConstantAction", "AbstractSetSecondaryHighlightAction", "PCodeDfgGraphType", "EditPrototypeOverrideAction"]
