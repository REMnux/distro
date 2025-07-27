from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.app.plugin.core.instructionsearch
import ghidra.app.plugin.core.instructionsearch.model
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table
import ghidra.util.task
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore


class EndianFlipWidget(ControlPanelWidget):
    """
    Flips the endianness of the user input, whether in binary or hex mode.
     
    Note that this class does not care whether the input is big or little endian; it just flips
    the bytes and leaves the interpretation up to the user.
    """

    @typing.type_check_only
    class EndianFlipper(java.awt.event.ActionListener):
        """
        Event handler for the flip button.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], parent: InsertBytesWidget):
        """
        Constructor.
        
        :param plugin: :param java.lang.String or str title: 
        :param InsertBytesWidget parent:
        """


class HintTextArea(javax.swing.JTextArea):
    """
    Simple text area that shows a text hint when the field is empty.
    
    Hint text will be shown in light grey, italicized, and in angle brackets.  Normal text will
    be plain black.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hint: typing.Union[java.lang.String, str]):
        """
        Constructs the class with the hint text to be shown.
        
        :param java.lang.String or str hint: the hint
        """

    def setError(self):
        """
        Invoked. when the text in the box does not pass validation.
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Need to override the setText method so we can set formatting attributes.
        
        :param java.lang.String or str text: the text
        """

    def setValid(self):
        """
        Invoked when the text in the box passes validation.
        """


class SelectionModeWidget(ControlPanelWidget):
    """
    Allows the user to specify whether the input mode is BINARY or HEX for the :obj:`InsertBytesWidget`.
    """

    class InputMode(java.lang.Enum[SelectionModeWidget.InputMode]):

        class_: typing.ClassVar[java.lang.Class]
        BINARY: typing.Final[SelectionModeWidget.InputMode]
        HEX: typing.Final[SelectionModeWidget.InputMode]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SelectionModeWidget.InputMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[SelectionModeWidget.InputMode]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    hexRB: javax.swing.JRadioButton
    binaryRB: javax.swing.JRadioButton

    def __init__(self, title: typing.Union[java.lang.String, str], parent: InsertBytesWidget):
        """
        Constructor.
        
        :param plugin: :param java.lang.String or str title: 
        :param InsertBytesWidget parent:
        """

    def getInputMode(self) -> SelectionModeWidget.InputMode:
        """
        
        
        :return: 
        :rtype: SelectionModeWidget.InputMode
        """

    def setInputMode(self, mode: SelectionModeWidget.InputMode):
        """
        
        
        :param SelectionModeWidget.InputMode mode:
        """

    @property
    def inputMode(self) -> SelectionModeWidget.InputMode:
        ...

    @inputMode.setter
    def inputMode(self, value: SelectionModeWidget.InputMode):
        ...


class SearchDirectionWidget(ControlPanelWidget):
    """
    Allows the user to define a custom search range for the :obj:`InstructionSearchDialog`.
    """

    class Direction(java.lang.Enum[SearchDirectionWidget.Direction]):

        class_: typing.ClassVar[java.lang.Class]
        FORWARD: typing.Final[SearchDirectionWidget.Direction]
        BACKWARD: typing.Final[SearchDirectionWidget.Direction]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SearchDirectionWidget.Direction:
            ...

        @staticmethod
        def values() -> jpype.JArray[SearchDirectionWidget.Direction]:
            ...


    @typing.type_check_only
    class ForwardSearchAction(javax.swing.AbstractAction):
        """
        Invoked when the user clicks the radio button indicating that subsequent searches should
        progress in the FORWARD direction.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BackwardSearchAction(javax.swing.AbstractAction):
        """
        Invoked when the user clicks the radio button indicating that subsequent searches should
        progress in the BACKWARD direction.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], dialog: InstructionSearchDialog):
        """
        
        
        :param plugin: :param java.lang.String or str title: 
        :param InstructionSearchDialog dialog:
        """

    def getSearchDirection(self) -> SearchDirectionWidget.Direction:
        ...

    @property
    def searchDirection(self) -> SearchDirectionWidget.Direction:
        ...


class InsertBytesWidget(docking.ReusableDialogComponentProvider, java.awt.event.KeyListener):
    """
    Widget that allows the user to input bytes in binary or hex format. The bytes
    will then be disassembled and displayed in the :obj:`InstructionTable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, dialog: InstructionSearchDialog):
        """
        Constructor.
        
        :param ghidra.program.model.listing.Program program: the current program
        :param InstructionSearchDialog dialog: the parent search dialog
        """

    def disassemble(self):
        ...

    def getInputString(self) -> str:
        ...

    def getSelectionModeWidget(self) -> SelectionModeWidget:
        ...

    def keyReleased(self, e: java.awt.event.KeyEvent):
        """
        Need to capture keystrokes so we can validate input on the fly. Every
        time a character is typed we check the entire input for correctness.
        
        Note that this MUST be done in the release handler; in the type or press
        handler the input widget has not officially been updated with the new
        character.
        
        :param java.awt.event.KeyEvent e: the event
        """

    def loadBytes(self, bytes: typing.Union[java.lang.String, str]):
        """
        Load a set of bytes (in string form; hex or binary) into the search
        dialog. The bytes are disassembled and displayed in the
        :obj:`InstructionTable`.
        
        :param java.lang.String or str bytes: the bytes to load
        """

    def setInputInvalid(self):
        """
        Flags the given string as invalid input
        """

    def setInputString(self, input: typing.Union[java.lang.String, str]):
        ...

    def showError(self):
        """
        Displays a pop-up containing any error message text set by the validator.
        """

    @typing.overload
    def validateInput(self) -> bool:
        """
        Verifies that the input entered by the user is valid. Meaning:
         
        * The string represents a hex or binary number.
        * The string contains only full bytes.
        
        
        :return: true if input is valid
        :rtype: bool
        """

    @typing.overload
    def validateInput(self, input: typing.Union[java.lang.String, str]) -> bool:
        """
        Verifies that the given string is valid binary or hex input.
        
        :param java.lang.String or str input: the string to validate
        :return: true if valid
        :rtype: bool
        """

    @property
    def selectionModeWidget(self) -> SelectionModeWidget:
        ...

    @property
    def inputString(self) -> java.lang.String:
        ...

    @inputString.setter
    def inputString(self, value: java.lang.String):
        ...


class AbstractInstructionTable(ghidra.util.table.GhidraTable):
    """
    Defines basic attributes of tables in the :obj:`InstructionSearchDialog`.
    """

    class OperandState(java.lang.Enum[AbstractInstructionTable.OperandState]):
        """
        Defines the states that a cell can take on. ACTIVE means it is in the
        'up' state (not masked). INACTIVE means has been depressed (will be
        masked). PREVIEW means that this is a cell in the preview table. NA means
        it is not a valid field (ie: a blank cell because the instruction has no
        operand for the particular column).
        """

        class_: typing.ClassVar[java.lang.Class]
        MASKED: typing.Final[AbstractInstructionTable.OperandState]
        NOT_MASKED: typing.Final[AbstractInstructionTable.OperandState]
        NA: typing.Final[AbstractInstructionTable.OperandState]
        PREVIEW: typing.Final[AbstractInstructionTable.OperandState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AbstractInstructionTable.OperandState:
            ...

        @staticmethod
        def values() -> jpype.JArray[AbstractInstructionTable.OperandState]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], dialog: InstructionSearchDialog):
        ...

    def getCellData(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject:
        """
        Returns the data object at the given cell location. We need to check
        first to make sure the row/col values map to a valid cell.
        
        :param jpype.JInt or int row: the row
        :param jpype.JInt or int col: the column
        :return: the value
        :rtype: ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject
        """

    def getDefaultRenderer(self, columnClass: java.lang.Class[typing.Any]) -> javax.swing.table.TableCellRenderer:
        """
        Must override so it doesn't return an instance of the base
        :obj:`TableCellRenderer`, which will override our changes in the
        :obj:`InstructionTableCellRenderer`.
        """

    def getToolbar(self) -> javax.swing.JToolBar:
        ...

    @property
    def toolbar(self) -> javax.swing.JToolBar:
        ...

    @property
    def defaultRenderer(self) -> javax.swing.table.TableCellRenderer:
        ...


class ControlPanelWidget(javax.swing.JPanel):
    """
    Abstract class to be used as the base for any widgets that need to be shown in the
    :obj:`ControlPanel`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str]):
        ...


class PreviewTablePanel(javax.swing.JPanel):
    """
    Container for the :obj:`PreviewTable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, dialog: InstructionSearchDialog):
        ...

    def buildPreview(self):
        ...

    def getScrollPane(self) -> javax.swing.JScrollPane:
        ...

    def getTable(self) -> PreviewTable:
        ...

    @property
    def scrollPane(self) -> javax.swing.JScrollPane:
        ...

    @property
    def table(self) -> PreviewTable:
        ...


class InstructionSearchMainPanel(javax.swing.JPanel):
    """
    Container for the :obj:`InstructionTable` and :obj:`PreviewTable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, dialog: InstructionSearchDialog):
        """
        Constructor.
        
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the instruction search plugin
        :param InstructionSearchDialog dialog: the parent dialog
        :raises InvalidInputException: if the search data is invalid
        """

    def buildPreview(self):
        """
        Displays the current search strings based on all user settings. What is
        displayed in the :obj:`PreviewTablePanel` is what will be used for any
        subsequent searches.
        
        :raises InvalidInputException:
        """

    def getInstructionTable(self) -> InstructionTable:
        ...

    def getInstructionTablePanel(self) -> InstructionTablePanel:
        ...

    def getPreviewTable(self) -> PreviewTable:
        ...

    def getPreviewTablePanel(self) -> PreviewTablePanel:
        ...

    @property
    def previewTablePanel(self) -> PreviewTablePanel:
        ...

    @property
    def instructionTablePanel(self) -> InstructionTablePanel:
        ...

    @property
    def previewTable(self) -> PreviewTable:
        ...

    @property
    def instructionTable(self) -> InstructionTable:
        ...


class ControlPanel(javax.swing.JPanel):
    """
    Container for widgets that control how the :obj:`InstructionSearchDialog` performs 
    its searches.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, dialog: InstructionSearchDialog):
        ...

    def getDirectionWidget(self) -> SearchDirectionWidget:
        ...

    def getRangeWidget(self) -> SelectionScopeWidget:
        ...

    @property
    def directionWidget(self) -> SearchDirectionWidget:
        ...

    @property
    def rangeWidget(self) -> SelectionScopeWidget:
        ...


class InstructionSearchDialog(docking.ReusableDialogComponentProvider, java.util.Observer):
    """
    The GUI component for the :obj:`InstructionSearchPlugin`.  This consists of two main panels
    for displaying instruction data, an area for control widgets, and a button panel:
    
    ------------------------------------
    |                |                 |
    |  Instruction   |    Preview      |
    |     Panel      |     Panel       |
    |                |                 |
    |-----------------------------------
    |         Control Widgets          |
    ------------------------------------
    |          Button Panel            |
    ------------------------------------
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, title: typing.Union[java.lang.String, str], taskMonitor: ghidra.util.task.TaskMonitor):
        """
        Constructor
        
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the instruction search plugin
        :param java.lang.String or str title: the title of the dialog
        :param ghidra.util.task.TaskMonitor taskMonitor: the task monitor
        """

    def addToInstructions(self, selection: ghidra.program.util.ProgramSelection, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin):
        """
        Adds the instructions in the given selection and displays them in the gui.
        
        :param ghidra.program.util.ProgramSelection selection: the current selection
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the parent plugin
        """

    def clear(self):
        """
        Clears out all instructions in the dialog.
        """

    def clearMessage(self):
        """
        Clears any text in the message panel.
        """

    def displayMessage(self, message: typing.Union[java.lang.String, str], status: java.awt.Color):
        """
        Displays a message with the given text and color (severity).
        
        :param java.lang.String or str message: the message to display
        :param java.awt.Color status: the severity of the message
        """

    def displaySearchResults(self, searchResults: java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata]):
        """
        Pops up a dialog containing the given search results.
        
        :param java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata] searchResults:
        """

    def getControlPanel(self) -> ControlPanel:
        ...

    def getMessagePanel(self) -> MessagePanel:
        ...

    def getPlugin(self) -> ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin:
        ...

    def getPreviewTablePanel(self) -> PreviewTablePanel:
        ...

    def getSearchData(self) -> ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData:
        ...

    def getTablePanel(self) -> InstructionTablePanel:
        ...

    @typing.overload
    def loadBytes(self, bytes: typing.Union[java.lang.String, str]):
        """
        Loads the given bytes into the manual entry field and populates the instruction table.
        
        :param java.lang.String or str bytes: binary or hex string
        """

    @typing.overload
    def loadBytes(self, addrSet: ghidra.program.model.address.AddressSet):
        """
        Loads the bytes found at the given address set, in whatever program is currently loaded.
        
        :param ghidra.program.model.address.AddressSet addrSet: the address of the bytes to load
        """

    @typing.overload
    def loadInstructions(self, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin):
        """
        Loads the currently-selected set of instructions in the listing and displays them in
        the given dialog.
        
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the parent plugin
        :raises InvalidInputException: if there's a problem loading instructions
        """

    @typing.overload
    def loadInstructions(self, selection: ghidra.program.util.ProgramSelection, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin):
        """
        Loads the instructions in the given selection and displays them in the gui.
        
        :param ghidra.program.util.ProgramSelection selection: the current selection
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the parent plugin
        """

    def populateSearchData(self, currentProgram: ghidra.program.model.listing.Program, selection: ghidra.program.util.ProgramSelection):
        """
        Loads instructions at the given program/selection and populates the search
        data object.
        
        :param ghidra.program.model.listing.Program currentProgram: the current program
        :param ghidra.program.util.ProgramSelection selection: the current selection
        """

    def showDialog(self, provider: docking.ComponentProvider):
        """
        Displays this dialog.
        
        :param docking.ComponentProvider provider: the component provider
        """

    def update(self, o: java.util.Observable, arg: java.lang.Object):
        """
        Invoked whenever the data model changes; when this happens we need to rebuild the
        UI to reflect the new instruction set, or simply update the preview panel in the case
        where the user has simply changed the model by toggling masks.
        """

    @property
    def previewTablePanel(self) -> PreviewTablePanel:
        ...

    @property
    def controlPanel(self) -> ControlPanel:
        ...

    @property
    def messagePanel(self) -> MessagePanel:
        ...

    @property
    def plugin(self) -> ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin:
        ...

    @property
    def searchData(self) -> ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData:
        ...

    @property
    def tablePanel(self) -> InstructionTablePanel:
        ...


class MessagePanel(javax.swing.JPanel):
    """
    Simple panel containing a JLabel for displaying error messages.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor.
        """

    def clear(self):
        """
        Removes message text from the display.
        """

    def getMessageText(self) -> str:
        ...

    def setMessageText(self, text: typing.Union[java.lang.String, str], foregroundColor: java.awt.Color):
        """
        Sets the text to be displayed.
        
        :param java.lang.String or str text: the new non-html text
        :param java.awt.Color foregroundColor: the text color
        """

    @property
    def messageText(self) -> java.lang.String:
        ...


@typing.type_check_only
class SearchInstructionsTask(ghidra.util.task.Task):
    """
    Task to perform a search from the :obj:`InstructionSearchDialog`, returning the NEXT or 
    PREVIOUS result found, depending on the search direction.
     
    
    This class searches for a single result within the appropriate search ranges (or the entire
    program if that option is selected). It's optimized to ignore ranges that are "out of scope"; 
    ie: if searching in the forward direction from a certain address, any ranges prior to that
    address will be ignored.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNextAddress(self, direction: SearchDirectionWidget.Direction, searchResults: java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata]) -> ghidra.program.model.address.Address:
        """
        Moves the cursor in the listing to the next search result past, or before (depending on 
        the given direction) the current address.
        
        :param SearchDirectionWidget.Direction direction: the direction to search (forward/backward)
        :param java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata] searchResults: the list of instructions to search
        :return: the address of the next result found
        :rtype: ghidra.program.model.address.Address
        """


@typing.type_check_only
class SearchAllInstructionsTask(ghidra.util.task.Task):
    """
    Task to perform a search for instruction patterns over a set of instruction ranges. This task
    searches for ALL results and displays them in a separate table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def doSearch(self, taskMonitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata]:
        """
        Execute a memory search using the current settings in the dialog, returning the results.
        
        :param ghidra.util.task.TaskMonitor taskMonitor: the task monitor
        :return: list of instruction matches
        :rtype: java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata]
        """


class SelectionScopeWidget(ControlPanelWidget):
    """
    Allows the user to define a custom search range for the :obj:`InstructionSearchDialog`.
    """

    @typing.type_check_only
    class SearchSelectionAction(javax.swing.AbstractAction):
        """
        Invoked when the user clicks the radio button that allows them to select a 
        custom search range.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchAllAction(javax.swing.AbstractAction):
        """
        Invoked when the user selects the button to set the search range to cover the
        entire program.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, title: typing.Union[java.lang.String, str], dialog: InstructionSearchDialog):
        """
        
        
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: 
        :param java.lang.String or str title: 
        :param InstructionSearchDialog dialog:
        """

    def getSearchRange(self) -> java.util.List[ghidra.program.model.address.AddressRange]:
        """
        Returns the current search range.
        """

    def updateSearchRangeAll(self):
        """
        Updates the current search range to encompass the entire program.
        """

    def updateSearchRangeBySelection(self):
        """
        Retrieves the currently-selected region in the listing and makes that the new search
        range.
        """

    @property
    def searchRange(self) -> java.util.List[ghidra.program.model.address.AddressRange]:
        ...


class PreviewTable(AbstractInstructionTable):
    """
    Displays the preview string for all instructions in the
    :obj:`InstructionTable`. This table is updated whenever a change is made to
    the mask settings in the instruction table.
    """

    class ViewType(java.lang.Enum[PreviewTable.ViewType]):

        class_: typing.ClassVar[java.lang.Class]
        BINARY: typing.Final[PreviewTable.ViewType]
        HEX: typing.Final[PreviewTable.ViewType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PreviewTable.ViewType:
            ...

        @staticmethod
        def values() -> jpype.JArray[PreviewTable.ViewType]:
            ...


    @typing.type_check_only
    class BinaryAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class HexAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class CopyAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    HEADER_COL_PREVIEW: typing.Final = "Search String Preview"

    def __init__(self, numColumns: typing.Union[jpype.JInt, int], plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, dialog: InstructionSearchDialog):
        """
        Constructor
        
        :param jpype.JInt or int numColumns: the number of columns in the table
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the parent plugin
        :param InstructionSearchDialog dialog: the search dialog
        """

    def addPreviewString(self, previewText: typing.Union[java.lang.String, str], index: typing.Union[java.lang.Integer, int]):
        """
        Adds a string to the preview table.
        
        :param java.lang.String or str previewText: the string to add
        :param java.lang.Integer or int index: the row in the preview table to update
        """

    def buildPreviewStrings(self):
        """
        Constructs the preview strings to display in the table, based on the
        current mask settings.
         
        
        This is a potentially long-running task so it's implemented in a
        background task. Also, note that we need to specify the dialog parent so
        we can't use the convenience TaskLauncher.launch... methods.
        """

    def getScrollableTracksViewportWidth(self) -> bool:
        """
        Must override this in order for horizontal scrolling to work. Scrolling
        isn't automatically given when embedding a jtable in a scrollpanel; the
        preferred width of the table must be explicitly set to the width of the
        contents of the widest cell.
         
        Note: We could override getPreferredSize() instead but we don't want to
        change the default behavior for setting the preferred height, only the
        width. So it's better to do it here.
        """

    def setPreviewText(self, row: typing.Union[jpype.JInt, int], val: typing.Union[java.lang.String, str]):
        """
        Replaces the contents of the preview table at the given row with the
        given string.
        
        :param jpype.JInt or int row: the row to replace
        :param java.lang.String or str val: the new text
        """

    @property
    def scrollableTracksViewportWidth(self) -> jpype.JBoolean:
        ...


class InstructionTableCellRenderer(ghidra.util.table.GhidraTableCellRenderer):
    """
    Table cell renderer that allows us to keep the default behavior of the GTable renderer,
    while adding some custom logic for changing background/foreground attributes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getTableCellRendererComponent(self, data: docking.widgets.table.GTableCellRenderingData) -> java.awt.Component:
        """
        Standard method that must be overridden when creating custom renderers.  The primary
        changes here are to change the attributes of the cell based on the contents of the
        underlying :obj:`InstructionTableDataObject`.
        """

    @property
    def tableCellRendererComponent(self) -> java.awt.Component:
        ...


class InstructionTable(AbstractInstructionTable):
    """
    Table that displays all selected instructions. The table is interactive,
    allowing toggling of mnemonics and operands between masked and unmasked
    states.
    """

    @typing.type_check_only
    class ClearMasksAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ReloadAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class AddAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ManualEntryAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class MaskUndefinedAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class MaskScalarsAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class MaskAddressesAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class MaskOperandsAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class NavAction(javax.swing.AbstractAction):
        """
        Defines an action for navigating to the address locations defined by the
        instructions in the table. This is to help users who lose their place in
        the listing and need to get back to where the original selection was.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, desc: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, dialog: InstructionSearchDialog):
        """
        Constructor
        
        :param jpype.JInt or int columns: the number of columns in the table
        :param ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin plugin: the parent plugin
        :param InstructionSearchDialog dialog: the parent dialog
        :raises InvalidInputException: if the given plugin is not valid
        """

    def getInsertBytesWidget(self) -> InsertBytesWidget:
        ...

    @property
    def insertBytesWidget(self) -> InsertBytesWidget:
        ...


class InstructionTablePanel(javax.swing.JPanel):
    """
    Container for the :obj:`InstructionTable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numColumns: typing.Union[jpype.JInt, int], plugin: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin, dialog: InstructionSearchDialog):
        ...

    def getScrollPane(self) -> javax.swing.JScrollPane:
        ...

    def getTable(self) -> InstructionTable:
        ...

    def getWorkPanel(self) -> javax.swing.JPanel:
        ...

    @property
    def scrollPane(self) -> javax.swing.JScrollPane:
        ...

    @property
    def workPanel(self) -> javax.swing.JPanel:
        ...

    @property
    def table(self) -> InstructionTable:
        ...



__all__ = ["EndianFlipWidget", "HintTextArea", "SelectionModeWidget", "SearchDirectionWidget", "InsertBytesWidget", "AbstractInstructionTable", "ControlPanelWidget", "PreviewTablePanel", "InstructionSearchMainPanel", "ControlPanel", "InstructionSearchDialog", "MessagePanel", "SearchInstructionsTask", "SearchAllInstructionsTask", "SelectionScopeWidget", "PreviewTable", "InstructionTableCellRenderer", "InstructionTable", "InstructionTablePanel"]
