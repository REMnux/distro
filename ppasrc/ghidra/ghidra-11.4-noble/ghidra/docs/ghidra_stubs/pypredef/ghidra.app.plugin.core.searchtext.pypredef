from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table.threaded
import ghidra.app.nav
import ghidra.app.plugin
import ghidra.app.util
import ghidra.app.util.query
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore


class AbstractSearchTableModel(ghidra.app.util.query.ProgramLocationPreviewTableModel):
    """
    Table model for showing the results of a "Search All"
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, options: SearchOptions):
        ...


class Searcher(java.lang.Object):
    """
    Search the program text
    """

    class TextSearchResult(java.lang.Record):
        """
        A record object that represents a single search result
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, programLocation: ghidra.program.util.ProgramLocation, offset: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def offset(self) -> int:
            ...

        def programLocation(self) -> ghidra.program.util.ProgramLocation:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getSearchOptions(self) -> SearchOptions:
        """
        Return the search options associated with this Searcher.
        
        :return: the search option
        :rtype: SearchOptions
        """

    def search(self) -> Searcher.TextSearchResult:
        """
        Get the next program location.
        
        :return: null if there is no next program location.
        :rtype: Searcher.TextSearchResult
        """

    def setMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Set the task monitor.
        
        :param ghidra.util.task.TaskMonitor monitor: monitor that allows the search to be canceled
        """

    @property
    def searchOptions(self) -> SearchOptions:
        ...


@typing.type_check_only
class ListingDisplaySearcher(Searcher):
    """
    This class attempts to search for text as it is rendered on the screen.  This is in
    contrast to the Program Database Searcher which searches the database.  This is
    needed because some information on the screen is rendered "on the fly" and not
    stored in the database.  This searcher is much slower, but delivers
    results that are in-line with what the user sees.
     
    
    The search is performed in two steps.  First it uses Instruction and Data iterators to
    find possible addresses where information would be rendered.  Then for each of those
    addresses, it uses the code browsers rendering engine to produce a textual representation
    for that address.  The textual representation also maintains information about the field
    that generated it so that the search can be constrained to specific fields such as the
    label or comment field.
     
     
    NOTE: This only searches defined instructions or data, which is possibly
    a mistake since this is more of a WYSIWYG search. However, searching undefined code units could
    make this slow search even more so.
    """

    @typing.type_check_only
    class MnemonicText(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ListingDisplaySearchTableModel(AbstractSearchTableModel):
    """
    Table model for showing results of "Search All" in an Listing Display Program Text search.
    """

    class_: typing.ClassVar[java.lang.Class]


class SearchTextPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.options.OptionsChangeListener, ghidra.util.task.TaskListener, ghidra.app.nav.NavigatableRemovalListener, docking.DockingContextListener):
    """
    Plugin to search text as it is displayed in the fields of the Code Browser.
    """

    @typing.type_check_only
    class TableLoadingListener(docking.widgets.table.threaded.ThreadedTableModelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchTextHighlightProvider(ghidra.app.util.ListingHighlightProvider, docking.ComponentProviderActivationListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        """
        The constructor for the SearchTextPlugin.
        
        :param ghidra.framework.plugintool.PluginTool plugintool: The tool required by this plugin.
        """

    def getNavigatable(self) -> ghidra.app.nav.Navigatable:
        ...

    @property
    def navigatable(self) -> ghidra.app.nav.Navigatable:
        ...


@typing.type_check_only
class SearchTextDialog(docking.ReusableDialogComponentProvider):
    """
    Dialog for showing options to search text in a Program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSearchOptions(self) -> SearchOptions:
        ...

    def repeatSearch(self):
        ...

    def setCurrentField(self, textField: ghidra.program.util.ProgramLocation, isInstruction: typing.Union[jpype.JBoolean, bool]):
        ...

    def setValueFieldText(self, selectedText: typing.Union[java.lang.String, str]):
        ...

    def show(self, componentProvider: docking.ComponentProvider):
        ...

    @property
    def searchOptions(self) -> SearchOptions:
        ...


@typing.type_check_only
class SearchTask(ghidra.util.task.Task):
    """
    Task to do a single search.
    """

    class_: typing.ClassVar[java.lang.Class]

    def cancel(self):
        """
        Called when program is deactivated but the task hasn't started to
        run yet. Cancel it when it does run.
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


@typing.type_check_only
class ListingDisplaySearchAddressIterator(java.lang.Object):
    """
    An iterator for returning addresses that can take in 1 or more search iterators to iterator over
    addresses provided by each of those search iterators.
    """

    class_: typing.ClassVar[java.lang.Class]


class SearchOptions(java.lang.Cloneable):
    """
    Simple class to hold options for searching the text in Program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, text: typing.Union[java.lang.String, str], quickSearch: typing.Union[jpype.JBoolean, bool], functions: typing.Union[jpype.JBoolean, bool], comments: typing.Union[jpype.JBoolean, bool], labels: typing.Union[jpype.JBoolean, bool], instructionMnemonics: typing.Union[jpype.JBoolean, bool], instructionOperands: typing.Union[jpype.JBoolean, bool], dataMnemonics: typing.Union[jpype.JBoolean, bool], dataOperands: typing.Union[jpype.JBoolean, bool], caseSensitive: typing.Union[jpype.JBoolean, bool], direction: typing.Union[jpype.JBoolean, bool], includeNonLoadedBlocks: typing.Union[jpype.JBoolean, bool], searchAll: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param java.lang.String or str text: string to match
        :param jpype.JBoolean or bool functions: true to search for function text
        :param jpype.JBoolean or bool comments: true to search comments
        :param jpype.JBoolean or bool labels: true to search labels
        :param instructionsMnemonic: true to search instruction mnemonics:param instructionsOperand: true to search instruction operands:param dataMnemonic: true to search data mnemonics:param dataValue: true to search data values:param jpype.JBoolean or bool caseSensitive: true if search is to be case sensitive
        :param jpype.JBoolean or bool direction: true means forward, false means backward search
        """

    def getText(self) -> str:
        """
        Get the text that is the pattern to search for.
        """

    def isCaseSensitive(self) -> bool:
        """
        Return true is search should be case sensitive.
        """

    def isForward(self) -> bool:
        """
        Return true if search is being done in the forward direction.
        """

    def searchBothDataMnemonicsAndOperands(self) -> bool:
        """
        Return true if data mnemonics should be searched.
        """

    def searchBothInstructionMnemonicAndOperands(self) -> bool:
        """
        Return true if instruction mnemonics should be searched.
        """

    def searchComments(self) -> bool:
        """
        Return true if comments should be searched.
        """

    def searchDataMnemonics(self) -> bool:
        ...

    def searchDataOperands(self) -> bool:
        ...

    def searchFunctions(self) -> bool:
        """
        Return true if functions should be searched/
        """

    def searchInstructionMnemonics(self) -> bool:
        ...

    def searchInstructionOperands(self) -> bool:
        ...

    def searchLabels(self) -> bool:
        """
        Return true if labels should be searched.
        """

    def searchOnlyDataMnemonics(self) -> bool:
        ...

    def searchOnlyDataOperands(self) -> bool:
        ...

    def searchOnlyInstructionMnemonics(self) -> bool:
        ...

    def searchOnlyInstructionOperands(self) -> bool:
        ...

    @property
    def forward(self) -> jpype.JBoolean:
        ...

    @property
    def caseSensitive(self) -> jpype.JBoolean:
        ...

    @property
    def text(self) -> java.lang.String:
        ...



__all__ = ["AbstractSearchTableModel", "Searcher", "ListingDisplaySearcher", "ListingDisplaySearchTableModel", "SearchTextPlugin", "SearchTextDialog", "SearchTask", "ListingDisplaySearchAddressIterator", "SearchOptions"]
