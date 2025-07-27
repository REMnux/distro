from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.list
import docking.widgets.table
import ghidra.app.nav
import ghidra.app.services
import ghidra.app.util
import ghidra.features.base.memsearch.bytesource
import ghidra.features.base.memsearch.combiner
import ghidra.features.base.memsearch.format
import ghidra.features.base.memsearch.matcher
import ghidra.features.base.memsearch.scan
import ghidra.features.base.memsearch.searcher
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.datastruct
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.task
import java.lang # type: ignore
import java.nio.charset # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.text # type: ignore


@typing.type_check_only
class MemorySearchControlPanel(javax.swing.JPanel):
    """
    Internal panel of the memory search window that manages the controls for the search feature. This
    panel can be added or removed via a toolbar action. This panel is showing by default.
    """

    class RestrictedInputDocument(javax.swing.text.DefaultStyledDocument):
        """
        Custom Document that validates user input on the fly.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def insertString(self, offs: typing.Union[jpype.JInt, int], str: typing.Union[java.lang.String, str], a: javax.swing.text.AttributeSet):
            """
            Called before new user input is inserted into the entry text field.  The super
            method is called if the input is accepted.
            """

        def remove(self, offs: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
            """
            Called before the user deletes some text.  If the result is valid, the super
            method is called.
            """


    @typing.type_check_only
    class SearchHistoryRenderer(docking.widgets.list.GComboBoxCellRenderer[ghidra.features.base.memsearch.matcher.ByteMatcher]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class SearchGuiModel(java.lang.Object):
    """
    Maintains the state of all the settings and controls for the memory search window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, settings: SearchSettings, regionChoices: java.util.List[ghidra.features.base.memsearch.bytesource.SearchRegion]):
        ...

    def addChangeCallback(self, changeCallback: java.util.function.Consumer[SearchSettings]):
        ...

    def getAlignment(self) -> int:
        ...

    def getDecimalByteSize(self) -> int:
        ...

    def getMatchCombiner(self) -> ghidra.features.base.memsearch.combiner.Combiner:
        ...

    def getMemoryRegionChoices(self) -> java.util.List[ghidra.features.base.memsearch.bytesource.SearchRegion]:
        ...

    def getSearchFormat(self) -> ghidra.features.base.memsearch.format.SearchFormat:
        ...

    def getSelectedMemoryRegions(self) -> java.util.Set[ghidra.features.base.memsearch.bytesource.SearchRegion]:
        ...

    def getSettings(self) -> SearchSettings:
        ...

    def getStringCharset(self) -> java.nio.charset.Charset:
        ...

    def hasSelection(self) -> bool:
        ...

    def includeDefinedData(self) -> bool:
        ...

    def includeInstructions(self) -> bool:
        ...

    def includeUndefinedData(self) -> bool:
        ...

    def isBigEndian(self) -> bool:
        ...

    def isCaseSensitive(self) -> bool:
        ...

    def isDecimalUnsigned(self) -> bool:
        ...

    def isSearchSelectionOnly(self) -> bool:
        ...

    def isSelectedRegion(self, region: ghidra.features.base.memsearch.bytesource.SearchRegion) -> bool:
        ...

    def parse(self, proposedText: typing.Union[java.lang.String, str]) -> ghidra.features.base.memsearch.matcher.ByteMatcher:
        ...

    def selectRegion(self, region: ghidra.features.base.memsearch.bytesource.SearchRegion, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setAlignment(self, alignment: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def setAutoRestrictSelection(self):
        ...

    @typing.overload
    def setAutoRestrictSelection(self, autoRestrictSelection: typing.Union[jpype.JBoolean, bool]):
        ...

    def setBigEndian(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setCaseSensitive(self, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setDecimalByteSize(self, byteSize: typing.Union[jpype.JInt, int]):
        ...

    def setDecimalUnsigned(self, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setHasSelection(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeDefinedData(self, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeInstructions(self, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeUndefinedData(self, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMatchCombiner(self, combiner: ghidra.features.base.memsearch.combiner.Combiner):
        ...

    def setSearchFormat(self, searchFormat: ghidra.features.base.memsearch.format.SearchFormat):
        ...

    def setSearchSelectionOnly(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSettings(self, newSettings: SearchSettings):
        ...

    def setStringCharset(self, charset: java.nio.charset.Charset):
        ...

    def setUseEscapeSequences(self, selected: typing.Union[jpype.JBoolean, bool]):
        ...

    def useEscapeSequences(self) -> bool:
        ...

    @property
    def settings(self) -> SearchSettings:
        ...

    @settings.setter
    def settings(self, value: SearchSettings):
        ...

    @property
    def memoryRegionChoices(self) -> java.util.List[ghidra.features.base.memsearch.bytesource.SearchRegion]:
        ...

    @property
    def stringCharset(self) -> java.nio.charset.Charset:
        ...

    @stringCharset.setter
    def stringCharset(self, value: java.nio.charset.Charset):
        ...

    @property
    def decimalByteSize(self) -> jpype.JInt:
        ...

    @decimalByteSize.setter
    def decimalByteSize(self, value: jpype.JInt):
        ...

    @property
    def caseSensitive(self) -> jpype.JBoolean:
        ...

    @caseSensitive.setter
    def caseSensitive(self, value: jpype.JBoolean):
        ...

    @property
    def searchFormat(self) -> ghidra.features.base.memsearch.format.SearchFormat:
        ...

    @searchFormat.setter
    def searchFormat(self, value: ghidra.features.base.memsearch.format.SearchFormat):
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @bigEndian.setter
    def bigEndian(self, value: jpype.JBoolean):
        ...

    @property
    def decimalUnsigned(self) -> jpype.JBoolean:
        ...

    @decimalUnsigned.setter
    def decimalUnsigned(self, value: jpype.JBoolean):
        ...

    @property
    def selectedMemoryRegions(self) -> java.util.Set[ghidra.features.base.memsearch.bytesource.SearchRegion]:
        ...

    @property
    def selectedRegion(self) -> jpype.JBoolean:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @alignment.setter
    def alignment(self, value: jpype.JInt):
        ...

    @property
    def searchSelectionOnly(self) -> jpype.JBoolean:
        ...

    @searchSelectionOnly.setter
    def searchSelectionOnly(self, value: jpype.JBoolean):
        ...

    @property
    def matchCombiner(self) -> ghidra.features.base.memsearch.combiner.Combiner:
        ...

    @matchCombiner.setter
    def matchCombiner(self, value: ghidra.features.base.memsearch.combiner.Combiner):
        ...


class MemoryScanControlPanel(javax.swing.JPanel):
    """
    Internal panel of the memory search window that manages the controls for the scan feature. This
    panel can be added or removed via a toolbar action. Not showing by default.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setSearchStatus(self, hasResults: typing.Union[jpype.JBoolean, bool], isBusy: typing.Union[jpype.JBoolean, bool]):
        ...


class SearchHistory(java.lang.Object):
    """
    Class for managing memory search history. It maintains a list of previously used ByteMatchers to
    do memory searching. Each ByteMatcher records the input search text and the search settings used
    to create it.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, maxHistory: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, other: SearchHistory):
        ...

    def addSearch(self, matcher: ghidra.features.base.memsearch.matcher.ByteMatcher):
        ...

    def getHistoryAsArray(self) -> jpype.JArray[ghidra.features.base.memsearch.matcher.ByteMatcher]:
        ...

    @property
    def historyAsArray(self) -> jpype.JArray[ghidra.features.base.memsearch.matcher.ByteMatcher]:
        ...


class CombinedMatchTableLoader(MemoryMatchTableLoader):
    """
    Table loader that performs a search and then combines the new results with existing results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, memSearcher: ghidra.features.base.memsearch.searcher.MemorySearcher, previousResults: java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch], combiner: ghidra.features.base.memsearch.combiner.Combiner):
        ...


class RefreshResultsTableLoader(MemoryMatchTableLoader):
    """
    Table loader that reloads the table with existing results after refreshing the byte values in
    those results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, matches: java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch]):
        ...


class MemoryMatchToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.features.base.memsearch.searcher.MemoryMatch, ghidra.program.util.ProgramLocation]):
    """
    Maps :obj:`MemoryMatch` objects (search result) to program locations to pick up 
    program location based table columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MemoryMatchToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.features.base.memsearch.searcher.MemoryMatch, ghidra.program.model.address.Address]):
    """
    Maps :obj:`MemoryMatch` objects (search result) to an address to pick up address based 
    table columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MemoryMatchTableLoader(java.lang.Object):
    """
    Interface for loading the memory search results table. Various implementations handle the
    different cases such as a search all, or a search next, or combining results with a previous
    search, etc.
    """

    class_: typing.ClassVar[java.lang.Class]

    def didTerminateEarly(self) -> bool:
        """
        Returns true if the search/loading did not fully complete. (Search limit reached, cancelled
        by user, etc.)
        
        :return: true if the search/loading did not fully complete
        :rtype: bool
        """

    def dispose(self):
        """
        Cleans up resources
        """

    def getFirstMatch(self) -> ghidra.features.base.memsearch.searcher.MemoryMatch:
        """
        Returns the first match found. Typically used to navigate the associated navigatable.
        
        :return: the first match found
        :rtype: ghidra.features.base.memsearch.searcher.MemoryMatch
        """

    def hasResults(self) -> bool:
        """
        Returns true if at least one match was found.
        
        :return: true if at least one match was found
        :rtype: bool
        """

    def loadResults(self, accumulator: ghidra.util.datastruct.Accumulator[ghidra.features.base.memsearch.searcher.MemoryMatch], monitor: ghidra.util.task.TaskMonitor):
        """
        Called by the table model to initiate searching and loading using the threaded table models
        threading infrastructure.
        
        :param ghidra.util.datastruct.Accumulator[ghidra.features.base.memsearch.searcher.MemoryMatch] accumulator: the accumulator to store results that will appear in the results table
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    @property
    def firstMatch(self) -> ghidra.features.base.memsearch.searcher.MemoryMatch:
        ...


class MemorySearchOptions(java.lang.Object):
    """
    Class for managing search tool options.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def __init__(self):
        ...

    def getByteDelimiter(self) -> str:
        ...

    def getByteGroupSize(self) -> int:
        ...

    def getSearchLimit(self) -> int:
        ...

    def isAutoRestrictSelection(self) -> bool:
        ...

    def isShowHighlights(self) -> bool:
        ...

    @property
    def byteDelimiter(self) -> java.lang.String:
        ...

    @property
    def showHighlights(self) -> jpype.JBoolean:
        ...

    @property
    def searchLimit(self) -> jpype.JInt:
        ...

    @property
    def autoRestrictSelection(self) -> jpype.JBoolean:
        ...

    @property
    def byteGroupSize(self) -> jpype.JInt:
        ...


class SearchSettings(java.lang.Object):
    """
    Immutable container for all the relevant search settings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getAlignment(self) -> int:
        ...

    def getDecimalByteSize(self) -> int:
        ...

    def getSearchAddresses(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSet:
        ...

    def getSearchFormat(self) -> ghidra.features.base.memsearch.format.SearchFormat:
        """
        Returns the :obj:`SearchFormat` to be used to parse the input text.
        
        :return: the search format to be used to parse the input text
        :rtype: ghidra.features.base.memsearch.format.SearchFormat
        """

    def getSelectedMemoryRegions(self) -> java.util.Set[ghidra.features.base.memsearch.bytesource.SearchRegion]:
        ...

    def getStringCharset(self) -> java.nio.charset.Charset:
        ...

    def includeDefinedData(self) -> bool:
        ...

    def includeInstructions(self) -> bool:
        ...

    def includeUndefinedData(self) -> bool:
        ...

    def isBigEndian(self) -> bool:
        ...

    def isCaseSensitive(self) -> bool:
        ...

    def isDecimalUnsigned(self) -> bool:
        ...

    def isSelectedRegion(self, region: ghidra.features.base.memsearch.bytesource.SearchRegion) -> bool:
        ...

    def useEscapeSequences(self) -> bool:
        ...

    def withAlignment(self, newAlignment: typing.Union[jpype.JInt, int]) -> SearchSettings:
        ...

    def withBigEndian(self, isBigEndian: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withCaseSensitive(self, b: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withDecimalByteSize(self, byteSize: typing.Union[jpype.JInt, int]) -> SearchSettings:
        ...

    def withDecimalUnsigned(self, b: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withIncludeDefinedData(self, b: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withIncludeInstructions(self, b: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withIncludeUndefinedData(self, b: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withSearchFormat(self, format: ghidra.features.base.memsearch.format.SearchFormat) -> SearchSettings:
        """
        Creates a copy of this settings object, but using the given search format.
        
        :param ghidra.features.base.memsearch.format.SearchFormat format: the new search format
        :return: a new search settings that is the same as this settings except for the format
        :rtype: SearchSettings
        """

    def withSelectedRegion(self, region: ghidra.features.base.memsearch.bytesource.SearchRegion, select: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    def withSelectedRegions(self, regions: java.util.Set[ghidra.features.base.memsearch.bytesource.SearchRegion]) -> SearchSettings:
        ...

    def withStringCharset(self, stringCharset: java.nio.charset.Charset) -> SearchSettings:
        ...

    def withUseEscapeSequence(self, b: typing.Union[jpype.JBoolean, bool]) -> SearchSettings:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def decimalUnsigned(self) -> jpype.JBoolean:
        ...

    @property
    def stringCharset(self) -> java.nio.charset.Charset:
        ...

    @property
    def selectedMemoryRegions(self) -> java.util.Set[ghidra.features.base.memsearch.bytesource.SearchRegion]:
        ...

    @property
    def decimalByteSize(self) -> jpype.JInt:
        ...

    @property
    def selectedRegion(self) -> jpype.JBoolean:
        ...

    @property
    def caseSensitive(self) -> jpype.JBoolean:
        ...

    @property
    def searchAddresses(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def searchFormat(self) -> ghidra.features.base.memsearch.format.SearchFormat:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...


class MemorySearchProvider(ghidra.framework.plugintool.ComponentProviderAdapter, docking.DockingContextListener, ghidra.app.nav.NavigatableRemovalListener, ghidra.framework.model.DomainObjectClosedListener):
    """
    ComponentProvider used to search memory and display search results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: MemorySearchPlugin, navigatable: ghidra.app.nav.Navigatable, settings: SearchSettings, options: MemorySearchOptions, history: SearchHistory):
        ...

    def getByteString(self) -> str:
        ...

    def getResultsPanel(self) -> MemorySearchResultsPanel:
        ...

    def getSearchInput(self) -> str:
        ...

    def getSearchResults(self) -> java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch]:
        ...

    def isBusy(self) -> bool:
        ...

    def isSearchSelection(self) -> bool:
        ...

    def scan(self, scanner: ghidra.features.base.memsearch.scan.Scanner):
        """
        Performs a scan on the current results, keeping only the results that match the type of scan.
        Note: this method is public to facilitate testing.
        
        :param ghidra.features.base.memsearch.scan.Scanner scanner: the scanner to use to reduce the results.
        """

    def search(self):
        ...

    def setSearchCombiner(self, combiner: ghidra.features.base.memsearch.combiner.Combiner):
        ...

    def setSearchInput(self, input: typing.Union[java.lang.String, str]):
        ...

    def setSearchSelectionOnly(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSettings(self, settings: SearchSettings):
        ...

    def showOptions(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def showScanPanel(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def showSearchPanel(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def searchSelection(self) -> jpype.JBoolean:
        ...

    @property
    def resultsPanel(self) -> MemorySearchResultsPanel:
        ...

    @property
    def searchInput(self) -> java.lang.String:
        ...

    @searchInput.setter
    def searchInput(self, value: java.lang.String):
        ...

    @property
    def byteString(self) -> java.lang.String:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def searchResults(self) -> java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch]:
        ...


class EmptyMemoryMatchTableLoader(MemoryMatchTableLoader):
    """
    Table loader for clearing the existing results
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FindOnceTableLoader(MemoryMatchTableLoader):
    """
    Table loader for executing an incremental search forwards or backwards and adding that result
    to the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, searcher: ghidra.features.base.memsearch.searcher.MemorySearcher, address: ghidra.program.model.address.Address, previousResults: java.util.List[ghidra.features.base.memsearch.searcher.MemoryMatch], panel: MemorySearchResultsPanel, forward: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class MemorySearchOptionsPanel(javax.swing.JPanel):
    """
    Internal panel of the memory search window that manages the controls for the search settings.
    This panel can be added or removed via a toolbar action. Not showing by default.
    """

    @typing.type_check_only
    class RestrictedInputDocument(javax.swing.text.DefaultStyledDocument):
        """
        Custom Document that validates user input on the fly.
        """

        class_: typing.ClassVar[java.lang.Class]

        def insertString(self, offs: typing.Union[jpype.JInt, int], str: typing.Union[java.lang.String, str], a: javax.swing.text.AttributeSet):
            """
            Called before new user input is inserted into the entry text field.  The super
            method is called if the input is accepted.
            """


    class_: typing.ClassVar[java.lang.Class]


class MemoryMatchHighlighter(ghidra.app.util.ListingHighlightProvider):
    """
    Listing highlight provider to highlight memory search results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, navigatable: ghidra.app.nav.Navigatable, model: MemoryMatchTableModel, options: MemorySearchOptions):
        ...


class MemorySearchResultsPanel(javax.swing.JPanel):
    """
    Internal panel of the memory search window that manages the display of the search results
    in a table. This panel also includes most of the search logic as it has direct access to the
    table for showing the results.
    """

    @typing.type_check_only
    class SearchOnceTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, forward: typing.Union[jpype.JBoolean, bool], searcher: ghidra.features.base.memsearch.searcher.MemorySearcher, start: ghidra.program.model.address.Address):
            ...


    @typing.type_check_only
    class RefreshAndScanTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, byteSource: ghidra.features.base.memsearch.bytesource.AddressableByteSource, scanner: ghidra.features.base.memsearch.scan.Scanner):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def clearResults(self):
        ...

    def dispose(self):
        ...

    def getMatchCount(self) -> int:
        ...

    def getSelectedMatch(self) -> ghidra.features.base.memsearch.searcher.MemoryMatch:
        ...

    def getTable(self) -> ghidra.util.table.GhidraTable:
        ...

    def hasResults(self) -> bool:
        ...

    def refreshAndMaybeScanForChanges(self, byteSource: ghidra.features.base.memsearch.bytesource.AddressableByteSource, scanner: ghidra.features.base.memsearch.scan.Scanner):
        ...

    def search(self, searcher: ghidra.features.base.memsearch.searcher.MemorySearcher, combiner: ghidra.features.base.memsearch.combiner.Combiner):
        ...

    def searchOnce(self, searcher: ghidra.features.base.memsearch.searcher.MemorySearcher, address: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def selectedMatch(self) -> ghidra.features.base.memsearch.searcher.MemoryMatch:
        ...

    @property
    def matchCount(self) -> jpype.JInt:
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...


class MemoryMatchTableModel(ghidra.util.table.AddressBasedTableModel[ghidra.features.base.memsearch.searcher.MemoryMatch]):
    """
    Table model for memory search results.
    """

    class MatchBytesColumn(docking.widgets.table.DynamicTableColumnExtensionPoint[ghidra.features.base.memsearch.searcher.MemoryMatch, java.lang.String, ghidra.program.model.listing.Program]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class MatchValueColumn(docking.widgets.table.DynamicTableColumnExtensionPoint[ghidra.features.base.memsearch.searcher.MemoryMatch, java.lang.String, ghidra.program.model.listing.Program]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ByteArrayRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ValueRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def isSortedOnAddress(self) -> bool:
        ...

    @property
    def sortedOnAddress(self) -> jpype.JBoolean:
        ...


class NewSearchTableLoader(MemoryMatchTableLoader):
    """
    Table loader that performs a search and displays the results in the table.
    """

    class_: typing.ClassVar[java.lang.Class]


class SearchMarkers(java.lang.Object):
    """
    Manages the :obj:`MarkerSet` for a given :obj:`MemorySearchProvider` window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program):
        ...

    def dispose(self):
        ...


class MemoryMatchtToFunctionTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.features.base.memsearch.searcher.MemoryMatch, ghidra.program.model.listing.Function]):
    """
    Maps :obj:`MemoryMatch` objects (search result) to functions to pick up function based 
    table columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MemorySearchPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.MemorySearchService):
    """
    Plugin for searching program memory.
    """

    @typing.type_check_only
    class SearchOnceTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, navigatable: ghidra.app.nav.Navigatable, forward: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def setShowOptionsPanel(self, show: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowScanPanel(self, show: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["MemorySearchControlPanel", "SearchGuiModel", "MemoryScanControlPanel", "SearchHistory", "CombinedMatchTableLoader", "RefreshResultsTableLoader", "MemoryMatchToProgramLocationTableRowMapper", "MemoryMatchToAddressTableRowMapper", "MemoryMatchTableLoader", "MemorySearchOptions", "SearchSettings", "MemorySearchProvider", "EmptyMemoryMatchTableLoader", "FindOnceTableLoader", "MemorySearchOptionsPanel", "MemoryMatchHighlighter", "MemorySearchResultsPanel", "MemoryMatchTableModel", "NewSearchTableLoader", "SearchMarkers", "MemoryMatchtToFunctionTableRowMapper", "MemorySearchPlugin"]
