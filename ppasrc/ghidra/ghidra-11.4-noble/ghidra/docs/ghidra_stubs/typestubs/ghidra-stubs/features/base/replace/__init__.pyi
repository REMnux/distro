from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.plugin
import ghidra.features.base.quickfix
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.classfinder
import ghidra.util.datastruct
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.regex # type: ignore


class SearchAndReplaceProvider(ghidra.features.base.quickfix.QuckFixTableProvider):
    """
    Subclass of the :obj:`QuckFixTableProvider` that customizes it specifically for search and replace
    operations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: SearchAndReplacePlugin, program: ghidra.program.model.listing.Program, query: SearchAndReplaceQuery):
        ...


class SearchAndReplaceQuckFixTableLoader(ghidra.features.base.quickfix.TableDataLoader[ghidra.features.base.quickfix.QuickFix]):
    """
    Class for loading search and replace items into a ThreadedTableModel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, query: SearchAndReplaceQuery):
        ...


class SearchAndReplaceQuery(java.lang.Object):
    """
    Immutable class for storing all related query information for performing a search and
    replace operation. It includes the search pattern, the search pattern text, the search lmiit,
    and the types of program elements to search.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, searchText: typing.Union[java.lang.String, str], replacementText: typing.Union[java.lang.String, str], searchTypes: java.util.Set[SearchType], isRegEx: typing.Union[jpype.JBoolean, bool], isCaseSensitive: typing.Union[jpype.JBoolean, bool], isWholeWord: typing.Union[jpype.JBoolean, bool], searchLimit: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param java.lang.String or str searchText: the user entered search pattern text. It will be used to generate the
        actual Pattern based on the various options.
        :param java.lang.String or str replacementText: the user entered replacement text.
        :param java.util.Set[SearchType] searchTypes: the types of program elements to search
        :param jpype.JBoolean or bool isRegEx: true if the given search text is to be interpreted as a regular expression.
        :param jpype.JBoolean or bool isCaseSensitive: true if the search text should be case sensitive
        :param jpype.JBoolean or bool isWholeWord: true, the search text should match the enter element in the case of a
        rename, or an entire word within a larger sentence in the case of a comment.
        :param jpype.JInt or int searchLimit: the maximum entries to find before terminating the search.
        """

    def containsSearchType(self, searchType: SearchType) -> bool:
        """
        Returns true if the given SearchType is to be included in the search.
        
        :param SearchType searchType: the SearchType to check if it is included in the search
        :return: true if the given SearchType is to be included in the search.
        :rtype: bool
        """

    def findAll(self, program: ghidra.program.model.listing.Program, accumulator: ghidra.util.datastruct.Accumulator[ghidra.features.base.quickfix.QuickFix], monitor: ghidra.util.task.TaskMonitor):
        """
        Method to initiate the search.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.util.datastruct.Accumulator[ghidra.features.base.quickfix.QuickFix] accumulator: the accumulator to store the generated :obj:`QuickFix`s
        :param ghidra.util.task.TaskMonitor monitor: the :obj:`TaskMonitor`
        :raises CancelledException: if the search is cancelled.
        """

    def getReplacementText(self) -> str:
        """
        Returns the replacement text that will replace matched elements.
        
        :return: the replacement text that will replace matched elements
        :rtype: str
        """

    def getSearchLimit(self) -> int:
        """
        Returns the maximum number of search matches to be found before stopping early.
        
        :return: the maximum number of search matches to be found before stopping early.
        :rtype: int
        """

    def getSearchPattern(self) -> java.util.regex.Pattern:
        """
        Returns the search :obj:`Pattern` used to search program elements.
        
        :return: the search :obj:`Pattern` used to search program elements
        :rtype: java.util.regex.Pattern
        """

    def getSearchText(self) -> str:
        """
        Returns the search text used to generate the pattern for this query.
        
        :return: the search text used to generate the pattern for this query
        :rtype: str
        """

    def getSelectedSearchTypes(self) -> java.util.Set[SearchType]:
        """
        Returns a set of all the SearchTypes to be included in this query.
        
        :return: a set of all the SearchTypes to be included in this query
        :rtype: java.util.Set[SearchType]
        """

    @property
    def searchText(self) -> java.lang.String:
        ...

    @property
    def replacementText(self) -> java.lang.String:
        ...

    @property
    def searchPattern(self) -> java.util.regex.Pattern:
        ...

    @property
    def searchLimit(self) -> jpype.JInt:
        ...

    @property
    def selectedSearchTypes(self) -> java.util.Set[SearchType]:
        ...


class SearchType(java.lang.Comparable[SearchType]):
    """
    Represents a ghidra program element type that can be individually included or excluded when doing
    a search and replace operation. The :obj:`SearchAndReplaceDialog` will include a checkbox for
    each of these types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handler: SearchAndReplaceHandler, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param SearchAndReplaceHandler handler: The :obj:`SearchAndReplaceHandler` that actually has the logic for doing
        the search for this program element type.
        :param java.lang.String or str name: the name of element type that is searchable
        :param java.lang.String or str description: a description of this type which would be suitable to display as a tooltip
        """

    def getDescription(self) -> str:
        """
        Returns a description of this search type.
        
        :return: a description of this search type
        :rtype: str
        """

    def getHandler(self) -> SearchAndReplaceHandler:
        """
        Returns the :obj:`SearchAndReplaceHandler` that can process this type.
        
        :return: the handler for processing this type
        :rtype: SearchAndReplaceHandler
        """

    def getName(self) -> str:
        """
        Returns the name of this search type.
        
        :return: the name of this search type
        :rtype: str
        """

    @staticmethod
    def getSearchTypes() -> java.util.Set[SearchType]:
        """
        Static convenience method for finding all known SearchTypes. It uses the
        :obj:`ClassSearcher` to find all :obj:`SearchAndReplaceHandler`s and then gathers up
        all the SearchTypes that each handler supports.
        
        :return: The set of all Known SearchTypes
        :rtype: java.util.Set[SearchType]
        """

    @property
    def handler(self) -> SearchAndReplaceHandler:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class RenameQuickFix(ghidra.features.base.quickfix.QuickFix):
    """
    Base class for QuickFix objects that rename Ghidra program elements.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program this applies to
        :param java.lang.String or str name: the original name of the element to rename
        :param java.lang.String or str newName: the new name for the element when this QuickFix is applied.
        """


class SearchAndReplaceDialog(docking.DialogComponentProvider):
    """
    Dialog for entering information to perform a search and replace operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, searchLimit: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param jpype.JInt or int searchLimit: the maximum number of search matches to find before stopping.
        """

    def getQuery(self) -> SearchAndReplaceQuery:
        """
        Returns the query generated by the dialog when the "Ok" button is pressed or null if the
        dialog was cancelled.
        
        :return: the SearchAndReplaceQuery generated by the information in the dialog when the 
        "Ok" button is pressed, or null if the dialog was cancelled.
        :rtype: SearchAndReplaceQuery
        """

    def isOkEnabled(self) -> bool:
        """
        Returns true if the "ok" button is enabled.
        
        :return: true if the "ok" button is enabled.
        :rtype: bool
        """

    def selectRegEx(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Selects the RegEx checkbox in the dialog.
        
        :param jpype.JBoolean or bool b: true to select RegEx, false to turn deselect it
        """

    def selectSearchType(self, searchType: typing.Union[java.lang.String, str]):
        """
        Sets the search type with the given name to be selected.
        
        :param java.lang.String or str searchType: the name of the search type to select
        """

    def setSarchAndReplaceText(self, searchText: typing.Union[java.lang.String, str], replaceText: typing.Union[java.lang.String, str]):
        """
        Sets the search and replace text fields with given values.
        
        :param java.lang.String or str searchText: the text to be put in the search field
        :param java.lang.String or str replaceText: the text to be put in the replace field
        """

    def setSearchLimit(self, searchLimit: typing.Union[jpype.JInt, int]):
        """
        Sets a new maximum number of search matches to find before stopping.
        
        :param jpype.JInt or int searchLimit: the new maximum number of search matches to find before stopping.
        """

    def show(self, tool: ghidra.framework.plugintool.PluginTool) -> SearchAndReplaceQuery:
        """
        Convenience method for initializing the dialog, showing it and returning the query.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool this dialog belongs to
        :return: the SearchAndReplaceQuery generated by the information in the dialog when the 
        "Ok" button is pressed, or null if the dialog was cancelled.
        :rtype: SearchAndReplaceQuery
        """

    @property
    def okEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def query(self) -> SearchAndReplaceQuery:
        ...


class SearchAndReplaceHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    Base class for discoverable SearchAndReplaceHandlers. A SearchAndReplaceHandler is responsible
    for searching one or more specific program elements (referred to as :obj:`SearchType`) for a
    given search pattern and generating the appropriate :obj:`QuickFix`. 
     
    
    Typically, one handler will handle related search elements for efficiency. For example, the 
    DataTypesSearchAndReplaceHandler is responsible for datatype names, field names, field comments,
    etc. The idea is to only loop through all the datatypes once, regardless of what aspect of a 
    datatype you are searching for.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def findAll(self, program: ghidra.program.model.listing.Program, query: SearchAndReplaceQuery, accumulator: ghidra.util.datastruct.Accumulator[ghidra.features.base.quickfix.QuickFix], monitor: ghidra.util.task.TaskMonitor):
        """
        Method to perform the search for the pattern and options as specified by the given 
        SearchAndReplaceQuery. As matches are found, appropriate :obj:`QuickFix`s are added to
        the given accumulator.
        
        :param ghidra.program.model.listing.Program program: the program being searched
        :param SearchAndReplaceQuery query: contains the search pattern, replacement pattern, and options related to the 
        query.
        :param ghidra.util.datastruct.Accumulator[ghidra.features.base.quickfix.QuickFix] accumulator: the accumulator that resulting QuickFix items are added to as they are 
        found.
        :param ghidra.util.task.TaskMonitor monitor: a :obj:`TaskMonitor` for reporting progress and checking if the search has
        been cancelled.
        :raises CancelledException: thrown if the operation has been cancelled via the taskmonitor
        """

    def getSearchAndReplaceTypes(self) -> java.util.Set[SearchType]:
        """
        Returns the set of :obj:`SearchType`s this handler supports.
        
        :return: the set of :obj:`SearchType`s this handler supports.
        :rtype: java.util.Set[SearchType]
        """

    @property
    def searchAndReplaceTypes(self) -> java.util.Set[SearchType]:
        ...


class SearchAndReplacePlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin to perform search and replace operations for many different program element types such
    as labels, functions, classes, datatypes, memory blocks, and more.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["SearchAndReplaceProvider", "SearchAndReplaceQuckFixTableLoader", "SearchAndReplaceQuery", "SearchType", "RenameQuickFix", "SearchAndReplaceDialog", "SearchAndReplaceHandler", "SearchAndReplacePlugin"]
