from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.nav
import ghidra.app.plugin.core.navigation
import ghidra.app.services
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class GoToServiceImpl(ghidra.app.services.GoToService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, defaultNavigatable: ghidra.app.nav.Navigatable):
        ...


class GoToAddressLabelDialog(docking.ReusableDialogComponentProvider, ghidra.app.services.GoToServiceListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, gotoService: ghidra.app.services.GoToService, plugin: ghidra.framework.plugintool.Plugin):
        ...

    def getHistory(self) -> java.util.List[java.lang.String]:
        ...

    def maxEntrysChanged(self):
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setCStyleInput(self, cStyleInput: typing.Union[jpype.JBoolean, bool]):
        ...

    def setCaseSensitive(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMemory(self, goToMemory: typing.Union[jpype.JBoolean, bool]):
        ...

    def setText(self, text: typing.Union[java.lang.String, str]):
        ...

    def show(self, nav: ghidra.app.nav.Navigatable, addr: ghidra.program.model.address.Address, tool: ghidra.framework.plugintool.PluginTool):
        """
        Popup up the dialog in the center of the tool.
        
        :param ghidra.app.nav.Navigatable nav: the Navigatable
        :param ghidra.program.model.address.Address addr: the address
        :param ghidra.framework.plugintool.PluginTool tool: the PluginTool
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def history(self) -> java.util.List[java.lang.String]:
        ...


class GoToQuery(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, navigatable: ghidra.app.nav.Navigatable, plugin: ghidra.framework.plugintool.Plugin, goToService: ghidra.app.services.GoToService, queryData: ghidra.app.services.QueryData, fromAddr: ghidra.program.model.address.Address, navigationOptions: ghidra.app.plugin.core.navigation.NavigationOptions, monitor: ghidra.util.task.TaskMonitor):
        ...

    def processQuery(self) -> bool:
        ...


class SymbolSearcher(java.lang.Object):
    """
    Class for searching for symbols that match a given query string.
     
    
    The query string may include full or partial (absolute or relative) namespace path information.
    The standard namespace delimiter ("::") is used to separate the query into it separate pieces,
    with each piece used to either match a namespace or a symbol name, with the symbol
    name piece always being the last piece (or the only piece).
     
    
    Both the namespace pieces and the symbol name piece may contain wildcards ("*" or "?") and those
    wildcards only apply to a single element. For example, if a symbol's full path was "a::b::c::d"
    and the query was "a::*::d", it would not match as the "*" can only match one element. 
     
    
    By default all queries are considered relative. In other words, the first namespace element
    does not need to be at the root global level. For example, in the "a::b::c::d" example, the "d"
    symbol could be found by "d", "c::d", "b::c::d". To avoid this behavior, the query may begin
    with a "::" delimiter which means the path is absolute and the first element must be at the
    root level. So, in the previous example, "::a::b::c::d" would match but, "::c::d" would not.
     
    
    There are also two parameters in the QueryData object that affect how the search algorithm is
    conducted. One is "Case Sensitive" and the other is "Include Dynamic Labels". If the search
    is case insensitive or there are wild cards in the symbol name, the only option is to do a full
    search of all defined symbols, looking for matches. If that is not the case, the search can
    do a direct look up of matching symbols using the program database's symbol index.
     
    
    If the "Include Dynamic Labels" options is on, then a brute force of the defined references is
    also performed, looking at all addresses that a reference points to, getting the dynamic 
    (not stored) symbol at that address and checking if it matches.
     
    
    One last behavior to note is that the search takes a list of programs to search. However, it
    only returns results from the FIRST program to have any results. If the need to search all
    programs completely is ever needed, a second "find" method could easily be added.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: ghidra.app.services.QueryData, limit: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        ...

    def findMatchingSymbolLocations(self, searchPrograms: java.util.List[ghidra.program.model.listing.Program]) -> java.util.List[ghidra.program.util.ProgramLocation]:
        ...


class GoToSymbolSearchTask(ghidra.util.task.Task):
    """
    Task for searching for symbols. All the logic for the search is done by the
    :obj:`SymbolSearcher`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, queryData: ghidra.app.services.QueryData, searchPrograms: java.util.List[ghidra.program.model.listing.Program], limit: typing.Union[jpype.JInt, int]):
        ...

    def getResults(self) -> java.util.List[ghidra.program.util.ProgramLocation]:
        ...

    @property
    def results(self) -> java.util.List[ghidra.program.util.ProgramLocation]:
        ...


class SymbolMatcher(java.lang.Object):
    """
    Class for matching symbol names with or without namespace paths and wildcards.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, queryString: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]):
        ...

    def getSymbolName(self) -> str:
        ...

    def hasFullySpecifiedName(self) -> bool:
        """
        Returns true if the symbol name part of the query string has no wildcards and is
        case sensitive.
        
        :return: true if the query has no wildcards and is case sensitive.
        :rtype: bool
        """

    def hasWildCardsInSymbolName(self) -> bool:
        """
        Returns true if there are wildcards in the symbol name.
        
        :return: true if there are wildcards in the symbol name
        :rtype: bool
        """

    def matches(self, symbol: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Returns true if the given symbol matches the query specification for this matcher.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to test
        :return: true if the given symbol matches the query specification for this matcher
        :rtype: bool
        """

    @property
    def symbolName(self) -> java.lang.String:
        ...



__all__ = ["GoToServiceImpl", "GoToAddressLabelDialog", "GoToQuery", "SymbolSearcher", "GoToSymbolSearchTask", "SymbolMatcher"]
