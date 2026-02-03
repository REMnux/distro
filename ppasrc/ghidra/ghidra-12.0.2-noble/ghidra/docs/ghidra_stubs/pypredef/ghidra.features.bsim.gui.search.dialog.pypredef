from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import generic.lsh.vector
import ghidra.app.services
import ghidra.features.bsim.gui
import ghidra.features.bsim.gui.filters
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.protocol
import ghidra.framework.plugintool
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import utility.function


class AbstractBSimSearchDialog(docking.DialogComponentProvider):
    """
    Base class for BSim Search dialogs that all have a server comboBox, and entries for the
    similarity and confidence values.
    """

    @typing.type_check_only
    class BSimQueryTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class SelectedFunctionsTableDialog(docking.DialogComponentProvider):
    """
    Dialog for display selected functions
    """

    @typing.type_check_only
    class FunctionsTableModel(ghidra.util.table.AddressBasedTableModel[ghidra.program.database.symbol.FunctionSymbol]):

        @typing.type_check_only
        class SymbolNameColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.database.symbol.FunctionSymbol, java.lang.String]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class MatchCountColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.database.symbol.FunctionSymbol, java.lang.Integer]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class SymbolAddressColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.database.symbol.FunctionSymbol, java.lang.String]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, functionSymbols: java.util.Set[ghidra.program.database.symbol.FunctionSymbol], gotoService: ghidra.app.services.GoToService, help: ghidra.util.HelpLocation):
        ...

    @typing.overload
    def __init__(self, functionSymbols: java.util.Set[ghidra.program.database.symbol.FunctionSymbol], gotoService: ghidra.app.services.GoToService, help: ghidra.util.HelpLocation, matchCounts: collections.abc.Mapping):
        ...


class BSimServerDialog(docking.DialogComponentProvider):
    """
    Dialog for managing BSim database server definitions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, serverManager: ghidra.features.bsim.gui.BSimServerManager):
        ...

    def getLastAdded(self) -> ghidra.features.bsim.query.BSimServerInfo:
        ...

    @property
    def lastAdded(self) -> ghidra.features.bsim.query.BSimServerInfo:
        ...


class FunctionSymbolToFunctionTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.database.symbol.FunctionSymbol, ghidra.program.model.listing.Function]):
    """
    Maps FunctionSymbols to Functions to get table columns for functions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BSimSearchSettings(java.lang.Object):
    """
    Class to hold all the settings for a BSim similar functions search
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, similarity: typing.Union[jpype.JDouble, float], confidence: typing.Union[jpype.JDouble, float], maxResults: typing.Union[jpype.JInt, int], filterSet: BSimFilterSet):
        ...

    def copy(self) -> BSimSearchSettings:
        """
        Returns a copy of this settings.
        
        :return: a copy of this settings.
        :rtype: BSimSearchSettings
        """

    def getBSimFilterSet(self) -> BSimFilterSet:
        """
        Returns the filters to be used for the query
        
        :return: the filters to be used for the query
        :rtype: BSimFilterSet
        """

    def getConfidence(self) -> float:
        """
        Returns the confidence criteria.
        
        :return: the confidence criteria.
        :rtype: float
        """

    def getMaxResults(self) -> int:
        """
        Returns the maximum number of matches for a single function.
        
        :return: the maximum number of matches for a single function
        :rtype: int
        """

    def getSimilarity(self) -> float:
        """
        Returns the similarity criteria.
        
        :return: the similarity criteria.
        :rtype: float
        """

    @property
    def similarity(self) -> jpype.JDouble:
        ...

    @property
    def maxResults(self) -> jpype.JInt:
        ...

    @property
    def confidence(self) -> jpype.JDouble:
        ...

    @property
    def bSimFilterSet(self) -> BSimFilterSet:
        ...


class CreateBsimServerInfoDialog(docking.DialogComponentProvider):
    """
    Dialog for entering new BSim database server definition
    """

    @typing.type_check_only
    class ServerPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DbPanel(CreateBsimServerInfoDialog.ServerPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FilePanel(CreateBsimServerInfoDialog.ServerPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NotifyingTextField(javax.swing.JTextField):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            ...

        @typing.overload
        def __init__(self, initialText: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class MyFieldListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class ConnectionPoolStatus(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BSimSearchService(java.lang.Object):
    """
    Interface used by the BSimSearchDialog to initiate BSim Queries
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLastUsedSearchSettings(self) -> BSimSearchSettings:
        """
        Returns the BSimSearchSettings that was used in the previous search or the default
        settings if no searches have been performed.
        
        :return: the BSimSearchSettings that was used in the previous search
        :rtype: BSimSearchSettings
        """

    def getLastUsedServer(self) -> ghidra.features.bsim.query.BSimServerInfo:
        """
        Returns the BSimServerInfo that was used in the previous search or null if no searches
        have been performed.
        
        :return: the BSimServerInfo that was used in the previous search
        :rtype: ghidra.features.bsim.query.BSimServerInfo
        """

    def performOverview(self, severCache: BSimServerCache, settings: BSimSearchSettings):
        """
        Initiates a BSim overview search using all the functions in the program.
        
        :param BSimServerCache severCache: the server to query
        :param BSimSearchSettings settings: the settings to use for the search
        """

    def search(self, severCache: BSimServerCache, settings: BSimSearchSettings, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
        """
        Initiates a BSim similar functions search.
        
        :param BSimServerCache severCache: the server to query
        :param BSimSearchSettings settings: the settings to use for the search
        :param java.util.Set[ghidra.program.database.symbol.FunctionSymbol] functions: the functions to search for similar matches
        """

    @property
    def lastUsedServer(self) -> ghidra.features.bsim.query.BSimServerInfo:
        ...

    @property
    def lastUsedSearchSettings(self) -> BSimSearchSettings:
        ...


class BSimServerCache(java.lang.Object):
    """
    Caches BSim database info for a Bsim database connection
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, severInfo: ghidra.features.bsim.query.BSimServerInfo):
        ...

    def getDatabaseInformation(self) -> ghidra.features.bsim.query.description.DatabaseInformation:
        ...

    def getLSHVectorFactory(self) -> generic.lsh.vector.LSHVectorFactory:
        """
        Get cached :obj:`LSHVectorFactory` for the active BSim Function Database
        
        :return: vector factory or null if DB server not set or never connected
        :rtype: generic.lsh.vector.LSHVectorFactory
        """

    def getServerInfo(self) -> ghidra.features.bsim.query.BSimServerInfo:
        ...

    @property
    def lSHVectorFactory(self) -> generic.lsh.vector.LSHVectorFactory:
        ...

    @property
    def serverInfo(self) -> ghidra.features.bsim.query.BSimServerInfo:
        ...

    @property
    def databaseInformation(self) -> ghidra.features.bsim.query.description.DatabaseInformation:
        ...


class FilterWidget(javax.swing.JPanel):
    """
    This class defines a widget for a single BSim filter. At a minimum
    it will consist of a combobox containing the available filters. It may optionally
    contain a secondary widget for specifying filter values. This secondary widget
    is filter-specific; for most filter types it will be a text entry field but as long
    as it implements the proper interface it is valid.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterTypes: java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType], removeConsumer: java.util.function.Consumer[FilterWidget], changeListener: utility.function.Callback):
        """
        Constructs a new filter widget.
        
        :param java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType] filterTypes: The list of filter types that can be chosen
        :param java.util.function.Consumer[FilterWidget] removeConsumer: the container to be notified that it should delete this object
        :param utility.function.Callback changeListener: listener to be notified when filter value changes
        """

    def getSelectedFilter(self) -> ghidra.features.bsim.gui.filters.BSimFilterType:
        """
        Returns the selected filter.
        
        :return: the filter
        :rtype: ghidra.features.bsim.gui.filters.BSimFilterType
        """

    def getValues(self) -> java.util.List[java.lang.String]:
        """
        Returns all values in the filter as a list. For filters that do not allow
        multiple entries, this will always return a list of only one item.
        
        :return: filter values
        :rtype: java.util.List[java.lang.String]
        """

    def hasValidValue(self) -> bool:
        ...

    def isBlank(self) -> bool:
        ...

    def setFilter(self, filter: ghidra.features.bsim.gui.filters.BSimFilterType, values: java.util.List[java.lang.String]):
        ...

    def setFilters(self, filters: java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType]):
        ...

    @property
    def blank(self) -> jpype.JBoolean:
        ...

    @property
    def values(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def selectedFilter(self) -> ghidra.features.bsim.gui.filters.BSimFilterType:
        ...


class BSimServerManagerListener(java.lang.Object):
    """
    Listener for when the list of defined BSim database definitions change
    """

    class_: typing.ClassVar[java.lang.Class]

    def serverListChanged(self):
        ...


class BSimOverviewDialog(AbstractBSimSearchDialog):
    """
    Dialog for initiating a BSim overview query.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, service: BSimSearchService, serverManager: ghidra.features.bsim.gui.BSimServerManager):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class BSimFilterSet(java.lang.Object):
    """
    Maintains the set of current filters in a nicer way than BSimFiler which breaks them down into
    filter pieces that doesn't maintain any order.
    """

    class FilterEntry(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, filterType: ghidra.features.bsim.gui.filters.BSimFilterType, values: java.util.List[java.lang.String]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def filterType(self) -> ghidra.features.bsim.gui.filters.BSimFilterType:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def values(self) -> java.util.List[java.lang.String]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addEntry(self, filterType: ghidra.features.bsim.gui.filters.BSimFilterType, values: java.util.List[java.lang.String]):
        """
        Adds a filter entry to this set of filters
        
        :param ghidra.features.bsim.gui.filters.BSimFilterType filterType: the BSimFilterType for the added filter
        :param java.util.List[java.lang.String] values: the list of values for the given filter type
        """

    def copy(self) -> BSimFilterSet:
        """
        Returns a copy of this FilterSet.
        
        :return: a copy of this FilterSet
        :rtype: BSimFilterSet
        """

    def getBSimFilter(self) -> ghidra.features.bsim.query.protocol.BSimFilter:
        """
        Returns the corresponding BSimFilter for this FilterSet.
        
        :return: the corresponding BSimFilter for this FilterSet
        :rtype: ghidra.features.bsim.query.protocol.BSimFilter
        """

    def getFilterEntries(self) -> java.util.List[BSimFilterSet.FilterEntry]:
        """
        Returns the filter entries contains in this FilterSet.
        
        :return: the filter entries contains in this FilterSet
        :rtype: java.util.List[BSimFilterSet.FilterEntry]
        """

    def removeAll(self, filterType: ghidra.features.bsim.gui.filters.BSimFilterType):
        """
        Removes all filter entries for the given FilterType.
        
        :param ghidra.features.bsim.gui.filters.BSimFilterType filterType: the type of filters to be removed from this set
        """

    def size(self) -> int:
        """
        Returns the number of filter entries in this filter set.
        
        :return: the number of filter entries in this filter set
        :rtype: int
        """

    @property
    def bSimFilter(self) -> ghidra.features.bsim.query.protocol.BSimFilter:
        ...

    @property
    def filterEntries(self) -> java.util.List[BSimFilterSet.FilterEntry]:
        ...


class BSimFilterPanel(javax.swing.JPanel):
    """
    Panel for specifying and managing BSim filters.
    """

    @typing.type_check_only
    class ScrollablePanel(javax.swing.JPanel, javax.swing.Scrollable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, changeListener: utility.function.Callback):
        """
        Constructs a filer panel with no filters
        
        :param utility.function.Callback changeListener: the callback when filters change
        """

    @typing.overload
    def __init__(self, filters: java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType], filterSet: BSimFilterSet, changeListener: utility.function.Callback):
        """
        Constructs a filer panel with existing filters
        
        :param java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType] filters: the list of filterTypes to display in the comboBox
        :param BSimFilterSet filterSet: the current filter settings
        :param utility.function.Callback changeListener: the callback when filters change
        """

    def getFilterSet(self) -> BSimFilterSet:
        """
        Returns the set of valid filters that are displayed in this filter panel
        
        :return: the set of valid filters that are displayed in this filter panel
        :rtype: BSimFilterSet
        """

    def hasValidFilters(self) -> bool:
        """
        Returns true the panel has only valid filters. (Blank filter is ok)
        
        :return: true the panel has only valid filters
        :rtype: bool
        """

    def setFilterSet(self, filterSet: BSimFilterSet):
        """
        Sets the panel to have the given filters
        
        :param BSimFilterSet filterSet: the set of filters to show in the panel
        """

    def setFilters(self, filters: java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType]):
        """
        Sets the choices for filter types in the filter comboBoxes.
        
        :param java.util.List[ghidra.features.bsim.gui.filters.BSimFilterType] filters: the filter types the user can choose
        """

    @property
    def filterSet(self) -> BSimFilterSet:
        ...

    @filterSet.setter
    def filterSet(self, value: BSimFilterSet):
        ...


class BSimServerTableModel(docking.widgets.table.GDynamicColumnTableModel[ghidra.features.bsim.query.BSimServerInfo, java.lang.Object]):
    """
    Table model for BSim database server definitions.
     
    NOTE: This implementation assumes modal dialog use and non-changing connection state
    while instance is in-use.  This was done to avoid adding a conection listener which could
    introduce excessive overhead into the connection pool use.
    """

    @typing.type_check_only
    class DatabaseNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.features.bsim.query.BSimServerInfo, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TypeColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.features.bsim.query.BSimServerInfo, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UserInfoColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.features.bsim.query.BSimServerInfo, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HostColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.features.bsim.query.BSimServerInfo, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PortColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.features.bsim.query.BSimServerInfo, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ConnectionStatusColumnRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ConnectionPoolStatus]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ConnectionStatusColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.features.bsim.query.BSimServerInfo, ConnectionPoolStatus, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverManager: ghidra.features.bsim.gui.BSimServerManager):
        ...


class BSimSearchDialog(AbstractBSimSearchDialog):
    """
    Dialog for initiating a BSim similar function match search.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, service: BSimSearchService, serverManager: ghidra.features.bsim.gui.BSimServerManager, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
        ...



__all__ = ["AbstractBSimSearchDialog", "SelectedFunctionsTableDialog", "BSimServerDialog", "FunctionSymbolToFunctionTableRowMapper", "BSimSearchSettings", "CreateBsimServerInfoDialog", "ConnectionPoolStatus", "BSimSearchService", "BSimServerCache", "FilterWidget", "BSimServerManagerListener", "BSimOverviewDialog", "BSimFilterSet", "BSimFilterPanel", "BSimServerTableModel", "BSimSearchDialog"]
