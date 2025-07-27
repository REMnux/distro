from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.features.bsim.gui.overview
import ghidra.features.bsim.gui.search.dialog
import ghidra.features.bsim.gui.search.results
import ghidra.features.bsim.query
import ghidra.features.bsim.query.facade
import ghidra.features.bsim.query.protocol
import ghidra.framework.plugintool
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class BSimServerManager(java.lang.Object):
    """
    Managers BSim database server definitions and connections
    """

    class_: typing.ClassVar[java.lang.Class]

    def addListener(self, listener: ghidra.features.bsim.gui.search.dialog.BSimServerManagerListener):
        ...

    def addServer(self, newServerInfo: ghidra.features.bsim.query.BSimServerInfo):
        """
        Add server to list.  Method must be invoked from swing thread only.
        
        :param ghidra.features.bsim.query.BSimServerInfo newServerInfo: new BSim DB server
        """

    @staticmethod
    def getDataSource(serverInfo: ghidra.features.bsim.query.BSimServerInfo) -> ghidra.features.bsim.query.BSimJDBCDataSource:
        """
        Convenience method to get a new or existing BSim JDBC datasource
        
        :param ghidra.features.bsim.query.BSimServerInfo serverInfo: BSim DB server info
        :return: BSim DB datasource or null if server does not support a
        :obj:`BSimJDBCDataSource`.
        :rtype: ghidra.features.bsim.query.BSimJDBCDataSource
        """

    @staticmethod
    def getDataSourceIfExists(serverInfo: ghidra.features.bsim.query.BSimServerInfo) -> ghidra.features.bsim.query.BSimJDBCDataSource:
        """
        Convenience method to get existing BSim JDBC datasource
        
        :param ghidra.features.bsim.query.BSimServerInfo serverInfo: BSim DB server info
        :return: BSim DB datasource or null if not instantiated or server does not support a
        :obj:`BSimJDBCDataSource`.
        :rtype: ghidra.features.bsim.query.BSimJDBCDataSource
        """

    def getServerInfos(self) -> java.util.Set[ghidra.features.bsim.query.BSimServerInfo]:
        """
        Get list of defined servers.  Method must be invoked from swing thread only.
        
        :return: list of defined servers
        :rtype: java.util.Set[ghidra.features.bsim.query.BSimServerInfo]
        """

    def removeListener(self, listener: ghidra.features.bsim.gui.search.dialog.BSimServerManagerListener):
        ...

    def removeServer(self, info: ghidra.features.bsim.query.BSimServerInfo, force: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Remove BSim DB server from list.  Method must be invoked from swing thread only.
        Specified server datasource will be dispose unless it is active or force is true.
        
        :param ghidra.features.bsim.query.BSimServerInfo info: BSim DB server to be removed
        :param jpype.JBoolean or bool force: true if server datasource should be disposed even when active.
        :return: true if server disposed and removed from list
        :rtype: bool
        """

    @property
    def serverInfos(self) -> java.util.Set[ghidra.features.bsim.query.BSimServerInfo]:
        ...


class BSimSearchPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Plugin for BSim search features
    """

    @typing.type_check_only
    class AbstractProgramTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OverviewTask(BSimSearchPlugin.AbstractProgramTask, ghidra.features.bsim.query.facade.SFResultsUpdateListener[ghidra.features.bsim.query.protocol.ResponseNearestVector]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, serverCache: ghidra.features.bsim.gui.search.dialog.BSimServerCache, settings: ghidra.features.bsim.gui.search.dialog.BSimSearchSettings, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
            ...


    @typing.type_check_only
    class SearchTask(BSimSearchPlugin.AbstractProgramTask, ghidra.features.bsim.query.facade.SFResultsUpdateListener[ghidra.features.bsim.query.facade.SFQueryResult]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, serverCache: ghidra.features.bsim.gui.search.dialog.BSimServerCache, settings: ghidra.features.bsim.gui.search.dialog.BSimSearchSettings, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
            ...


    @typing.type_check_only
    class MyBSimSearchService(ghidra.features.bsim.gui.search.dialog.BSimSearchService):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    HELP_TOPIC: typing.Final = "BSimSearchPlugin"

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        ...

    def closeAllProviders(self):
        ...

    def doBSimSearch(self, program: ghidra.program.model.listing.Program, functionAddresses: java.util.List[ghidra.program.model.address.Address], showDialog: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def providerClosed(self, provider: ghidra.features.bsim.gui.search.results.BSimSearchResultsProvider):
        ...

    @typing.overload
    def providerClosed(self, overviewProvider: ghidra.features.bsim.gui.overview.BSimOverviewProvider):
        ...



__all__ = ["BSimServerManager", "BSimSearchPlugin"]
