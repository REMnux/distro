from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.protocol
import ghidra.program.database.symbol
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


R = typing.TypeVar("R")


class SFQueryResult(java.lang.Object):
    """
    The result of a call to :meth:`SimilarFunctionQueryService.querySimilarFunctions(SFQueryInfo, SFResultsUpdateListener, ghidra.util.task.TaskMonitor) <SimilarFunctionQueryService.querySimilarFunctions>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDatabaseInfo(self) -> DatabaseInfo:
        """
        Returns the function database information representing the database server.
        
        :return: the function database information representing the database server.
        :rtype: DatabaseInfo
        """

    def getQuery(self) -> SFQueryInfo:
        """
        The original query used to get the results represented by this object.
        
        :return: the original query used to get the results represented by this object.
        :rtype: SFQueryInfo
        """

    def getSimilarityResults(self) -> java.util.List[ghidra.features.bsim.query.protocol.SimilarityResult]:
        ...

    @property
    def query(self) -> SFQueryInfo:
        ...

    @property
    def databaseInfo(self) -> DatabaseInfo:
        ...

    @property
    def similarityResults(self) -> java.util.List[ghidra.features.bsim.query.protocol.SimilarityResult]:
        ...


class DefaultSFQueryServiceFactory(SFQueryServiceFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SFOverviewInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_QUERIES_PER_STAGE: typing.Final = 10

    def __init__(self, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
        """
        Constructs an overview request with default parameters.
        
        :param java.util.Set[ghidra.program.database.symbol.FunctionSymbol] functions: required--a set of functions (at least one) for which an overview will be 
                            computed.  All functions must be from the same program.
        :raises IllegalArgumentException: if ``functions`` is ``null``/empty or functions
        are from multiple programs.
        """

    def buildQueryNearestVector(self) -> ghidra.features.bsim.query.protocol.QueryNearestVector:
        ...

    def getFunctions(self) -> java.util.Set[ghidra.program.database.symbol.FunctionSymbol]:
        ...

    def getNumberOfStages(self, queries_per_stage: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getPreFilter(self) -> ghidra.features.bsim.query.protocol.PreFilter:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        
        
        :return: the program from which all queried functions are from
        :rtype: ghidra.program.model.listing.Program
        """

    def getSignificanceThreshold(self) -> float:
        ...

    def getSimilarityThreshold(self) -> float:
        ...

    def getVectorMax(self) -> int:
        ...

    def setSignificanceThreshold(self, significanceThreshold: typing.Union[jpype.JDouble, float]):
        ...

    def setSimilarityThreshold(self, similarityThreshold: typing.Union[jpype.JDouble, float]):
        ...

    def setVectorMax(self, max: typing.Union[jpype.JInt, int]):
        ...

    @property
    def preFilter(self) -> ghidra.features.bsim.query.protocol.PreFilter:
        ...

    @property
    def significanceThreshold(self) -> jpype.JDouble:
        ...

    @significanceThreshold.setter
    def significanceThreshold(self, value: jpype.JDouble):
        ...

    @property
    def functions(self) -> java.util.Set[ghidra.program.database.symbol.FunctionSymbol]:
        ...

    @property
    def numberOfStages(self) -> jpype.JInt:
        ...

    @property
    def similarityThreshold(self) -> jpype.JDouble:
        ...

    @similarityThreshold.setter
    def similarityThreshold(self, value: jpype.JDouble):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def vectorMax(self) -> jpype.JInt:
        ...

    @vectorMax.setter
    def vectorMax(self, value: jpype.JInt):
        ...


class SimilarFunctionQueryService(java.lang.AutoCloseable):
    """
    A simple class that allows the user to query a server for functions that match a given 
    set of functions.
    """

    @typing.type_check_only
    class NullListener(SFResultsUpdateListener[R], typing.Generic[R]):
        """
        A dumby listener that will be called as incremental results arrive from database queries.  
        No action is tacken for all results
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def changePassword(self, username: typing.Union[java.lang.String, str], newPassword: jpype.JArray[jpype.JChar]) -> str:
        """
        Issue password change request to the server
        
        :param java.lang.String or str username: to change
        :param jpype.JArray[jpype.JChar] newPassword: is password data
        :return: null if change was successful, or the error message
        :rtype: str
        """

    def dispose(self):
        ...

    def generateQueryNearest(self, queryInfo: SFQueryInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.features.bsim.query.protocol.QueryNearest:
        """
        Given a list of functions to query, prepare the final QueryNearest object which will be marshalled to the
        server.  This involves generating the signatures for each of the function and accumulating their
        FunctionDescriptions
        
        :param SFQueryInfo queryInfo: is the high-level form of query, with the list of FunctionSymbols and other parameters
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the QueryNearest object ready for the queryStaged method
        :rtype: ghidra.features.bsim.query.protocol.QueryNearest
        :raises QueryDatabaseException: if transferring functions fails
        """

    def generateQueryNearestVector(self, overviewInfo: SFOverviewInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.features.bsim.query.protocol.QueryNearestVector:
        ...

    def getDatabaseCompatibility(self) -> str:
        """
        Returns a string explaining the database compatibility between this client and the server.
        
        :return: a string explaining the compatibility, or null if it could not be determined
        :rtype: str
        """

    def getDatabaseConnectionType(self) -> ghidra.features.bsim.query.FunctionDatabase.ConnectionType:
        ...

    def getDatabaseInformation(self) -> ghidra.features.bsim.query.description.DatabaseInformation:
        ...

    def getDatabaseStatus(self) -> ghidra.features.bsim.query.FunctionDatabase.Status:
        ...

    def getLSHVectorFactory(self) -> generic.lsh.vector.LSHVectorFactory:
        ...

    def getLastError(self) -> ghidra.features.bsim.query.FunctionDatabase.BSimError:
        ...

    def getServerInfo(self) -> ghidra.features.bsim.query.BSimServerInfo:
        """
        Return the :obj:`server info object <BSimServerInfo>` for this database
        
        :return: the server info object or null if not currently associated with 
        a :obj:`FunctionDatabase`.
        :rtype: ghidra.features.bsim.query.BSimServerInfo
        """

    def getUserName(self) -> str:
        ...

    def initializeDatabase(self, serverURLString: typing.Union[java.lang.String, str]):
        ...

    def overviewSimilarFunctions(self, overviewInfo: SFOverviewInfo, listener: SFResultsUpdateListener[ghidra.features.bsim.query.protocol.ResponseNearestVector], monitor: ghidra.util.task.TaskMonitor) -> ghidra.features.bsim.query.protocol.ResponseNearestVector:
        """
        Query the given server for similar function overview information
        
        :param SFOverviewInfo overviewInfo: is details of the overview query
        :param SFResultsUpdateListener[ghidra.features.bsim.query.protocol.ResponseNearestVector] listener: is the listener to be informed of the query status and incremental results 
                coming back, may be null
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the ResponseNearestVector
        :rtype: ghidra.features.bsim.query.protocol.ResponseNearestVector
        :raises QueryDatabaseException: if the database connection cannot be established
        :raises CancelledException: if the query is cancelled by the user
        """

    def queryRaw(self, query: ghidra.features.bsim.query.protocol.BSimQuery[typing.Any], stagingManager: ghidra.features.bsim.query.protocol.StagingManager, listener: SFResultsUpdateListener[ghidra.features.bsim.query.protocol.QueryResponseRecord], monitor: ghidra.util.task.TaskMonitor) -> ghidra.features.bsim.query.protocol.QueryResponseRecord:
        """
        A lower-level (more flexible) query of the database.  The query is not staged.
        
        :param ghidra.features.bsim.query.protocol.BSimQuery[typing.Any] query: is the raw query information
        :param ghidra.features.bsim.query.protocol.StagingManager stagingManager: is how to split up the query, can be null
        :param SFResultsUpdateListener[ghidra.features.bsim.query.protocol.QueryResponseRecord] listener: is the listener to be informed of the query status and incremental results 
                coming back, may be null
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the raw response record from the database
        :rtype: ghidra.features.bsim.query.protocol.QueryResponseRecord
        :raises QueryDatabaseException: if the database connection cannot be established
        :raises CancelledException: if the query is cancelled by the user
        """

    def querySimilarFunctions(self, queryInfo: SFQueryInfo, listener: SFResultsUpdateListener[SFQueryResult], monitor: ghidra.util.task.TaskMonitor) -> SFQueryResult:
        """
        Query the given server with the parameters provider by ``queryInfo``.
        
        :param SFQueryInfo queryInfo: a query info object containing the settings for the query
        :param SFResultsUpdateListener[SFQueryResult] listener: is the listener to be informed of the query status and incremental results 
                coming back, may be null
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use; can be null
        :return: the result object containing the retrieved similar functions; null if the query
                was cancelled
        :rtype: SFQueryResult
        :raises QueryDatabaseException: if the query execution fails
        :raises CancelledException: if the query is cancelled by the user
        """

    def setNumberOfStages(self, val: typing.Union[jpype.JInt, int]):
        ...

    def updateProgram(self, newProgram: ghidra.program.model.listing.Program):
        ...

    @property
    def lSHVectorFactory(self) -> generic.lsh.vector.LSHVectorFactory:
        ...

    @property
    def databaseCompatibility(self) -> java.lang.String:
        ...

    @property
    def lastError(self) -> ghidra.features.bsim.query.FunctionDatabase.BSimError:
        ...

    @property
    def databaseConnectionType(self) -> ghidra.features.bsim.query.FunctionDatabase.ConnectionType:
        ...

    @property
    def serverInfo(self) -> ghidra.features.bsim.query.BSimServerInfo:
        ...

    @property
    def databaseStatus(self) -> ghidra.features.bsim.query.FunctionDatabase.Status:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...

    @property
    def databaseInformation(self) -> ghidra.features.bsim.query.description.DatabaseInformation:
        ...


class SFQueryInfo(java.lang.Object):
    """
    A simple container object to hold information that is to be sent to a database server as
    part of a query to find functions that are similar to those given in the constructor of this
    class.  For a list of configurable parameters, see the setter methods of this class.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_QUERIES_PER_STAGE: typing.Final = 10
    """
    The number of queries to make for the given set of functions.  For example, if 100 functions
    are submitted and the number of stages is 10, then 10 queries will be made to the server, 
    with 10 functions per request.
     
    
    This defaults to 1, which means to send all functions in one query.
    """


    def __init__(self, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
        """
        Constructs a query request with default parameters.
        
        :param java.util.Set[ghidra.program.database.symbol.FunctionSymbol] functions: required--a set of functions (at least one) for which similar functions
                        will searched.  All functions must be from the same program.
        :raises IllegalArgumentException: if ``functions`` is ``null``/empty or functions
        are from multiple programs.
        """

    def buildQueryNearest(self) -> ghidra.features.bsim.query.protocol.QueryNearest:
        ...

    def getBsimFilter(self) -> ghidra.features.bsim.query.protocol.BSimFilter:
        ...

    def getFilterInfoStrings(self) -> java.util.Collection[java.lang.String]:
        ...

    def getFunctions(self) -> java.util.Set[ghidra.program.database.symbol.FunctionSymbol]:
        """
        Returns the input functions for which matches will be searched.
        
        :return: the input functions for which matches will be searched.
        :rtype: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]
        """

    def getMaximumResults(self) -> int:
        """
        The maximum number of similar functions to return **for a given input function**
        The default value is :const:`QueryNearest.DEFAULT_MAX_MATCHES`.
        
        :return: The maximum number of similar functions to return
        :rtype: int
        """

    def getNumberOfStages(self, queries_per_stage: typing.Union[jpype.JInt, int]) -> int:
        """
        The number of queries to make for the given set of functions.  For example, if 100 functions
        are submitted and the number of stages is 10, then 10 queries will be made to the server, 
        with 10 functions per request.
         
        
        This defaults to 1, which means to send all functions in one query.
        
        :param jpype.JInt or int queries_per_stage: how many queries to initiate per stage
        :return: the number of queries to make for the given set of functions.
        :rtype: int
        """

    def getPreFilter(self) -> ghidra.features.bsim.query.protocol.PreFilter:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        
        
        :return: the program from which all queried functions are from
        :rtype: ghidra.program.model.listing.Program
        """

    def getSignificanceThreshold(self) -> float:
        """
        Gets the threshold under which a potential similar function will not be matched.  This
        threshold is for how significant the match is (for example, smaller function matches
        are less significant).  Higher is more significant.  There is no upper bound. The 
        default value is :const:`QueryNearest.DEFAULT_SIGNIFICANCE_THRESHOLD`.
        
        :return: threshold under which a potential similar function will not be matched.
        :rtype: float
        """

    def getSimilarityThreshold(self) -> float:
        """
        Gets the threshold under which a potential similar function will not be matched.  This
        threshold is for how similar the potential function is. This is a value from 0.0 to 1.0. The 
        default value is :const:`QueryNearest.DEFAULT_SIMILARITY_THRESHOLD`.
        
        :return: threshold under which a potential similar function will not be matched.
        :rtype: float
        """

    def setFunctions(self, functions: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
        """
        Sets the input functions for which matches will be searched.
        
        :param java.util.Set[ghidra.program.database.symbol.FunctionSymbol] functions: the input functions for which matches will be searched.
        """

    def setMaximumResults(self, maximumResults: typing.Union[jpype.JInt, int]):
        """
        
        
        :param jpype.JInt or int maximumResults: the new maximum
        
        .. seealso::
        
            | :obj:`.getMaximumResults()`
        """

    def setSignificanceThreshold(self, significanceThreshold: typing.Union[jpype.JDouble, float]):
        """
        
        
        :param jpype.JDouble or float significanceThreshold: the new threshold
        
        .. seealso::
        
            | :obj:`.getSignificanceThreshold()`
        """

    def setSimilarityThreshold(self, similarityThreshold: typing.Union[jpype.JDouble, float]):
        """
        
        
        :param jpype.JDouble or float similarityThreshold: the new threshold
        
        .. seealso::
        
            | :obj:`.getSimilarityThreshold()`
        """

    @property
    def maximumResults(self) -> jpype.JInt:
        ...

    @maximumResults.setter
    def maximumResults(self, value: jpype.JInt):
        ...

    @property
    def preFilter(self) -> ghidra.features.bsim.query.protocol.PreFilter:
        ...

    @property
    def significanceThreshold(self) -> jpype.JDouble:
        ...

    @significanceThreshold.setter
    def significanceThreshold(self, value: jpype.JDouble):
        ...

    @property
    def functions(self) -> java.util.Set[ghidra.program.database.symbol.FunctionSymbol]:
        ...

    @functions.setter
    def functions(self, value: java.util.Set[ghidra.program.database.symbol.FunctionSymbol]):
        ...

    @property
    def bsimFilter(self) -> ghidra.features.bsim.query.protocol.BSimFilter:
        ...

    @property
    def filterInfoStrings(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def numberOfStages(self) -> jpype.JInt:
        ...

    @property
    def similarityThreshold(self) -> jpype.JDouble:
        ...

    @similarityThreshold.setter
    def similarityThreshold(self, value: jpype.JDouble):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class QueryDatabaseException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], e: java.lang.Exception):
        ...

    @typing.overload
    def __init__(self, e: java.lang.Exception):
        ...


class SFQueryServiceFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def createSFQueryService(self, program: ghidra.program.model.listing.Program) -> SimilarFunctionQueryService:
        ...


class DatabaseInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverURL: typing.Union[java.lang.String, str], databaseInformation: ghidra.features.bsim.query.description.DatabaseInformation):
        ...

    def getDescription(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getOwner(self) -> str:
        ...

    def getServerURL(self) -> str:
        ...

    def getVersion(self) -> str:
        ...

    def isReadOnly(self) -> bool:
        ...

    @property
    def owner(self) -> java.lang.String:
        ...

    @property
    def serverURL(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def version(self) -> java.lang.String:
        ...


class SFResultsUpdateListener(java.lang.Object, typing.Generic[R]):
    """
    A listener that will be called as incremental results arrive from database queries.  
    The results given to this listener are always a subset of the complete results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def resultAdded(self, partialResponse: ghidra.features.bsim.query.protocol.QueryResponseRecord):
        """
        Called as incremental results arrive from database queries.  The results given to
        this listener are always a subset of the complete results--they are not comprehensive.
        Consumer should be able to safely cast response based upon the type of query being performed.
        
        :param ghidra.features.bsim.query.protocol.QueryResponseRecord partialResponse: a partial result record with the recently received results.
        """

    def setFinalResult(self, result: R):
        """
        Callback to supply the final accumulated result.
        
        :param R result: accumulated query result or null if a failure occured which prevented
        results from being returned.
        """


class FunctionSymbolIterator(java.util.Iterator[ghidra.program.model.listing.Function]):
    """
    Convert an iterator over FunctionSymbols into an iterator over the Functions
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iter: java.util.Iterator[ghidra.program.database.symbol.FunctionSymbol]):
        ...



__all__ = ["SFQueryResult", "DefaultSFQueryServiceFactory", "SFOverviewInfo", "SimilarFunctionQueryService", "SFQueryInfo", "QueryDatabaseException", "SFQueryServiceFactory", "DatabaseInfo", "SFResultsUpdateListener", "FunctionSymbolIterator"]
