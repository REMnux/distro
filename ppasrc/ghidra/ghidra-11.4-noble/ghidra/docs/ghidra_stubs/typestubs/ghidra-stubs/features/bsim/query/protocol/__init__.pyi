from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra.features.bsim.gui.filters
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.program.model.listing
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


R = typing.TypeVar("R")


class QueryOptionalExist(BSimQuery[ResponseOptionalExist]):
    """
    Query whether an optional table exists. If it doesn't exist it can be created.
    If it exists, it can be cleared
    """

    class_: typing.ClassVar[java.lang.Class]
    optionalresponse: ResponseOptionalExist
    tableName: java.lang.String
    keyType: jpype.JInt
    valueType: jpype.JInt
    attemptCreation: jpype.JBoolean
    clearTable: jpype.JBoolean

    def __init__(self):
        ...


class DropDatabase(BSimQuery[ResponseDropDatabase]):

    class_: typing.ClassVar[java.lang.Class]
    databaseName: java.lang.String
    dropResponse: ResponseDropDatabase

    def __init__(self):
        ...


class ResponseChildren(QueryResponseRecord):
    """
    Response to a QueryChildren request to a BSim database.  A full FunctionDescription is returned for
    every name in the original request and their children (1-level).  The FunctionDescriptions corresponding
    to the original list of function names are also collected in the -correspond- array.
    """

    class_: typing.ClassVar[java.lang.Class]
    manage: ghidra.features.bsim.query.description.DescriptionManager
    correspond: java.util.List[ghidra.features.bsim.query.description.FunctionDescription]
    qchild: QueryChildren

    def __init__(self, qc: QueryChildren):
        ...


class NullStaging(StagingManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PairNote(java.lang.Object):
    """
    Result of a comparison between two functions.
    Includes descriptors for the original functions, the similarity and significance scores
    and other score information.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, f1: ghidra.features.bsim.query.description.FunctionDescription, f2: ghidra.features.bsim.query.description.FunctionDescription, sm: typing.Union[jpype.JDouble, float], sf: typing.Union[jpype.JDouble, float], dp: typing.Union[jpype.JDouble, float], c1: typing.Union[jpype.JInt, int], c2: typing.Union[jpype.JInt, int], ic: typing.Union[jpype.JInt, int]):
        ...

    def getDotProduct(self) -> float:
        ...

    def getFunc1HashCount(self) -> int:
        ...

    def getFunc2HashCount(self) -> int:
        ...

    def getIntersectionCount(self) -> int:
        ...

    def getSignificance(self) -> float:
        ...

    def getSimilarity(self) -> float:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, writer: java.io.Writer):
        ...

    @property
    def significance(self) -> jpype.JDouble:
        ...

    @property
    def similarity(self) -> jpype.JDouble:
        ...

    @property
    def func2HashCount(self) -> jpype.JInt:
        ...

    @property
    def func1HashCount(self) -> jpype.JInt:
        ...

    @property
    def dotProduct(self) -> jpype.JDouble:
        ...

    @property
    def intersectionCount(self) -> jpype.JInt:
        ...


class ResponseError(QueryResponseRecord):

    class_: typing.ClassVar[java.lang.Class]
    errorMessage: java.lang.String

    def __init__(self):
        ...


class SimilarityVectorResult(java.lang.Object):
    """
    A collection of vector matches to an (originally) queried function
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, f: ghidra.features.bsim.query.description.FunctionDescription):
        ...

    def addNotes(self, newnotes: java.util.List[ghidra.features.bsim.query.description.VectorResult]):
        ...

    def getBase(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    def getTotalCount(self) -> int:
        ...

    def iterator(self) -> java.util.Iterator[ghidra.features.bsim.query.description.VectorResult]:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory, qmanage: ghidra.features.bsim.query.description.DescriptionManager, exeMap: collections.abc.Mapping):
        ...

    def saveXml(self, write: java.io.Writer):
        ...

    def sortNotes(self):
        ...

    @property
    def totalCount(self) -> jpype.JInt:
        ...

    @property
    def base(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...


class ResponseDelete(QueryResponseRecord):
    """
    Response to a QueryDelete request containing a listing of the md5's of successfully deleted executables and
    a count of their functions. If a requested executable could not be deleted for some reason it is listed in
    a separate -missedlist-
    """

    class DeleteResult(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        md5: java.lang.String
        name: java.lang.String
        funccount: jpype.JInt

        def __init__(self):
            ...

        def restoreXml(self, parser: ghidra.xml.XmlPullParser):
            ...

        def saveXml(self, fwrite: java.io.Writer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    reslist: java.util.List[ResponseDelete.DeleteResult]
    missedlist: java.util.List[ExeSpecifier]

    def __init__(self):
        ...


class QueryInfo(BSimQuery[ResponseInfo]):
    """
    Request the DatabaseInformation object for a specific BSim database.
    """

    class_: typing.ClassVar[java.lang.Class]
    inforesponse: ResponseInfo

    def __init__(self):
        ...


class InstallTagRequest(BSimQuery[ResponseInfo]):
    """
    Request that a new function tag be installed for a specific BSim server
    """

    class_: typing.ClassVar[java.lang.Class]
    tag_name: java.lang.String
    installresponse: ResponseInfo

    def __init__(self):
        ...


class ResponseUpdate(QueryResponseRecord):
    """
    Response to a QueryUpdate request to a BSim database.  Simple counts of successful updates are given.
    References to any original ExecutableRecord or FunctionDescription objects that could not be updated
    are also returned.
    """

    class_: typing.ClassVar[java.lang.Class]
    badexe: java.util.List[ghidra.features.bsim.query.description.ExecutableRecord]
    badfunc: java.util.List[ghidra.features.bsim.query.description.FunctionDescription]
    exeupdate: jpype.JInt
    funcupdate: jpype.JInt
    qupdate: QueryUpdate

    def __init__(self, q: QueryUpdate):
        ...


class ResponseNearestVector(QueryResponseRecord):
    """
    Response to a QueryNearestVector request. It provides basic stats on the number of matching vectors and functions.
    Only a list of the matching vectors is returned, not the detailed FunctionDescription records of matches.
    Results are returned as SimilarityVectorResult objects, which cross-reference the original function queried and
    any similar vectors.
    """

    class_: typing.ClassVar[java.lang.Class]
    totalvec: jpype.JInt
    totalmatch: jpype.JInt
    uniquematch: jpype.JInt
    result: java.util.List[SimilarityVectorResult]
    qnear: QueryNearestVector

    def __init__(self, q: QueryNearestVector):
        ...


class PasswordChange(BSimQuery[ResponsePassword]):
    """
    Request a password change for a specific user
    Currently provides no explicit protection for password data on the client.
    Should be used in conjunction with connection encryption (SSL) to protect
    data in transit to the server.
    """

    class_: typing.ClassVar[java.lang.Class]
    passwordResponse: ResponsePassword
    username: java.lang.String
    newPassword: jpype.JArray[jpype.JChar]

    def __init__(self):
        ...

    def clearPassword(self):
        """
        Clear the password data.  (Should be) used by database client immediately upon sending request to server
        """


class InsertRequest(BSimQuery[ResponseInsert]):
    """
    Request that specific executables and functions (as described by ExecutableRecords and FunctionDescriptions)
    by inserted into a BSim database.
    """

    class_: typing.ClassVar[java.lang.Class]
    manage: ghidra.features.bsim.query.description.DescriptionManager
    repo_override: java.lang.String
    path_override: java.lang.String
    insertresponse: ResponseInsert

    def __init__(self):
        ...


class ClusterNote(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, f: ghidra.features.bsim.query.description.FunctionDescription, ss: typing.Union[jpype.JInt, int], ms: typing.Union[jpype.JDouble, float], sig: typing.Union[jpype.JDouble, float]):
        ...

    def getFunctionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    def getMaxSimilarity(self) -> float:
        ...

    def getSignificance(self) -> float:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, manage: ghidra.features.bsim.query.description.DescriptionManager, xrefMap: collections.abc.Mapping):
        ...

    def saveXml(self, write: java.io.Writer):
        ...

    @property
    def significance(self) -> jpype.JDouble:
        ...

    @property
    def maxSimilarity(self) -> jpype.JDouble:
        ...

    @property
    def functionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...


class QueryCluster(BSimQuery[ResponseCluster]):

    class_: typing.ClassVar[java.lang.Class]
    manage: typing.Final[ghidra.features.bsim.query.description.DescriptionManager]
    clusterresponse: ResponseCluster
    thresh: jpype.JDouble
    signifthresh: jpype.JDouble
    vectormax: jpype.JInt

    def __init__(self):
        ...


class QueryUpdate(BSimQuery[ResponseUpdate]):
    """
    Request to update the metadata fields of various ExecutableRecords and FunctionDescriptions within a BSim database.
    This allows quick updates of metadata fields like executable names, function names, and other descriptive metadata fields,
    without affecting the main index. ExecutableRecord descriptions will be replaced based on the md5 of the executable,
    and FunctionDescriptions are replaced based on their address within an identified executable.
    within an executable.
    """

    class_: typing.ClassVar[java.lang.Class]
    manage: ghidra.features.bsim.query.description.DescriptionManager
    updateresponse: ResponseUpdate

    def __init__(self):
        ...


class QueryVectorMatch(BSimQuery[ResponseVectorMatch]):
    """
    Request all functions described by a particular feature vector. Vectors are specified
    by a known id, and multiple vectors can be specified at once.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_MAX_FUNCTIONS: typing.Final = 200
    matchresponse: ResponseVectorMatch
    max: jpype.JInt
    fillinCategories: jpype.JBoolean
    bsimFilter: BSimFilter
    vectorIds: java.util.List[java.lang.Long]

    def __init__(self):
        ...


class QueryPair(BSimQuery[ResponsePair]):
    """
    A list of descriptor pairs to be sent to the server.
    Each pair describes a pair of functions in the database whose vectors are to be compared
    """

    class_: typing.ClassVar[java.lang.Class]
    pairs: java.util.List[PairInput]
    pairResponse: ResponsePair

    def __init__(self):
        ...


class ResponseCluster(QueryResponseRecord):

    class_: typing.ClassVar[java.lang.Class]
    notes: java.util.List[ClusterNote]
    query: QueryCluster

    def __init__(self, q: QueryCluster):
        ...


class ResponseVectorId(QueryResponseRecord):
    """
    Response to a QueryVectorId request to a BSim database.  For each id in the
    request, return a VectorResult, which contains the corresponding full vector,
    or return null
    """

    class_: typing.ClassVar[java.lang.Class]
    vectorResults: java.util.List[ghidra.features.bsim.query.description.VectorResult]

    def __init__(self):
        ...


class ResponseName(QueryResponseRecord):
    """
    Response to a request for specific executables and functions given by name.
    Full ExecutableRecords and FunctionDescriptions are instantiated in this object's DescriptionManager
    """

    class_: typing.ClassVar[java.lang.Class]
    manage: typing.Final[ghidra.features.bsim.query.description.DescriptionManager]
    uniqueexecutable: jpype.JBoolean
    printselfsig: jpype.JBoolean
    printjustexe: jpype.JBoolean

    def __init__(self):
        ...

    def printRaw(self, stream: java.io.PrintStream, vectorFactory: generic.lsh.vector.LSHVectorFactory, format: typing.Union[jpype.JInt, int]):
        ...


class InstallMetadataRequest(BSimQuery[ResponseInfo]):
    """
    Request that the high-level meta-data fields (name,owner,description) of a database be changed
    """

    class_: typing.ClassVar[java.lang.Class]
    dbname: java.lang.String
    owner: java.lang.String
    description: java.lang.String
    installresponse: ResponseInfo

    def __init__(self):
        ...


class ResponseOptionalExist(QueryResponseRecord):
    """
    Response to a QueryOptionalExist, reporting whether an optional table exists
    """

    class_: typing.ClassVar[java.lang.Class]
    tableExists: jpype.JBoolean
    wasCreated: jpype.JBoolean

    def __init__(self):
        ...


class QueryExeInfo(BSimQuery[ResponseExe]):
    """
    Query of executable records
    """

    class_: typing.ClassVar[java.lang.Class]
    exeresponse: ResponseExe
    limit: jpype.JInt
    filterMd5: java.lang.String
    filterExeName: java.lang.String
    filterArch: java.lang.String
    filterCompilerName: java.lang.String
    sortColumn: ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn
    includeFakes: jpype.JBoolean
    fillinCategories: jpype.JBoolean

    @typing.overload
    def __init__(self):
        """
        Default query for the first 20 executables in the database
        """

    @typing.overload
    def __init__(self, limit: typing.Union[jpype.JInt, int], filterMd5: typing.Union[java.lang.String, str], filterExeName: typing.Union[java.lang.String, str], filterArch: typing.Union[java.lang.String, str], filterCompilerName: typing.Union[java.lang.String, str], sortColumn: ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn, includeFakes: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param jpype.JInt or int limit: the max number of results to return
        :param java.lang.String or str filterMd5: md5 the md5 filter
        :param java.lang.String or str filterExeName: the exe filter
        :param java.lang.String or str filterArch: the architecture filter
        :param java.lang.String or str filterCompilerName: the compiler name filter
        :param ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn sortColumn: the primary sort column name
        :param jpype.JBoolean or bool includeFakes: if false, will exclude generated MD5s starting with "bbbbbbbbaaaaaaaa"
        """


class ExeSpecifier(java.lang.Comparable[ExeSpecifier]):

    class_: typing.ClassVar[java.lang.Class]
    exename: java.lang.String
    arch: java.lang.String
    execompname: java.lang.String
    exemd5: java.lang.String

    def __init__(self):
        ...

    def getExeNameWithMD5(self) -> str:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    def transfer(self, op2: ghidra.features.bsim.query.description.ExecutableRecord):
        ...

    @property
    def exeNameWithMD5(self) -> java.lang.String:
        ...


class CreateDatabase(BSimQuery[ResponseInfo]):

    class_: typing.ClassVar[java.lang.Class]
    config_template: java.lang.String
    info: ghidra.features.bsim.query.description.DatabaseInformation
    inforesponse: ResponseInfo

    def __init__(self):
        ...


class QueryDelete(BSimQuery[ResponseDelete]):
    """
    Request that a specific list of executables be deleted from a BSim database
    """

    class_: typing.ClassVar[java.lang.Class]
    exelist: java.util.List[ExeSpecifier]
    respdelete: ResponseDelete

    def __init__(self):
        ...

    def addSpecifier(self, spec: ExeSpecifier):
        ...


class QueryNearestVector(BSimQuery[ResponseNearestVector]):
    """
    For specific functions, query for the list of vectors that are similar to a functions vector,
    without recovering the descriptions of functions that instantiate these vectors.
    """

    class_: typing.ClassVar[java.lang.Class]
    manage: ghidra.features.bsim.query.description.DescriptionManager
    nearresponse: ResponseNearestVector
    thresh: jpype.JDouble
    signifthresh: jpype.JDouble
    vectormax: jpype.JInt

    def __init__(self):
        ...


class InsertOptionalValues(BSimQuery[ResponseOptionalExist]):
    """
    Insert key/value pairs into an optional table
    """

    class_: typing.ClassVar[java.lang.Class]
    optionalresponse: ResponseOptionalExist
    tableName: java.lang.String
    keyType: jpype.JInt
    valueType: jpype.JInt
    keys: jpype.JArray[java.lang.Object]
    values: jpype.JArray[java.lang.Object]

    def __init__(self):
        ...


class ResponseInsert(QueryResponseRecord):
    """
    A simple response to an InsertRequest to a BSim database.
    This object provides separate counts of executables successfully inserted and functions successfully inserted.
    """

    class_: typing.ClassVar[java.lang.Class]
    numexe: jpype.JInt
    numfunc: jpype.JInt

    def __init__(self):
        ...


class SimilarityNote(java.lang.Comparable[SimilarityNote]):
    """
    A description of a single function match
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, f: ghidra.features.bsim.query.description.FunctionDescription, sm: typing.Union[jpype.JDouble, float], sf: typing.Union[jpype.JDouble, float]):
        ...

    def getFunctionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    def getSignificance(self) -> float:
        ...

    def getSimilarity(self) -> float:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, manage: ghidra.features.bsim.query.description.DescriptionManager, exeMap: collections.abc.Mapping):
        ...

    def saveXml(self, write: java.io.Writer):
        ...

    def setTransfer(self, op2: SimilarityNote, manage: ghidra.features.bsim.query.description.DescriptionManager, transsig: typing.Union[jpype.JBoolean, bool]):
        ...

    def transfer(self, manage: ghidra.features.bsim.query.description.DescriptionManager, transsig: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def significance(self) -> jpype.JDouble:
        ...

    @property
    def similarity(self) -> jpype.JDouble:
        ...

    @property
    def functionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...


class ResponseInfo(QueryResponseRecord):

    class_: typing.ClassVar[java.lang.Class]
    info: ghidra.features.bsim.query.description.DatabaseInformation

    def __init__(self):
        ...


class FilterAtom(java.lang.Object):
    """
    A single element for filtering on specific properties of ExecutableRecords or FunctionDescriptions
    Each FilterAtom consists of a FilterTemplate describing the property to filter on, and how the filter should apply,
    and a String -value- that the property should match (or not)
    """

    class_: typing.ClassVar[java.lang.Class]
    type: ghidra.features.bsim.gui.filters.BSimFilterType
    value: java.lang.String

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, type: ghidra.features.bsim.gui.filters.BSimFilterType, value: typing.Union[java.lang.String, str]):
        ...

    def evaluate(self, rec: ghidra.features.bsim.query.description.ExecutableRecord) -> bool:
        """
        
        
        :param ghidra.features.bsim.query.description.ExecutableRecord rec: is a specific ExecutableRecord
        :return: true if this FilterAtom would let the specific executable pass the filter
        :rtype: bool
        """

    def getInfoString(self) -> str:
        ...

    def getValueString(self) -> str:
        ...

    def isValid(self) -> bool:
        """
        Returns true if this Atom has a non-null value
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def infoString(self) -> java.lang.String:
        ...

    @property
    def valueString(self) -> java.lang.String:
        ...


class PairInput(java.lang.Object):
    """
    Identifiers for a pair of functions
    """

    class_: typing.ClassVar[java.lang.Class]
    execA: ExeSpecifier
    funcA: FunctionEntry
    execB: ExeSpecifier
    funcB: FunctionEntry

    def __init__(self):
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, writer: java.io.Writer):
        ...


class PreFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addPredicate(self, predicate: java.util.function.BiPredicate[ghidra.program.model.listing.Program, ghidra.features.bsim.query.description.FunctionDescription]):
        ...

    def clearFilters(self):
        ...

    def getAndReducedPredicate(self) -> java.util.function.BiPredicate[ghidra.program.model.listing.Program, ghidra.features.bsim.query.description.FunctionDescription]:
        ...

    def getOrReducedPredicate(self) -> java.util.function.BiPredicate[ghidra.program.model.listing.Program, ghidra.features.bsim.query.description.FunctionDescription]:
        ...

    @property
    def orReducedPredicate(self) -> java.util.function.BiPredicate[ghidra.program.model.listing.Program, ghidra.features.bsim.query.description.FunctionDescription]:
        ...

    @property
    def andReducedPredicate(self) -> java.util.function.BiPredicate[ghidra.program.model.listing.Program, ghidra.features.bsim.query.description.FunctionDescription]:
        ...


class QueryResponseRecord(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDescriptionManager(self) -> ghidra.features.bsim.query.description.DescriptionManager:
        ...

    def getLocalStagingCopy(self) -> QueryResponseRecord:
        """
        
        
        :return: a partial clone of this query suitable for holding local stages of the query via StagingManager
        :rtype: QueryResponseRecord
        """

    def getName(self) -> str:
        ...

    def mergeResults(self, subresponse: QueryResponseRecord):
        """
        Combine partial results from subresponse into this global response
        
        :param QueryResponseRecord subresponse: the partial response to merge into this
        :raises LSHException: for errors performing the merge
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    def sort(self):
        """
        Perform any preferred sorting on the result of a query
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def localStagingCopy(self) -> QueryResponseRecord:
        ...

    @property
    def descriptionManager(self) -> ghidra.features.bsim.query.description.DescriptionManager:
        ...


class ResponseDropDatabase(QueryResponseRecord):
    """
    Response of server indicating whether a password change request (:obj:`PasswordChange`) succeeded
    """

    class_: typing.ClassVar[java.lang.Class]
    operationSupported: jpype.JBoolean
    dropSuccessful: jpype.JBoolean
    errorMessage: java.lang.String

    def __init__(self):
        ...


class ResponsePassword(QueryResponseRecord):
    """
    Response of server indicating whether a password change request (:obj:`PasswordChange`) succeeded
    """

    class_: typing.ClassVar[java.lang.Class]
    changeSuccessful: jpype.JBoolean
    errorMessage: java.lang.String

    def __init__(self):
        ...


class QueryExeCount(BSimQuery[ResponseExe]):
    """
    Query for counting the number of executable records in the database.
     
    
    This contains all the information required to get a list of all executables in the
    BSim database that meet a set of filter criteria. The results are stored in the
    :obj:`.exeresponse` object.
    """

    class_: typing.ClassVar[java.lang.Class]
    exeresponse: ResponseExe
    filterMd5: java.lang.String
    filterExeName: java.lang.String
    filterArch: java.lang.String
    filterCompilerName: java.lang.String
    includeFakes: jpype.JBoolean

    @typing.overload
    def __init__(self):
        """
        Query for count of all executables not including libraries
        """

    @typing.overload
    def __init__(self, filterMd5: typing.Union[java.lang.String, str], filterExeName: typing.Union[java.lang.String, str], filterArch: typing.Union[java.lang.String, str], filterCompilerName: typing.Union[java.lang.String, str], includeFakes: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param java.lang.String or str filterMd5: md5 filter
        :param java.lang.String or str filterExeName: executable name filter
        :param java.lang.String or str filterArch: architecture filter
        :param java.lang.String or str filterCompilerName: compiler name filter
        :param jpype.JBoolean or bool includeFakes: if true, include MD5s that start with ``bbbbbbbbaaaaaaa``
        """


class ResponseExe(QueryResponseRecord):
    """
    Response to a request for executables from a :obj:`BulkSignatures` call.
    """

    class_: typing.ClassVar[java.lang.Class]
    records: java.util.List[ghidra.features.bsim.query.description.ExecutableRecord]
    manage: ghidra.features.bsim.query.description.DescriptionManager
    recordCount: jpype.JInt

    def __init__(self):
        """
        Constructor.
        """


class QueryVectorId(BSimQuery[ResponseVectorId]):
    """
    Request vectors from the database by the their ids. Allows users to retrieve raw feature
    vectors without going through functions (FunctionDescription and DescriptionManager)
    """

    class_: typing.ClassVar[java.lang.Class]
    vectorIds: java.util.List[java.lang.Long]
    vectorIdResponse: ResponseVectorId

    def __init__(self):
        ...


class ExecutableResultWithDeDuping(java.lang.Comparable[ExecutableResultWithDeDuping]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rec: ghidra.features.bsim.query.description.ExecutableRecord):
        ...

    def addFunction(self, signif: typing.Union[jpype.JDouble, float]):
        ...

    @staticmethod
    def generate(iter: java.util.Iterator[SimilarityResult], duplicationInfo: collections.abc.Mapping) -> java.util.Collection[ExecutableResultWithDeDuping]:
        ...

    def getExecutableRecord(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        ...

    def getFunctionCount(self) -> int:
        """
        
        
        :return: number of functions with matches into this executable
        :rtype: int
        """

    def getSignificanceSum(self) -> float:
        """
        
        
        :return: sum of significance scores for all matching functions
        :rtype: float
        """

    @property
    def executableRecord(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        ...

    @property
    def significanceSum(self) -> jpype.JDouble:
        ...

    @property
    def functionCount(self) -> jpype.JInt:
        ...


class QueryOptionalValues(BSimQuery[ResponseOptionalValues]):
    """
    Query for values from an optional table, given a set of keys
    """

    class_: typing.ClassVar[java.lang.Class]
    optionalresponse: ResponseOptionalValues
    keys: jpype.JArray[java.lang.Object]
    tableName: java.lang.String
    keyType: jpype.JInt
    valueType: jpype.JInt

    def __init__(self):
        ...


class ResponseAdjustIndex(QueryResponseRecord):
    """
    Response to an AdjustVectorIndex request, returning a boolean value of either success or failure of the request
    """

    class_: typing.ClassVar[java.lang.Class]
    success: jpype.JBoolean
    operationSupported: jpype.JBoolean

    def __init__(self):
        ...


class StagingManager(java.lang.Object):
    """
    Abstract class for splitting up a (presumably large) query into smaller pieces
    The object must be configured by a call to setQuery with details of the staged query
    and then typically a call to setGlobalManager which specifies the data for the whole query
     
    Placing the actual staged queries is accomplished by first calling initialize,
    which establishes the first stage query, obtainable via the getQuery method.
    Successive stage queries are built by calling nextStage repeatedly until it returns false.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getQueriesMade(self) -> int:
        ...

    def getQuery(self) -> BSimQuery[typing.Any]:
        """
        Get the current staged query
        
        :return: the QueryResponseRecord object
        :rtype: BSimQuery[typing.Any]
        """

    def getTotalSize(self) -> int:
        ...

    def initialize(self, q: BSimQuery[typing.Any]) -> bool:
        """
        Establish the first query stage
        
        :param BSimQuery[typing.Any] q: the query
        :return: true if the initial query is constructed
        :rtype: bool
        :raises LSHException: if the initialization fails
        """

    def nextStage(self) -> bool:
        """
        Establish the next query stage
        
        :return: true if a next query is constructed
        :rtype: bool
        :raises LSHException: if creating the new query fails
        """

    @property
    def queriesMade(self) -> jpype.JInt:
        ...

    @property
    def totalSize(self) -> jpype.JInt:
        ...

    @property
    def query(self) -> BSimQuery[typing.Any]:
        ...


class QueryNearest(BSimQuery[ResponseNearest]):
    """
    Query nearest matches within database to a set of functions
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_SIMILARITY_THRESHOLD: typing.Final = 0.7
    """
    The default value for the similarity threshold. This
    threshold is for how similar the potential function is. This is a value from 0.0 to 1.0.
    """

    DEFAULT_SIGNIFICANCE_THRESHOLD: typing.Final = 0.0
    """
    The default value for the significance threshold.  This
    threshold is for how significant the match is (for example, smaller function matches
    are less significant).  Higher is more significant.  There is no upper bound.
    """

    DEFAULT_MAX_MATCHES: typing.Final = 100
    """
    The default value for the maximum number of similar functions to return 
    **for a given input function**
    """

    manage: ghidra.features.bsim.query.description.DescriptionManager
    nearresponse: ResponseNearest
    thresh: jpype.JDouble
    signifthresh: jpype.JDouble
    max: jpype.JInt
    vectormax: jpype.JInt
    fillinCategories: jpype.JBoolean
    bsimFilter: BSimFilter

    def __init__(self):
        ...


class ResponseVectorMatch(QueryResponseRecord):
    """
    Response to a request for functions with specific vector ids
    Full ExecutableRecords and FunctionDescriptions are instantiated in this object's DescriptionManager
    """

    class_: typing.ClassVar[java.lang.Class]
    manage: ghidra.features.bsim.query.description.DescriptionManager

    def __init__(self):
        ...


class SimilarityResult(java.lang.Iterable[SimilarityNote]):
    """
    A collection of matches to an (originally) queried function
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, f: ghidra.features.bsim.query.description.FunctionDescription):
        ...

    def addNote(self, f: ghidra.features.bsim.query.description.FunctionDescription, similarity: typing.Union[jpype.JDouble, float], significance: typing.Union[jpype.JDouble, float]):
        ...

    def getBase(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    def getTotalCount(self) -> int:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, qmanage: ghidra.features.bsim.query.description.DescriptionManager, rmanage: ghidra.features.bsim.query.description.DescriptionManager, qMap: collections.abc.Mapping, rMap: collections.abc.Mapping):
        ...

    def saveXml(self, write: java.io.Writer):
        ...

    def setTotalCount(self, count: typing.Union[jpype.JInt, int]):
        ...

    def setTransfer(self, op2: SimilarityResult, qmanage: ghidra.features.bsim.query.description.DescriptionManager, rmanage: ghidra.features.bsim.query.description.DescriptionManager, transsig: typing.Union[jpype.JBoolean, bool]):
        ...

    def size(self) -> int:
        ...

    def sortNotes(self):
        ...

    def transfer(self, manage: ghidra.features.bsim.query.description.DescriptionManager, transsig: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def totalCount(self) -> jpype.JInt:
        ...

    @totalCount.setter
    def totalCount(self, value: jpype.JInt):
        ...

    @property
    def base(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...


class ResponsePrewarm(QueryResponseRecord):
    """
    Response to a PrewarmRequest indicating that number of database blocks that were preloaded
    """

    class_: typing.ClassVar[java.lang.Class]
    blockCount: jpype.JInt
    operationSupported: jpype.JBoolean

    def __init__(self):
        ...


class ResponseNearest(QueryResponseRecord):
    """
    Response to a QueryNearest request.  A full description in terms of ExecutableRecords and FunctionDescriptions
    is returned.  The linked list of SimilarityResults explicitly describes the similarities between the functions
    in the original request and the new functions being returned.  A SimilarityResult cross-references
    FunctionDescription objects between the request DescriptionManager and this response object's DescriptionManager
    """

    class_: typing.ClassVar[java.lang.Class]
    totalfunc: jpype.JInt
    totalmatch: jpype.JInt
    uniquematch: jpype.JInt
    manage: typing.Final[ghidra.features.bsim.query.description.DescriptionManager]
    result: java.util.List[SimilarityResult]
    qnear: QueryNearest

    def __init__(self, q: QueryNearest):
        ...


class BSimFilter(java.lang.Object):
    """
    Suitable for client side filtering by calling isFiltered with an ExecutableRecord
    or evaluate with a FunctionDescription. Contains information for passing filter to 
    server side. Each 'atom' of the filter (FilterAtom) is expressed as an operator and 
    a value string. The operator (FilterType) indicates what part of the ExecutableRecord 
    or FunctionDescription must match (or not match) the value string.
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

    def addAtom(self, type: ghidra.features.bsim.gui.filters.BSimFilterType, val: typing.Union[java.lang.String, str]):
        ...

    def clear(self):
        ...

    def evaluate(self, func: ghidra.features.bsim.query.description.FunctionDescription) -> bool:
        """
        Returns true if all filters resolve correctly for the given function description. There are 
        4 main types of filters, each of which must be evaluated differently:
         
        1) Positive Filter:     ``"<filter name> matches <filter value>"``. 
                For these, filter out any result that does not contain all elements (at a minimum) of the 
                filter value.
                ie: FILTER = "SetA",         RESULT = "SetA" => keep it
                    FILTER = "SetA, SetB",     RESULT = "SetA"    => filter out
         
        2) Negative Filter:     ``"<filter name> does not match <filter value>"``
                For these, filter out any result that does not contain EXACTLY the filter value.
                ie: FILTER = "SetA",         RESULT = "SetA, SetB"   => keep it
                    FILTER = "SetA, SetB",     RESULT = "SetA, SetB"    => filter out
         
        3) Positive Exe Filter:     Same as #1, but custom exe filters are stored differently than
                'normal' categories and must be processed separately.
         
        4) Negative Exe Filter:    Same as #2, but custom exe filters are stored differently than
                'normal' categories and must be processed separately.
         
        
        :param ghidra.features.bsim.query.description.FunctionDescription func: the function description
        :return: true if all filters resolve to true
        :rtype: bool
        """

    def getAtom(self, i: typing.Union[jpype.JInt, int]) -> FilterAtom:
        ...

    def getFilterEntries(self) -> java.util.List[BSimFilter.FilterEntry]:
        ...

    def isEmpty(self) -> bool:
        ...

    def numAtoms(self) -> int:
        ...

    def replaceWith(self, other: BSimFilter):
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    @property
    def filterEntries(self) -> java.util.List[BSimFilter.FilterEntry]:
        ...

    @property
    def atom(self) -> FilterAtom:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ChildAtom(FilterAtom):

    class_: typing.ClassVar[java.lang.Class]
    name: java.lang.String
    exename: java.lang.String

    def __init__(self):
        ...

    def clone(self) -> FilterAtom:
        ...

    def getInfoString(self) -> str:
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    @property
    def infoString(self) -> java.lang.String:
        ...


class PrewarmRequest(BSimQuery[ResponsePrewarm]):
    """
    Request that the database preload portions of the main vector table so that initial queries return faster from
    a server that has just been restarted.
    """

    class_: typing.ClassVar[java.lang.Class]
    mainIndexConfig: jpype.JInt
    secondaryIndexConfig: jpype.JInt
    vectorTableConfig: jpype.JInt
    prewarmresponse: ResponsePrewarm

    def __init__(self):
        ...


class AdjustVectorIndex(BSimQuery[ResponseAdjustIndex]):
    """
    Request that a BSim database either drop or build its main vector index
    """

    class_: typing.ClassVar[java.lang.Class]
    doRebuild: jpype.JBoolean
    adjustresponse: ResponseAdjustIndex

    def __init__(self):
        ...

    def buildResponseTemplate(self):
        ...


class ResponseOptionalValues(QueryResponseRecord):

    class_: typing.ClassVar[java.lang.Class]
    resultArray: jpype.JArray[java.lang.Object]
    tableExists: jpype.JBoolean

    def __init__(self):
        ...


class FunctionEntry(java.lang.Object):
    """
    Identifying information for a function within a single executable
    """

    class_: typing.ClassVar[java.lang.Class]
    funcName: java.lang.String
    address: jpype.JLong

    def __init__(self, desc: ghidra.features.bsim.query.description.FunctionDescription):
        ...

    @staticmethod
    def restoreXml(parser: ghidra.xml.XmlPullParser) -> FunctionEntry:
        ...

    def saveXml(self, writer: java.io.Writer):
        ...


class QueryName(BSimQuery[ResponseName]):
    """
    Query for a single function in a single executable by giving either the md5 of the executable, or its name
    and version. Then give the name of the function.  If the name of the function is empty, this query
    returns all functions in the executable
    """

    class_: typing.ClassVar[java.lang.Class]
    spec: ExeSpecifier
    funcname: java.lang.String
    nameresponse: ResponseName
    maxfunc: jpype.JInt
    printselfsig: jpype.JBoolean
    printjustexe: jpype.JBoolean
    fillinSigs: jpype.JBoolean
    fillinCallgraph: jpype.JBoolean
    fillinCategories: jpype.JBoolean

    def __init__(self):
        ...


class BSimQuery(java.lang.Object, typing.Generic[R]):
    """
    :obj:`BSimQuery` facilitates all BSim :obj:`FunctionDatabase` queries
    which when executed provide a specific :obj:`QueryResponseRecord`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    def buildResponseTemplate(self):
        ...

    def clearResponse(self):
        ...

    def execute(self, database: ghidra.features.bsim.query.FunctionDatabase) -> R:
        """
        Executes this query via the :meth:`FunctionDatabase.query(BSimQuery) <FunctionDatabase.query>` method.
        The use of this method is preferred due to its type enforcement on the returned
        response object.
        
        :param ghidra.features.bsim.query.FunctionDatabase database: BSim function database to be queried
        :return: query response or null on error (see :meth:`FunctionDatabase.getLastError() <FunctionDatabase.getLastError>`).
        :rtype: R
        """

    def getDescriptionManager(self) -> ghidra.features.bsim.query.description.DescriptionManager:
        ...

    def getLocalStagingCopy(self) -> BSimQuery[typing.Any]:
        """
        
        
        :return: a partial clone of this query suitable for holding local stages of the query via StagingManager
        :rtype: BSimQuery[typing.Any]
        """

    def getName(self) -> str:
        ...

    def getResponse(self) -> R:
        ...

    @staticmethod
    def restoreQuery(parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory) -> BSimQuery[typing.Any]:
        """
        Restore a query from a stream
        
        :param ghidra.xml.XmlPullParser parser: is the XmlPullParser already queued up with the stream to process
        :param generic.lsh.vector.LSHVectorFactory vectorFactory: is used to generate any vector objects from the XML
        :return: one of the Query* instances derived from QueryResponseRecord
        :rtype: BSimQuery[typing.Any]
        :raises LSHException: for errors creating the command
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    @property
    def response(self) -> R:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def localStagingCopy(self) -> BSimQuery[typing.Any]:
        ...

    @property
    def descriptionManager(self) -> ghidra.features.bsim.query.description.DescriptionManager:
        ...


class QueryChildren(BSimQuery[ResponseChildren]):
    """
    Query based on a single executable and a specific list of functions names within the executable
    The response will be the corresponding FunctionDescription records and a record for each child
    of the specified functions
    """

    class_: typing.ClassVar[java.lang.Class]
    md5sum: java.lang.String
    name_exec: java.lang.String
    arch: java.lang.String
    name_compiler: java.lang.String
    functionKeys: java.util.List[FunctionEntry]
    childrenresponse: ResponseChildren

    def __init__(self):
        ...


class InstallCategoryRequest(BSimQuery[ResponseInfo]):
    """
    Request that a new executable category be installed for a specific BSim server.
    """

    class_: typing.ClassVar[java.lang.Class]
    type_name: java.lang.String
    isdatecolumn: jpype.JBoolean
    installresponse: ResponseInfo

    def __init__(self):
        ...


class ResponsePair(QueryResponseRecord):
    """
    A list of records (PairNote) each describing the comparison of a pair of functions on the server
    This response also includes various statistics (counts and averages) on the results
    """

    class Accumulator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        sumSim: jpype.JDouble
        sumSimSquare: jpype.JDouble
        sumSig: jpype.JDouble
        sumSigSquare: jpype.JDouble
        missedExe: jpype.JInt
        missedFunc: jpype.JInt
        missedVector: jpype.JInt
        pairCount: jpype.JInt

        def __init__(self):
            ...

        def merge(self, responsePair: ResponsePair):
            """
            Accumulate from already summarized statistics in a ResponsePair
            This method can be called multiple times to aggregate responses from multiple ResponsePairs
            
            :param ResponsePair responsePair: to be merged
            """


    class_: typing.ClassVar[java.lang.Class]
    averageSim: jpype.JDouble
    simStdDev: jpype.JDouble
    averageSig: jpype.JDouble
    sigStdDev: jpype.JDouble
    scale: jpype.JDouble
    pairCount: jpype.JInt
    missedExe: jpype.JInt
    missedFunc: jpype.JInt
    missedVector: jpype.JInt
    notes: java.util.List[PairNote]

    def __init__(self):
        ...

    def fillOutStatistics(self, accumulator: ResponsePair.Accumulator):
        ...

    def saveXmlTail(self, fwrite: java.io.Writer):
        ...


class FunctionStaging(StagingManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, stagesize: typing.Union[jpype.JInt, int]):
        ...



__all__ = ["QueryOptionalExist", "DropDatabase", "ResponseChildren", "NullStaging", "PairNote", "ResponseError", "SimilarityVectorResult", "ResponseDelete", "QueryInfo", "InstallTagRequest", "ResponseUpdate", "ResponseNearestVector", "PasswordChange", "InsertRequest", "ClusterNote", "QueryCluster", "QueryUpdate", "QueryVectorMatch", "QueryPair", "ResponseCluster", "ResponseVectorId", "ResponseName", "InstallMetadataRequest", "ResponseOptionalExist", "QueryExeInfo", "ExeSpecifier", "CreateDatabase", "QueryDelete", "QueryNearestVector", "InsertOptionalValues", "ResponseInsert", "SimilarityNote", "ResponseInfo", "FilterAtom", "PairInput", "PreFilter", "QueryResponseRecord", "ResponseDropDatabase", "ResponsePassword", "QueryExeCount", "ResponseExe", "QueryVectorId", "ExecutableResultWithDeDuping", "QueryOptionalValues", "ResponseAdjustIndex", "StagingManager", "QueryNearest", "ResponseVectorMatch", "SimilarityResult", "ResponsePrewarm", "ResponseNearest", "BSimFilter", "ChildAtom", "PrewarmRequest", "AdjustVectorIndex", "ResponseOptionalValues", "FunctionEntry", "QueryName", "BSimQuery", "QueryChildren", "InstallCategoryRequest", "ResponsePair", "FunctionStaging"]
