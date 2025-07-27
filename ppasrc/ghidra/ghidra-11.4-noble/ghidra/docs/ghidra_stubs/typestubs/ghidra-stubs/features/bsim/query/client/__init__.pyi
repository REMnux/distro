from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import generic.lsh.vector
import ghidra.features.bsim.gui.filters
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.protocol
import ghidra.util.task
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.sql # type: ignore
import java.util # type: ignore
import org.xml.sax # type: ignore


VF = typing.TypeVar("VF")


class CancelledSQLException(java.sql.SQLException):
    """
    :obj:`CancelledSQLException` indicates a SQL operation was intentionally cancelled.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reason: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str reason: reason SQL operation was cancelled.
        """


class TableScoreCaching(ScoreCaching):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, d: ghidra.features.bsim.query.FunctionDatabase):
        ...


class TemporaryScoreCaching(ScoreCaching):
    """
    An in-memory score cacher.  It supports commitSelfScore() and getSelfScore()
    calls, but the commits have no backing storage and vanish with each new instantiation
    of this object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IDSQLResolution(java.lang.Object):
    """
    Class for managing filter elements (FilterTemplate) that need to be resolved (typically to an id)
    before they can be converted to an SQL clause.
    """

    class Architecture(IDSQLResolution):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, nm: typing.Union[java.lang.String, str]):
            ...


    class Compiler(IDSQLResolution):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, nm: typing.Union[java.lang.String, str]):
            ...


    class ExeCategory(IDSQLResolution):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cat: typing.Union[java.lang.String, str], val: typing.Union[java.lang.String, str]):
            ...


    class ExternalFunction(IDSQLResolution):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, exe: typing.Union[java.lang.String, str], func: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    id1: jpype.JLong
    id2: jpype.JLong

    def __init__(self):
        ...

    def resolve(self, columnDatabase: AbstractSQLFunctionDatabase[typing.Any], exe: ghidra.features.bsim.query.description.ExecutableRecord):
        ...


class SQLEffects(java.lang.Object):
    """
    Container for collecting and sorting SQL string representations of FilterTemplates
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addFunctionFilter(self, flag: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JBoolean, bool]):
        ...

    def addLink(self, value: typing.Union[java.lang.String, str]):
        ...

    def addWhere(self, filter: ghidra.features.bsim.gui.filters.BSimFilterType, val: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def createFilter(exeFilter: ghidra.features.bsim.query.protocol.BSimFilter, idres: jpype.JArray[IDSQLResolution], db: ghidra.features.bsim.query.SQLFunctionDatabase) -> BSimSqlClause:
        """
        Given a general ExecutableFilter object, return a set of matching SQL string pieces,
        ready to be pasted into the full SQL statement.  The routine is handed an array of IDResolution references
        matching individual FilterAtoms as returned by ExecutableFilter.getAtom(i).  The IDResolution, if non-null,
        holds any pre-calculated ids associated with the corresponding FilterAtom
        
        :param ghidra.features.bsim.query.protocol.BSimFilter exeFilter: is the general filter
        :param jpype.JArray[IDSQLResolution] idres: is the array holding pre-calculated ids
        :param ghidra.features.bsim.query.SQLFunctionDatabase db: SQL function database
        :return: BSimFilterSQL, holding the table clause and the where clause
        :rtype: BSimSqlClause
        :raises SQLException: for errors building the SQL clause
        """

    def setExeTable(self):
        ...

    def setPathTable(self):
        ...


class ExecutableComparison(java.lang.Object):
    """
    Compare an entire set of executables to each other by combining
    significance scores between functions.  If individual functions
    demonstrate multiple similarities, its score contributions are not
    over counted, and the final scores are symmetric.  Scoring is efficient
    because it iterates over the precomputed clusters of similar functions
    in a BSim database.  The algorithm does divide and conquer based on
    clusters of similar functions, which greatly improves efficiency over
    full quadratic comparison of all functions. This can be further bounded
    by putting a threshold on how close functions have to be to be considered
    in the same cluster and on how many functions can be in a cluster before
    ignoring their score contributions.
    """

    class Count(java.lang.Object):
        """
        Mutable integer class for histogram
        """

        class_: typing.ClassVar[java.lang.Class]
        value: jpype.JInt

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, database: ghidra.features.bsim.query.FunctionDatabase, hitCountThreshold: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Initialize a comparison object with an active connection and thresholds, using the matrix scorer
        
        :param ghidra.features.bsim.query.FunctionDatabase database: is the active connection to a BSim database
        :param jpype.JInt or int hitCountThreshold: is the maximum number of functions to consider in one cluster
        :param ghidra.util.task.TaskMonitor monitor: is a monitor to provide progress and cancellation checks
        :raises LSHException: if the database connection is not established
        """

    @typing.overload
    def __init__(self, database: ghidra.features.bsim.query.FunctionDatabase, hitCountThreshold: typing.Union[jpype.JInt, int], md5: typing.Union[java.lang.String, str], cache: ScoreCaching, monitor: ghidra.util.task.TaskMonitor):
        """
        Initialize a comparison object with an active connection and thresholds, using the row scorer
        
        :param ghidra.features.bsim.query.FunctionDatabase database: is the active connection to a BSim database
        :param jpype.JInt or int hitCountThreshold: is the maximum number of functions to consider in one cluster
        :param java.lang.String or str md5: is the 32-character md5 string of the executable to single out for comparison
        :param ScoreCaching cache: holds the self-scores or is null if normalized scores aren't needed
        :param ghidra.util.task.TaskMonitor monitor: is a monitor to provide progress and cancellation checks
        :raises LSHException: if the database connection is not established
        """

    def addAllExecutables(self, limit: typing.Union[jpype.JInt, int]):
        """
        Add all executables currently in the database to this object for comparison.
        
        :param jpype.JInt or int limit: is the max number of executables to compare against (if greater than zero)
        :raises LSHException: for problems retrieving ExecutableRecords from the database
        """

    def addExecutable(self, md5: typing.Union[java.lang.String, str]):
        """
        Register an executable to be scored
        
        :param java.lang.String or str md5: is the MD5 string of the executable
        :raises LSHException: if the executable is not in the database
        """

    def fillinSelfScores(self):
        """
        Generate any missing self-scores within the list of registered executables.
        
        :raises LSHException: for problems retrieving vectors
        :raises CancelledException: if the user clicks "cancel"
        """

    def getExceedCount(self) -> int:
        """
        
        
        :return: number of clusters that exceeded hitCountThreshold
        :rtype: int
        """

    def getMaxHitCount(self) -> int:
        """
        
        
        :return: maximum hit count seen for a cluster
        :rtype: int
        """

    def getScorer(self) -> ExecutableScorer:
        """
        
        
        :return: the ExecutableScorer to allow examination of scores
        :rtype: ExecutableScorer
        """

    def isConfigured(self) -> bool:
        """
        
        
        :return: true if similarity and significance thresholds have been set
        :rtype: bool
        """

    def performScoring(self):
        """
        Perform scoring between all registered executables.
        
        :raises LSHException: for any connection issues during the process
        :raises CancelledException: if the monitor reports cancellation
        """

    def resetThresholds(self, simThreshold: typing.Union[jpype.JDouble, float], sigThreshold: typing.Union[jpype.JDouble, float]):
        """
        Remove any old scores and set new thresholds for the scorer
        
        :param jpype.JDouble or float simThreshold: is the similarity threshold for new scores
        :param jpype.JDouble or float sigThreshold: is the significance threshold for new scores
        :raises LSHException: if there are problems saving new thresholds
        """

    @property
    def configured(self) -> jpype.JBoolean:
        ...

    @property
    def maxHitCount(self) -> jpype.JInt:
        ...

    @property
    def scorer(self) -> ExecutableScorer:
        ...

    @property
    def exceedCount(self) -> jpype.JInt:
        ...


class IdHistogram(java.lang.Comparable[IdHistogram]):
    """
    Lightweight object container of an LSHVector and its count within a collection of functions (database/executable)
    TODO: This should likely be merged with SignatureRecord
    """

    class_: typing.ClassVar[java.lang.Class]
    id: jpype.JLong
    count: jpype.JInt
    vec: generic.lsh.vector.LSHVector

    def __init__(self):
        ...

    @staticmethod
    def buildVectorIdHistogram(iter: java.util.Iterator[ghidra.features.bsim.query.description.FunctionDescription]) -> java.util.TreeSet[IdHistogram]:
        """
        
        
        :param java.util.Iterator[ghidra.features.bsim.query.description.FunctionDescription] iter: is iterator over functions whose vectors are to be histogrammed
        :return: the sorted list of pairs (hash,count)
        :rtype: java.util.TreeSet[IdHistogram]
        """

    @staticmethod
    def collectVectors(manage: ghidra.features.bsim.query.description.DescriptionManager, iter: java.util.Iterator[ghidra.features.bsim.query.description.FunctionDescription]) -> java.util.Set[IdHistogram]:
        """
        Organize/histogram LSHVectors by hash.  Take into account functions that don't have a vector.
        Record hashes in the FunctionDescription's SignatureRecord
        
        :param ghidra.features.bsim.query.description.DescriptionManager manage: is the container of the FunctionDescriptions
        :param java.util.Iterator[ghidra.features.bsim.query.description.FunctionDescription] iter: is the iterator over the FunctionDescriptions being collected
        :return: the histogram as a set of (id,count,vec) triples
        :rtype: java.util.Set[IdHistogram]
        """


class NoDatabaseException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class FileScoreCaching(ScoreCaching):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fileName: typing.Union[java.lang.String, str]):
        ...


class ExecutableScorer(java.lang.Object):
    """
    Class for accumulating a matrix of scores between pairs of executables
    ExecutableRecords are registered with addExecutable. Scoring is accumulated
    by repeatedly providing clusters of functions to scoreCluster.
    """

    class FunctionPair(java.lang.Comparable[ExecutableScorer.FunctionPair]):
        """
        Container for a pair of FunctionDescriptions, possibly from different DescriptionManagers
        along with similarity/significance information
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, a: ghidra.features.bsim.query.description.FunctionDescription, b: ghidra.features.bsim.query.description.FunctionDescription, sim: typing.Union[jpype.JDouble, float], sig: typing.Union[jpype.JDouble, float]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def commitSelfScore(self):
        """
        Commit the singled out executables self-significance score to permanent storage
        
        :raises LSHException: if there's a problem writing, or the operation isn't supported
        """

    def countSelfScores(self) -> int:
        """
        
        
        :return: number of executable self-significance scores are (will be) available
        :rtype: int
        """

    @typing.overload
    def getExecutable(self, md5: typing.Union[java.lang.String, str]) -> ghidra.features.bsim.query.description.ExecutableRecord:
        """
        Retrieve a specific ExecutableRecord by md5
        
        :param java.lang.String or str md5: is the MD5 string
        :return: the matching ExecutableRecord
        :rtype: ghidra.features.bsim.query.description.ExecutableRecord
        :raises LSHException: if the ExecutableRecord isn't present
        """

    @typing.overload
    def getExecutable(self, index: typing.Union[jpype.JInt, int]) -> ghidra.features.bsim.query.description.ExecutableRecord:
        """
        Get the index-th executable. NOTE: The first index is 1
        
        :param jpype.JInt or int index: of the executable to retrieve
        :return: the ExecutableRecord describing the executable
        :rtype: ghidra.features.bsim.query.description.ExecutableRecord
        """

    @typing.overload
    def getNormalizedScore(self, a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int], useLibrary: typing.Union[jpype.JBoolean, bool]) -> float:
        """
        Computes a score comparing two executables, normalized between 0.0 and 1.0,
        indicating the percentage of functional similarity between the two.
        1.0 means "identical" 0.0 means completely "dissimilar"
        
        :param jpype.JInt or int a: is the index of the first executable
        :param jpype.JInt or int b: is the index of the second executable
        :param jpype.JBoolean or bool useLibrary: is true if the score measures percent "containment"
                of the smaller executable in the larger.
        :return: the normalized score
        :rtype: float
        :raises LSHException: if the self-scores for either executable are not available
        """

    @typing.overload
    def getNormalizedScore(self, a: typing.Union[jpype.JInt, int], useLibrary: typing.Union[jpype.JBoolean, bool]) -> float:
        ...

    @typing.overload
    def getScore(self, a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int]) -> float:
        """
        Return the similarity score between two executables
        
        :param jpype.JInt or int a: is the index matching getXrefIndex() of the first executable
        :param jpype.JInt or int b: is the index matching getXrefIndex() of the second executable
        :return: the similarity score
        :rtype: float
        """

    @typing.overload
    def getScore(self, a: typing.Union[jpype.JInt, int]) -> float:
        """
        Get score of executable (as compared to our singled out executable)
        
        :param jpype.JInt or int a: is the index of the executable
        :return: the score
        :rtype: float
        """

    def getSelfScore(self, a: typing.Union[jpype.JInt, int]) -> float:
        """
        Retrieve the similarity score of an executable with itself
        
        :param jpype.JInt or int a: is the index of the executable
        :return: its self-similarity score
        :rtype: float
        :raises LSHException: if the score is not accessible
        """

    def getSigThreshold(self) -> float:
        """
        
        
        :return: the significance threshold associated with these scores
        :rtype: float
        """

    def getSimThreshold(self) -> float:
        """
        
        
        :return: the similarity threshold associated with these scores
            OR -1.0 if no threshold has been set
        :rtype: float
        """

    def getSingularExecutable(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        """
        
        
        :return: ExecutableRecord being singled out for comparison
        :rtype: ghidra.features.bsim.query.description.ExecutableRecord
        """

    def getSingularSelfScore(self) -> float:
        ...

    def numExecutables(self) -> int:
        """
        
        
        :return: the number of executables being compared
        :rtype: int
        """

    def resetStorage(self, simThresh: typing.Union[jpype.JDouble, float], sigThresh: typing.Union[jpype.JDouble, float]):
        """
        Clear any persistent storage for self-significance scores, and establish new thresholds
        
        :param jpype.JDouble or float simThresh: is the new similarity threshold
        :param jpype.JDouble or float sigThresh: is the new significance threshold
        :raises LSHException: if there's a problem clearing storage
        """

    def setSingleExecutable(self, md5: typing.Union[java.lang.String, str]):
        """
        Set a single executable as focus to enable the single parameter getScore(int)
        
        :param java.lang.String or str md5: is the 32-character md5 hash of the executable single out
        :raises LSHException: if we can't find the executable
        """

    @property
    def sigThreshold(self) -> jpype.JDouble:
        ...

    @property
    def score(self) -> jpype.JFloat:
        ...

    @property
    def selfScore(self) -> jpype.JFloat:
        ...

    @property
    def singularSelfScore(self) -> jpype.JFloat:
        ...

    @property
    def simThreshold(self) -> jpype.JDouble:
        ...

    @property
    def singularExecutable(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        ...

    @property
    def executable(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        ...


class BSimSqlClause(java.lang.Record):
    """
    The SQL clauses for all the filters that are to be used in a BSim query
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tableClause: typing.Union[java.lang.String, str], whereClause: typing.Union[java.lang.String, str]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def tableClause(self) -> str:
        ...

    def toString(self) -> str:
        ...

    def whereClause(self) -> str:
        ...


class RowKeySQL(ghidra.features.bsim.query.description.RowKey):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, i: typing.Union[jpype.JLong, int]):
        ...


class AbstractSQLFunctionDatabase(ghidra.features.bsim.query.SQLFunctionDatabase, typing.Generic[VF]):
    """
    Defines the BSim :obj:`FunctionDatabase` backed by an SQL database.
     
    Simple, one-column tables that only contain string data use the
    :obj:`SQLStringTable` class and are defined in this class. More complex
    tables are defined in their own classes in the
    :obj:`ghidra.features.bsim.query.client.tables` package.
    """

    class_: typing.ClassVar[java.lang.Class]
    SQL_TIME_FORMAT: typing.Final = "YYYY-MM-DD HH24:MI:SS.MSz"
    JAVA_TIME_FORMAT: typing.Final = "yyyy-MM-dd HH:mm:ss.SSSZ"
    supportedLayoutVersion: typing.Final[jpype.JInt]

    @staticmethod
    def appendEscapedLiteral(buf: java.lang.StringBuilder, str: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.StringBuilder buf: the string builder object
        :param java.lang.String or str str: the string to parse
        :raises SQLException: if there is a zero byte in the string
        """

    def getFunctionTags(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of all function tags in the database.
        
        :return: list of function tags
        :rtype: java.util.List[java.lang.String]
        """

    @property
    def functionTags(self) -> java.util.List[java.lang.String]:
        ...


class PostgresFunctionDatabase(AbstractSQLFunctionDatabase[generic.lsh.vector.WeightedLSHCosineVectorFactory]):
    """
    Defines the BSim :obj:`FunctionDatabase` backed by a PostgreSQL database.
     
    Simple, one-column tables that only contain string data use the
    :obj:`SQLStringTable` class and are defined in this class. More complex
    tables are defined in their own classes in the
    :obj:`ghidra.features.bsim.query.client.tables` package.
    """

    class_: typing.ClassVar[java.lang.Class]
    LAYOUT_VERSION: typing.Final = 6

    def __init__(self, postgresUrl: java.net.URL, async_: typing.Union[jpype.JBoolean, bool]):
        ...


class FunctionDatabaseProxy(ghidra.features.bsim.query.FunctionDatabase):

    @typing.type_check_only
    class XmlErrorHandler(org.xml.sax.ErrorHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, url: java.net.URL):
        ...


class ScoreCaching(java.lang.Object):
    """
    Store and retrieve self-significance scores for executables specified by md5.
    These are generally too expensive to compute on the fly, so this class
    provides a persistence model for obtaining them.  These scores also depend
    on specific threshold settings, so there is a method for checking the settings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def commitSelfScore(self, md5: typing.Union[java.lang.String, str], score: typing.Union[jpype.JFloat, float]):
        """
        Commit a new self-significance score for an executable
        
        :param java.lang.String or str md5: is the 32-character md5 string specifying the executable
        :param jpype.JFloat or float score: is the score to commit
        :raises LSHException: if there's a problem saving the value
        """

    def getSelfScore(self, md5: typing.Union[java.lang.String, str]) -> float:
        """
        Retrieve the self-significance score for a given executable
        
        :param java.lang.String or str md5: is the 32-character md5 string specifying the executable
        :return: the corresponding score
        :rtype: float
        :raises LSHException: if the score is not obtainable
        """

    def getSigThreshold(self) -> float:
        """
        
        
        :return: significance threshold configured with this cache
                OR return -1 if the score is unconfigured
        :rtype: float
        :raises LSHException: for problems retrieving configuration
        """

    def getSimThreshold(self) -> float:
        """
        
        
        :return: similarity threshold configured with this cache
                OR return -1 if the score is unconfigured
        :rtype: float
        :raises LSHException: for problems retrieving configuration
        """

    def prefetchScores(self, exeSet: java.util.Set[ghidra.features.bsim.query.description.ExecutableRecord], missing: java.util.List[ghidra.features.bsim.query.description.ExecutableRecord]):
        """
        Pre-load self-scores for a set of executables.
        
        :param java.util.Set[ghidra.features.bsim.query.description.ExecutableRecord] exeSet: is the set of executables to check
        :param java.util.List[ghidra.features.bsim.query.description.ExecutableRecord] missing: (optional - may be null) will contain the list of exes missing a score
        :raises LSHException: if there are problems loading scores
        """

    def resetStorage(self, simThresh: typing.Union[jpype.JDouble, float], sigThresh: typing.Union[jpype.JDouble, float]):
        """
        Clear out any existing scores, and reset to an empty database
        
        :param jpype.JDouble or float simThresh: is new similarity threshold to associate with scores
        :param jpype.JDouble or float sigThresh: is new significance threshold to associate with scores
        :raises LSHException: if there is a problem modifying storage
        """

    @property
    def sigThreshold(self) -> jpype.JDouble:
        ...

    @property
    def selfScore(self) -> jpype.JFloat:
        ...

    @property
    def simThreshold(self) -> jpype.JDouble:
        ...


class Configuration(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    info: ghidra.features.bsim.query.description.DatabaseInformation
    k: jpype.JInt
    L: jpype.JInt
    weightfactory: generic.lsh.vector.WeightFactory
    idflookup: generic.lsh.vector.IDFLookup

    def __init__(self):
        ...

    def loadTemplate(self, rootPath: generic.jar.ResourceFile, filename: typing.Union[java.lang.String, str]):
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...


class ExecutableScorerSingle(ExecutableScorer):
    """
    ExecutableComparison scorer to use when we are comparing exactly one executable
    against a set of other executables (one to many).  We override the :obj:`ExecutableScorer`
    (compare many to many) so that it effectively accesses only a single row
    of the scoring matrix to get the "one to many" behavior we want.
    The getNormalizedScore() methods on the base class require that executable self-scores,
    other than the singled-out executable's self-score, be cached in some way.
    Thus this scorer needs a :obj:`ScoreCaching` class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cache: ScoreCaching):
        """
        Construct the scorer.  If normalized scores are required, a self-score cacher
        must be provided.
        
        :param ScoreCaching cache: is the self-score cacher or null
        :raises LSHException: for problems initializing the cache
        """

    def prefetchSelfScores(self, missing: java.util.List[ghidra.features.bsim.query.description.ExecutableRecord]):
        """
        Pre-load self-scores of the registered executables.
        
        :param java.util.List[ghidra.features.bsim.query.description.ExecutableRecord] missing: (optional - may be null) will contain the list of exes missing a score
        :raises LSHException: if there are problems loading scores
        """



__all__ = ["CancelledSQLException", "TableScoreCaching", "TemporaryScoreCaching", "IDSQLResolution", "SQLEffects", "ExecutableComparison", "IdHistogram", "NoDatabaseException", "FileScoreCaching", "ExecutableScorer", "BSimSqlClause", "RowKeySQL", "AbstractSQLFunctionDatabase", "PostgresFunctionDatabase", "FunctionDatabaseProxy", "ScoreCaching", "Configuration", "ExecutableScorerSingle"]
