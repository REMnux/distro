from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra.features.bsim.query.description
import java.lang # type: ignore
import java.sql # type: ignore
import java.util # type: ignore


S = typing.TypeVar("S")


class KeyValueTable(SQLComplexTable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getValue(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        
        
        :param java.lang.String or str key: the key to get the value for
        :return: the value associated with key or throw exception if key not present
        :rtype: str
        :raises SQLException: if the sql statement cannot be parsed
        """

    def writeBasicInfo(self, info: ghidra.features.bsim.query.description.DatabaseInformation):
        """
        Inserts some properties from the :obj:`DatabaseInformation` object to the table.
        
        :param ghidra.features.bsim.query.description.DatabaseInformation info: the database information
        :raises SQLException: if the database info cannot be stored in the table
        """

    def writeExecutableCategories(self, info: ghidra.features.bsim.query.description.DatabaseInformation):
        """
        
        
        :param ghidra.features.bsim.query.description.DatabaseInformation info: the database information
        :raises SQLException: if the table insert fails
        """

    def writeFunctionTags(self, info: ghidra.features.bsim.query.description.DatabaseInformation):
        """
        
        
        :param ghidra.features.bsim.query.description.DatabaseInformation info: the database information
        :raises SQLException: if the table insert fails
        """

    @property
    def value(self) -> java.lang.String:
        ...


class SQLComplexTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tableName: typing.Union[java.lang.String, str], idColumnName: typing.Union[java.lang.String, str]):
        ...

    def close(self):
        ...

    def create(self, st: java.sql.Statement):
        """
        Creates the db table.
        
        :param java.sql.Statement st: the query statement
        :raises SQLException: if there is a problem
        """

    def delete(self, id: typing.Union[jpype.JLong, int]) -> int:
        """
        Deletes the row with the given id from the db. Users must set the ``DELETE_STMT`` string
        to delete the exact table they need.
        
        :param jpype.JLong or int id: the database row ID
        :return: the number of deleted rows
        :rtype: int
        :raises SQLException: if there is a problem creating or executing the query
        """

    def drop(self, st: java.sql.Statement):
        """
        Drops the current table.
        NOTE: If explicitly created index tables exist they should be removed first
        or this method override.
        
        :param java.sql.Statement st: the query statement
        :raises SQLException: if there is a problem with the execute update command
        """

    def insert(self, *arguments: java.lang.Object) -> int:
        """
        Inserts a row(s) into the db. The arguments passed to this function are by definition 
        not known, so they are left as a variable-length list of :obj:`Object` instances, to be
        interpreted by the implementer.
        
        :param jpype.JArray[java.lang.Object] arguments: any arguments required for the insert
        :return: to be defined by the implementor
        :rtype: int
        :raises SQLException: if there is a problem executing the insert command
        """

    def setConnection(self, db: java.sql.Connection):
        ...


class WeightTable(SQLComplexTable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def recoverWeights(self, factory: generic.lsh.vector.WeightFactory):
        """
        
        
        :param generic.lsh.vector.WeightFactory factory: the weight factory
        :raises SQLException: if there is an error creating/executing the query
        """


class DescriptionTable(SQLComplexTable):
    """
    This is the SQL table "desctable", which holds one row for each function ingested into the database.
    A row (DescriptionRow) consists of basic meta-data about the function: name, address, executable
    """

    class DescriptionRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        rowid: jpype.JLong
        func_name: java.lang.String
        id_exe: jpype.JLong
        id_sig: jpype.JLong
        addr: jpype.JLong
        flags: jpype.JInt

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, exeTable: ExeTable):
        ...

    @staticmethod
    def convertDescriptionRow(descRow: DescriptionTable.DescriptionRow, exeRecord: ghidra.features.bsim.query.description.ExecutableRecord, descManager: ghidra.features.bsim.query.description.DescriptionManager, sigRecord: ghidra.features.bsim.query.description.SignatureRecord) -> ghidra.features.bsim.query.description.FunctionDescription:
        """
        Given a function's raw meta-data from a desctable row (DescriptionRow), build the
        corresponding high-level FunctionDescription
        
        :param DescriptionTable.DescriptionRow descRow: is the function's row meta-data
        :param ghidra.features.bsim.query.description.ExecutableRecord exeRecord: is the ExecutableRecord for executable containing the function
        :param ghidra.features.bsim.query.description.DescriptionManager descManager: is the container that will hold the new FunctionDescription
        :param ghidra.features.bsim.query.description.SignatureRecord sigRecord: is SignatureRecord associated with the function (may be null)
        :return: the new FunctionDescription
        :rtype: ghidra.features.bsim.query.description.FunctionDescription
        """

    def convertDescriptionRows(self, descList: java.util.List[ghidra.features.bsim.query.description.FunctionDescription], rowList: java.util.List[DescriptionTable.DescriptionRow], executable: ghidra.features.bsim.query.description.ExecutableRecord, descManager: ghidra.features.bsim.query.description.DescriptionManager, sigRecord: ghidra.features.bsim.query.description.SignatureRecord):
        """
        Given rows from desctable describing functions of a single executable,
        build the list of corresponding FunctionDescription objects
        
        :param java.util.List[ghidra.features.bsim.query.description.FunctionDescription] descList: is resulting list of FunctionDescriptions
        :param java.util.List[DescriptionTable.DescriptionRow] rowList: is the list of DescriptionRows
        :param ghidra.features.bsim.query.description.ExecutableRecord executable: is the ExecutableRecord of the single executable
        :param ghidra.features.bsim.query.description.DescriptionManager descManager: is the container to hold the new FunctionDescriptions
        :param ghidra.features.bsim.query.description.SignatureRecord sigRecord: is a single SignatureRecord to associate with any new
                    FunctionDescription (can be null)
        """

    @staticmethod
    def extractDescriptionRow(resultSet: java.sql.ResultSet, descRow: DescriptionTable.DescriptionRow):
        """
        Extract column meta-data of a desctable row from the SQL result set
        
        :param java.sql.ResultSet resultSet: is the low-level result set (returned by an SQL query)
        :param DescriptionTable.DescriptionRow descRow: is the DescriptionRow
        :raises SQLException: if there is a problem parsing the result set
        """

    def extractDescriptionRows(self, resultSet: java.sql.ResultSet, maxRows: typing.Union[jpype.JInt, int]) -> java.util.List[DescriptionTable.DescriptionRow]:
        """
        Extract a list of desctable rows from the SQL result set
        Only build up to -max- DescriptionRow objects, but still run through all rows in the set.
        
        :param java.sql.ResultSet resultSet: is the ResultSet to run through
        :param jpype.JInt or int maxRows: is the maximum number of DescriptionRows to build
        :return: a list of the new DescriptionRows
        :rtype: java.util.List[DescriptionTable.DescriptionRow]
        :raises SQLException: if there is a problem parsing the result set
        """

    def insert(self, *arguments: java.lang.Object) -> int:
        """
        Assuming all the necessary ids have been filled in, store the function as a row in desctable
        
        :param jpype.JArray[java.lang.Object] arguments: must be a single :obj:`FunctionDescription`
        :raises SQLException: if there is a problem creating or executing the query
        """

    def queryFuncName(self, executableId: typing.Union[jpype.JLong, int], functionName: typing.Union[java.lang.String, str], maxRows: typing.Union[jpype.JInt, int]) -> java.util.List[DescriptionTable.DescriptionRow]:
        """
        Return DescriptionRow objects that match a given -functionName-
        and the row id within exetable of a specific executable
        
        :param jpype.JLong or int executableId: is the row id of the executable to match
        :param java.lang.String or str functionName: is the name of the function to match
        :param jpype.JInt or int maxRows: is the maximum number of functions to return
        :return: linked of DescriptionRow objects
        :rtype: java.util.List[DescriptionTable.DescriptionRow]
        :raises SQLException: if there is an error creating or executing the query
        """

    def queryFuncNameAddr(self, executableId: typing.Union[jpype.JLong, int], functionName: typing.Union[java.lang.String, str], functionAddress: typing.Union[jpype.JLong, int]) -> DescriptionTable.DescriptionRow:
        """
        Query the description table for the row describing a single function.
        A function is uniquely identified by: its name, address, and the executable it is in
        
        :param jpype.JLong or int executableId: is the row id (of exetable) of the executable containing the function
        :param java.lang.String or str functionName: is the name of the function
        :param jpype.JLong or int functionAddress: is the address of the function
        :return: the corresponding row of the table, or null
        :rtype: DescriptionTable.DescriptionRow
        :raises SQLException: if there is an error creating or executing the query
        """

    def querySingleDescriptionId(self, descManager: ghidra.features.bsim.query.description.DescriptionManager, rowId: typing.Union[jpype.JLong, int]) -> ghidra.features.bsim.query.description.FunctionDescription:
        """
        Given the row id of the function within desctable, extract the FunctionDescription object
        
        :param ghidra.features.bsim.query.description.DescriptionManager descManager: is the container which will hold the object
        :param jpype.JLong or int rowId: is the row id of the function within desctable
        :return: the FunctionDescription
        :rtype: ghidra.features.bsim.query.description.FunctionDescription
        :raises SQLException: if there is a problem creating or executing the query
        :raises LSHException: if there is a problem parsing the result set
        """

    def queryVectorIdMatch(self, vectorId: typing.Union[jpype.JLong, int], maxRows: typing.Union[jpype.JInt, int]) -> java.util.List[DescriptionTable.DescriptionRow]:
        """
        Return function DescriptionRow objects that have a matching vector id
        
        :param jpype.JLong or int vectorId: is the row id of the feature vector we want to match
        :param jpype.JInt or int maxRows: is the maximum number of function rows to return
        :return: list of resulting DescriptionRows
        :rtype: java.util.List[DescriptionTable.DescriptionRow]
        :raises SQLException: if there is a problem creating or executing the query
        """

    def queryVectorIdMatchFilter(self, vectorId: typing.Union[jpype.JLong, int], tableClause: typing.Union[java.lang.String, str], whereClause: typing.Union[java.lang.String, str], maxRows: typing.Union[jpype.JInt, int]) -> java.util.List[DescriptionTable.DescriptionRow]:
        """
        Return function DescriptionRow objects that have a matching vector id
        and that also pass additional filters.  The filters must be encoded
        as a "WHERE" clause of an SQL "SELECT" statement on desctable. Additional
        tables joined to desctable to satisfy the filter must be encoded as
        a "FROM" clause of the "SELECT".
        
        :param jpype.JLong or int vectorId: is the row id of the feature vector (vectortable) we want to match on
        :param java.lang.String or str tableClause: is the additional "FROM" clause needed for the filter
        :param java.lang.String or str whereClause: is the "WHERE" clause needed for the filter
        :param jpype.JInt or int maxRows: is the maximum number of rows to return
        :return: a list of resulting DescriptionRows
        :rtype: java.util.List[DescriptionTable.DescriptionRow]
        :raises SQLException: if there is an error creating or executing the query
        """


class IdfLookupTable(SQLComplexTable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def recoverIDFLookup(self, lookup: generic.lsh.vector.IDFLookup):
        """
        
        
        :param generic.lsh.vector.IDFLookup lookup: the IDF lookup
        :raises SQLException: if there is an error creating/executing the query
        """


class CachedStatement(java.lang.Object, typing.Generic[S]):
    """
    :obj:`CachedStatement` provides a cached :obj:`Statement` container which is intended to
    supply a reusable instance for use within a single thread.  Attempts to use the statement
    in multiple threads is considered unsafe.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def close(self):
        """
        Close the currently cached :obj:`Statement`.  This method may be invoked
        from any thread but should be properly coordinated with its use in the statement
        owner thread.
        """

    def getStatement(self) -> S:
        """
        Get the current cached :obj:`Statement`.
        
        :return: the current cached :obj:`Statement` or null if not yet established.
        :rtype: S
        :raises RuntimeException: if the current thread does not correspond to the owner
        thread of a previously established statement.  This is considered a programming
        error if this occurs.
        """

    def prepareIfNeeded(self, statementSupplier: StatementSupplier[S]) -> S:
        """
        Get the associated cached :obj:`Statement` or prepare one via the specified 
        ``statementSupplier`` if not yet established.  Tf the supplier is used
        the owner thread for the statement will be established based on the 
        :meth:`Thread.currentThread() <Thread.currentThread>`.
        
        :param StatementSupplier[S] statementSupplier: statement supplier function which must return a valid
        instance or throw an exception.
        :return: statement
        :rtype: S
        :raises SQLException: if supplier fails to produce a statement
        :raises RuntimeException: if the current thread does not correspond to the owner
        thread of a previously established statement.  This is considered a programming
        error if this occurs.
        """

    def setStatement(self, s: S):
        """
        Set the associated :obj:`Statement` instance.  This method may be used in place of
        :meth:`prepareIfNeeded(StatementSupplier) <.prepareIfNeeded>` although it is not preferred since it
        can result in replacement of one previously established.  The :meth:`getStatement() <.getStatement>`
        should be used first to ensure one was not previously set.  An error will be logged
        if the invocation replaces an existing statement which will be forced closed.
         
        
        The owner thread for the statement will be established based on the 
        :meth:`Thread.currentThread() <Thread.currentThread>`.
        
        :param S s: statement to be cached
        """

    @property
    def statement(self) -> S:
        ...

    @statement.setter
    def statement(self, value: S):
        ...


class ExeToCategoryTable(SQLComplexTable):

    @typing.type_check_only
    class CategoryRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        id_exe: jpype.JLong
        id_type: jpype.JLong
        id_category: jpype.JLong


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, catstringtable: SQLStringTable):
        """
        Constructor
        
        :param SQLStringTable catstringtable: table containing all category values
        """

    def queryExecutableCategories(self, exeid: typing.Union[jpype.JLong, int], max: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.features.bsim.query.description.CategoryRecord]:
        """
        
        
        :param jpype.JLong or int exeid: the executable table id
        :param jpype.JInt or int max: the max number of records to return
        :return: the list of category records
        :rtype: java.util.List[ghidra.features.bsim.query.description.CategoryRecord]
        :raises SQLException: if there is a problem creating or executing the query
        """

    def storeExecutableCategories(self, erec: ghidra.features.bsim.query.description.ExecutableRecord):
        """
        
        
        :param ghidra.features.bsim.query.description.ExecutableRecord erec: the executable record
        :raises SQLException: if there is a problem inserting the category
        """


class StatementSupplier(java.lang.Object, typing.Generic[S]):
    """
    :obj:`StatementSupplier` provides a callback function to generate a :obj:`Statement`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def get(self) -> S:
        """
        Return a :obj:`Statement` for use within the current thread.
        
        :return: statement
        :rtype: S
        :raises SQLException: if callback fails when producing the statement
        """


class ExeTable(SQLComplexTable):

    class ExeTableOrderColumn(java.lang.Enum[ExeTable.ExeTableOrderColumn]):

        class_: typing.ClassVar[java.lang.Class]
        MD5: typing.Final[ExeTable.ExeTableOrderColumn]
        NAME: typing.Final[ExeTable.ExeTableOrderColumn]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ExeTable.ExeTableOrderColumn:
            ...

        @staticmethod
        def values() -> jpype.JArray[ExeTable.ExeTableOrderColumn]:
            ...


    class ExecutableRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        rowid: jpype.JLong
        md5: java.lang.String
        exename: java.lang.String
        arch_id: jpype.JLong
        compiler_id: jpype.JLong
        date_milli: jpype.JLong
        repo_id: jpype.JLong
        path_id: jpype.JLong

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    TABLE_NAME: typing.Final = "exetable"

    def __init__(self, archtable: SQLStringTable, compilertable: SQLStringTable, repositorytable: SQLStringTable, pathtable: SQLStringTable, exeCategoryTable: ExeToCategoryTable):
        """
        Constructor
        
        :param SQLStringTable archtable: the architecture table
        :param SQLStringTable compilertable: the compiler table
        :param SQLStringTable repositorytable: the repository table
        :param SQLStringTable pathtable: the path table
        :param ExeToCategoryTable exeCategoryTable: the category table
        """

    def extractExecutableRows(self, rs: java.sql.ResultSet, vecres: java.util.List[ghidra.features.bsim.query.description.ExecutableRecord], res: ghidra.features.bsim.query.description.DescriptionManager, max: typing.Union[jpype.JInt, int]) -> int:
        """
        Creates :obj:`ExecutableRecord` objects from :obj:`ResultSet` and stores
        them in the given list.
        
        :param java.sql.ResultSet rs: the result set
        :param java.util.List[ghidra.features.bsim.query.description.ExecutableRecord] vecres: the list of executable records
        :param ghidra.features.bsim.query.description.DescriptionManager res: the description manager
        :param jpype.JInt or int max: the max number of rows to return
        :return: the number of rows returned
        :rtype: int
        :raises SQLException: if there is an problem parsing the result set
        :raises LSHException: if there is an problem creating the executable record
        """

    def makeExecutableRecord(self, manager: ghidra.features.bsim.query.description.DescriptionManager, row: ExeTable.ExecutableRow) -> ghidra.features.bsim.query.description.ExecutableRecord:
        """
        Make an ExecutableRecord within the DescriptionManager container, given
        database row information
        
        :param ghidra.features.bsim.query.description.DescriptionManager manager: is the DescriptionManager that will contain the new record
        :param ExeTable.ExecutableRow row: is the columnar values for the executable from the database
        :return: the new ExecutableRecord
        :rtype: ghidra.features.bsim.query.description.ExecutableRecord
        :raises SQLException: if there is a problem parsing the table objects
        :raises LSHException: if there is a problem creating a new exec library or record
        """

    def queryAllExe(self, limit: typing.Union[jpype.JInt, int], filterMd5: typing.Union[java.lang.String, str], filterExeName: typing.Union[java.lang.String, str], filterArch: typing.Union[jpype.JLong, int], filterCompilerName: typing.Union[jpype.JLong, int], sortColumn: ExeTable.ExeTableOrderColumn, includeFakes: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ExeTable.ExecutableRow]:
        """
        Returns a list of all rows in the exe table matching a given filter.
        
        :param jpype.JInt or int limit: the max number of results to return
        :param java.lang.String or str filterMd5: md5 must contain this
        :param java.lang.String or str filterExeName: exe name must contain this
        :param jpype.JLong or int filterArch: if non-zero architecture must match this id
        :param jpype.JLong or int filterCompilerName: if non-zero compiler must match this id
        :param ExeTable.ExeTableOrderColumn sortColumn: the name of the column that should define the sorting order
        :param jpype.JBoolean or bool includeFakes: if false, will exclude generated MD5s starting with "bbbbbbbbaaaaaaaa"
        :return: list of executables
        :rtype: java.util.List[ExeTable.ExecutableRow]
        :raises SQLException: when preparing or executing the query
        """

    def queryExeCount(self, filterMd5: typing.Union[java.lang.String, str], filterExeName: typing.Union[java.lang.String, str], filterArch: typing.Union[jpype.JLong, int], filterCompilerName: typing.Union[jpype.JLong, int], includeFakes: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Returns a count of all records in the database matching the filter criteria.
        
        :param java.lang.String or str filterMd5: md5 must contain this
        :param java.lang.String or str filterExeName: exe name must contain this
        :param jpype.JLong or int filterArch: if non-zero, force matching architecture id
        :param jpype.JLong or int filterCompilerName: if non-zero, force matching compiler id
        :param jpype.JBoolean or bool includeFakes: if true, include MD5s that start with 'bbbbbbbbaaaaaaa'
        :return: total number of records in the database
        :rtype: int
        :raises SQLException: when preparing or executing the query
        """

    def queryMd5ExeMatch(self, md5: typing.Union[java.lang.String, str]) -> ExeTable.ExecutableRow:
        """
        Return the executable with matching md5 (if any)
        
        :param java.lang.String or str md5: the md5 hash to query
        :return: the ExecutableRow data or null
        :rtype: ExeTable.ExecutableRow
        :raises SQLException: if there is a problem creating or executing the query
        """

    def queryNameExeMatch(self, vecres: java.util.List[ghidra.features.bsim.query.description.ExecutableRecord], res: ghidra.features.bsim.query.description.DescriptionManager, nm: typing.Union[java.lang.String, str], max: typing.Union[jpype.JInt, int]) -> int:
        """
        Executes a database query to return a list of records matching an executalble name 
        filter.
        
        :param java.util.List[ghidra.features.bsim.query.description.ExecutableRecord] vecres: the list of executable records to populate
        :param ghidra.features.bsim.query.description.DescriptionManager res: the description manager
        :param java.lang.String or str nm: the name to query for
        :param jpype.JInt or int max: the max number of records to return
        :return: the number of records returned
        :rtype: int
        :raises SQLException: if there is a problem creating the query statement
        :raises LSHException: if there is a problem extracting executable rows
        """

    def querySingleExecutable(self, manage: ghidra.features.bsim.query.description.DescriptionManager, name: typing.Union[java.lang.String, str], arch: typing.Union[java.lang.String, str], cname: typing.Union[java.lang.String, str]) -> ghidra.features.bsim.query.description.ExecutableRecord:
        """
        Query for a unique executable based on -name- and possibly other metadata
        
        :param ghidra.features.bsim.query.description.DescriptionManager manage: the container to store the result
        :param java.lang.String or str name: the name the executable must match
        :param java.lang.String or str arch: the architecture the executable must match (may be zero length)
        :param java.lang.String or str cname: the compiler name the executable must match (may be zero length)
        :return: the unique resulting ExecutableRecord or null, if none or more
                than 1 is found
        :rtype: ghidra.features.bsim.query.description.ExecutableRecord
        :raises SQLException: if there is a problem querying for the executable name
        :raises LSHException: if there is a problem querying for the executable name or transferring the exec
        """

    def querySingleExecutableId(self, id: typing.Union[jpype.JLong, int]) -> ExeTable.ExecutableRow:
        """
        Query for a single executable based on its exetable -id-
        
        :param jpype.JLong or int id: the exetable id
        :return: the executable row
        :rtype: ExeTable.ExecutableRow
        :raises SQLException: if there is a problem creating or executing the query
        """

    def updateExecutable(self, rec: ghidra.features.bsim.query.description.ExecutableRecord.Update):
        """
        Updates records in the database with information in the given :obj:`ExecutableRecord`.
        
        :param ghidra.features.bsim.query.description.ExecutableRecord.Update rec: the executable record to update
        :raises SQLException: if there is a problem creating or executing the query
        """


class CallgraphTable(SQLComplexTable):

    class CallgraphRow(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        src: jpype.JLong
        dest: jpype.JLong

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def extractCallgraphRow(pgres: java.sql.ResultSet) -> CallgraphTable.CallgraphRow:
        """
        
        
        :param java.sql.ResultSet pgres: the result set to extract from
        :return: the new :obj:`CallgraphRow`
        :rtype: CallgraphTable.CallgraphRow
        :raises SQLException: if there's an error parsing the :obj:`ResultSet`
        """

    def queryCallgraphRows(self, func: ghidra.features.bsim.query.description.FunctionDescription, trackcallgraph: typing.Union[jpype.JBoolean, bool]) -> java.util.List[CallgraphTable.CallgraphRow]:
        """
        
        
        :param ghidra.features.bsim.query.description.FunctionDescription func: the function description
        :param jpype.JBoolean or bool trackcallgraph: true if the database tracks call graph information
        :return: the list of :obj:`CallgraphRow`s
        :rtype: java.util.List[CallgraphTable.CallgraphRow]
        :raises SQLException: if there is a problem parsing the :obj:`ResultSet` objects
        """


class OptionalTable(java.lang.Object):
    """
    Database table that has exactly two columns: key and value
    The column types are variable and are determined upon initialization.
    They are specified by giving an integer "type code" as listed in java.sql.Types
    The key column will be marked as UNIQUE.
    The JDBC driver will map between Java and SQL types.
    The readValue() writeValue() and deleteValue() methods simply take and return an Object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, nm: typing.Union[java.lang.String, str], kType: typing.Union[jpype.JInt, int], vType: typing.Union[jpype.JInt, int], d: java.sql.Connection):
        """
        Construct this table for a specific connection
        
        :param java.lang.String or str nm: is the formal SQL name of the table
        :param jpype.JInt or int kType: is the type-code of the key (as specified in java.sql.Types)
        :param jpype.JInt or int vType: is the type-code of the value (as specified in java.sql.Types)
        :param java.sql.Connection d: is the connection to the SQL server
        """

    def clearTable(self):
        """
        Clear all rows from the table
        
        :raises SQLException: for problems with the connection
        """

    def close(self):
        """
        Free any resources and relinquish references to the connection
        """

    def createTable(self):
        """
        Create this specific table in the database
        
        :raises SQLException: for problems with the connection
        """

    def deleteValue(self, key: java.lang.Object):
        """
        Deletes the row corresponding to a given key
        
        :param java.lang.Object key: identifies the table row
        :raises SQLException: for problems with the connection
        """

    def exists(self) -> bool:
        """
        Determine whether a given table exists in the database
        
        :return: true is the table exists
        :rtype: bool
        :raises SQLException: for problems with the connection
        """

    def getKeyType(self) -> int:
        """
        
        
        :return: type-code of key column
        :rtype: int
        """

    def getName(self) -> str:
        """
        
        
        :return: the formal sql name of the table
        :rtype: str
        """

    def getValueType(self) -> int:
        """
        
        
        :return: type-code of value column
        :rtype: int
        """

    def lockForWrite(self):
        """
        Lock the table for writing
        
        :raises SQLException: if the server reports an error
        """

    def readValue(self, key: java.lang.Object) -> java.lang.Object:
        """
        Given a key, retrieve the corresponding value
        
        :param java.lang.Object key: identifies the table row
        :return: the value corresponding to the key
        :rtype: java.lang.Object
        :raises SQLException: for problems with the connection
        """

    def writeValue(self, key: java.lang.Object, value: java.lang.Object):
        """
        Associate a new value with a given key
        
        :param java.lang.Object key: identifies the table row
        :param java.lang.Object value: is stored at that row
        :raises SQLException: for problems with the connection
        """

    @property
    def valueType(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def keyType(self) -> jpype.JInt:
        ...


class SQLStringTable(java.lang.Object):

    class StringRecord(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        id: jpype.JLong
        value: java.lang.String
        prev: SQLStringTable.StringRecord
        next: SQLStringTable.StringRecord

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], maxloaded: typing.Union[jpype.JInt, int]):
        ...

    def close(self):
        ...

    def createTable(self):
        """
        Create this specific table in the database
        
        :raises SQLException: if the create statement fails
        """

    def getString(self, id: typing.Union[jpype.JLong, int]) -> str:
        """
        Try to fetch string from our memory cache, or load it from database, or return empty string
        
        :param jpype.JLong or int id: the row ID
        :return: the string fetched from the table, or empty string if not found
        :rtype: str
        :raises SQLException: if there is a problem parsing the table record(s)
        """

    def readStringId(self, value: typing.Union[java.lang.String, str]) -> int:
        """
        Try to read the id of a specific string in the table
        
        :param java.lang.String or str value: is the string to try to find
        :return: the id of the string or 0 if the string is not in the table
        :rtype: int
        :raises SQLException: if the result set cannot be parsed
        """

    def setConnection(self, db: java.sql.Connection):
        ...

    def writeString(self, val: typing.Union[java.lang.String, str]) -> int:
        ...

    @property
    def string(self) -> java.lang.String:
        ...



__all__ = ["KeyValueTable", "SQLComplexTable", "WeightTable", "DescriptionTable", "IdfLookupTable", "CachedStatement", "ExeToCategoryTable", "StatementSupplier", "ExeTable", "CallgraphTable", "OptionalTable", "SQLStringTable"]
