from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra.features.bsim.query
import ghidra.features.bsim.query.client
import ghidra.features.bsim.query.client.tables
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.elastic
import java.lang # type: ignore
import java.net # type: ignore
import java.sql # type: ignore
import java.util # type: ignore


class VectorStoreEntry(java.lang.Record):
    """
    A record containing an :obj:`LSHVector` and a count of the number of functions in the 
    database which share the vector
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JLong, int], vec: generic.lsh.vector.LSHVector, count: typing.Union[jpype.JInt, int], selfSig: typing.Union[jpype.JDouble, float]):
        ...

    def count(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def id(self) -> int:
        ...

    def selfSig(self) -> float:
        ...

    def toString(self) -> str:
        ...

    def vec(self) -> generic.lsh.vector.LSHVector:
        ...


class BSimVectorStoreManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getVectorStore(serverInfo: ghidra.features.bsim.query.BSimServerInfo) -> VectorStore:
        ...

    @staticmethod
    def remove(serverInfo: ghidra.features.bsim.query.BSimServerInfo):
        ...


class H2FileFunctionDatabase(ghidra.features.bsim.query.client.AbstractSQLFunctionDatabase[ghidra.features.bsim.query.elastic.Base64VectorFactory]):

    class_: typing.ClassVar[java.lang.Class]
    OVERVIEW_FUNCS_PER_STAGE: typing.Final = 1024
    QUERY_FUNCS_PER_STAGE: typing.Final = 256
    LAYOUT_VERSION: typing.Final = 1

    @typing.overload
    def __init__(self, bsimURL: java.net.URL):
        """
        Constructor used to connect to an existing H2 file database
        
        :param java.net.URL bsimURL: local file URL for H2 database
        """

    @typing.overload
    def __init__(self, serverInfo: ghidra.features.bsim.query.BSimServerInfo):
        """
        Constructor used to connect to an existing H2 file database
        
        :param ghidra.features.bsim.query.BSimServerInfo serverInfo: local file info for H2 database
        """

    def readVectorMap(self) -> java.util.Map[java.lang.Long, VectorStoreEntry]:
        """
        Create vector map which maps vector ID to :obj:`VectorStoreEntry`
        
        :return: vector map
        :rtype: java.util.Map[java.lang.Long, VectorStoreEntry]
        :raises SQLException: if error occurs while reading map data
        """


class VectorStore(java.lang.Iterable[VectorStoreEntry]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverInfo: ghidra.features.bsim.query.BSimServerInfo):
        ...

    def delete(self, id: typing.Union[jpype.JLong, int]):
        ...

    def getVectorById(self, id: typing.Union[jpype.JLong, int]) -> VectorStoreEntry:
        ...

    def invalidate(self):
        ...

    @typing.overload
    def update(self, entry: VectorStoreEntry):
        ...

    @typing.overload
    def update(self, id: typing.Union[jpype.JLong, int], count: typing.Union[jpype.JInt, int]):
        ...

    @property
    def vectorById(self) -> VectorStoreEntry:
        ...


class H2VectorTable(ghidra.features.bsim.query.client.tables.SQLComplexTable):

    class_: typing.ClassVar[java.lang.Class]
    TABLE_NAME: typing.Final = "h2_vectable"

    def __init__(self, vectorFactory: ghidra.features.bsim.query.elastic.Base64VectorFactory, vectorStore: VectorStore):
        ...

    def deleteVector(self, id: typing.Union[jpype.JLong, int], countDiff: typing.Union[jpype.JInt, int]) -> int:
        """
        Update vector table entry with the specified countDiff.  Record will be removed
        if reduced vector count less-than-or-equal zero.
        
        :param jpype.JLong or int id: vector ID
        :param jpype.JInt or int countDiff: positive vector count reduction
        :return: 0 if decrement short of 0, return 1 if record was removed, return
                -1 if there was a problem
        :rtype: int
        :raises SQLException: if an error occurs
        """

    def queryVectorById(self, id: typing.Union[jpype.JLong, int]) -> ghidra.features.bsim.query.description.VectorResult:
        """
        Get vector details which correspond to specified vector ID
        
        :param jpype.JLong or int id: vector ID
        :return: vector details
        :rtype: ghidra.features.bsim.query.description.VectorResult
        :raises SQLException: if error occurs
        """

    def readVectors(self) -> java.util.Map[java.lang.Long, VectorStoreEntry]:
        """
        Read all vectors from table and generate an ID-based vector map
        
        :return: vector map (ID->VectorStoreEntry)
        :rtype: java.util.Map[java.lang.Long, VectorStoreEntry]
        :raises SQLException: if error occurs
        """

    def updateVector(self, vec: generic.lsh.vector.LSHVector, countDiff: typing.Union[jpype.JInt, int]) -> int:
        """
        Update or insert vector table entry with the specified positive countDiff.
        
        :param generic.lsh.vector.LSHVector vec: vector
        :param jpype.JInt or int countDiff: positive vector count change
        :return: vector ID which was updated or created
        :rtype: int
        :raises SQLException: if an error occurs
        """


class BSimH2FileDBConnectionManager(java.lang.Object):

    class BSimH2FileDataSource(ghidra.features.bsim.query.BSimJDBCDataSource):
        """
        :obj:`BSimH2FileDataSource` provides a pooled DB data source for a specific H2 File DB.
        """

        class_: typing.ClassVar[java.lang.Class]

        def delete(self) -> bool:
            """
            Delete the database files associated with this H2 File DB.  This will fail immediately 
            if active connections exist.  Otherwise removal will be attempted and this data source 
            will no longer be valid.
            
            :return: true if DB sucessfully removed
            :rtype: bool
            """

        def exists(self) -> bool:
            """
            Determine if the stored DB file exists.
            
            :return: true if the stored DB file exists
            :rtype: bool
            """

        def getConnection(self) -> java.sql.Connection:
            """
            Get a connection to the H2 file database.
            It is important to note that if the database does not exist and empty one will
            be created.  The :meth:`exists() <.exists>` method should be used to check for the database
            existance prior to connecting the first time.
            
            :return: database connection
            :rtype: java.sql.Connection
            :raises SQLException: if a database error occurs
            """

        @property
        def connection(self) -> java.sql.Connection:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getAllDataSources() -> java.util.Collection[BSimH2FileDBConnectionManager.BSimH2FileDataSource]:
        """
        Get all H2 File DB data sorces which exist in the JVM.
        
        :return: all H2 File DB data sorces
        :rtype: java.util.Collection[BSimH2FileDBConnectionManager.BSimH2FileDataSource]
        """

    @staticmethod
    @typing.overload
    def getDataSource(fileServerInfo: ghidra.features.bsim.query.BSimServerInfo) -> BSimH2FileDBConnectionManager.BSimH2FileDataSource:
        """
        Get an existing or new H2 File DB data source for the specified H2 File
        specified by ``fileServerInfo``.
        
        :param ghidra.features.bsim.query.BSimServerInfo fileServerInfo: H2 File DB info
        :return: new or existing H2 File DB data source
        :rtype: BSimH2FileDBConnectionManager.BSimH2FileDataSource
        :raises IllegalArgumentException: if ``fileServerInfo`` does not specify an
        H2 File DB type.
        """

    @staticmethod
    @typing.overload
    def getDataSource(h2FileUrl: java.net.URL) -> BSimH2FileDBConnectionManager.BSimH2FileDataSource:
        ...

    @staticmethod
    def getDataSourceIfExists(serverInfo: ghidra.features.bsim.query.BSimServerInfo) -> BSimH2FileDBConnectionManager.BSimH2FileDataSource:
        """
        Get the existing H2 File DB data source for the specified BSim DB server info.
        This may return null if the H2 File DB exists but a 
        :meth:`data source <.getDataSource>`
        has not yet been established within the running JVM.
        
        :param ghidra.features.bsim.query.BSimServerInfo serverInfo: BSim DB server info
        :return: existing H2 File data source or null if server info does not correspond to an
        H2 File or has not be established as an H2 File data source.
        :rtype: BSimH2FileDBConnectionManager.BSimH2FileDataSource
        """



__all__ = ["VectorStoreEntry", "BSimVectorStoreManager", "H2FileFunctionDatabase", "VectorStore", "H2VectorTable", "BSimH2FileDBConnectionManager"]
