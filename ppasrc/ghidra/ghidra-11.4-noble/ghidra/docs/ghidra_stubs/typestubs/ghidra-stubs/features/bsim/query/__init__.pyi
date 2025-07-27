from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.cache
import generic.concurrent
import generic.jar
import generic.lsh.vector
import ghidra
import ghidra.features.bsim.gui.search.results
import ghidra.features.bsim.query.client
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.protocol
import ghidra.framework
import ghidra.framework.plugintool.util
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.sql # type: ignore
import java.util # type: ignore
import org.apache.commons.dbcp2 # type: ignore


class CompareSignatures(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vFactory: generic.lsh.vector.LSHVectorFactory):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def run(self, args: jpype.JArray[java.lang.String]):
        ...


class LSHException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class GenSignatures(java.lang.Object):
    """
    Generate decompiler signatures for a set of functions
    """

    @typing.type_check_only
    class CallRecord(java.lang.Object):
        """
        Info for resolving a call to a unique function in the database.
        For normal functions you need the triple (executable, function name, address)
        For calls to library (external) functions, only the library executable
        and the function name are needed, and the address is filled in with -1
        """

        class_: typing.ClassVar[java.lang.Class]
        exerec: ghidra.features.bsim.query.description.ExecutableRecord
        funcname: java.lang.String
        address: jpype.JLong


    class SignatureTask(DecompileFunctionTask):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, callgraph: typing.Union[jpype.JBoolean, bool]):
        """
        Prepare for generation of signature information and (possibly) callgraph information
        
        :param jpype.JBoolean or bool callgraph: is true if the user wants callgraph information to be generated at the same time as signatures
        """

    def addDateColumnName(self, name: typing.Union[java.lang.String, str]):
        ...

    def addExecutableCategories(self, names: java.util.List[java.lang.String]):
        ...

    def addFunctionTags(self, names: java.util.List[java.lang.String]):
        ...

    def clear(self):
        """
        Clear out any accumulated signatures
        """

    def dispose(self):
        ...

    def getDescriptionManager(self) -> ghidra.features.bsim.query.description.DescriptionManager:
        ...

    @staticmethod
    def getPathFromDomainFile(program: ghidra.program.model.listing.Program) -> str:
        """
        Build an ExecutableRecord path from the domain file.
        WARNING: Make sure the program has been saved previously before calling this, otherwise you get
        an (inaccurate) result of "/"
        
        :param ghidra.program.model.listing.Program program: the current program
        :return: the path to this program within the repository as a string
        :rtype: str
        """

    @staticmethod
    def getWeightsFile(id1: ghidra.program.model.lang.LanguageID, id2: ghidra.program.model.lang.LanguageID) -> generic.jar.ResourceFile:
        """
        Return the weights file that should be used to compare functions between two programs
        
        :param ghidra.program.model.lang.LanguageID id1: is the language of the first program
        :param ghidra.program.model.lang.LanguageID id2: is the language of the second program  (can be same as first program)
        :return: the XML weights file, or null if there is no valid weights file
        :rtype: generic.jar.ResourceFile
        :raises IOException: if the module data directory cannot be found
        """

    def openProgram(self, prog: ghidra.program.model.listing.Program, nmover: typing.Union[java.lang.String, str], archover: typing.Union[java.lang.String, str], compover: typing.Union[java.lang.String, str], repo: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str]):
        """
        Prepare to collect signatures for a new program, essentially by starting up a new decompiler process
        and creating an ExecutableRecord
        
        :param ghidra.program.model.listing.Program prog: is the program to prepare for
        :param java.lang.String or str nmover: if not null, overrides the "name" of the executable
        :param java.lang.String or str archover: if not null, overrides the "architecture" of the executable
        :param java.lang.String or str compover: if not null, overrides the "compiler" used to build the executable
        :param java.lang.String or str repo: the repository containing the executable
        :param java.lang.String or str path: the path (within the repo) where the executable can be found
        :raises LSHException: if a new executable record cannot be created
        """

    def scanFunction(self, func: ghidra.program.model.listing.Function):
        """
        Calculate signatures for a single function
        
        :param ghidra.program.model.listing.Function func: is the function to scan
        :raises DecompileException: if the decompiler task fails
        """

    def scanFunctions(self, functions: java.util.Iterator[ghidra.program.model.listing.Function], countestimate: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Generate signatures for a (potentially large) set of functions by spawning multiple
        threads to parallelize the work
        
        :param java.util.Iterator[ghidra.program.model.listing.Function] functions: the set of functions to signature
        :param jpype.JInt or int countestimate: estimated number of functions (to initialize the monitor)
        :param ghidra.util.task.TaskMonitor monitor: controls interruptions and progress reports
        :raises DecompileException: if the functions cannot be decompiled
        """

    def scanFunctionsMetadata(self, iter: java.util.Iterator[ghidra.program.model.listing.Function], monitor: ghidra.util.task.TaskMonitor):
        """
        Generate just the update metadata for functions in the currently open program
        if -iter- is null, generate metadata for all functions
        
        :param java.util.Iterator[ghidra.program.model.listing.Function] iter: iterates over the set of Functions to generate metadata for
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    def setVectorFactory(self, vFactory: generic.lsh.vector.LSHVectorFactory):
        ...

    def transferCachedFunctions(self, otherman: ghidra.features.bsim.query.description.DescriptionManager, functions: java.util.Iterator[ghidra.program.model.listing.Function], preFilter: ghidra.features.bsim.query.protocol.PreFilter) -> int:
        ...

    @property
    def descriptionManager(self) -> ghidra.features.bsim.query.description.DescriptionManager:
        ...


class BSimInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BSimJDBCDataSource(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Dispose pooled datasource.
        """

    def getActiveConnections(self) -> int:
        """
        Get the number of active connections in the associated connection pool
        
        :return: number of active connections
        :rtype: int
        """

    def getConnection(self) -> java.sql.Connection:
        """
        Get DB :obj:`Connection` object performing any required authentication.
        
        :return: :obj:`Connection` object
        :rtype: java.sql.Connection
        :raises SQLException: if connection fails
        """

    def getConnectionType(self) -> FunctionDatabase.ConnectionType:
        ...

    def getIdleConnections(self) -> int:
        """
        Get the number of idle connections in the associated connection pool
        
        :return: number of idle connections
        :rtype: int
        """

    def getServerInfo(self) -> BSimServerInfo:
        """
        Get the server info that corresponds to this data source.  It is important to note
        that the returned instance is normalized for the purpose of caching and may not
        match the original server info object used to obtain this data source instance.
        
        :return: server info
        :rtype: BSimServerInfo
        """

    def getStatus(self) -> FunctionDatabase.Status:
        ...

    @property
    def idleConnections(self) -> jpype.JInt:
        ...

    @property
    def serverInfo(self) -> BSimServerInfo:
        ...

    @property
    def activeConnections(self) -> jpype.JInt:
        ...

    @property
    def connection(self) -> java.sql.Connection:
        ...

    @property
    def connectionType(self) -> FunctionDatabase.ConnectionType:
        ...

    @property
    def status(self) -> FunctionDatabase.Status:
        ...


class MinimalErrorLogger(ghidra.util.DefaultErrorLogger):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BSimServerInfo(java.lang.Comparable[BSimServerInfo]):

    class DBType(java.lang.Enum[BSimServerInfo.DBType]):
        """
        Enumerated Database Types
        """

        class_: typing.ClassVar[java.lang.Class]
        postgres: typing.Final[BSimServerInfo.DBType]
        elastic: typing.Final[BSimServerInfo.DBType]
        file: typing.Final[BSimServerInfo.DBType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BSimServerInfo.DBType:
            ...

        @staticmethod
        def values() -> jpype.JArray[BSimServerInfo.DBType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_POSTGRES_PORT: typing.Final = 5432
    """
    Default port used for :obj:`DBType.postgres` server
    """

    DEFAULT_ELASTIC_PORT: typing.Final = 9200
    """
    Default port used for :obj:`DBType.elastic` server
    """

    H2_FILE_EXTENSION: typing.Final = ".mv.db"
    """
    File extension imposed for :obj:`DBType.file` server.
    This is a rigid H2 database convention.
    """


    @typing.overload
    def __init__(self, dbType: BSimServerInfo.DBType, userinfo: typing.Union[java.lang.String, str], host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], dbName: typing.Union[java.lang.String, str]):
        """
        Construct a new :obj:`BSimServerInfo` object
        
        :param BSimServerInfo.DBType dbType: BSim DB type
        :param java.lang.String or str userinfo: connection user info, ``username[:password]``  (ignored for :obj:`DBType.file`).  
        If blank, :meth:`ClientUtil.getUserName() <ClientUtil.getUserName>` is used.
        :param java.lang.String or str host: host name (ignored for :obj:`DBType.file`)
        :param jpype.JInt or int port: port number (ignored for :obj:`DBType.file`)
        :param java.lang.String or str dbName: name of database (simple database name except for :obj:`DBType.file`
        which should reflect an absolute file path.  On Windows OS the path may start with a
        drive letter.
        :raises IllegalArgumentException: if invalid arguments are specified
        """

    @typing.overload
    def __init__(self, dbType: BSimServerInfo.DBType, host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], dbName: typing.Union[java.lang.String, str]):
        """
        Construct a new :obj:`BSimServerInfo` object.  For non-file database the user's defaut 
        username is used (see :meth:`ClientUtil.getUserName() <ClientUtil.getUserName>`).
        
        :param BSimServerInfo.DBType dbType: BSim DB type
        :param java.lang.String or str host: host name (ignored for :obj:`DBType.file`)
        :param jpype.JInt or int port: port number (ignored for :obj:`DBType.file`)
        :param java.lang.String or str dbName: name of database (simple database name except for :obj:`DBType.file`
        which should reflect an absolute file path.  On Windows OS the path may start with a
        drive letter.
        :raises IllegalArgumentException: if invalid arguments are specified
        """

    @typing.overload
    def __init__(self, dbName: typing.Union[java.lang.String, str]):
        """
        Construct a new :obj:`BSimServerInfo` object for a :obj:`DBType.file` type database.
        
        :param java.lang.String or str dbName: name of database which should reflect an absolute file path.  
        On Windows OS the path may start with a drive letter.
        :raises IllegalArgumentException: if invalid arguments are specified
        """

    @typing.overload
    def __init__(self, url: java.net.URL):
        """
        Construct a new :obj:`BSimServerInfo` object from a suitable database URL
        (i.e., ``postgresql:``, ``https:``, ``elastic:``, ``file:``).
        
        :param java.net.URL url: supported BSim database URL.  For non-file URLs, the hostname or 
        address may be preceeded by a DB username (e.g., postgresql://user@host:port/dbname
        :raises java.lang.IllegalArgumentException: if unsupported URL protocol specified
        """

    def getDBName(self) -> str:
        """
        Get the DB Name
        
        :return: DB name
        :rtype: str
        """

    def getDBType(self) -> BSimServerInfo.DBType:
        """
        
        
        :return: BSim database type
        :rtype: BSimServerInfo.DBType
        """

    def getFunctionDatabase(self, async_: typing.Union[jpype.JBoolean, bool]) -> FunctionDatabase:
        """
        Get a BSim :obj:`FunctionDatabase` instance which corresponds to this DB server info.
        The :obj:`Closeable` instance should be closed when no longer in-use to ensure that 
        any associated database connection and resources are properly closed.
        
        :param jpype.JBoolean or bool async: true if database commits should be asynchronous (may not be applicable)
        :return: BSim function database instance
        :rtype: FunctionDatabase
        """

    def getPort(self) -> int:
        """
        Get the port number.
        
        :return: port number
        :rtype: int
        """

    def getServerName(self) -> str:
        """
        Get the server hostname or IP address as originally specified.
        
        :return: hostname or IP address as originally specified
        :rtype: str
        """

    def getShortDBName(self) -> str:
        """
        Get the DB Name.  In the case of :obj:`DBType.file` the directory path will
        be excluded from returned name.
        
        :return: shortened DB Name
        :rtype: str
        """

    def getUserInfo(self) -> str:
        """
        Get the remote database user information to be used when establishing a connection.
        
        :return: remote database user information (null for :obj:`DBType.file`).
        :rtype: str
        """

    def getUserName(self) -> str:
        """
        Get the remote database user name to be used when establishing a connection.
        User name obtained from the user information which was provided during instantiation.
        
        :return: remote database user information (null for :obj:`DBType.file`).
        :rtype: str
        """

    def hasDefaultLogin(self) -> bool:
        """
        Determine if user info was stipulated during construction
        
        :return: true if user info was stipulated during construction
        :rtype: bool
        """

    def hasPassword(self) -> bool:
        """
        Determine if user information includes password.
        NOTE: Use of passwords with this object and URLs is discouraged.
        
        :return: true if user information includes password which
        :rtype: bool
        """

    def isWindowsFilePath(self) -> bool:
        """
        Determine if this server info corresponds to Windows OS file path.
        
        :return: true if this server info corresponds to Windows OS file path.
        :rtype: bool
        """

    def setUserInfo(self, bds: org.apache.commons.dbcp2.BasicDataSource):
        ...

    def toURL(self) -> java.net.URL:
        """
        Return BSim server info in URL.
        Warning: If userinfo with password has been specified it will be returned in the URL.
        
        :return: BSim server info in URL
        :rtype: java.net.URL
        :raises MalformedURLException: if unable to form supported URL
        """

    def toURLString(self) -> str:
        """
        Return BSim server info in URL format.
        Warning: If userinfo with password has been specified it will be returned in the URL.
        
        :return: BSim server info in URL format
        :rtype: str
        """

    @property
    def userInfo(self) -> java.lang.String:
        ...

    @property
    def shortDBName(self) -> java.lang.String:
        ...

    @property
    def dBName(self) -> java.lang.String:
        ...

    @property
    def port(self) -> jpype.JInt:
        ...

    @property
    def dBType(self) -> BSimServerInfo.DBType:
        ...

    @property
    def windowsFilePath(self) -> jpype.JBoolean:
        ...

    @property
    def serverName(self) -> java.lang.String:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...

    @property
    def functionDatabase(self) -> FunctionDatabase:
        ...


class BSimDBConnectTaskCoordinator(java.lang.Object):
    """
    Provides the ability to synchronize concurrent connection task
    instances within the same thread.  This can occur within the swing thread due to the presence
    of a modal task dialog event queue.  It also allows password cancelation to be propogated to the
    other tasks(s).
    """

    class DBConnectionSupplier(java.lang.Object):
        """
        DB connection supplier
        """

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> java.sql.Connection:
            """
            Get a database connection.
            
            :return: database connection
            :rtype: java.sql.Connection
            :raises CancelledException: if connection attempt cancelled
            :raises SQLException: if a database connection error occurs
            """


    @typing.type_check_only
    class DBConnectTask(ghidra.util.task.Task):
        """
        Task for connecting to Postgres DB server with Swing thread.
        """

        class_: typing.ClassVar[java.lang.Class]

        def run(self, monitor: ghidra.util.task.TaskMonitor):
            """
            Completes and necessary authentication and obtains a DB connection.
            If a connection error occurs, an exception will be stored.
            
            :raises CancelledException: if task cancelled
            
            .. seealso::
            
                | :obj:`ghidra.util.task.Task.run(ghidra.util.task.TaskMonitor)`
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverInfo: BSimServerInfo):
        ...

    def getConnection(self, connectionSupplier: BSimDBConnectTaskCoordinator.DBConnectionSupplier) -> java.sql.Connection:
        """
        Initiate a DB connection.
        
        :param BSimDBConnectTaskCoordinator.DBConnectionSupplier connectionSupplier: DB connection supplier
        :return: DB connection
        :rtype: java.sql.Connection
        :raises SQLException: if a database connection error occured
        :raises CancelledSQLException: if task was cancelled (password entry cancelled)
        """

    @property
    def connection(self) -> java.sql.Connection:
        ...


class BSimClientFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def buildClient(bsimServerInfo: BSimServerInfo, async_: typing.Union[jpype.JBoolean, bool]) -> FunctionDatabase:
        """
        Given the URL for a BSim server construct the appropriate BSim client object 
        (implementing FunctionDatabase).  Returned instance must be 
        :meth:`closed <FunctionDatabase.close>` when done using it to prevent depletion
        of database connections.
        
        :param BSimServerInfo bsimServerInfo: BSim server details
        :param jpype.JBoolean or bool async: true if database commits should be asynchronous
        :return: the database client
        :rtype: FunctionDatabase
        """

    @staticmethod
    @typing.overload
    def buildClient(bsimURL: java.net.URL, async_: typing.Union[jpype.JBoolean, bool]) -> FunctionDatabase:
        """
        Given the URL for a BSim server construct the appropriate BSim client object 
        (implementing FunctionDatabase).  Returned instance must be 
        :meth:`closed <FunctionDatabase.close>` when done using it to prevent depletion
        of database connections.
        
        :param java.net.URL bsimURL: URL supplied by the user
        :param jpype.JBoolean or bool async: true if database commits should be synchronous
        :return: the database client
        :rtype: FunctionDatabase
        :raises MalformedURLException: if there's a problem creating the elastic database
        """

    @staticmethod
    def buildURL(urlString: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Build a root URL for connecting to a BSim database.
        1) A valid protocol must be provided.
        2) There must be a path of exactly 1 element, which names the specific repository
        Acceptable protocols are  postgresql://  https://,  (or possibly http://) file:/
        
        :param java.lang.String or str urlString: the URL to build
        :return: the parsed URL object
        :rtype: java.net.URL
        :raises MalformedURLException: if the URL string cannot be parsed
        """

    @staticmethod
    def checkBSimServerURL(url: java.net.URL):
        """
        Validate BSim DB URL.
        Acceptable protocols are  postgresql://  https://,  (or possibly http://) file:/
        
        :param java.net.URL url: BSim DB URL
        :raises MalformedURLException: if the URL string is not a support BSim DB URL
        """

    @staticmethod
    def deriveBSimURL(urlString: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Construct the root URL to a specific BSim repository given a "related" URL.
        The root URL will have an explicit protocol, a hostname + other mods (the authority), and 1 level of path
            this first level path indicates the particular repository being referenced on the host.
        The "related" URL -url- can be an explicitly provided URL pointing to the BSim repository,
            possibly with additional path levels, which are simply stripped from the final root URL.
        Alternately -url- can reference a ghidra server, as indicated by the "ghidra" protocol.
            In this case the true BSim URL is derived from ghidra URL in some way
        
        :param java.lang.String or str urlString: is the "related" URL
        :return: the root BSim URL
        :rtype: java.net.URL
        :raises MalformedURLException: if the given URL string cannot be parsed
        :raises java.lang.IllegalArgumentException: if local ghidra URL is specified
        """


class ServerConfig(java.lang.Object):
    """
    Class for modifying the PostgreSQL configuration files describing
    the main server settings (postgresql.conf)
    the connection settings  (pg_hba.conf)
    the identification map   (pg_ident.conf)
    """

    @typing.type_check_only
    class ConfigLine(java.lang.Object):
        """
        Class that holds a single configuration option from the PostgreSQL configuration file
        """

        class_: typing.ClassVar[java.lang.Class]
        key: java.lang.String
        value: java.lang.String
        comment: java.lang.String
        status: jpype.JInt

        def parseUptoKey(self, line: typing.Union[java.lang.String, str]):
            ...

        def parseValue(self, line: typing.Union[java.lang.String, str]):
            ...

        def skipValueParseComment(self, line: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ConnectLine(java.lang.Comparable[ServerConfig.ConnectLine]):
        """
        Class that holds an entry from the PostgreSQL connection configuration file
        """

        class_: typing.ClassVar[java.lang.Class]
        type: java.lang.String
        database: java.lang.String
        user: java.lang.String
        address: java.lang.String
        method: java.lang.String
        options: java.lang.String
        isMatched: jpype.JBoolean

        def emit(self, writer: java.io.Writer):
            """
            Emit the line, formatted as it should appear in the connection file
            
            :param java.io.Writer writer: the stream writer
            :raises IOException: if appending to the stream fails
            """

        def isLocal(self) -> bool:
            """
            Determine if the connection is coming either from UNIX socket or "localhost"
            
            :return: true if the connection is local in this sense
            :rtype: bool
            """

        def parse(self, line: typing.Union[java.lang.String, str]):
            """
            Parse the fields out of a line of the connection file
            
            :param java.lang.String or str line: the text to parse
            :raises IOException: if the text is not formatted properly to parse
            """

        def restoreXml(self, el: ghidra.xml.XmlElement):
            """
            Restore a connection entry from an XML tag
            
            :param ghidra.xml.XmlElement el: the XML element to restore
            """

        @property
        def local(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class IdentLine(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            ...

        @typing.overload
        def __init__(self, mName: typing.Union[java.lang.String, str], sysName: typing.Union[java.lang.String, str], rName: typing.Union[java.lang.String, str]):
            ...

        def emit(self, writer: java.io.Writer):
            ...

        def matchRole(self, mName: typing.Union[java.lang.String, str], rName: typing.Union[java.lang.String, str]) -> bool:
            ...

        @staticmethod
        def needsDoubleQuotes(name: typing.Union[java.lang.String, str]) -> bool:
            ...

        def parse(self, line: typing.Union[java.lang.String, str]) -> bool:
            """
            Parse a single line from the pg_ident.conf file and recover the
            map name, system name, and role
            
            :param java.lang.String or str line: is the incoming of text
            :return: true if the line is an ident entry, false if it is a comment
            :rtype: bool
            :raises IOException: if the text cannot be parsed
            """

        def setSystemName(self, sysName: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addKey(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Add a key/value pair directly into the configuration file
        
        :param java.lang.String or str key: the key to add/update
        :param java.lang.String or str value: the value to insert
        """

    def getHostAuthentication(self) -> str:
        ...

    def getLocalAuthentication(self) -> str:
        ...

    def getValue(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        Retrieve the value associated with a particular key from a (parsed) configuration file
        
        :param java.lang.String or str key: identifies the value to return
        :return: the value
        :rtype: str
        """

    def patchConfig(self, inFile: jpype.protocol.SupportsPath, outFile: jpype.protocol.SupportsPath):
        """
        Given a set of key/value pairs, established via restoreXml or manually entered via addKey,
        read in an existing configuration file, and write out an altered form, where:
        1) Keys matching something in the keyValue map have their value altered to match the map
        2) Keys that don't match anything in the map, are output unaltered
        3) Comments, both entire line and those coming after key/value pairs, are preserved
        
        :param jpype.protocol.SupportsPath inFile: the file to read
        :param jpype.protocol.SupportsPath outFile: the new file to write
        :raises IOException: if the files cannot be read from or written to
        """

    def patchConnect(self, inFile: jpype.protocol.SupportsPath, outFile: jpype.protocol.SupportsPath):
        """
        Read in a connection file and write out an altered version of the file where:
        1) Any entry that matches something in connectSet, has its authentication method altered
        2) Any entry that does not match into connectSet is commented out in the output
        3) Entire line comments are preserved
        
        :param jpype.protocol.SupportsPath inFile: the file to read
        :param jpype.protocol.SupportsPath outFile: the new file to write
        :raises IOException: if the files cannot be read from or written to
        """

    @staticmethod
    def patchIdent(inFile: jpype.protocol.SupportsPath, outFile: jpype.protocol.SupportsPath, mapName: typing.Union[java.lang.String, str], systemName: typing.Union[java.lang.String, str], roleName: typing.Union[java.lang.String, str], addUser: typing.Union[jpype.JBoolean, bool]):
        """
        Add/remove an identify entry to pg_ident.conf
        
        :param jpype.protocol.SupportsPath inFile: is a copy of pg_ident.conf to modify
        :param jpype.protocol.SupportsPath outFile: becomes the modified copy of pg_ident.conf
        :param java.lang.String or str mapName: is the map being modified
        :param java.lang.String or str systemName: is the system name (map from)
        :param java.lang.String or str roleName: is the database role (map to)
        :param jpype.JBoolean or bool addUser: is true if the map entry is to be added, false if the entry should be removed
        :raises IOException: if the file cannot be read from or written to
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Read a set of key/value pairs and connection entries to use for patching, from an XML file
        
        :param ghidra.xml.XmlPullParser parser: the XML parser
        """

    def scanConfig(self, inFile: jpype.protocol.SupportsPath):
        """
        Parse a configuration file
        
        :param jpype.protocol.SupportsPath inFile: is the path to the file
        :raises IOException: if the file cannot be read
        """

    def scanConnect(self, inFile: jpype.protocol.SupportsPath):
        """
        Read in all the entries of the connection file
        
        :param jpype.protocol.SupportsPath inFile: the file to read in
        :raises IOException: if the file cannot be read/parsed
        """

    def setHostAuthentication(self, val: typing.Union[java.lang.String, str], options: typing.Union[java.lang.String, str]):
        ...

    def setLocalAuthentication(self, val: typing.Union[java.lang.String, str], options: typing.Union[java.lang.String, str]):
        ...

    @property
    def localAuthentication(self) -> java.lang.String:
        ...

    @property
    def hostAuthentication(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.lang.String:
        ...


class FunctionDatabase(java.lang.AutoCloseable):

    class Status(java.lang.Enum[FunctionDatabase.Status]):

        class_: typing.ClassVar[java.lang.Class]
        Unconnected: typing.Final[FunctionDatabase.Status]
        Busy: typing.Final[FunctionDatabase.Status]
        Error: typing.Final[FunctionDatabase.Status]
        Ready: typing.Final[FunctionDatabase.Status]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FunctionDatabase.Status:
            ...

        @staticmethod
        def values() -> jpype.JArray[FunctionDatabase.Status]:
            ...


    class ConnectionType(java.lang.Enum[FunctionDatabase.ConnectionType]):

        class_: typing.ClassVar[java.lang.Class]
        SSL_No_Authentication: typing.Final[FunctionDatabase.ConnectionType]
        SSL_Password_Authentication: typing.Final[FunctionDatabase.ConnectionType]
        Unencrypted_No_Authentication: typing.Final[FunctionDatabase.ConnectionType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FunctionDatabase.ConnectionType:
            ...

        @staticmethod
        def values() -> jpype.JArray[FunctionDatabase.ConnectionType]:
            ...


    class ErrorCategory(java.lang.Enum[FunctionDatabase.ErrorCategory]):

        class_: typing.ClassVar[java.lang.Class]
        Unused: typing.Final[FunctionDatabase.ErrorCategory]
        Nonfatal: typing.Final[FunctionDatabase.ErrorCategory]
        Fatal: typing.Final[FunctionDatabase.ErrorCategory]
        Initialization: typing.Final[FunctionDatabase.ErrorCategory]
        Format: typing.Final[FunctionDatabase.ErrorCategory]
        Nodatabase: typing.Final[FunctionDatabase.ErrorCategory]
        Connection: typing.Final[FunctionDatabase.ErrorCategory]
        Authentication: typing.Final[FunctionDatabase.ErrorCategory]
        AuthenticationCancelled: typing.Final[FunctionDatabase.ErrorCategory]

        def getInteger(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FunctionDatabase.ErrorCategory:
            ...

        @staticmethod
        def values() -> jpype.JArray[FunctionDatabase.ErrorCategory]:
            ...

        @property
        def integer(self) -> jpype.JInt:
            ...


    class BSimError(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        category: FunctionDatabase.ErrorCategory
        message: java.lang.String

        def __init__(self, cat: FunctionDatabase.ErrorCategory, msg: typing.Union[java.lang.String, str]):
            ...


    class DatabaseNonFatalException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def changePassword(self, newPassword: jpype.JArray[jpype.JChar]) -> str:
        """
        Issue password change request to the server.
        The method :meth:`isPasswordChangeAllowed() <.isPasswordChangeAllowed>` must be invoked first to ensure that
        the user password may be changed.
        
        :param jpype.JArray[jpype.JChar] newPassword: is password data
        :return: null if change was successful, or the error message
        :rtype: str
        """

    @staticmethod
    def checkSettingsForInsert(manage: ghidra.features.bsim.query.description.DescriptionManager, info: ghidra.features.bsim.query.description.DatabaseInformation) -> bool:
        ...

    @staticmethod
    def checkSettingsForQuery(manage: ghidra.features.bsim.query.description.DescriptionManager, info: ghidra.features.bsim.query.description.DatabaseInformation):
        ...

    def close(self):
        """
        Close down (the connection with) the database
        """

    def compareLayout(self) -> int:
        """
        Return -1 if info layout version is earlier than current client expectation
        Return 1 if info layout version is later than current client expectation
        Return 0 if info version and client version are the same
        
        :return: comparison of actual database layout with layout expected by client
        :rtype: int
        """

    @staticmethod
    def constructFatalError(flags: typing.Union[jpype.JInt, int], newrec: ghidra.features.bsim.query.description.ExecutableRecord, orig: ghidra.features.bsim.query.description.ExecutableRecord) -> str:
        ...

    @staticmethod
    def constructNonfatalError(flags: typing.Union[jpype.JInt, int], newrec: ghidra.features.bsim.query.description.ExecutableRecord, orig: ghidra.features.bsim.query.description.ExecutableRecord) -> str:
        ...

    @staticmethod
    def generateLSHVectorFactory() -> generic.lsh.vector.WeightedLSHCosineVectorFactory:
        """
        Central location for building vector factory used by FunctionDatabase
        
        :return: the LSHVectorFactory object
        :rtype: generic.lsh.vector.WeightedLSHCosineVectorFactory
        """

    @staticmethod
    def getConfigurationTemplates() -> java.util.List[java.io.File]:
        """
        Returns a list of all configuration template files.
        
        :return: list of template files
        :rtype: java.util.List[java.io.File]
        """

    def getConnectionType(self) -> FunctionDatabase.ConnectionType:
        """
        
        
        :return: the type of connection
        :rtype: FunctionDatabase.ConnectionType
        """

    def getInfo(self) -> ghidra.features.bsim.query.description.DatabaseInformation:
        """
        
        
        :return: an information object giving general characteristics and descriptions of this database
        :rtype: ghidra.features.bsim.query.description.DatabaseInformation
        """

    def getLSHVectorFactory(self) -> generic.lsh.vector.LSHVectorFactory:
        """
        
        
        :return: factory the database is using to create LSHVector objects
        :rtype: generic.lsh.vector.LSHVectorFactory
        """

    def getLastError(self) -> FunctionDatabase.BSimError:
        """
        If the last query failed to produce a response, use this method to recover the error message
        
        :return: a String describing the error
        :rtype: FunctionDatabase.BSimError
        """

    def getOverviewFunctionsPerStage(self) -> int:
        """
        Get the maximum number of functions to be queried per staged query when performing
        an overview query.
        
        :return: maximum number of functions to be queried per staged query, or 0 for default
        which is generally ten (10) per stage.  See :obj:`SFOverviewInfo.DEFAULT_QUERIES_PER_STAGE`.
        :rtype: int
        """

    def getQueriedFunctionsPerStage(self) -> int:
        """
        Get the maximum number of functions to be queried per staged query when searching
        for similar functions.
        
        :return: maximum number of functions to be queried per staged query, or 0 for default
        which is generally ten (10) per stage.  See :obj:`SFQueryInfo.DEFAULT_QUERIES_PER_STAGE`.
        :rtype: int
        """

    def getServerInfo(self) -> BSimServerInfo:
        """
        Return the :obj:`server info object <BSimServerInfo>` for this database
        
        :return: the server info object
        :rtype: BSimServerInfo
        """

    def getStatus(self) -> FunctionDatabase.Status:
        """
        
        
        :return: the status of the current connection with this database
        :rtype: FunctionDatabase.Status
        """

    def getURLString(self) -> str:
        ...

    def getUserName(self) -> str:
        """
        
        
        :return: username (being used to establish connection)
        :rtype: str
        """

    def initialize(self) -> bool:
        """
        Initialize (a connection with) the database. If initialization is not successful, this routine will
        return false and an error description can be obtained using getLastError
        
        :return: true if the database ready for querying
        :rtype: bool
        """

    @staticmethod
    def isConfigTemplate(file: jpype.protocol.SupportsPath) -> bool:
        """
        Determines if a given xml file is a config template. This is done by opening the file
        and checking for the presence of a ``<dbconfig>`` root tag.
        
        :param jpype.protocol.SupportsPath file: the file to inspect
        :return: true if the file is config template
        :rtype: bool
        """

    def isPasswordChangeAllowed(self) -> bool:
        """
        Determine if the connected database supports a user password change.
        
        :return: true if a password change is permitted, else false.
        :rtype: bool
        """

    @staticmethod
    def loadConfigurationTemplate(configname: typing.Union[java.lang.String, str]) -> ghidra.features.bsim.query.client.Configuration:
        ...

    def query(self, query: ghidra.features.bsim.query.protocol.BSimQuery[typing.Any]) -> ghidra.features.bsim.query.protocol.QueryResponseRecord:
        """
        Send a query to the database.  The response is returned as a QueryResponseRecord.
        If this is null, an error has occurred and an error message can be obtained from getLastError
        
        :param ghidra.features.bsim.query.protocol.BSimQuery[typing.Any] query: an object describing the query
        :return: the response object or null if there is an error
        :rtype: ghidra.features.bsim.query.protocol.QueryResponseRecord
        """

    @property
    def lSHVectorFactory(self) -> generic.lsh.vector.LSHVectorFactory:
        ...

    @property
    def passwordChangeAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def overviewFunctionsPerStage(self) -> jpype.JInt:
        ...

    @property
    def lastError(self) -> FunctionDatabase.BSimError:
        ...

    @property
    def serverInfo(self) -> BSimServerInfo:
        ...

    @property
    def queriedFunctionsPerStage(self) -> jpype.JInt:
        ...

    @property
    def uRLString(self) -> java.lang.String:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...

    @property
    def connectionType(self) -> FunctionDatabase.ConnectionType:
        ...

    @property
    def status(self) -> FunctionDatabase.Status:
        ...

    @property
    def info(self) -> ghidra.features.bsim.query.description.DatabaseInformation:
        ...


class DecompileFunctionTask(java.lang.Object):
    """
    Interface for a task that is initialized with a program, and a number of workers.
    Then the task is replicated for that number of workers, and each replicated task
    has its -decompile- method called some number of times with different functions
    and produces some output object
    """

    class_: typing.ClassVar[java.lang.Class]

    def clone(self, worker: typing.Union[jpype.JInt, int]) -> DecompileFunctionTask:
        ...

    def decompile(self, func: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor):
        ...

    def initializeGlobal(self, program: ghidra.program.model.listing.Program):
        ...

    def shutdown(self):
        ...


class ChildMatchRecord(java.lang.Comparable[ChildMatchRecord]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, match: ghidra.features.bsim.gui.search.results.BSimMatchResult, vec: generic.lsh.vector.LSHVector):
        ...

    def getSignificanceWithChildren(self) -> float:
        ...

    def getSimilarFunction(self) -> ghidra.features.bsim.gui.search.results.BSimMatchResult:
        ...

    def getSimilarityWithChildren(self) -> float:
        ...

    def getVecWithChildren(self) -> generic.lsh.vector.LSHVector:
        ...

    def setSignificanceWithChildren(self, newSignif: typing.Union[jpype.JDouble, float]):
        ...

    def setSimilarityWithChildren(self, newSim: typing.Union[jpype.JDouble, float]):
        ...

    @property
    def similarityWithChildren(self) -> jpype.JDouble:
        ...

    @similarityWithChildren.setter
    def similarityWithChildren(self, value: jpype.JDouble):
        ...

    @property
    def similarFunction(self) -> ghidra.features.bsim.gui.search.results.BSimMatchResult:
        ...

    @property
    def vecWithChildren(self) -> generic.lsh.vector.LSHVector:
        ...

    @property
    def significanceWithChildren(self) -> jpype.JDouble:
        ...

    @significanceWithChildren.setter
    def significanceWithChildren(self, value: jpype.JDouble):
        ...


class BsimPluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "BSim"

    def __init__(self):
        ...


class BSimPostgresDBConnectionManager(java.lang.Object):

    class BSimPostgresDataSource(BSimJDBCDataSource):

        class_: typing.ClassVar[java.lang.Class]

        def getUserName(self) -> str:
            ...

        def initializeFrom(self, otherDs: BSimPostgresDBConnectionManager.BSimPostgresDataSource):
            ...

        def setPassword(self, username: typing.Union[java.lang.String, str], newPassword: jpype.JArray[jpype.JChar]):
            """
            Update password on :obj:`BasicDataSource` for use with future connect attempts.
            Has no affect if username does not match username on data source.
            
            :param java.lang.String or str username: username
            :param jpype.JArray[jpype.JChar] newPassword: updated password
            """

        def setPreferredUserName(self, userName: typing.Union[java.lang.String, str]):
            ...

        @property
        def userName(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def getDataSource(postgresServerInfo: BSimServerInfo) -> BSimPostgresDBConnectionManager.BSimPostgresDataSource:
        ...

    @staticmethod
    @typing.overload
    def getDataSource(postgresUrl: java.net.URL) -> BSimPostgresDBConnectionManager.BSimPostgresDataSource:
        ...

    @staticmethod
    def getDataSourceIfExists(serverInfo: BSimServerInfo) -> BSimPostgresDBConnectionManager.BSimPostgresDataSource:
        ...


class BSimControlLaunchable(ghidra.GhidraLaunchable):

    @typing.type_check_only
    class IOThread(java.lang.Thread):
        """
        Class for processing standard output or standard error for processes invoked by BSimControl
        The streams can be optionally suppressed or dumped to System.out
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, input: java.io.InputStream, suppressOut: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    COMMAND_START: typing.Final = "start"
    COMMAND_STOP: typing.Final = "stop"
    COMMAND_STATUS: typing.Final = "status"
    COMMAND_RESET_PASSWORD: typing.Final = "resetpassword"
    COMMAND_CHANGE_PRIVILEGE: typing.Final = "changeprivilege"
    COMMAND_ADDUSER: typing.Final = "adduser"
    COMMAND_DROPUSER: typing.Final = "dropuser"
    COMMAND_CHANGEAUTH: typing.Final = "changeauth"
    CAFILE_OPTION: typing.Final = "--cafile"
    AUTH_OPTION: typing.Final = "--auth"
    DN_OPTION: typing.Final = "--dn"
    PORT_OPTION: typing.Final = "--port"
    USER_OPTION: typing.Final = "--user"
    CERT_OPTION: typing.Final = "--cert"
    NO_LOCAL_AUTH_OPTION: typing.Final = "--noLocalAuth"
    FORCE_OPTION: typing.Final = "--force"

    def __init__(self):
        """
        Constructor for launching from the console
        """

    def run(self, params: jpype.JArray[java.lang.String]):
        """
        Runs the command specified by the given set of params.
        
        :param jpype.JArray[java.lang.String] params: the parameters specifying the command
        :raises IllegalArgumentException: if invalid params have been specified
        :raises java.lang.Exception: if there's an error during the operation
        :raises CancelledException: if processing is cancelled
        """


class SQLFunctionDatabase(FunctionDatabase):

    class_: typing.ClassVar[java.lang.Class]

    def formatBitAndSQL(self, v1: typing.Union[java.lang.String, str], v2: typing.Union[java.lang.String, str]) -> str:
        """
        Generate SQL bitwise-and syntax for use in database query WHERE clause
        
        :param java.lang.String or str v1: first value
        :param java.lang.String or str v2: second value
        :return: SQL
        :rtype: str
        """


class ParallelDecompileTask(java.lang.Object):
    """
    Run decompilation across multiple functions in a single program, distributing the task across
    a specific number of threads
    """

    @typing.type_check_only
    class ParallelDecompilerCallback(generic.concurrent.QCallback[ghidra.program.model.listing.Function, ghidra.program.model.listing.Function]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DecompilerTaskFactory(generic.cache.CountingBasicFactory[DecompileFunctionTask]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, prog: ghidra.program.model.listing.Program, mon: ghidra.util.task.TaskMonitor, ftask: DecompileFunctionTask):
        ...

    def decompile(self, iter: java.util.Iterator[ghidra.program.model.listing.Function], functionCount: typing.Union[jpype.JInt, int]):
        ...



__all__ = ["CompareSignatures", "LSHException", "GenSignatures", "BSimInitializer", "BSimJDBCDataSource", "MinimalErrorLogger", "BSimServerInfo", "BSimDBConnectTaskCoordinator", "BSimClientFactory", "ServerConfig", "FunctionDatabase", "DecompileFunctionTask", "ChildMatchRecord", "BsimPluginPackage", "BSimPostgresDBConnectionManager", "BSimControlLaunchable", "SQLFunctionDatabase", "ParallelDecompileTask"]
