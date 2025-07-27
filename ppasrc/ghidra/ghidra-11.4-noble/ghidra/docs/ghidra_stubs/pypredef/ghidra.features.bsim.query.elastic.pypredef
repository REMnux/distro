from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.gson # type: ignore
import generic.lsh.vector
import ghidra.features.bsim.gui.filters
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.protocol
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


class Base64Lite(java.lang.Object):
    """
    Lightweight Base64 encoder for writing chars directly to StringBuilders and giving
    direct access to the encode and decode arrays
    """

    class_: typing.ClassVar[java.lang.Class]
    encode: typing.Final[jpype.JArray[jpype.JChar]]
    decode: typing.Final[jpype.JArray[jpype.JInt]]

    def __init__(self):
        ...

    @staticmethod
    def decodeLongBase64(val: typing.Union[java.lang.String, str]) -> int:
        """
        Decode (up to 11) base64 characters to produce a long
        
        :param java.lang.String or str val: is the String to decode
        :return: the decode long
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def encodeLongBase64(buf: java.lang.StringBuilder, val: typing.Union[jpype.JLong, int]):
        """
        Encode a long value in base64 to a StringBuilder "stream".
        Omit initial 'A' characters if the high-order bits of the value are zero
        
        :param java.lang.StringBuilder buf: is the buffer to write to
        :param jpype.JLong or int val: is the long value to encode
        """

    @staticmethod
    @typing.overload
    def encodeLongBase64(val: typing.Union[jpype.JLong, int]) -> str:
        """
        Encode a long value in base64 to a String. Omit initial 'A' characters if the high-order bits of the value are zero
        
        :param jpype.JLong or int val: is the long to encode
        :return: the encoded String
        :rtype: str
        """

    @staticmethod
    def encodeLongBase64Padded(buf: java.lang.StringBuilder, val: typing.Union[jpype.JLong, int]):
        """
        Encode a long value in base64 to the StringBuilder "stream" padding out with 'A' characters
        so that exactly 11 characters are always written to the stream
        
        :param java.lang.StringBuilder buf: is the buffer to write to
        :param jpype.JLong or int val: is the long value to encode
        """


class ElasticConnection(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    POST: typing.Final = "POST"
    PUT: typing.Final = "PUT"
    GET: typing.Final = "GET"
    DELETE: typing.Final = "DELETE"

    def __init__(self, url: typing.Union[java.lang.String, str], repo: typing.Union[java.lang.String, str]):
        ...

    def executeBulk(self, path: typing.Union[java.lang.String, str], body: typing.Union[java.lang.String, str]) -> com.google.gson.JsonObject:
        """
        Send a bulk request to the elasticsearch server.  This is a special format for combining multiple commands
        and is structured slightly differently from other commands.
        
        :param java.lang.String or str path: is the specific URL path receiving the bulk command
        :param java.lang.String or str body: is structured list of JSON commands and source
        :return: the response as parsed JsonObject
        :rtype: com.google.gson.JsonObject
        :raises ElasticException: for any problems with the connection
        """

    def executeRawStatement(self, command: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], body: typing.Union[java.lang.String, str]) -> com.google.gson.JsonObject:
        """
        Send a raw request to the server that is not specific to the repository.
        Intended for general configuration or security commands
        
        :param java.lang.String or str command: is the type of command
        :param java.lang.String or str path: is the specific URL path receiving the command
        :param java.lang.String or str body: is JSON document describing the command
        :return: the response as parsed JsonObject
        :rtype: com.google.gson.JsonObject
        :raises ElasticException: for any problems with the connection
        """

    def executeStatement(self, command: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], body: typing.Union[java.lang.String, str]) -> com.google.gson.JsonObject:
        """
        Execute an elastic search statement and return the JSON response to user
        
        :param java.lang.String or str command: is the type of command
        :param java.lang.String or str path: is the overarching ``index/type/<command>``
        :param java.lang.String or str body: is JSON document describing the request
        :return: the parsed response as a JsonObject
        :rtype: com.google.gson.JsonObject
        :raises ElasticException: for any problems with the connection
        """

    def executeStatementExpectFailure(self, command: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], body: typing.Union[java.lang.String, str]) -> com.google.gson.JsonObject:
        """
        Execute an elastic search statement and return the JSON response to user
        Do not throw an exception on failure, just return the error response
        
        :param java.lang.String or str command: is the type of command
        :param java.lang.String or str path: is the overarching ``index/type/<command>``
        :param java.lang.String or str body: is JSON document describing the request
        :return: the parsed response as a JsonObject
        :rtype: com.google.gson.JsonObject
        :raises ElasticException: for any problems with the connection
        """

    def executeStatementNoResponse(self, command: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], body: typing.Union[java.lang.String, str]):
        """
        Execute an elasticsearch command where we are not expecting a response
        
        :param java.lang.String or str command: is the type of the command
        :param java.lang.String or str path: is the overarching ``index/type/<command>``
        :param java.lang.String or str body: is the JSON document describing the request
        :raises ElasticException: for any problems with the connecting
        """

    def executeURIOnly(self, command: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str]) -> com.google.gson.JsonObject:
        ...

    def lastRequestSuccessful(self) -> bool:
        ...


class ElasticDatabase(ghidra.features.bsim.query.FunctionDatabase):
    """
    Implement the BSim database interface on top of an ElasticSearch back-end
    ElasticSearch holds records as JSON documents.  Documents
    are stored in a specific "index". The primary BSim document index/types are:
    executable/exe      is executable metadata corresponding to the ExecutableRecord object
    executable/function is function metadata corresponding to the FunctionDescription object
    vector/vector       is the main feature vector corresponding to an LSHVector object
    meta/meta           is a document containing the duplication count for a particular feature vector
    """

    class_: typing.ClassVar[java.lang.Class]
    LAYOUT_VERSION: typing.Final = 3
    MAX_VECTOR_OVERALL: typing.Final = 9000
    MAX_FUNCTION_WINDOW: typing.Final = 500
    MAX_FUNCTIONUPDATE_WINDOW: typing.Final = 500
    MAX_VECTORCOUNT_WINDOW: typing.Final = 100
    MAX_VECTORDELETE_WINDOW: typing.Final = 100
    MAX_FUNCTION_BULK: typing.Final = 200
    MAX_VECTOR_BULK: typing.Final = 200

    def __init__(self, baseURL: java.net.URL):
        """
        Construct the database connection given a URL.  The URL protocol must be http, and the URL
        path must contain exactly one element naming the particular repository on the server.
        
        :param java.net.URL baseURL: is the http URL
        :raises MalformedURLException: if the URL is malformed
        """

    @staticmethod
    def escape(s: typing.Union[java.lang.String, str]) -> str:
        ...

    def isInitialized(self) -> bool:
        """
        
        
        :return: true if a connection has been successfully initialized
        :rtype: bool
        """

    def recoverExternalFunctionId(self, exeName: typing.Union[java.lang.String, str], funcName: typing.Union[java.lang.String, str], arch: typing.Union[java.lang.String, str]) -> str:
        """
        Given the name of an executable library, its architecture, and a function name,
        return the id of the document describing this specific function.
        These 3 Strings are designed to uniquely identify a library function.
        
        :param java.lang.String or str exeName: is the name of the executable
        :param java.lang.String or str funcName: is the name of the function
        :param java.lang.String or str arch: is the executable architecture
        :return: the document id of the matching function
        :rtype: str
        :raises ElasticException: if the function (the executable) doesn't exist
        """

    @property
    def initialized(self) -> jpype.JBoolean:
        ...


class ElasticException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class IDElasticResolution(java.lang.Object):

    class ExternalFunction(IDElasticResolution):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, exe: typing.Union[java.lang.String, str], func: typing.Union[java.lang.String, str]):
            ...

        def resolve(self, database: ElasticDatabase, exe: ghidra.features.bsim.query.description.ExecutableRecord):
            ...


    class_: typing.ClassVar[java.lang.Class]
    idString: java.lang.String

    def __init__(self):
        ...

    def resolve(self, database: ElasticDatabase, exe: ghidra.features.bsim.query.description.ExecutableRecord):
        ...


class ElasticUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    K_SETTING: typing.Final = "k_setting"
    L_SETTING: typing.Final = "l_setting"
    LSH_WEIGHTS: typing.Final = "lsh_weights"
    IDF_CONFIG: typing.Final = "idf_config"

    def __init__(self):
        ...


class ElasticEffects(java.lang.Object):
    """
    Container for collecting an elasticsearch query filter document from BSimFilter elements
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addChildId(self, id: typing.Union[java.lang.String, str]):
        ...

    def addDateParam(self, key: typing.Union[java.lang.String, str], date: java.util.Date):
        ...

    def addDocValue(self, val: typing.Union[java.lang.String, str]):
        ...

    def addFuncParam(self, key: typing.Union[java.lang.String, str], val: typing.Union[java.lang.String, str]):
        ...

    def addFunctionFilter(self, flag: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JBoolean, bool]):
        ...

    def addParam(self, key: typing.Union[java.lang.String, str], val: typing.Union[java.lang.String, str]):
        ...

    def addScriptElement(self, filter: ghidra.features.bsim.gui.filters.BSimFilterType, value: typing.Union[java.lang.String, str]):
        ...

    def addStandalone(self, filter: ghidra.features.bsim.gui.filters.BSimFilterType, value: typing.Union[java.lang.String, str]):
        ...

    def assignArgument(self) -> str:
        ...

    def buildFunctionFilter(self) -> str:
        ...

    @staticmethod
    def createFilter(filter: ghidra.features.bsim.query.protocol.BSimFilter, idres: jpype.JArray[IDElasticResolution]) -> str:
        ...


class Handler(java.net.URLStreamHandler):
    """
    Dummy stream handler, so we can create URL objects with protocol "elastic"
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def registerHandler():
        ...


class RowKeyElastic(ghidra.features.bsim.query.description.RowKey):
    """
    A "document id" that uniquely indexes documents, within the ElasticSearch database,
    that describe executables :obj:`ExecutableRecord` and functions :obj:`FunctionDescription`
    This plays the same role as the row id for executable and function rows in an SQL
    database.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, val: typing.Union[jpype.JLong, int]):
        """
        Initialize a key from a 64-bit long value
        
        :param jpype.JLong or int val: is (least significant) 64-bits of the key
        """

    @typing.overload
    def __init__(self, a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int], c: typing.Union[jpype.JInt, int]):
        """
        Create 96-bit, given 3 32-bit integers
        
        :param jpype.JInt or int a: is most significant 32-bits
        :param jpype.JInt or int b: is middle 32-bits
        :param jpype.JInt or int c: is least significant 32-bits
        """

    @typing.overload
    def __init__(self, md5: typing.Union[java.lang.String, str]):
        """
        Construct key from String representation of an md5 hash.
        The key is initialized from the last 96-bits of the hash
        
        :param java.lang.String or str md5: is the hash
        """

    @typing.overload
    def __init__(self):
        """
        Key initialized to zero
        """

    def generateExeIdString(self) -> str:
        """
        Emit the key as a base64 string of 16-characters.
        Used to encode executable document ids
        
        :return: the String encoding
        :rtype: str
        """

    def generateFunctionId(self, buffer: java.lang.StringBuilder, func: ghidra.features.bsim.query.description.FunctionDescription):
        """
        Generate an id string for a FunctionDescription.  If the function is not from a library,
        just use the counter id already set for the function and emit it as a decimal string.
        If it is from a library, emit an id, 4 bytes of which is from the md5 placeholder hash of the library,
        the rest of the id is a base64 encoding of a hash generated from:
        the remainder of the md5 placeholder hash of the library
        the name of the function
        
        :param java.lang.StringBuilder buffer: holds the emitted id string
        :param ghidra.features.bsim.query.description.FunctionDescription func: is the function being labeled
        """

    def generateLibraryFunctionId(self, buffer: java.lang.StringBuilder, funcName: typing.Union[java.lang.String, str]):
        """
        Generate an encoded document id from 64 bits of this key + additional bits
        derived from a name string.  This encodes the document id of a library function given
        just the function Name and the RowKey (this) of the containing library executable. 
        The final String encodes 80-bits of id in 14 characters.
        
        :param java.lang.StringBuilder buffer: is the StringBuilder to encode the id to
        :param java.lang.String or str funcName: is a function name that is hashed into the final encoded id
        """

    @staticmethod
    def parseExeIdString(id: typing.Union[java.lang.String, str]) -> RowKeyElastic:
        """
        Parse an encoded document id of an executable back into a key
        
        :param java.lang.String or str id: is the encoded String
        :return: the decoded RowKey
        :rtype: RowKeyElastic
        """

    @staticmethod
    def parseFunctionId(val: typing.Union[java.lang.String, str]) -> RowKeyElastic:
        """
        Parse an encoded document id of a function back into a key
        This handles both the normal function form: 64-bits encoded as decimal and
        the library function form: 80-bits encoded in base64
        
        :param java.lang.String or str val: is the encoded String
        :return: the decoded RowKey
        :rtype: RowKeyElastic
        """


class Base64VectorFactory(generic.lsh.vector.WeightedLSHCosineVectorFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def allocateBuffer() -> jpype.JArray[jpype.JChar]:
        ...

    def restoreVectorFromBase64(self, input: java.io.Reader, buffer: jpype.JArray[jpype.JChar]) -> generic.lsh.vector.LSHVector:
        ...



__all__ = ["Base64Lite", "ElasticConnection", "ElasticDatabase", "ElasticException", "IDElasticResolution", "ElasticUtilities", "ElasticEffects", "Handler", "RowKeyElastic", "Base64VectorFactory"]
