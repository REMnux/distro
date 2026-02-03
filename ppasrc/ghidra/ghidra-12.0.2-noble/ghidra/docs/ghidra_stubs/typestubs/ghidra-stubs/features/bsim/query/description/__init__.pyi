from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class DescriptionManager(java.lang.Object):
    """
    Container for metadata about executables (ExecutableRecord),
    functions (FunctionDescription) and their associated signatures (SignatureRecord)
    Generally holds sets of functions that are either being inserted into
    are queried from a BSim database
    """

    class_: typing.ClassVar[java.lang.Class]
    LAYOUT_VERSION: typing.Final = 5

    def __init__(self):
        ...

    def attachSignature(self, fd: FunctionDescription, srec: SignatureRecord):
        """
        Associate a signature with a specific function
        
        :param FunctionDescription fd: is the FunctionDescription
        :param SignatureRecord srec: is the SignatureRecord
        """

    def cacheExecutableByRow(self, erec: ExecutableRecord, rowKey: RowKey):
        """
        Create an internal map entry from a database id to an executable
        
        :param ExecutableRecord erec: is the ExecutableRecord
        :param RowKey rowKey: is the database (row) id
        """

    def clear(self):
        """
        Reset to a completely empty container
        """

    def clearFunctions(self):
        """
        Clear out all functions from the container, but leave the executables
        """

    def containsDescription(self, fname: typing.Union[java.lang.String, str], address: typing.Union[jpype.JLong, int], exe: ExecutableRecord) -> FunctionDescription:
        """
        Find a function (within an executable) by its name and address (both must be provided)
        If the function doesn't exist, null is returned, no exception is thrown
        
        :param java.lang.String or str fname: - the name of the function
        :param jpype.JLong or int address: - the address of the function
        :param ExecutableRecord exe: - the executable (possibly) containing the function
        :return: a FunctionDescription or null
        :rtype: FunctionDescription
        """

    @typing.overload
    def findExecutable(self, md5: typing.Union[java.lang.String, str]) -> ExecutableRecord:
        """
        Lookup an executable in the container via md5
        
        :param java.lang.String or str md5: is the md5 to search for
        :return: return the matching ExecutableRecord
        :rtype: ExecutableRecord
        :raises LSHException: if the executable cannot be found
        """

    @typing.overload
    def findExecutable(self, name: typing.Union[java.lang.String, str], arch: typing.Union[java.lang.String, str], comp: typing.Union[java.lang.String, str]) -> ExecutableRecord:
        """
        Search for executable based an name, and possibly other qualifying information.
        This is relatively inefficient as it just iterates through the list.
        
        :param java.lang.String or str name: is the name that the executable must match
        :param java.lang.String or str arch: is null or must match the executable's architecture string
        :param java.lang.String or str comp: is null or must match the executable's compiler string
        :return: the matching executable
        :rtype: ExecutableRecord
        :raises LSHException: if a matching executable doesn't exist
        """

    def findExecutableByRow(self, rowKey: RowKey) -> ExecutableRecord:
        """
        Look up an executable via database id. This uses an internal map which
        must have been explicitly populated via cacheExecutableByRow
        
        :param RowKey rowKey: is the database (row) id to lookup
        :return: the associated ExecutableRecord or null if not found
        :rtype: ExecutableRecord
        """

    def findFunction(self, fname: typing.Union[java.lang.String, str], address: typing.Union[jpype.JLong, int], exe: ExecutableRecord) -> FunctionDescription:
        """
        Find a function (within an executable) by its name and address (both must be provided)
        If the request function does not exist, an exception is thrown
        
        :param java.lang.String or str fname: - the name of the function
        :param jpype.JLong or int address: - the address of the function
        :param ExecutableRecord exe: - the ExecutableRecord containing the function
        :return: the FunctionDescription
        :rtype: FunctionDescription
        :raises LSHException: if a matching function does not exist
        """

    def findFunctionByName(self, fname: typing.Union[java.lang.String, str], exe: ExecutableRecord) -> FunctionDescription:
        """
        Find a function within an executable by name. The name isn't guaranteed to be unique. If there
        are more than one, the first in address order is returned. If none are found, null is returned
        
        :param java.lang.String or str fname: is the name of the function to match
        :param ExecutableRecord exe: is the ExecutableRecord containing the function
        :return: a FunctionDescription or null
        :rtype: FunctionDescription
        """

    def generateExecutableXrefMap(self) -> java.util.Map[java.lang.Integer, ExecutableRecord]:
        """
        Assign an internal id to all executables and also create a map from id to executable.
        As with :obj:`DescriptionManager.populateExecutableXref`,
        ids are assigned in order starting at 1
        
        :return: the populated Map object
        :rtype: java.util.Map[java.lang.Integer, ExecutableRecord]
        """

    def generateFunctionIdMap(self, funcmap: collections.abc.Mapping):
        """
        Generate a map from (row) id to function, for all functions in this container
        
        :param collections.abc.Mapping funcmap: is the map to populate
        """

    def getExecutableRecordSet(self) -> java.util.TreeSet[ExecutableRecord]:
        ...

    def getMajorVersion(self) -> int:
        """
        
        
        :return: the major version number of the decompiler used for signatures
        :rtype: int
        """

    def getMinorVersion(self) -> int:
        """
        
        
        :return: the minor version number of the decompiler used for signatures
        :rtype: int
        """

    def getSettings(self) -> int:
        """
        
        
        :return: the settings of the signature strategy used for this container
        :rtype: int
        """

    def listAllFunctions(self) -> java.util.Iterator[FunctionDescription]:
        """
        
        
        :return: an iterator over all functions in the container
        :rtype: java.util.Iterator[FunctionDescription]
        """

    def listFunctions(self, exe: ExecutableRecord) -> java.util.Iterator[FunctionDescription]:
        """
        Generate an iterator over all functions belonging to a specific executable
        
        :param ExecutableRecord exe: is the specific executable
        :return: iterator over all functions in -exe-
        :rtype: java.util.Iterator[FunctionDescription]
        """

    def listFunctionsAfter(self, func: FunctionDescription) -> java.util.Iterator[FunctionDescription]:
        """
        Using the standard exe-md5, function name, address sorting, return an
        iterator over all functions starting with the first function after
        an indicated -func-
        
        :param FunctionDescription func: is FunctionDescription indicating where the iterator should start (after)
        :return: the new iterator
        :rtype: java.util.Iterator[FunctionDescription]
        """

    def makeCallgraphLink(self, src: FunctionDescription, dest: FunctionDescription, lhash: typing.Union[jpype.JInt, int]):
        """
        Mark a parent/child relationship between to functions
        
        :param FunctionDescription src: is the parent FunctionDescription
        :param FunctionDescription dest: is the child FunctionDescription
        :param jpype.JInt or int lhash: is a hash indicating where in -src- the call to -dest- is made
        """

    def matchAndSetXrefs(self, manage: DescriptionManager):
        """
        For every ExecutableRecord in this container, if it is also in ``manage``,
        copy the xrefValue from the ``manage`` version, otherwise 
        set the xrefValue to zero
        
        :param DescriptionManager manage: is the other container match from
        """

    def newExecutableLibrary(self, enm: typing.Union[java.lang.String, str], arc: typing.Union[java.lang.String, str], id: RowKey) -> ExecutableRecord:
        """
        Create a new "library" executable in the container.
        Functions in this container (will) have no body or address
        
        :param java.lang.String or str enm: is the name of the library
        :param java.lang.String or str arc: is the architecture of the library
        :param RowKey id: is the database id associated with the library (may be null)
        :return: the new ExecutableRecord object
        :rtype: ExecutableRecord
        :raises LSHException: if attributes are invalid or the
        library already exists with different metadata
        """

    def newExecutableRecord(self, md5: typing.Union[java.lang.String, str], enm: typing.Union[java.lang.String, str], cnm: typing.Union[java.lang.String, str], arc: typing.Union[java.lang.String, str], dt: java.util.Date, repo: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], id: RowKey) -> ExecutableRecord:
        """
        Create a new executable record, which should be identified uniquely
        identified via its md5sum
        
        :param java.lang.String or str md5: is the MD5 hash of the executable
        :param java.lang.String or str enm: is the name of the executable
        :param java.lang.String or str cnm: is the name of the compiler used to build the executable
        :param java.lang.String or str arc: is the architecture of the executable
        :param java.util.Date dt: is the date (of ingest)
        :param java.lang.String or str repo: is the repository containing the executable
        :param java.lang.String or str path: is the path (within the repo) to the executable
        :param RowKey id: is the database (row) is associated with the executable (may be null)
        :return: the new ExecutableRecord object
        :rtype: ExecutableRecord
        :raises LSHException: if attributes are invalid, or the executable 
            already exists with different metadata
        """

    def newFunctionDescription(self, fnm: typing.Union[java.lang.String, str], address: typing.Union[jpype.JLong, int], erec: ExecutableRecord) -> FunctionDescription:
        """
        Allocate a new function in the container
        
        :param java.lang.String or str fnm: is the name of the new function
        :param jpype.JLong or int address: is the address (offset) of the function
        :param ExecutableRecord erec: is the executable containing the function
        :return: the new FunctionDescription
        :rtype: FunctionDescription
        """

    @typing.overload
    def newSignature(self, vec: generic.lsh.vector.LSHVector, count: typing.Union[jpype.JInt, int]) -> SignatureRecord:
        """
        Generate a SignatureRecord given a specific feature vector
        
        :param generic.lsh.vector.LSHVector vec: is the feature vector (LSHVector)
        :param jpype.JInt or int count: is a count of functions sharing this feature vector
        :return: the new SignatureRecord
        :rtype: SignatureRecord
        """

    @typing.overload
    def newSignature(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory, count: typing.Union[jpype.JInt, int]) -> SignatureRecord:
        """
        Parse a signature (SignatureRecord) from an XML stream
        
        :param ghidra.xml.XmlPullParser parser: is the XML parser
        :param generic.lsh.vector.LSHVectorFactory vectorFactory: is the factory used to generate the underlying feature vector
        :param jpype.JInt or int count: is the count of functions sharing the feature vector
        :return: the new SignatureRecord
        :rtype: SignatureRecord
        """

    def numExecutables(self) -> int:
        """
        
        
        :return: the number of executables described by this container
        :rtype: int
        """

    def numFunctions(self) -> int:
        """
        
        
        :return: the number of functions described by this container
        :rtype: int
        """

    def overrideRepository(self, repo: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str]):
        """
        Override the repository setting of every executable in this manager
        
        :param java.lang.String or str repo: is the repository string to override with
        :param java.lang.String or str path: is the path string to override with
        """

    def populateExecutableXref(self):
        """
        Assign an internal id to all executables for purposes of cross-referencing in XML
        Indices are assigned in order starting at 1 (0 indicates an index has NOT been assigned)
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory):
        """
        Reconstruct a container by deserializing an XML stream
        
        :param ghidra.xml.XmlPullParser parser: is the XML parser
        :param generic.lsh.vector.LSHVectorFactory vectorFactory: is the factory to use for building feature vectors
        :raises LSHException: if there are inconsistencies in the XML
        """

    def saveXml(self, fwrite: java.io.Writer):
        """
        Serialize the entire container to an XML stream
        
        :param java.io.Writer fwrite: is the stream to write to
        :raises IOException: if there are problems writing to the stream
        """

    def setExeAlreadyStored(self, erec: ExecutableRecord):
        """
        Mark that an executable has (already) been stored in the database
        
        :param ExecutableRecord erec: is the ExecutableRecord
        """

    def setExeCategories(self, erec: ExecutableRecord, cats: java.util.List[CategoryRecord]):
        """
        Set the categories associated with a particular executable.
        This replaces any existing categories
        
        :param ExecutableRecord erec: is the ExecutableRecord to set
        :param java.util.List[CategoryRecord] cats: is the list of categories (CategoryRecord), may be null
        """

    def setExeRowId(self, erec: ExecutableRecord, id: RowKey):
        """
        Associate a database id with a particular executable
        
        :param ExecutableRecord erec: is the ExecutableRecord
        :param RowKey id: is the database (row) id
        """

    def setFunctionDescriptionFlags(self, fd: FunctionDescription, fl: typing.Union[jpype.JInt, int]):
        """
        Associate function "tags" or attributes with a specific function
        
        :param FunctionDescription fd: is the FunctionDescription
        :param jpype.JInt or int fl: is the encoded bitfield of attributes
        """

    def setFunctionDescriptionId(self, fd: FunctionDescription, id: RowKey):
        """
        Associate a database id with a particular function
        
        :param FunctionDescription fd: is the FunctionDescription
        :param RowKey id: is the database (row) id
        """

    def setSettings(self, set: typing.Union[jpype.JInt, int]):
        """
        Establish the particular settings of the signature strategy used to
        generate SignatureRecords for this container
        
        :param jpype.JInt or int set: is the encoded bit-field of settings
        """

    @typing.overload
    def setSignatureId(self, frec: FunctionDescription, id: typing.Union[jpype.JLong, int]):
        """
        Associate a signature's id with a particular function
        
        :param FunctionDescription frec: is the FunctionDescription
        :param jpype.JLong or int id: is the signature's database id
        """

    @typing.overload
    def setSignatureId(self, sigrec: SignatureRecord, id: typing.Union[jpype.JLong, int]):
        """
        Associate a database id with a particular SignatureRecord
        
        :param SignatureRecord sigrec: is the SignatureRecord
        :param jpype.JLong or int id: is the signature's database id
        """

    def setVersion(self, maj: typing.Union[jpype.JShort, int], min: typing.Union[jpype.JShort, int]):
        """
        Set the version number of the decompiler used to generate SignatureRecords
        for this container
        
        :param jpype.JShort or int maj: is the major number
        :param jpype.JShort or int min: is the minor
        """

    def transferExecutable(self, erec: ExecutableRecord) -> ExecutableRecord:
        """
        Transfer an executable from another container into this container
        
        :param ExecutableRecord erec: is the ExecutableRecord from the other container
        :return: the new transferred ExecutableRecord
        :rtype: ExecutableRecord
        :raises LSHException: if the executable already exists with different metadata
        """

    def transferFunction(self, fdesc: FunctionDescription, transsig: typing.Union[jpype.JBoolean, bool]) -> FunctionDescription:
        """
        Transfer a function from another container into this container
        
        :param FunctionDescription fdesc: is the FunctionDescription to transfer
        :param jpype.JBoolean or bool transsig: is true if the SignatureRecord should be transferred as well
        :return: the new transferred FunctionDescription
        :rtype: FunctionDescription
        :raises LSHException: if the function already exists with different metadata
        """

    def transferSettings(self, op2: DescriptionManager):
        """
        Transfer decompiler and signature settings into this container
        
        :param DescriptionManager op2: is the container to transfer from
        """

    @property
    def settings(self) -> jpype.JInt:
        ...

    @settings.setter
    def settings(self, value: jpype.JInt):
        ...

    @property
    def executableRecordSet(self) -> java.util.TreeSet[ExecutableRecord]:
        ...

    @property
    def minorVersion(self) -> jpype.JShort:
        ...

    @property
    def majorVersion(self) -> jpype.JShort:
        ...


class SignatureRecord(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, v: generic.lsh.vector.LSHVector):
        ...

    def getCount(self) -> int:
        ...

    def getLSHVector(self) -> generic.lsh.vector.LSHVector:
        ...

    def getVectorId(self) -> int:
        ...

    @staticmethod
    def restoreXml(parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory, man: DescriptionManager, fdesc: FunctionDescription, count: typing.Union[jpype.JInt, int]):
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    @property
    def vectorId(self) -> jpype.JLong:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def lSHVector(self) -> generic.lsh.vector.LSHVector:
        ...


class DatabaseInformation(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    databasename: java.lang.String
    owner: java.lang.String
    description: java.lang.String
    major: jpype.JShort
    minor: jpype.JShort
    settings: jpype.JInt
    execats: java.util.List[java.lang.String]
    functionTags: java.util.List[java.lang.String]
    dateColumnName: java.lang.String
    layout_version: jpype.JInt
    readonly: jpype.JBoolean
    trackcallgraph: jpype.JBoolean

    def __init__(self):
        ...

    def checkSignatureSettings(self, maj: typing.Union[jpype.JShort, int], min: typing.Union[jpype.JShort, int], set: typing.Union[jpype.JInt, int]) -> int:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        ...

    def saveXml(self, write: java.io.Writer):
        ...


class CategoryRecord(java.lang.Comparable[CategoryRecord]):
    """
    A user-defined category associated with an executable
    Specified by a -type- and then the particular -category- (within the type) that
    the executable belongs to.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, t: typing.Union[java.lang.String, str], c: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def enforceTypeCharacters(val: typing.Union[java.lang.String, str]) -> bool:
        ...

    def getCategory(self) -> str:
        ...

    def getType(self) -> str:
        ...

    @staticmethod
    def restoreXml(parser: ghidra.xml.XmlPullParser) -> CategoryRecord:
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    @property
    def type(self) -> java.lang.String:
        ...

    @property
    def category(self) -> java.lang.String:
        ...


class ExecutableRecord(java.lang.Comparable[ExecutableRecord]):
    """
    Metadata about a specific executable, as stored in a BSim database
    There are two basic varieties:
    Normal executables, which can be viewed as a container of functions where
        each function has a body and an address (and a corresponding feature vector)
    Library executables, which contains functions that can only be identified by
        name and have no body (or corresponding feature vector)
    """

    class Update(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        update: ExecutableRecord
        name_exec: jpype.JBoolean
        architecture: jpype.JBoolean
        name_compiler: jpype.JBoolean
        repository: jpype.JBoolean
        path: jpype.JBoolean
        date: jpype.JBoolean
        categories: jpype.JBoolean
        catinsert: java.util.List[CategoryRecord]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EMPTY_DATE: typing.Final[java.util.Date]
    ALREADY_STORED: typing.Final = 1
    LIBRARY: typing.Final = 2
    CATEGORIES_SET: typing.Final = 4
    METADATA_NAME: typing.Final = 1
    METADATA_ARCH: typing.Final = 2
    METADATA_COMP: typing.Final = 4
    METADATA_DATE: typing.Final = 8
    METADATA_REPO: typing.Final = 16
    METADATA_PATH: typing.Final = 32
    METADATA_LIBR: typing.Final = 64

    @typing.overload
    def __init__(self, md5: typing.Union[java.lang.String, str], execName: typing.Union[java.lang.String, str], compilerName: typing.Union[java.lang.String, str], architecture: typing.Union[java.lang.String, str], date: java.util.Date, id: RowKey, repo: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str]):
        """
        Construct a normal (non-library) record.  Fill-in all fields except categories.
        Categories are marked as NOT set
        
        :param java.lang.String or str md5: is the md5 checksum
        :param java.lang.String or str execName: is the executable name
        :param java.lang.String or str compilerName: is the compiler name
        :param java.lang.String or str architecture: is the processor architecture
        :param java.util.Date date: is the date of ingest (may be null)
        :param RowKey id: is the row id of the record
        :param java.lang.String or str repo: is the repository containing the executable (may be null)
        :param java.lang.String or str path: is the path to the executable (may be null)
        """

    @typing.overload
    def __init__(self, md5: typing.Union[java.lang.String, str], enm: typing.Union[java.lang.String, str], cnm: typing.Union[java.lang.String, str], arc: typing.Union[java.lang.String, str], dt: java.util.Date, uc: java.util.List[CategoryRecord], id: RowKey, repo: typing.Union[java.lang.String, str], pth: typing.Union[java.lang.String, str]):
        """
        Construct a normal (non-library) record.  Fill-in all fields.
        
        :param java.lang.String or str md5: is the md5 checksum
        :param java.lang.String or str enm: is the executable name
        :param java.lang.String or str cnm: is the compiler name
        :param java.lang.String or str arc: is the architecture
        :param java.util.Date dt: is the date of ingest (may be null)
        :param java.util.List[CategoryRecord] uc: is the categories (may be null, categories are considered SET regardless)
        :param RowKey id: is the row id of the record
        :param java.lang.String or str repo: is the repository containing the executable (may be null)
        :param java.lang.String or str pth: is the path to the executable (may be null)
        """

    @typing.overload
    def __init__(self, enm: typing.Union[java.lang.String, str], arc: typing.Union[java.lang.String, str], id: RowKey):
        """
        Constructor for a "library" executable
        
        :param java.lang.String or str enm: is the name of the library
        :param java.lang.String or str arc: is the architecture for functions in the library
        :param RowKey id: is the database (row) id of the record (may be null)
        """

    @staticmethod
    def calcLibraryMd5Placeholder(enm: typing.Union[java.lang.String, str], arc: typing.Union[java.lang.String, str]) -> str:
        """
        Generate a placeholder md5 string for a library executable based just
        on its name and architecture
        
        :param java.lang.String or str enm: is the name of the library
        :param java.lang.String or str arc: is the architecture
        :return: the placeholder md5 String
        :rtype: str
        """

    def categoriesAreSet(self) -> bool:
        """
        
        
        :return: true if categories have been queried in (does not mean that it has any categories)
        :rtype: bool
        """

    def compareCategory(self, op2: ExecutableRecord) -> bool:
        """
        Compare the set of categories that -this- and -op2- belong to
        
        :param ExecutableRecord op2: is executable to compare with this
        :return: true if the categories are exactly the same
        :rtype: bool
        """

    def compareMetadata(self, o: ExecutableRecord) -> int:
        """
        Compare just the metadata portion (names and versions) of two ExecutableRecords
        We do NOT compare categories as these may not have been read into the object yet
        
        :param ExecutableRecord o: is ExecutableRecord to compare with this
        :return: bit vector with a 1 bit for every field that differs
        :rtype: int
        """

    def diffForUpdate(self, res: ExecutableRecord.Update, fromDB: ExecutableRecord) -> bool:
        """
        Assuming this is a (possibly) updated variant of another executable metadata record
        Prepare an Update record describing the difference between the two records
        
        :param ExecutableRecord.Update res: is the Update record to fill in
        :param ExecutableRecord fromDB: is the other ExecutableRecord metadata
        :return: true if overall there has been an update
        :rtype: bool
        """

    def getAllCategories(self) -> java.util.List[CategoryRecord]:
        """
        
        
        :return: the list of :obj:`CategoryRecord`s associated with this executable
        :rtype: java.util.List[CategoryRecord]
        """

    def getArchitecture(self) -> str:
        """
        
        
        :return: the architecture associated with the executable
        :rtype: str
        """

    def getCategory(self, type: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        Return the executable's settings for a specific category type
        
        :param java.lang.String or str type: is the category type
        :return: the list of settings with this type (or null)
        :rtype: java.util.List[java.lang.String]
        """

    def getDate(self) -> java.util.Date:
        """
        
        
        :return: the date this executable was ingested into the database
        :rtype: java.util.Date
        """

    def getExeCategoryAlphabetic(self, type: typing.Union[java.lang.String, str]) -> str:
        """
        Get all the category settings of a specific type in alphabetic order.
        Multiple values are returned in a single String separated by ','
        
        :param java.lang.String or str type: is the type of category to retrieve
        :return: the concatenated list of settings
        :rtype: str
        """

    def getMd5(self) -> str:
        """
        
        
        :return: the MD5 hash of the executable
        :rtype: str
        """

    def getNameCompiler(self) -> str:
        """
        
        
        :return: the name of the compiler that built this executable
        :rtype: str
        """

    def getNameExec(self) -> str:
        """
        
        
        :return: the name of the executable
        :rtype: str
        """

    def getPath(self) -> str:
        """
        
        
        :return: the (repository relative) path to the executable
        :rtype: str
        """

    def getRepository(self) -> str:
        """
        
        
        :return: the URL of the repository containing this executable
        :rtype: str
        """

    def getRowId(self) -> RowKey:
        """
        
        
        :return: the database (row) id of this executable object
        :rtype: RowKey
        """

    def getURLString(self) -> str:
        """
        
        
        :return: the fully formed URL to this executable or null
        :rtype: str
        """

    def getXrefIndex(self) -> int:
        """
        
        
        :return: the internal cross-referencing index for this executable
        :rtype: int
        """

    def hasCategory(self, type: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if an executable has been set with a specific category value
        
        :param java.lang.String or str type: is the type of category to check
        :param java.lang.String or str value: is the value to check for
        :return: true if the executable has that value, false otherwise
        :rtype: bool
        """

    def isAlreadyStored(self) -> bool:
        """
        
        
        :return: true if this database record has already been stored in the database
        :rtype: bool
        """

    def isLibrary(self) -> bool:
        """
        
        
        :return: true if this executable is a "library" (functions identified only by name)
        :rtype: bool
        """

    @staticmethod
    def isLibraryHash(md5: typing.Union[java.lang.String, str]) -> bool:
        """
        Identify whether an md5 string is a placeholder hash
        (as generated by :obj:`ExecutableRecord.calcLibraryMd5Placeholder`)
        
        :param java.lang.String or str md5: is the md5 string
        :return: true if it is a placeholder, false otherwise
        :rtype: bool
        """

    def printRaw(self) -> str:
        """
        Get the formatted raw executable metadata as a string
        
        :return: formatted metadata
        :rtype: str
        """

    @staticmethod
    def restoreXml(parser: ghidra.xml.XmlPullParser, man: DescriptionManager) -> ExecutableRecord:
        """
        Build a new :obj:`ExecutableRecord` by deserializing from an XML stream
        
        :param ghidra.xml.XmlPullParser parser: is the XML parser
        :param DescriptionManager man: is the DescriptionManager that should hold the new executable
        :return: the new ExecutableRecord
        :rtype: ExecutableRecord
        :raises LSHException: if there are inconsistencies in the XML description
        """

    def saveXml(self, fwrite: java.io.Writer):
        """
        Serialize this executable (meta-data) to an XML stream
        
        :param java.io.Writer fwrite: is the XML stream
        :raises IOException: if there are I/O errors writing to the stream
        """

    @property
    def date(self) -> java.util.Date:
        ...

    @property
    def xrefIndex(self) -> jpype.JInt:
        ...

    @property
    def nameCompiler(self) -> java.lang.String:
        ...

    @property
    def alreadyStored(self) -> jpype.JBoolean:
        ...

    @property
    def repository(self) -> java.lang.String:
        ...

    @property
    def rowId(self) -> RowKey:
        ...

    @property
    def exeCategoryAlphabetic(self) -> java.lang.String:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def nameExec(self) -> java.lang.String:
        ...

    @property
    def library(self) -> jpype.JBoolean:
        ...

    @property
    def allCategories(self) -> java.util.List[CategoryRecord]:
        ...

    @property
    def uRLString(self) -> java.lang.String:
        ...

    @property
    def category(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def md5(self) -> java.lang.String:
        ...

    @property
    def architecture(self) -> java.lang.String:
        ...


class CallgraphEntry(java.lang.Comparable[CallgraphEntry]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, d: FunctionDescription, lhash: typing.Union[jpype.JInt, int]):
        ...

    def getFunctionDescription(self) -> FunctionDescription:
        ...

    def getLocalHash(self) -> int:
        ...

    @staticmethod
    def restoreXml(parser: ghidra.xml.XmlPullParser, man: DescriptionManager, src: FunctionDescription):
        ...

    def saveXml(self, src: FunctionDescription, fwrite: java.io.Writer):
        ...

    @property
    def functionDescription(self) -> FunctionDescription:
        ...

    @property
    def localHash(self) -> jpype.JInt:
        ...


class RowKey(java.lang.Comparable[RowKey]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLong(self) -> int:
        """
        
        
        :return: the (least significant) 64-bits of the row key
        :rtype: int
        """

    @property
    def long(self) -> jpype.JLong:
        ...


class VectorResult(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    vectorid: jpype.JLong
    sim: jpype.JDouble
    signif: jpype.JDouble
    hitcount: jpype.JInt
    vec: generic.lsh.vector.LSHVector

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, vid: typing.Union[jpype.JLong, int], cnt: typing.Union[jpype.JInt, int], sm: typing.Union[jpype.JDouble, float], sg: typing.Union[jpype.JDouble, float], v: generic.lsh.vector.LSHVector):
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory):
        ...

    def saveXml(self, write: java.io.Writer):
        ...


class FunctionDescriptionMapper(java.lang.Object):
    """
    Scan a description XML file and for each ``<fdesc>`` tag, parse it, build the 
    FunctionDescription object and call handleFunction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def handleExecutable(self, erec: ExecutableRecord):
        ...

    def handleFunction(self, fdesc: FunctionDescription, rnum: typing.Union[jpype.JInt, int]):
        ...

    def processFile(self, parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory):
        ...


class FunctionDescription(java.lang.Comparable[FunctionDescription]):

    class Update(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        update: FunctionDescription
        function_name: jpype.JBoolean
        flags: jpype.JBoolean

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ex: ExecutableRecord, name: typing.Union[java.lang.String, str], addr: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def createAddressToFunctionMap(iter: java.util.Iterator[FunctionDescription]) -> java.util.Map[java.lang.Long, FunctionDescription]:
        """
        Create a map from addresses to functions
        
        :param java.util.Iterator[FunctionDescription] iter: is the list of functions to map
        :return: the Map
        :rtype: java.util.Map[java.lang.Long, FunctionDescription]
        """

    def diffForUpdate(self, res: FunctionDescription.Update, fromDB: FunctionDescription) -> bool:
        """
        Update the boolean fields in -res- to true, for every field in -this- that needs to be updated from -fromDB-
        
        :param FunctionDescription.Update res: stores the boolean results for which fields to update
        :param FunctionDescription fromDB: is the metadata to compare with -this- to decided if updates are necessary
        :return: true if one or more updates is necessary
        :rtype: bool
        """

    @staticmethod
    def generateUpdates(iter: java.util.Iterator[FunctionDescription], addrMap: collections.abc.Mapping, badList: java.util.List[FunctionDescription]) -> java.util.List[FunctionDescription.Update]:
        """
        Match new functions to old functions via the address, test if there is an update between the two functions,
        generate an update record if there is, return the list of updates
        
        :param java.util.Iterator[FunctionDescription] iter: is the list of NEW functions
        :param collections.abc.Mapping addrMap: is a map from address to OLD functions
        :param java.util.List[FunctionDescription] badList: is a container for new functions that could not be mapped to old
        :return: the list of Update records
        :rtype: java.util.List[FunctionDescription.Update]
        """

    def getAddress(self) -> int:
        ...

    def getCallgraphRecord(self) -> java.util.List[CallgraphEntry]:
        ...

    def getExecutableRecord(self) -> ExecutableRecord:
        ...

    def getFlags(self) -> int:
        ...

    def getFunctionName(self) -> str:
        ...

    def getId(self) -> RowKey:
        ...

    def getSignatureRecord(self) -> SignatureRecord:
        ...

    def getVectorId(self) -> int:
        ...

    def printRaw(self) -> str:
        ...

    @staticmethod
    def restoreXml(parser: ghidra.xml.XmlPullParser, vectorFactory: generic.lsh.vector.LSHVectorFactory, man: DescriptionManager, erec: ExecutableRecord) -> FunctionDescription:
        ...

    def saveXml(self, fwrite: java.io.Writer):
        ...

    def setSignatureRecord(self, srec: SignatureRecord):
        ...

    def sortCallgraph(self):
        ...

    @property
    def executableRecord(self) -> ExecutableRecord:
        ...

    @property
    def address(self) -> jpype.JLong:
        ...

    @property
    def functionName(self) -> java.lang.String:
        ...

    @property
    def vectorId(self) -> jpype.JLong:
        ...

    @property
    def signatureRecord(self) -> SignatureRecord:
        ...

    @signatureRecord.setter
    def signatureRecord(self, value: SignatureRecord):
        ...

    @property
    def flags(self) -> jpype.JInt:
        ...

    @property
    def callgraphRecord(self) -> java.util.List[CallgraphEntry]:
        ...

    @property
    def id(self) -> RowKey:
        ...



__all__ = ["DescriptionManager", "SignatureRecord", "DatabaseInformation", "CategoryRecord", "ExecutableRecord", "CallgraphEntry", "RowKey", "VectorResult", "FunctionDescriptionMapper", "FunctionDescription"]
