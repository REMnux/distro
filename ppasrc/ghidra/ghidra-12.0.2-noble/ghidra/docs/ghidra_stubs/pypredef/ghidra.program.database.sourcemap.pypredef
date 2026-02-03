from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra.framework.data
import ghidra.framework.model
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.sourcemap
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.net # type: ignore


@typing.type_check_only
class SourceMapAdapterV0(SourceMapAdapter, db.DBListener):
    """
    Initial version of :obj:`SourceMapAdapter`
    """

    class_: typing.ClassVar[java.lang.Class]


class SourceMapEntryIteratorDB(ghidra.program.model.sourcemap.SourceMapEntryIterator):
    """
    Database implementation of :obj:`SourceMapEntryIterator`
    """

    class_: typing.ClassVar[java.lang.Class]


class SourceFileManagerDB(ghidra.program.model.sourcemap.SourceFileManager, ghidra.program.database.ManagerDB, db.util.ErrorHandler):
    """
    Database Manager for managing source files and source map information.
    """

    @typing.type_check_only
    class SourceMapEntryData(java.lang.Record):
        """
        A record for storing information about new source map entries which must be created
        during :obj:`.moveAddressRange` or :obj:`.deleteAddressRange`
        """

        class_: typing.ClassVar[java.lang.Class]

        def baseAddress(self) -> ghidra.program.model.address.Address:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def length(self) -> int:
            ...

        def lineNumber(self) -> int:
            ...

        def sourceFileId(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, addrMap: ghidra.program.database.map.AddressMapDB, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor
        
        :param db.DBHandle dbh: database handle
        :param ghidra.program.database.map.AddressMapDB addrMap: map longs to addresses
        :param ghidra.framework.data.OpenMode openMode: mode
        :param ghidra.util.Lock lock: program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises VersionException: if the database is incompatible with the current schema
        """


class SourceFileIdType(java.lang.Enum[SourceFileIdType]):
    """
    An enum whose values represent source file id types, such as md5 or sha1.
    """

    class_: typing.ClassVar[java.lang.Class]
    NONE: typing.Final[SourceFileIdType]
    UNKNOWN: typing.Final[SourceFileIdType]
    TIMESTAMP_64: typing.Final[SourceFileIdType]
    MD5: typing.Final[SourceFileIdType]
    SHA1: typing.Final[SourceFileIdType]
    SHA256: typing.Final[SourceFileIdType]
    SHA512: typing.Final[SourceFileIdType]
    MAX_LENGTH: typing.Final = 64

    def getByteLength(self) -> int:
        """
        Returns the byte length of the corresponding identifier. A value of 0 indicates
        no restriction.
        
        :return: byte length of identifier
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SourceFileIdType:
        ...

    @staticmethod
    def values() -> jpype.JArray[SourceFileIdType]:
        ...

    @property
    def byteLength(self) -> jpype.JInt:
        ...


@typing.type_check_only
class SourceMapAdapter(java.lang.Object):
    """
    Base class for adapters to access the Source Map table.
     
    
    Each entry in the table corresponds to a single :obj:`SourceMapEntry` and so records
    a :obj:`SourceFile`, a line number, a base address, and a length.
      
    
    There are a number of restrictions on a :obj:`SourceMapEntry`, which are listed in that 
    interface's top-level documentation.  It is the responsibility of the :obj:`SourceFileManager`
    to enforce these restrictions.
    """

    class_: typing.ClassVar[java.lang.Class]


class SourceFile(java.lang.Comparable[SourceFile]):
    """
    A SourceFile is an immutable object representing a source file.  It contains an
    absolute path along with an optional :obj:`SourceFileIdType` and identifier. 
    For example, if the id type is :obj:`SourceFileIdType.MD5`, the identifier would
    be the md5 sum of the source file (stored as a byte array).
     
    
    Note: path parameters are assumed to be absolute file paths with forward slashes as the
    separator.  For other cases, e.g. windows paths, consider the static convenience methods in
    the ``SourceFileUtils`` class.
     
    
    Note: you can use ``SourceFileUtils.hexStringToByteArray`` to convert hex Strings to byte 
    arrays. You can use ``SourceFileUtils.longToByteArray`` to convert long values to the
    appropriate byte arrays.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str]):
        """
        Constructor requiring only a path.  The path will be normalized (see :obj:`URI.normalize`)
        The id type will be set to ``SourceFileIdType.NONE`` and the identifier will 
        be set to an array of length 0.
        
        :param java.lang.String or str path: path
        """

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str], type: SourceFileIdType, identifier: jpype.JArray[jpype.JByte]):
        """
        Constructor. The path will be normalized (see :obj:`URI.normalize`).
         
        
        Note: if ``type`` is ``SourceFileIdType.NONE``, the ``identifier``
        parameter is ignored.
         
        
        Note: use ``SourceFileUtils.longToByteArray`` to convert a ``long`` value
        to the appropriate ``byte`` array.
        
        :param java.lang.String or str path: path
        :param SourceFileIdType type: id type
        :param jpype.JArray[jpype.JByte] identifier: id
        """

    def getFilename(self) -> str:
        """
        Returns the filename
        
        :return: filename
        :rtype: str
        """

    def getIdAsString(self) -> str:
        """
        Returns a String representation of the identifier
        
        :return: id display string
        :rtype: str
        """

    def getIdType(self) -> SourceFileIdType:
        """
        Returns the source file identifier type
        
        :return: id type
        :rtype: SourceFileIdType
        """

    def getIdentifier(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns (a copy of) the identifier
        
        :return: identifier
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getPath(self) -> str:
        """
        Returns the path
        
        :return: path
        :rtype: str
        """

    def getUri(self) -> java.net.URI:
        """
        Returns a file URI for this SourceFile.
        
        :return: uri
        :rtype: java.net.URI
        """

    @property
    def idAsString(self) -> java.lang.String:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def identifier(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def idType(self) -> SourceFileIdType:
        ...

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def uri(self) -> java.net.URI:
        ...


class UserDataPathTransformer(ghidra.program.model.sourcemap.SourcePathTransformer, ghidra.framework.model.DomainObjectClosedListener):
    """
    An implementation of :obj:`SourcePathTransformer` that stores transform information using
    :obj:`ProgramUserData`.  This means that transform information will be stored locally
    but not checked in to a shared project.
    
     
    
    Use the static method :obj:`UserDataPathTransformer.getPathTransformer` to get the transformer 
    for a program. 
    
     
    
    Synchronization policy: ``userData``, ``pathMap``, ``fileMap``, and
    ``programsToTransformers`` must be protected.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getPathTransformer(program: ghidra.program.model.listing.Program) -> ghidra.program.model.sourcemap.SourcePathTransformer:
        """
        Returns the path transformer for ``program``
        
        :param ghidra.program.model.listing.Program program: program
        :return: path transformer
        :rtype: ghidra.program.model.sourcemap.SourcePathTransformer
        """

    @staticmethod
    def validateDirectoryPath(directory: typing.Union[java.lang.String, str]):
        """
        Throws an :obj:`IllegalArgumentException` if ``directory`` is not
        a valid, normalized directory path (with forward slashes).
        
        :param java.lang.String or str directory: path to validate
        """


@typing.type_check_only
class SourceFileAdapter(java.lang.Object):
    """
    Base class for adapters to access the Source File table.  The table has one column, which stores
    the path of the source file (as a String).
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SourceFileAdapterV0(SourceFileAdapter, db.DBListener):
    """
    Initial version of :obj:`SourceFileAdapter`.
    """

    class_: typing.ClassVar[java.lang.Class]


class SourceMapEntryDB(ghidra.program.model.sourcemap.SourceMapEntry):
    """
    Database implementation of :obj:`SourceMapEntry` interface.
     
    
    Note: clients should drop and reacquire all SourceMapEntryDB objects upon undo/redo, 
    ProgramEvent.SOURCE_MAP_CHANGED, and ProgramEvent.SOURCE_FILE_REMOVED.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["SourceMapAdapterV0", "SourceMapEntryIteratorDB", "SourceFileManagerDB", "SourceFileIdType", "SourceMapAdapter", "SourceFile", "UserDataPathTransformer", "SourceFileAdapter", "SourceFileAdapterV0", "SourceMapEntryDB"]
