from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class DebugFileProvider(DebugInfoProvider):
    """
    A :obj:`DebugInfoProvider` that can directly provide :obj:`files <File>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFile(self, debugInfo: ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> java.io.File:
        """
        Searches for a debug file that fulfills the criteria specified in the 
        :obj:`ExternalDebugInfo`.
        
        :param ExternalDebugInfo debugInfo: search criteria
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: File of the matching file, or ``null`` if not found
        :rtype: java.io.File
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """


class HttpDebugInfoDProvider(DebugStreamProvider):
    """
    Queries debuginfod REST servers for debug objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverURI: java.net.URI) -> None:
        """
        Creates a new instance of a HttpSymbolServer.
        
        :param java.net.URI serverURI: URI / URL of the symbol server
        """

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> HttpDebugInfoDProvider:
        ...

    def getNotFoundCount(self) -> int:
        ...

    def getRetriedCount(self) -> int:
        ...

    @staticmethod
    def matches(name: typing.Union[java.lang.String, str]) -> bool:
        ...

    def setHttpRequestTimeoutMs(self, httpRequestTimeoutMs: typing.Union[jpype.JInt, int]) -> None:
        ...

    def setMaxRetryCount(self, maxRetryCount: typing.Union[jpype.JInt, int]) -> None:
        ...

    @property
    def notFoundCount(self) -> jpype.JInt:
        ...

    @property
    def retriedCount(self) -> jpype.JInt:
        ...


class DebugInfoProvider(java.lang.Object):
    """
    Base interface for objects that can provide DWARF debug files.  See :obj:`DebugFileProvider` or
    :obj:`DebugStreamProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDescriptiveName(self) -> str:
        """
        :return: a human formatted string describing this provider, used in UI prompts or lists
        :rtype: str
        """

    def getName(self) -> str:
        """
        :return: the name of this instance, which should be a serialized copy of this instance, 
        typically like "something://serialized_data"
        :rtype: str
        """

    def getStatus(self, monitor: ghidra.util.task.TaskMonitor) -> DebugInfoProviderStatus:
        """
        :return: DebugInfoProviderStatus representing this provider's current status
        :rtype: DebugInfoProviderStatus
        
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        """

    @property
    def descriptiveName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def status(self) -> DebugInfoProviderStatus:
        ...


class DebugInfoProviderCreatorContext(java.lang.Record):
    """
    Information that might be needed to create a new :obj:`DebugInfoProvider` instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, registry: DebugInfoProviderRegistry, program: ghidra.program.model.listing.Program) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def program(self) -> ghidra.program.model.listing.Program:
        ...

    def registry(self) -> DebugInfoProviderRegistry:
        ...

    def toString(self) -> str:
        ...


class BuildIdDebugFileProvider(DebugFileProvider):
    """
    A :obj:`DebugFileProvider` that expects the external debug files to be named using the hexadecimal
    value of the hash of the file, and to be arranged in a bucketed directory hierarchy using the
    first 2 hexdigits of the hash.
     
    
    For example, the debug file with hash ``6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f`` would
    be stored as "6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug" (under some root directory).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rootDir: jpype.protocol.SupportsPath) -> None:
        """
        Creates a new :obj:`BuildIdDebugFileProvider` at the specified directory.
        
        :param jpype.protocol.SupportsPath rootDir: path to the root directory of the build-id directory (typically ends with
        "./build-id")
        """

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> BuildIdDebugFileProvider:
        """
        Creates a new :obj:`BuildIdDebugFileProvider` instance using the specified name string.
        
        :param java.lang.String or str name: string, earlier returned from :meth:`getName() <.getName>`
        :param DebugInfoProviderCreatorContext context: :obj:`DebugInfoProviderCreatorContext` to allow accessing information outside
        of the name string that might be needed to create a new instance
        :return: new :obj:`BuildIdDebugFileProvider` instance
        :rtype: BuildIdDebugFileProvider
        """

    @staticmethod
    def matches(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified name string specifies a BuildIdDebugFileProvider.
        
        :param java.lang.String or str name: string to test
        :return: boolean true if name specifies a BuildIdDebugFileProvider
        :rtype: bool
        """


class DisabledDebugInfoProvider(DebugInfoProvider):
    """
    Wrapper around a DebugInfoProvider that prevents it from being queried, but retains it in the
    configuration list.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delegate: DebugInfoProvider) -> None:
        ...

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> DebugInfoProvider:
        """
        Factory method to create new instances from a name string.
        
        :param java.lang.String or str name: string, earlier returned from :meth:`getName() <.getName>`
        :param DebugInfoProviderCreatorContext context: :obj:`DebugInfoProviderCreatorContext` to allow accessing information outside
        of the name string that might be needed to create a new instance
        :return: new instance, or null if invalid name string
        :rtype: DebugInfoProvider
        """

    def getDelegate(self) -> DebugInfoProvider:
        ...

    @staticmethod
    def matches(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Predicate that tests if the name string is an instance of a disabled name.
        
        :param java.lang.String or str name: string
        :return: boolean true if the string should be handled by the DisabledSymbolServer class
        :rtype: bool
        """

    @property
    def delegate(self) -> DebugInfoProvider:
        ...


class SameDirDebugInfoProvider(DebugFileProvider):
    """
    A :obj:`DebugFileProvider` that only looks in the program's original import directory for
    matching debug files.
    """

    class_: typing.ClassVar[java.lang.Class]
    DESC: typing.Final = "Program\'s Import Location"

    def __init__(self, progDir: jpype.protocol.SupportsPath) -> None:
        """
        Creates a new :obj:`SameDirDebugInfoProvider` at the specified directory.
        
        :param jpype.protocol.SupportsPath progDir: path to the program's import directory
        """

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> SameDirDebugInfoProvider:
        """
        Creates a new :obj:`SameDirDebugInfoProvider` instance using the current program's
        import location.
        
        :param java.lang.String or str name: unused
        :param DebugInfoProviderCreatorContext context: :obj:`DebugInfoProviderCreatorContext`
        :return: new :obj:`SameDirDebugInfoProvider` instance
        :rtype: SameDirDebugInfoProvider
        """

    @staticmethod
    def matches(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified name string specifies a SameDirDebugInfoProvider.
        
        :param java.lang.String or str name: string to test
        :return: boolean true if locString specifies a SameDirDebugInfoProvider
        :rtype: bool
        """


class ExternalDebugInfo(java.lang.Object):
    """
    Metadata needed to find an ELF/DWARF external debug file, retrieved from an ELF binary's
    ".gnu_debuglink" section and/or ".note.gnu.build-id" section.  
     
    
    The debuglink can provide a filename and crc of the external debug file, while the build-id
    can provide a hash that is converted to a filename that identifies the external debug file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filename: typing.Union[java.lang.String, str], crc: typing.Union[jpype.JInt, int], buildId: typing.Union[java.lang.String, str], objectType: ObjectType, extra: typing.Union[java.lang.String, str]) -> None:
        """
        Constructor to create an :obj:`ExternalDebugInfo` instance.
        
        :param java.lang.String or str filename: filename of external debug file, or null
        :param jpype.JInt or int crc: crc32 of external debug file, or 0 if no filename
        :param java.lang.String or str buildId: build-id hash digest found in ".note.gnu.build-id" section, or null if
        not present
        :param ObjectType objectType: :obj:`ObjectType` specifies what kind of debug file is specified by the
        other info
        :param java.lang.String or str extra: additional information used by :obj:`ObjectType.SOURCE`
        """

    @staticmethod
    def forBuildId(buildId: typing.Union[java.lang.String, str]) -> ExternalDebugInfo:
        """
        :return: a new ExternalDebugInfo instance created using the specified Build-Id value
        :rtype: ExternalDebugInfo
        
        
        :param java.lang.String or str buildId: hex string
        """

    @staticmethod
    def forDebugLink(debugLinkFilename: typing.Union[java.lang.String, str], crc: typing.Union[jpype.JInt, int]) -> ExternalDebugInfo:
        """
        :return: a new ExternalDebugInfo instance created using the specified debuglink values
        :rtype: ExternalDebugInfo
        
        
        :param java.lang.String or str debugLinkFilename: filename from debuglink section
        :param jpype.JInt or int crc: crc32 from debuglink section
        """

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ExternalDebugInfo:
        """
        Create a new :obj:`ExternalDebugInfo` from information found in the specified program.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to query
        :return: new :obj:`ExternalDebugInfo` or null if no external debug metadata found in
        program
        :rtype: ExternalDebugInfo
        """

    def getBuildId(self) -> str:
        """
        Return the build-id.
        
        :return: build-id hash string
        :rtype: str
        """

    def getCrc(self) -> int:
        """
        Return the crc of the external debug file.  Not valid if filename is missing.
        
        :return: int crc32 of external debug file.
        :rtype: int
        """

    def getExtra(self) -> str:
        ...

    def getFilename(self) -> str:
        """
        Return the filename of the external debug file, or null if not specified.
        
        :return: String filename of external debug file, or null if not specified
        :rtype: str
        """

    def getObjectType(self) -> ObjectType:
        ...

    def hasBuildId(self) -> bool:
        """
        :return: true if buildId is available, false if not
        :rtype: bool
        """

    def hasDebugLink(self) -> bool:
        """
        Return true if there is a filename
        
        :return: boolean true if filename is available, false if not
        :rtype: bool
        """

    def withType(self, newObjectType: ObjectType, newExtra: typing.Union[java.lang.String, str]) -> ExternalDebugInfo:
        ...

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def crc(self) -> jpype.JInt:
        ...

    @property
    def extra(self) -> java.lang.String:
        ...

    @property
    def buildId(self) -> java.lang.String:
        ...

    @property
    def objectType(self) -> ObjectType:
        ...


class ExternalDebugFilesService(java.lang.Object):
    """
    A collection of :obj:`providers <DebugFileProvider>` that can be queried to find a
    DWARF external debug file.  Typically this will be an ELF binary that contains the debug
    information that was stripped from the original ELF binary, but can also include ability
    to fetch original binaries as well as source files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, storage: DebugFileStorage, providers: java.util.List[DebugInfoProvider]) -> None:
        """
        Creates a new instance using a :obj:`DebugFileStorage`, and a list of providers.
        
        :param DebugFileStorage storage: :obj:`DebugFileStorage`
        :param java.util.List[DebugInfoProvider] providers: list of :obj:`providers <DebugFileProvider>` to search
        """

    def addProvider(self, provider: DebugInfoProvider) -> None:
        """
        Adds a :obj:`DebugInfoProvider` as a location to search.
        
        :param DebugInfoProvider provider: :obj:`DebugInfoProvider` to add
        """

    def find(self, debugInfo: ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> java.io.File:
        """
        Searches for the specified external debug file.
        
        :param ExternalDebugInfo debugInfo: information about the external debug file
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: found file, or ``null`` if not found
        :rtype: java.io.File
        :raises IOException: if error
        """

    @staticmethod
    def forProgram(program: ghidra.program.model.listing.Program) -> ExternalDebugFilesService:
        """
        Get a new instance of :obj:`ExternalDebugFilesService` using the previously saved 
        information (via :meth:`saveToPrefs(ExternalDebugFilesService) <.saveToPrefs>`), for the specified program.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: new :obj:`ExternalDebugFilesService` instance
        :rtype: ExternalDebugFilesService
        """

    @staticmethod
    def fromPrefs(context: DebugInfoProviderCreatorContext) -> ExternalDebugFilesService:
        """
        Get a new instance of :obj:`ExternalDebugFilesService` using the previously saved 
        information (via :meth:`saveToPrefs(ExternalDebugFilesService) <.saveToPrefs>`).
        
        :param DebugInfoProviderCreatorContext context: created via :meth:`DebugInfoProviderRegistry.newContext(ghidra.program.model.listing.Program) <DebugInfoProviderRegistry.newContext>`
        :return: new :obj:`ExternalDebugFilesService` instance
        :rtype: ExternalDebugFilesService
        """

    @staticmethod
    def getDefault() -> ExternalDebugFilesService:
        """
        :return: an ExternalDebugFilesService instance with default search locations
        :rtype: ExternalDebugFilesService
        """

    @staticmethod
    def getMinimal() -> ExternalDebugFilesService:
        """
        :return: an ExternalDebugFilesService instance with no additional search locations
        :rtype: ExternalDebugFilesService
        """

    def getProviders(self) -> java.util.List[DebugInfoProvider]:
        """
        Returns the configured providers.
        
        :return: list of providers
        :rtype: java.util.List[DebugInfoProvider]
        """

    def getStorage(self) -> DebugFileStorage:
        ...

    @staticmethod
    def saveToPrefs(service: ExternalDebugFilesService) -> None:
        """
        Serializes an :obj:`ExternalDebugFilesService` to a string and writes to the Ghidra
        global preferences.
        
        :param ExternalDebugFilesService service: the :obj:`ExternalDebugFilesService` to commit to preferences
        """

    @property
    def storage(self) -> DebugFileStorage:
        ...

    @property
    def providers(self) -> java.util.List[DebugInfoProvider]:
        ...


class DebugFileStorage(DebugFileProvider):
    """
    A :obj:`DebugInfoProvider` that also allows storing files
    """

    class_: typing.ClassVar[java.lang.Class]

    def putStream(self, id: ExternalDebugInfo, stream: DebugStreamProvider.StreamInfo, monitor: ghidra.util.task.TaskMonitor) -> java.io.File:
        ...


class DebugInfoProviderStatus(java.lang.Enum[DebugInfoProviderStatus]):

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN: typing.Final[DebugInfoProviderStatus]
    VALID: typing.Final[DebugInfoProviderStatus]
    INVALID: typing.Final[DebugInfoProviderStatus]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DebugInfoProviderStatus:
        ...

    @staticmethod
    def values() -> jpype.JArray[DebugInfoProviderStatus]:
        ...


class LocalDirDebugInfoDProvider(DebugFileStorage):
    """
    Provides debug files found in a debuginfod-client compatible directory structure.
     
    
    Provides ability to store files.
     
    
    Does not try to follow debuginfod's file age-off logic or config values.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_FILE_AGE_MS: typing.Final[jpype.JLong]
    GHIDRACACHE_NAME: typing.Final = "$DEFAULT"
    USERHOMECACHE_NAME: typing.Final = "$DEBUGINFOD_CLIENT_CACHE"

    @typing.overload
    def __init__(self, rootDir: jpype.protocol.SupportsPath) -> None:
        ...

    @typing.overload
    def __init__(self, rootDir: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str], descriptiveName: typing.Union[java.lang.String, str]) -> None:
        ...

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> LocalDirDebugInfoDProvider:
        """
        Creates a new :obj:`BuildIdDebugFileProvider` instance using the specified name string.
        
        :param java.lang.String or str name: string, earlier returned from :meth:`getName() <.getName>`
        :param DebugInfoProviderCreatorContext context: :obj:`DebugInfoProviderCreatorContext` to allow accessing information outside
        of the name string that might be needed to create a new instance
        :return: new :obj:`BuildIdDebugFileProvider` instance
        :rtype: LocalDirDebugInfoDProvider
        """

    def getDirectory(self) -> java.io.File:
        ...

    @staticmethod
    def getGhidraCacheInstance() -> LocalDirDebugInfoDProvider:
        """
        :return: a new LocalDirDebugInfoDProvider that stores files in a Ghidra specific cache
        directory
        :rtype: LocalDirDebugInfoDProvider
        """

    def getRootDir(self) -> java.io.File:
        ...

    @staticmethod
    def getUserHomeCacheInstance() -> LocalDirDebugInfoDProvider:
        """
        :return: a new LocalDirDebugInfoDProvider that stores files in the same directory that the
        debuginfod-find CLI tool would (/home/user/.cache/debuginfod_client/)
        :rtype: LocalDirDebugInfoDProvider
        """

    @staticmethod
    def matches(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified name string specifies a LocalDirDebugInfoDProvider.
        
        :param java.lang.String or str name: string to test
        :return: boolean true if name specifies a LocalDirDebugInfoDProvider
        :rtype: bool
        """

    def performCacheMaintIfNeeded(self) -> None:
        ...

    def performInitMaintIfNeeded(self) -> None:
        ...

    def purgeAll(self) -> None:
        ...

    def setNeedsMaintCheck(self, needsInitMaintCheck: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @property
    def rootDir(self) -> java.io.File:
        ...

    @property
    def directory(self) -> java.io.File:
        ...


class DebugInfoProviderRegistry(java.lang.Object):
    """
    List of :obj:`DebugInfoProvider` types that can be saved / restored from a configuration string.
    """

    @typing.type_check_only
    class DebugInfoProviderCreator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def create(self, name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> DebugInfoProvider:
            """
            Creates a new :obj:`DebugFileProvider` instance using the provided name string.
            
            :param java.lang.String or str name: string, previously returned by :meth:`DebugFileProvider.getName() <DebugFileProvider.getName>`
            :param DebugInfoProviderCreatorContext context: :obj:`context <DebugInfoProviderCreatorContext>`
            :return: new :obj:`DebugFileProvider`
            :rtype: DebugInfoProvider
            """


    @typing.type_check_only
    class DebugInfoProviderCreationInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        """
        Creates a new registry
        """

    def create(self, name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> DebugInfoProvider:
        """
        Creates a :obj:`DebugFileProvider` using the specified name string.
        
        :param java.lang.String or str name: string previously returned by :meth:`DebugFileProvider.getName() <DebugFileProvider.getName>`
        :param DebugInfoProviderCreatorContext context: a :obj:`context <DebugInfoProviderCreatorContext>`
        :return: new :obj:`DebugFileProvider` instance, or null if there are no registered matching
        providers
        :rtype: DebugInfoProvider
        """

    @staticmethod
    def getInstance() -> DebugInfoProviderRegistry:
        ...

    def newContext(self, program: ghidra.program.model.listing.Program) -> DebugInfoProviderCreatorContext:
        """
        Creates a new :obj:`context <DebugInfoProviderCreatorContext>`.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: new :obj:`DebugInfoProviderCreatorContext`
        :rtype: DebugInfoProviderCreatorContext
        """

    def register(self, testFunc: java.util.function.Predicate[java.lang.String], createFunc: DebugInfoProviderRegistry.DebugInfoProviderCreator) -> None:
        """
        Adds a :obj:`DebugFileProvider` to this registry.
        
        :param java.util.function.Predicate[java.lang.String] testFunc: a :obj:`Predicate` that tests a name string, returning true if the
        string specifies the provider in question
        :param DebugInfoProviderRegistry.DebugInfoProviderCreator createFunc: a :obj:`DebugInfoProviderCreator` that will create a new 
        :obj:`DebugFileProvider` instance given a name string and a
        :obj:`context <DebugInfoProviderCreatorContext>`
        """


class DebugStreamProvider(DebugInfoProvider):
    """
    A :obj:`DebugInfoProvider` that returns debug objects as a stream.
    """

    class StreamInfo(java.lang.Record, java.io.Closeable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, is_: java.io.InputStream, contentLength: typing.Union[jpype.JLong, int]) -> None:
            ...

        def contentLength(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def is_(self) -> java.io.InputStream:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getStream(self, id: ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> DebugStreamProvider.StreamInfo:
        ...


class LocalDirDebugLinkProvider(DebugFileProvider):
    """
    Searches for DWARF external debug files specified via a debug-link filename / crc in a directory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, searchDir: jpype.protocol.SupportsPath) -> None:
        """
        Creates a new :obj:`LocalDirDebugLinkProvider` at the specified dir.
        
        :param jpype.protocol.SupportsPath searchDir: path to the root directory of where to search
        """

    @staticmethod
    def calcCRC(f: jpype.protocol.SupportsPath) -> int:
        """
        Calculates the crc32 for the specified file.
        
        :param jpype.protocol.SupportsPath f: :obj:`File` to read
        :return: int crc32
        :rtype: int
        :raises IOException: if error reading file
        """

    @staticmethod
    def create(name: typing.Union[java.lang.String, str], context: DebugInfoProviderCreatorContext) -> LocalDirDebugLinkProvider:
        """
        Creates a new :obj:`LocalDirDebugLinkProvider` instance using the specified name string.
        
        :param java.lang.String or str name: string, earlier returned from :meth:`getName() <.getName>`
        :param DebugInfoProviderCreatorContext context: :obj:`DebugInfoProviderCreatorContext` to allow accessing information outside
        of the name string that might be needed to create a new instance
        :return: new :obj:`LocalDirDebugLinkProvider` instance
        :rtype: LocalDirDebugLinkProvider
        """

    @staticmethod
    def matches(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified name string specifies a LocalDirDebugLinkProvider.
        
        :param java.lang.String or str name: string to test
        :return: boolean true if name specifies a LocalDirDebugLinkProvider name
        :rtype: bool
        """


class DWARFExternalDebugFilesPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]
    HELP_TOPIC: typing.Final = "DWARFExternalDebugFilesPlugin"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        ...


class ObjectType(java.lang.Enum[ObjectType]):

    class_: typing.ClassVar[java.lang.Class]
    DEBUGINFO: typing.Final[ObjectType]
    EXECUTABLE: typing.Final[ObjectType]
    SOURCE: typing.Final[ObjectType]

    def getPathString(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ObjectType:
        ...

    @staticmethod
    def values() -> jpype.JArray[ObjectType]:
        ...

    @property
    def pathString(self) -> java.lang.String:
        ...



__all__ = ["DebugFileProvider", "HttpDebugInfoDProvider", "DebugInfoProvider", "DebugInfoProviderCreatorContext", "BuildIdDebugFileProvider", "DisabledDebugInfoProvider", "SameDirDebugInfoProvider", "ExternalDebugInfo", "ExternalDebugFilesService", "DebugFileStorage", "DebugInfoProviderStatus", "LocalDirDebugInfoDProvider", "DebugInfoProviderRegistry", "DebugStreamProvider", "LocalDirDebugLinkProvider", "DWARFExternalDebugFilesPlugin", "ObjectType"]
