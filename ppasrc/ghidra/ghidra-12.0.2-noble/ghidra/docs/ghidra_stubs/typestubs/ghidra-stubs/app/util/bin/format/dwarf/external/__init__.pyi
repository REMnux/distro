from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.formats.gfilesystem
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class SearchLocation(java.lang.Object):
    """
    Represents a collection of dwarf external debug files that can be searched.
    """

    class_: typing.ClassVar[java.lang.Class]

    def findDebugFile(self, debugInfo: ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL:
        """
        Searchs for a debug file that fulfills the criteria specified in the :obj:`ExternalDebugInfo`.
        
        :param ExternalDebugInfo debugInfo: search criteria
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`FSRL` of the matching file, or ``null`` if not found
        :rtype: ghidra.formats.gfilesystem.FSRL
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    def getDescriptiveName(self) -> str:
        """
        Returns a human formatted string describing this location, used in UI prompts or lists.
        
        :return: formatted string
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of this instance, which should be a serialized copy of this instance.
        
        :return: String serialized data of this instance, typically in "something://serialized_data"
        form
        :rtype: str
        """

    @property
    def descriptiveName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class SearchLocationRegistry(java.lang.Object):
    """
    List of :obj:`SearchLocation` types that can be saved / restored from a configuration string.
    """

    class SearchLocationCreator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def create(self, locString: typing.Union[java.lang.String, str], context: SearchLocationCreatorContext) -> SearchLocation:
            """
            Creates a new :obj:`SearchLocation` instance using the provided location string.
            
            :param java.lang.String or str locString: location string, previously returned by :meth:`SearchLocation.getName() <SearchLocation.getName>`
            :param SearchLocationCreatorContext context: :obj:`context <SearchLocationCreatorContext>`
            :return: new :obj:`SearchLocation`
            :rtype: SearchLocation
            """


    @typing.type_check_only
    class SearchLocationCreationInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, registerDefault: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new registry, optionally registering the default SearchLocations.
        
        :param jpype.JBoolean or bool registerDefault: boolean flag, if true register the built-in :obj:`SearchLocation`s
        """

    def createSearchLocation(self, locString: typing.Union[java.lang.String, str], context: SearchLocationCreatorContext) -> SearchLocation:
        """
        Creates a :obj:`SearchLocation` using the provided location string.
        
        :param java.lang.String or str locString: location string (previously returned by :meth:`SearchLocation.getName() <SearchLocation.getName>`
        :param SearchLocationCreatorContext context: a :obj:`context <SearchLocationCreatorContext>`
        :return: new :obj:`SearchLocation` instance, or null if there are no registered matching
        SearchLocations
        :rtype: SearchLocation
        """

    @staticmethod
    def getInstance() -> SearchLocationRegistry:
        ...

    def newContext(self, program: ghidra.program.model.listing.Program) -> SearchLocationCreatorContext:
        """
        Creates a new :obj:`context <SearchLocationCreatorContext>`.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: new :obj:`SearchLocationCreatorContext`
        :rtype: SearchLocationCreatorContext
        """

    def register(self, testFunc: java.util.function.Predicate[java.lang.String], createFunc: SearchLocationRegistry.SearchLocationCreator):
        """
        Adds a :obj:`SearchLocation` to this registry.
        
        :param java.util.function.Predicate[java.lang.String] testFunc: a :obj:`Predicate` that tests a location string, returning true if the
        string specifies the SearchLocation in question
        :param SearchLocationRegistry.SearchLocationCreator createFunc: a :obj:`SearchLocationCreator` that will create a new :obj:`SearchLocation`
        instance given a location string and a :obj:`context <SearchLocationCreatorContext>`
        """


class ExternalDebugInfo(java.lang.Object):
    """
    Metadata needed to find an ELF/DWARF external debug file, retrieved from an ELF binary's
    ".gnu_debuglink" section and/or ".note.gnu.build-id" section.  
     
    
    The debuglink can provide a filename and crc of the external debug file, while the build-id
    can provide a hash that is converted to a filename that identifies the external debug file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filename: typing.Union[java.lang.String, str], crc: typing.Union[jpype.JInt, int], hash: jpype.JArray[jpype.JByte]):
        """
        Constructor to create an :obj:`ExternalDebugInfo` instance.
        
        :param java.lang.String or str filename: filename of external debug file, or null
        :param jpype.JInt or int crc: crc32 of external debug file, or 0 if no filename
        :param jpype.JArray[jpype.JByte] hash: build-id hash digest found in ".note.gnu.build-id" section, or null if
        not present
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

    def getCrc(self) -> int:
        """
        Return the crc of the external debug file.  Not valid if filename is missing.
        
        :return: int crc32 of external debug file.
        :rtype: int
        """

    def getFilename(self) -> str:
        """
        Return the filename of the external debug file, or null if not specified.
        
        :return: String filename of external debug file, or null if not specified
        :rtype: str
        """

    def getHash(self) -> jpype.JArray[jpype.JByte]:
        """
        Return the build-id hash digest.
        
        :return: byte array containing the build-id hash (usually 20 bytes)
        :rtype: jpype.JArray[jpype.JByte]
        """

    def hasFilename(self) -> bool:
        """
        Return true if there is a filename
        
        :return: boolean true if filename is available, false if not
        :rtype: bool
        """

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def crc(self) -> jpype.JInt:
        ...

    @property
    def hash(self) -> jpype.JArray[jpype.JByte]:
        ...


class ExternalDebugFilesService(java.lang.Object):
    """
    A collection of :obj:`search locations <SearchLocation>` that can be queried to find a
    DWARF external debug file, which is a second ELF binary that contains the debug information
    that was stripped from the original ELF binary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, searchLocations: java.util.List[SearchLocation]):
        """
        Creates a new instance using the list of search locations.
        
        :param java.util.List[SearchLocation] searchLocations: list of :obj:`search locations <SearchLocation>`
        """

    def findDebugFile(self, debugInfo: ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL:
        """
        Searches for the specified external debug file.
         
        
        Returns the FSRL of a matching file, or null if not found.
        
        :param ExternalDebugInfo debugInfo: information about the external debug file
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`FSRL` of found file, or ``null`` if not found
        :rtype: ghidra.formats.gfilesystem.FSRL
        :raises IOException: if error
        """

    def getSearchLocations(self) -> java.util.List[SearchLocation]:
        """
        Returns the configured search locations.
        
        :return: list of search locations
        :rtype: java.util.List[SearchLocation]
        """

    @property
    def searchLocations(self) -> java.util.List[SearchLocation]:
        ...


class BuildIdSearchLocation(SearchLocation):
    """
    A :obj:`SearchLocation` that expects the external debug files to be named using the hexadecimal
    value of the hash of the file, and to be arranged in a bucketed directory hierarchy using the
    first 2 hexdigits of the hash.
     
    
    For example, the debug file with hash ``6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f`` would
    be stored as "6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug" (under some root directory).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rootDir: jpype.protocol.SupportsPath):
        """
        Creates a new :obj:`BuildIdSearchLocation` at the specified location.
        
        :param jpype.protocol.SupportsPath rootDir: path to the root directory of the build-id directory (typically ends with
        "./build-id")
        """

    @staticmethod
    def create(locString: typing.Union[java.lang.String, str], context: SearchLocationCreatorContext) -> BuildIdSearchLocation:
        """
        Creates a new :obj:`BuildIdSearchLocation` instance using the specified location string.
        
        :param java.lang.String or str locString: string, earlier returned from :meth:`getName() <.getName>`
        :param SearchLocationCreatorContext context: :obj:`SearchLocationCreatorContext` to allow accessing information outside
        of the location string that might be needed to create a new instance
        :return: new :obj:`BuildIdSearchLocation` instance
        :rtype: BuildIdSearchLocation
        """

    @staticmethod
    def isBuildIdSearchLocation(locString: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified location string specifies a BuildIdSearchLocation.
        
        :param java.lang.String or str locString: string to test
        :return: boolean true if locString specifies a BuildId location
        :rtype: bool
        """


class LocalDirectorySearchLocation(SearchLocation):
    """
    A :obj:`SearchLocation` that recursively searches for dwarf external debug files 
    under a configured directory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, searchDir: jpype.protocol.SupportsPath):
        """
        Creates a new :obj:`LocalDirectorySearchLocation` at the specified location.
        
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
    def create(locString: typing.Union[java.lang.String, str], context: SearchLocationCreatorContext) -> LocalDirectorySearchLocation:
        """
        Creates a new :obj:`LocalDirectorySearchLocation` instance using the specified location string.
        
        :param java.lang.String or str locString: string, earlier returned from :meth:`getName() <.getName>`
        :param SearchLocationCreatorContext context: :obj:`SearchLocationCreatorContext` to allow accessing information outside
        of the location string that might be needed to create a new instance
        :return: new :obj:`LocalDirectorySearchLocation` instance
        :rtype: LocalDirectorySearchLocation
        """

    @staticmethod
    def isLocalDirSearchLoc(locString: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified location string specifies a LocalDirectorySearchLocation.
        
        :param java.lang.String or str locString: string to test
        :return: boolean true if locString specifies a local dir search location
        :rtype: bool
        """


class SameDirSearchLocation(SearchLocation):
    """
    A :obj:`SearchLocation` that only looks in the program's original import directory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, progDir: jpype.protocol.SupportsPath):
        """
        Creates a new :obj:`SameDirSearchLocation` at the specified location.
        
        :param jpype.protocol.SupportsPath progDir: path to the program's import directory
        """

    @staticmethod
    def create(locString: typing.Union[java.lang.String, str], context: SearchLocationCreatorContext) -> SameDirSearchLocation:
        """
        Creates a new :obj:`SameDirSearchLocation` instance using the current program's
        import location.
        
        :param java.lang.String or str locString: unused
        :param SearchLocationCreatorContext context: :obj:`SearchLocationCreatorContext`
        :return: new :obj:`SameDirSearchLocation` instance
        :rtype: SameDirSearchLocation
        """

    @staticmethod
    def isSameDirSearchLocation(locString: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified location string specifies a SameDirSearchLocation.
        
        :param java.lang.String or str locString: string to test
        :return: boolean true if locString specifies a BuildId location
        :rtype: bool
        """


class DWARFExternalDebugFilesPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def getExternalDebugFilesService(context: SearchLocationCreatorContext) -> ExternalDebugFilesService:
        """
        Get a new instance of :obj:`ExternalDebugFilesService` using the previously saved 
        information (via :meth:`saveExternalDebugFilesService(ExternalDebugFilesService) <.saveExternalDebugFilesService>`).
        
        :param SearchLocationCreatorContext context: created via :meth:`SearchLocationRegistry.newContext(ghidra.program.model.listing.Program) <SearchLocationRegistry.newContext>`
        :return: new :obj:`ExternalDebugFilesService` instance
        :rtype: ExternalDebugFilesService
        """

    @staticmethod
    def saveExternalDebugFilesService(service: ExternalDebugFilesService):
        """
        Serializes an :obj:`ExternalDebugFilesService` to a string and writes to the Ghidra
        global preferences.
        
        :param ExternalDebugFilesService service: the :obj:`ExternalDebugFilesService` to commit to preferences
        """


class SearchLocationCreatorContext(java.lang.Object):
    """
    Information outside of a location string that might be needed to create a new :obj:`SearchLocation`
    instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, registry: SearchLocationRegistry, program: ghidra.program.model.listing.Program):
        """
        Create a new context object with references to the registry and the current program.
        
        :param SearchLocationRegistry registry: :obj:`SearchLocationRegistry`
        :param ghidra.program.model.listing.Program program: the current :obj:`Program`
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        
        
        :return: the current :obj:`Program`
        :rtype: ghidra.program.model.listing.Program
        """

    def getRegistry(self) -> SearchLocationRegistry:
        """
        
        
        :return: the :obj:`SearchLocationRegistry` that is creating the :obj:`SearchLocation`
        :rtype: SearchLocationRegistry
        """

    @property
    def registry(self) -> SearchLocationRegistry:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...



__all__ = ["SearchLocation", "SearchLocationRegistry", "ExternalDebugInfo", "ExternalDebugFilesService", "BuildIdSearchLocation", "LocalDirectorySearchLocation", "SameDirSearchLocation", "DWARFExternalDebugFilesPlugin", "SearchLocationCreatorContext"]
