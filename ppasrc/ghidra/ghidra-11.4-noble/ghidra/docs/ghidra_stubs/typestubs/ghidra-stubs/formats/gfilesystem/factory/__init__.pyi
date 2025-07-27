from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


FSTYPE = typing.TypeVar("FSTYPE")


class GFileSystemProbeBytesOnly(GFileSystemProbe):
    """
    A :obj:`GFileSystemProbe` interface for filesystems that can be detected using
    just a few bytes from the beginning of the containing file.
     
    
    Filesystem probes of this type are given precedence when possible since they
    tend to be simpler and quicker.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_BYTESREQUIRED: typing.Final = 65536
    """
    Maximum that any GFileSystemProbeBytesOnly is allowed to specify as its
    :meth:`GFileSystemProbeBytesOnly.getBytesRequired() <GFileSystemProbeBytesOnly.getBytesRequired>`.
    """


    def getBytesRequired(self) -> int:
        """
        The minimum number of bytes needed to be supplied to the
        :meth:`probeStartBytes(FSRL, byte[]) <.probeStartBytes>` method.
        
        :return: min number of bytes needed for probe
        :rtype: int
        """

    def probeStartBytes(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, startBytes: jpype.JArray[jpype.JByte]) -> bool:
        """
        Probes the supplied ``startBytes`` byte[] array to determine if this filesystem
        implementation can handle the file.
        
        :param ghidra.formats.gfilesystem.FSRL containerFSRL: the :obj:`FSRL` of the file containing the bytes being probed.
        :param jpype.JArray[jpype.JByte] startBytes: a byte array, with a length of at least :meth:`getBytesRequired() <.getBytesRequired>`
        containing bytes from the beginning (ie. offset 0) of the probed file.
        :return: ``true`` if the specified file is handled by this filesystem implementation,
        ``false`` if not.
        :rtype: bool
        """

    @property
    def bytesRequired(self) -> jpype.JInt:
        ...


class GFileSystemBaseFactory(GFileSystemFactoryByteProvider[ghidra.formats.gfilesystem.GFileSystemBase], GFileSystemProbeByteProvider):
    """
    A :obj:`GFileSystemFactory` implementation that probes and creates instances of
    :obj:`GFileSystemBase` which use the legacy filesystem lifecycle pattern.
     
    
    For each operation, this factory will mint a new instance of a GFileSystemBase-derived
    fs, using its 3 param constructor, and call its isValid() or open().
     
    
    After an isValid() call, the newly minted filesystem instance is thrown away.
     
    
    This class requires special support in the :obj:`FileSystemFactoryMgr` to push
    the fsClass into each factory instance after it is constructed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setFileSystemClass(self, fsClass: java.lang.Class[ghidra.formats.gfilesystem.GFileSystemBase]):
        ...


class FileSystemFactoryMgr(java.lang.Object):
    """
    Statically scoped mugger that handles the dirty work of probing for and creating
    :obj:`GFileSystem` instances.
     
    
    Auto-discovers all :obj:`GFileSystem` instances in the classpath that have a
    :obj:`FileSystemInfo` annotation.
    """

    @typing.type_check_only
    class Singleton(java.lang.Object):
        """
        A way to delay initialization of the global FileSystemFactoryMgr until it is first used.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getAllFilesystemNames(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of all registered filesystem implementation descriptions.
        
        :return: list of strings
        :rtype: java.util.List[java.lang.String]
        """

    def getFileSystemType(self, fsClass: java.lang.Class[ghidra.formats.gfilesystem.GFileSystem]) -> str:
        """
        Returns the file system type of the specified :obj:`GFileSystem` class.
        
        :param java.lang.Class[ghidra.formats.gfilesystem.GFileSystem] fsClass: Class to inspect
        :return: String file system type, from the :meth:`FileSystemInfo.type() <FileSystemInfo.type>` annotation.
        :rtype: str
        """

    @staticmethod
    def getInstance() -> FileSystemFactoryMgr:
        """
        :return: The single global :obj:`FileSystemFactoryMgr` instance.
        :rtype: FileSystemFactoryMgr
        """

    def mountFileSystem(self, fsType: typing.Union[java.lang.String, str], byteProvider: ghidra.app.util.bin.ByteProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.GFileSystem:
        """
        Creates a new :obj:`GFileSystem` instance when the filesystem type is already
        known, consuming the specified ByteProvider.
        
        :param java.lang.String or str fsType: filesystem type string, ie. "file", "zip".
        :param ghidra.app.util.bin.ByteProvider byteProvider: :obj:`ByteProvider`, will be owned by the new file system
        :param ghidra.formats.gfilesystem.FileSystemService fsService: reference to the :obj:`FileSystemService` instance.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to use for canceling and updating progress.
        :return: new :obj:`GFileSystem` instance.
        :rtype: ghidra.formats.gfilesystem.GFileSystem
        :raises IOException: if error when opening the filesystem or unknown fsType.
        :raises CancelledException: if the user canceled the operation.
        """

    @typing.overload
    def probe(self, byteProvider: ghidra.app.util.bin.ByteProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, conflictResolver: ghidra.formats.gfilesystem.FileSystemProbeConflictResolver, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.GFileSystem:
        """
        Probes the specified file for a supported :obj:`GFileSystem` implementation, and
        if found, creates a new filesystem instance.
        
        :param ghidra.app.util.bin.ByteProvider byteProvider: container :obj:`ByteProvider`, will be owned by the new filesystem
        :param ghidra.formats.gfilesystem.FileSystemService fsService: reference to the :obj:`FileSystemService` instance.
        :param ghidra.formats.gfilesystem.FileSystemProbeConflictResolver conflictResolver: :obj:`conflict resolver <FileSystemProbeConflictResolver>` to
        use when more than one :obj:`GFileSystem` implementation can handle the specified
        file.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to use for canceling and updating progress.
        :return: new :obj:`GFileSystem` instance or null not supported.
        :rtype: ghidra.formats.gfilesystem.GFileSystem
        :raises IOException: if error accessing the containing file
        :raises CancelledException: if the user cancels the operation
        """

    @typing.overload
    def probe(self, byteProvider: ghidra.app.util.bin.ByteProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, conflictResolver: ghidra.formats.gfilesystem.FileSystemProbeConflictResolver, priorityFilter: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.GFileSystem:
        """
        Probes the specified file for a supported :obj:`GFileSystem` implementation, and
        if found, creates a new filesystem instance.  The ByteProvider is owned by the new
        file system.
        
        :param ghidra.app.util.bin.ByteProvider byteProvider: container :obj:`ByteProvider`, will be owned by the new filesystem
        :param ghidra.formats.gfilesystem.FileSystemService fsService: reference to the :obj:`FileSystemService` instance.
        :param ghidra.formats.gfilesystem.FileSystemProbeConflictResolver conflictResolver: :obj:`conflict resolver <FileSystemProbeConflictResolver>` to
        use when more than one :obj:`GFileSystem` implementation can handle the specified
        file.
        :param jpype.JInt or int priorityFilter: limits the probe to filesystems that have a :meth:`FileSystemInfo.priority() <FileSystemInfo.priority>`
        greater than or equal to this value.  Use :obj:`FileSystemInfo.PRIORITY_LOWEST` to
        include all filesystem implementations.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to use for canceling and updating progress.
        :return: new :obj:`GFileSystem` instance or null not supported.
        :rtype: ghidra.formats.gfilesystem.GFileSystem
        :raises IOException: if error accessing the containing file
        :raises CancelledException: if the user cancels the operation
        """

    def test(self, byteProvider: ghidra.app.util.bin.ByteProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if the specified file contains a supported :obj:`GFileSystem`.
        
        :param ghidra.app.util.bin.ByteProvider byteProvider: 
        :param ghidra.formats.gfilesystem.FileSystemService fsService: reference to the :obj:`FileSystemService` instance.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to use for canceling and updating progress.
        :return: ``true`` if the file seems to contain a filesystem, ``false`` if it does not.
        :rtype: bool
        :raises IOException: if error when accessing the containing file
        :raises CancelledException: if the user canceled the operation
        """

    @property
    def allFilesystemNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def fileSystemType(self) -> java.lang.String:
        ...


class GFileSystemProbeByteProvider(GFileSystemProbe):
    """
    A :obj:`GFileSystemProbe` interface for filesystems that need to examine
    a :obj:`ByteProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def probe(self, byteProvider: ghidra.app.util.bin.ByteProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Probes the specified ``ByteProvider`` to determine if this filesystem implementation
        can handle the file.
        
        :param ghidra.app.util.bin.ByteProvider byteProvider: a :obj:`ByteProvider` containing the contents of the file being probed. 
        Implementors of this method should **NOT** :meth:`close() <ByteProvider.close>` this
        object.
        :param ghidra.formats.gfilesystem.FileSystemService fsService: a reference to the :obj:`FileSystemService` object
        :param ghidra.util.task.TaskMonitor monitor: a :obj:`TaskMonitor` that should be polled to see if the user has
        requested to cancel the operation, and updated with progress information.
        :return: ``true`` if the specified file is handled by this filesystem implementation, 
        ``false`` if not.
        :rtype: bool
        :raises IOException: if there is an error reading files.
        :raises CancelledException: if the user cancels
        """


class GFileSystemFactory(java.lang.Object, typing.Generic[FSTYPE]):
    """
    An empty interface that is a common type for the real factory interfaces to derive from.
    """

    class_: typing.ClassVar[java.lang.Class]


class GFileSystemFactoryIgnore(GFileSystemFactory[ghidra.formats.gfilesystem.GFileSystem]):
    """
    Marker class that tells the :obj:`FileSystemFactoryMgr` to not register this
    filesystem instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GFileSystemFactoryByteProvider(GFileSystemFactory[FSTYPE], typing.Generic[FSTYPE]):
    """
    A :obj:`GFileSystemFactory` interface for filesystem implementations
    that use a :obj:`ByteProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def create(self, targetFSRL: ghidra.formats.gfilesystem.FSRLRoot, byteProvider: ghidra.app.util.bin.ByteProvider, fsService: ghidra.formats.gfilesystem.FileSystemService, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.GFileSystem:
        """
        Constructs a new :obj:`GFileSystem` instance that handles the specified file.
        
        :param ghidra.formats.gfilesystem.FSRLRoot targetFSRL: the :obj:`FSRLRoot` of the filesystem being created.
        :param ghidra.app.util.bin.ByteProvider byteProvider: a :obj:`ByteProvider` containing the contents of the file being probed.
        This method is responsible for closing this byte provider instance.
        :param ghidra.formats.gfilesystem.FileSystemService fsService: a reference to the :obj:`FileSystemService` object
        :param ghidra.util.task.TaskMonitor monitor: a :obj:`TaskMonitor` that should be polled to see if the user has
        requested to cancel the operation, and updated with progress information.
        :return: a new :obj:`GFileSystem` derived instance.
        :rtype: ghidra.formats.gfilesystem.GFileSystem
        :raises IOException: if there is an error reading files.
        :raises CancelledException: if the user cancels
        """


class GFileSystemProbe(java.lang.Object):
    """
    An empty interface that is a common type for the real probe interfaces to derive from.
     
    
    See :obj:`GFileSystemProbeBytesOnly`, :obj:`GFileSystemProbeByteProvider`
    """

    class_: typing.ClassVar[java.lang.Class]


class FileSystemInfoRec(java.lang.Object):
    """
    Holds information read from a :obj:`FileSystemInfo` annotation.
    """

    class_: typing.ClassVar[java.lang.Class]
    BY_PRIORITY: typing.Final[java.util.Comparator[FileSystemInfoRec]]
    """
    A static :obj:`Comparator` that will order :obj:`FileSystemInfoRec` by their
    :meth:`priority <FileSystemInfoRec.getPriority>`, with the highest priority
    elements sorted to the beginning of the list.
    """


    @staticmethod
    def fromClass(fsClazz: java.lang.Class[ghidra.formats.gfilesystem.GFileSystem]) -> FileSystemInfoRec:
        """
        Instantiate a new :obj:`FileSystemInfoRec` from the information found in the
        :obj:`FileSystemInfo` annotation attached to the specified Class.
        
        :param java.lang.Class[ghidra.formats.gfilesystem.GFileSystem] fsClazz: class to query for file system info.
        :return: new :obj:`FileSystemInfoRec`, or null if the class doesn't have
        valid file system meta data.
        :rtype: FileSystemInfoRec
        """

    def getDescription(self) -> str:
        """
        Filesystem description, ie. "XYZ Vendor Filesystem Type 1"
        
        :return: description string
        :rtype: str
        """

    def getFSClass(self) -> java.lang.Class[ghidra.formats.gfilesystem.GFileSystem]:
        """
        The :obj:`Class` of the filesystem implementation.
        
        :return: :obj:`GFileSystem` derived class.
        :rtype: java.lang.Class[ghidra.formats.gfilesystem.GFileSystem]
        """

    def getFactory(self) -> GFileSystemFactory[typing.Any]:
        """
        The :obj:`GFileSystemFactory` instance that will create new filesystem
        instances when needed.
        
        :return: :obj:`GFileSystemFactory` for this filesystem
        :rtype: GFileSystemFactory[typing.Any]
        """

    def getPriority(self) -> int:
        """
        Filesystem relative priority.
         
        
        See :meth:`FileSystemInfo.priority() <FileSystemInfo.priority>`.
        
        :return: priority int
        :rtype: int
        """

    def getType(self) -> str:
        """
        Filesystem 'type', ie. "file", or "zip", etc.
        
        :return: type string
        :rtype: str
        """

    @property
    def factory(self) -> GFileSystemFactory[typing.Any]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def fSClass(self) -> java.lang.Class[ghidra.formats.gfilesystem.GFileSystem]:
        ...

    @property
    def type(self) -> java.lang.String:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...



__all__ = ["GFileSystemProbeBytesOnly", "GFileSystemBaseFactory", "FileSystemFactoryMgr", "GFileSystemProbeByteProvider", "GFileSystemFactory", "GFileSystemFactoryIgnore", "GFileSystemFactoryByteProvider", "GFileSystemProbe", "FileSystemInfoRec"]
