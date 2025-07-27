from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.formats.gfilesystem.crypto
import ghidra.formats.gfilesystem.factory
import ghidra.formats.gfilesystem.fileinfo
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.classfinder
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


FSTYPE = typing.TypeVar("FSTYPE")
METADATATYPE = typing.TypeVar("METADATATYPE")


class SingleFileSystemIndexHelper(java.lang.Object):
    """
    A helper class used by GFilesystem implementors that have a single file to handle lookups
    and requests for that file.
     
    
    This class is patterned on FileSystemIndexHelper and has pretty much the same api.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fs: GFileSystem, fsFSRL: FSRLRoot, payloadFilename: typing.Union[java.lang.String, str], length: typing.Union[jpype.JLong, int], payloadMD5: typing.Union[java.lang.String, str]):
        """
        Creates a new instance.
        
        A "root" directory GFile will be auto-created for the filesystem.
        
        :param GFileSystem fs: the :obj:`GFileSystem` that this index will be for.
        :param FSRLRoot fsFSRL: the :obj:`fsrl <FSRLRoot>` of the filesystem itself.
        (this parameter is explicitly passed here so there is no possibility of trying to call
        back to the fs's :meth:`GFileSystem.getFSRL() <GFileSystem.getFSRL>` on a half-constructed filesystem.)
        :param java.lang.String or str payloadFilename: name of the single file that this filesystem holds.
        :param jpype.JLong or int length: length of the payload file.
        :param java.lang.String or str payloadMD5: md5 of the payload file.
        """

    def clear(self):
        """
        Clears the data held by this object.
        """

    def getFileCount(self) -> int:
        """
        Number of files in this index.
        
        :return: number of file in this index.
        :rtype: int
        """

    def getListing(self, directory: GFile) -> java.util.List[GFile]:
        """
        Mirrors :meth:`GFileSystem.getListing(GFile) <GFileSystem.getListing>` interface.
        
        :param GFile directory: :obj:`GFile` directory to get the list of child files that have been
        added to this index, null means root directory.
        :return: :obj:`List` of GFile files that are in the specified directory, never null.
        :rtype: java.util.List[GFile]
        :raises IOException: if already closed.
        """

    def getPayloadFile(self) -> GFile:
        """
        Gets the 'payload' file, ie. the main file of this filesystem.
        
        :return: :obj:`GFile` payload file.
        :rtype: GFile
        """

    def getRootDir(self) -> GFile:
        """
        Gets the root :obj:`GFile` object for this filesystem index.
        
        :return: root :obj:`GFile` object.
        :rtype: GFile
        """

    def getRootDirFSRL(self) -> FSRL:
        """
        Gets the root dir's FSRL.
        
        :return: :obj:`FSRL` of the root dir.
        :rtype: FSRL
        """

    def isClosed(self) -> bool:
        """
        Returns true if this object has been :meth:`clear() <.clear>`'ed.
        
        :return: boolean true if data has been cleared.
        :rtype: bool
        """

    def isPayloadFile(self, file: GFile) -> bool:
        """
        Returns true if the specified file is the payload file.
        
        :param GFile file: GFile to test
        :return: boolean true if it is the payload file
        :rtype: bool
        """

    @typing.overload
    def lookup(self, path: typing.Union[java.lang.String, str]) -> GFile:
        """
        Mirrors :meth:`GFileSystem.lookup(String) <GFileSystem.lookup>` interface.
        
        :param java.lang.String or str path: path and filename of a file to find (either "/" for root or the payload file's
        path).
        :return: :obj:`GFile` instance or null if requested path is not the same as the payload file.
        :rtype: GFile
        """

    @typing.overload
    def lookup(self, baseDir: GFile, path: typing.Union[java.lang.String, str], nameComp: java.util.Comparator[java.lang.String]) -> GFile:
        """
        Mirrors :meth:`GFileSystem.lookup(String) <GFileSystem.lookup>` interface.
        
        :param GFile baseDir: starting directory
        :param java.lang.String or str path: path and filename of a file to find (either "/" for root or the payload file's
        path).
        :param java.util.Comparator[java.lang.String] nameComp: optional :obj:`Comparator` that compares file names.  Suggested values are 
        ``String::compareTo`` or ``String::compareToIgnoreCase`` or ``null``.
        :return: :obj:`GFile` instance or null if requested path is not the same as
        the payload file.
        :rtype: GFile
        """

    @property
    def rootDirFSRL(self) -> FSRL:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def rootDir(self) -> GFile:
        ...

    @property
    def listing(self) -> java.util.List[GFile]:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...

    @property
    def payloadFile(self) -> GFile:
        ...


@typing.type_check_only
class FileSystemInstanceManager(FileSystemEventListener):
    """
    A threadsafe cache of :obj:`GFileSystem` instances (organized by their :obj:`FSRLRoot`)
     
    
    Any filesystems that are not referenced by outside users (via a :obj:`FileSystemRef`) will
    be closed and removed from the cache when the next :meth:`cacheMaint() <.cacheMaint>` is performed.
    """

    @typing.type_check_only
    class FSCacheInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rootFS: GFileSystem):
        """
        Creates a new FileSystemCache object.
        
        :param GFileSystem rootFS: reference to the global root file system, which is a special case
        file system that is not subject to eviction.
        """

    def add(self, fs: GFileSystem):
        """
        Adds a new :obj:`GFileSystem` to the cache.
        
        :param GFileSystem fs: :obj:`GFileSystem` to add to this cache.
        """

    def cacheMaint(self):
        """
        Performs maintainence on the filesystem cache, closing() any filesystems
        that are not used anymore.
        """

    def clear(self):
        """
        Forcefully closes any filesystems in the cache, then clears the list of
        cached filesystems.
        """

    def closeAllUnused(self):
        """
        Removes any unused filesystems in the cache.
        """

    def getFilesystemRefMountedAt(self, containerFSRL: FSRL) -> FileSystemRef:
        """
        Returns a new :obj:`FileSystemRef` to a already mounted :obj:`filesystem <GFileSystem>`
        (keeping the filesystem pinned in memory without the risk of it being closed during
        a race condition).
         
        
        The caller is responsible for :meth:`closing <FileSystemRef.close>` it when done.
         
        
        Returns null if there is no filesystem mounted at the requested container fsrl.
        
        :param FSRL containerFSRL: :obj:`FSRL` location where a filesystem is already mounted
        :return: new :obj:`FileSystemRef` to the already mounted filesystem, or null
        :rtype: FileSystemRef
        """

    def getMountedFilesystems(self) -> java.util.List[FSRLRoot]:
        """
        Returns a list of mounted file systems.
        
        :return: :obj:`List` of :obj:`FSRLRoot` of filesystems that are currently mounted.
        :rtype: java.util.List[FSRLRoot]
        """

    def getRef(self, fsrl: FSRLRoot) -> FileSystemRef:
        """
        Returns a new :obj:`FileSystemRef` to an existing, already open :obj:`filesystem <GFileSystem>`.
        Caller is responsible for :meth:`closing <FileSystemRef.close>` it.
         
        
        Returns NULL if the requested filesystem isn't already open and mounted in the cache.
        
        :param FSRLRoot fsrl: :obj:`FSRLRoot` of the desired filesystem.
        :return: a new :obj:`FileSystemRef` or null if the filesystem is not currently mounted.
        :rtype: FileSystemRef
        """

    def isFilesystemMountedAt(self, containerFSRL: FSRL) -> bool:
        """
        Returns true if there is a filesystem in the cache that has a containerFSRL that
        is :meth:`equiv <FSRL.isEquivalent>` to the specified FSRL.
        
        :param FSRL containerFSRL: :obj:`FSRL` location to query for currently mounted filesystem.
        :return: true if there is a filesystem mounted using that containerFSRL.
        :rtype: bool
        """

    def releaseImmediate(self, ref: FileSystemRef):
        """
        Closes the specified ref, and if no other refs to the file system remain, closes the file system.
        
        :param FileSystemRef ref: :obj:`FileSystemRef` to close
        """

    @property
    def ref(self) -> FileSystemRef:
        ...

    @property
    def filesystemRefMountedAt(self) -> FileSystemRef:
        ...

    @property
    def filesystemMountedAt(self) -> jpype.JBoolean:
        ...

    @property
    def mountedFilesystems(self) -> java.util.List[FSRLRoot]:
        ...


class FileSystemEventListener(java.lang.Object):
    """
    Events broadcast when a :obj:`GFileSystem` is closed or has a :obj:`FileSystemRef` change.
    """

    class_: typing.ClassVar[java.lang.Class]

    def onFilesystemClose(self, fs: GFileSystem):
        """
        Called by GFilesystem's :meth:`GFileSystem.close() <GFileSystem.close>`, before any destructive changes
        are made to the filesystem instance.
        
        :param GFileSystem fs: :obj:`GFileSystem` that is about to be closed.
        """

    def onFilesystemRefChange(self, fs: GFileSystem, refManager: FileSystemRefManager):
        """
        Called by :obj:`FileSystemRefManager` when a new :obj:`FileSystemRef` is created or
        released.
        
        :param GFileSystem fs: :obj:`GFileSystem` that is being updated.
        :param FileSystemRefManager refManager: :obj:`FileSystemRefManager` that is tracking the modified GFileSystem.
        """


class FileSystemRef(java.io.Closeable):
    """
    A handle to a :obj:`GFileSystem` which allows tracking the current users of the filesystem.
     
    
    Instances must be :meth:`closed <.close>` when not needed anymore, and should not be
    shared across threads.
    """

    class_: typing.ClassVar[java.lang.Class]

    def close(self):
        """
        Closes this reference, releasing it from the :obj:`FileSystemRefManager`.
        """

    def dup(self) -> FileSystemRef:
        """
        Creates a duplicate ref.
        
        :return: a new duplicate :obj:`FileSystemRef`
        :rtype: FileSystemRef
        """

    def getFilesystem(self) -> GFileSystem:
        """
        :obj:`GFileSystem` this ref points to.
        
        :return: :obj:`GFileSystem` this ref points to.
        :rtype: GFileSystem
        """

    def isClosed(self) -> bool:
        """
        Returns true if this ref was :meth:`closed <.close>`.
        
        :return: boolean true if this ref was closed.
        :rtype: bool
        """

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def filesystem(self) -> GFileSystem:
        ...


class LocalFileSystemSub(GFileSystem, GFileHashProvider):
    """
    A :obj:`GFileSystem` interface to a part of the user's local / native file system.
     
    
    This class is a sub-view of the :obj:`LocalFileSystem`, and returns hybrid GFile objects
    that have fully specified FSRL paths that are valid in the Root filesystem, but relative
    GFile paths.
     
    
    This class's name doesn't end with "FileSystem" to ensure it will not be auto-discovered
    by the FileSystemFactoryMgr.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rootDir: jpype.protocol.SupportsPath, rootFS: LocalFileSystem):
        ...


class GFileSystem(java.io.Closeable, java.lang.Iterable[GFile], ghidra.util.classfinder.ExtensionPoint):
    """
    Interface that represents a filesystem that contains files.
     
    
    Operations take a :obj:`TaskMonitor` if they need to be cancel-able.
     
    
    Use a :obj:`FileSystemService instance <FileSystemService>` to discover and 
    open instances of filesystems in files or to open a known :obj:`FSRL` path or to
    deal with creating :meth:`temp files <FileSystemService.createTempFile>`.
     
    
    NOTE:
    
    ALL GFileSystem sub-CLASSES MUST END IN "FileSystem". If not, the ClassSearcher
    will not find them.
     
    
    Also note that this interface came after the original abstract class GFileSystem and its many
    implementations, and usage is being migrated to this interface where possible and as
    time permits.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def files(self) -> java.lang.Iterable[GFile]:
        """
        Gets an :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        
        :return: An :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        :rtype: java.lang.Iterable[GFile]
        """

    @typing.overload
    def files(self, dir: GFile) -> java.lang.Iterable[GFile]:
        """
        Gets an :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        
        :param GFile dir: The :obj:`directory <GFile>` to start iterating at in this :obj:`GFileSystem`. If
        ``null``, iteration will start at the root of the :obj:`GFileSystem`.
        :raises UncheckedIOException: if ``dir`` is not a directory
        :return: An :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        :rtype: java.lang.Iterable[GFile]
        """

    @typing.overload
    def files(self, fileFilter: java.util.function.Predicate[GFile]) -> java.lang.Iterable[GFile]:
        """
        Gets an :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        
        :param java.util.function.Predicate[GFile] fileFilter: A filter to apply to the :obj:`files <GFile>` iterated over
        :return: An :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        :rtype: java.lang.Iterable[GFile]
        """

    @typing.overload
    def files(self, dir: GFile, fileFilter: java.util.function.Predicate[GFile]) -> java.lang.Iterable[GFile]:
        """
        Gets an :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        
        :param GFile dir: The :obj:`directory <GFile>` to start iterating at in this :obj:`GFileSystem`. If
        ``null``, iteration will start at the root of the :obj:`GFileSystem`.
        :param java.util.function.Predicate[GFile] fileFilter: A filter to apply to the :obj:`files <GFile>` iterated over
        :raises UncheckedIOException: if ``dir`` is not a directory
        :return: An :obj:`Iterable` over this :obj:`GFileSystem`'s :obj:`files <GFile>`.
        :rtype: java.lang.Iterable[GFile]
        """

    def getByteProvider(self, file: GFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a :obj:`ByteProvider` that contains the contents of the specified :obj:`GFile`.
         
        
        The caller is responsible for closing the provider.
        
        :param GFile file: :obj:`GFile` to get bytes for
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update progress
        :return: new :obj:`ByteProvider` that contains the contents of the file, or NULL if file
        doesn't have data
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises IOException: if error
        :raises CancelledException: if user cancels
        """

    def getDescription(self) -> str:
        """
        Returns a description of this file system.
         
        
        This default implementation returns the description value in :obj:`FileSystemInfo`
        annotation.
        
        :return: description string
        :rtype: str
        """

    def getFSRL(self) -> FSRLRoot:
        """
        File system's FSRL
        
        :return: :obj:`FSRLRoot` of this filesystem.
        :rtype: FSRLRoot
        """

    def getFileAttributes(self, file: GFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes:
        """
        Returns a container of :obj:`FileAttribute` values.
         
        
        Implementors of this method are not required to add FSRL, NAME, or PATH values unless
        the values are non-standard.
        
        :param GFile file: :obj:`GFile` to get the attributes for
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`FileAttributes` instance (possibly read-only), maybe empty but never null
        :rtype: ghidra.formats.gfilesystem.fileinfo.FileAttributes
        """

    def getFileCount(self) -> int:
        """
        Returns the number of files in the filesystem, if known, otherwise -1 if not known.
        
        :return: number of files in this filesystem, -1 if not known.
        :rtype: int
        """

    def getInputStream(self, file: GFile, monitor: ghidra.util.task.TaskMonitor) -> java.io.InputStream:
        """
        Returns an :obj:`InputStream` that contains the contents of the specified :obj:`GFile`.
         
        
        The caller is responsible for closing the stream.
        
        :param GFile file: :obj:`GFile` to get an InputStream for
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update progress
        :return: new :obj:`InputStream` contains the contents of the file or NULL if the
        file doesn't have data.
        :rtype: java.io.InputStream
        :raises IOException: if IO problem
        :raises CancelledException: if user cancels.
        """

    @staticmethod
    def getInputStreamHelper(file: GFile, fs: GFileSystem, monitor: ghidra.util.task.TaskMonitor) -> java.io.InputStream:
        """
        Default implementation of getting an :obj:`InputStream` from a :obj:`GFile`'s
        :obj:`ByteProvider`.
        
        :param GFile file: :obj:`GFile`
        :param GFileSystem fs: the :obj:`filesystem <GFileSystem>` containing the file
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to allow canceling
        :return: new :obj:`InputStream` containing bytes of the file
        :rtype: java.io.InputStream
        :raises CancelledException: if canceled
        :raises IOException: if error
        """

    def getListing(self, directory: GFile) -> java.util.List[GFile]:
        """
        Returns a list of :obj:`files <GFile>` that reside in the specified directory on
        this filesystem.
        
        :param GFile directory: NULL means root of filesystem.
        :return: :obj:`List` of :obj:`GFile` instances of file in the requested directory.
        :rtype: java.util.List[GFile]
        :raises IOException: if IO problem.
        """

    def getName(self) -> str:
        """
        File system volume name.
         
        
        Typically the name of the container file, or a internally stored 'volume' name.
        
        :return: string filesystem volume name.
        :rtype: str
        """

    def getRefManager(self) -> FileSystemRefManager:
        """
        Returns the :obj:`ref manager <FileSystemRefManager>` that is responsible for
        creating and releasing :obj:`refs <FileSystemRef>` to this filesystem.
        
        :return: :obj:`FileSystemRefManager` that manages references to this filesystem.
        :rtype: FileSystemRefManager
        """

    def getRootDir(self) -> GFile:
        """
        Returns the file system's root directory.
         
        
        Note: using ``null`` when calling :meth:`getListing(GFile) <.getListing>` is also valid.
        
        :return: file system's root directory
        :rtype: GFile
        """

    def getType(self) -> str:
        """
        Returns the type of this file system.
         
        
        This default implementation returns the type value in :obj:`FileSystemInfo`
        annotation.
        
        :return: type string
        :rtype: str
        """

    def isClosed(self) -> bool:
        """
        Returns true if the filesystem has been :meth:`closed <.close>`
        
        :return: boolean true if the filesystem has been closed.
        :rtype: bool
        """

    def isStatic(self) -> bool:
        """
        Indicates if this filesystem is a static snapshot or changes.
        
        :return: boolean true if the filesystem is static or false if dynamic content.
        :rtype: bool
        """

    @typing.overload
    def lookup(self, path: typing.Union[java.lang.String, str]) -> GFile:
        """
        Retrieves a :obj:`GFile` from this filesystem based on its full path and filename, using
        this filesystem's default name comparison logic (eg. case sensitive vs insensitive).
        
        :param java.lang.String or str path: string path and filename of a file located in this filesystem.  Use 
        ``null`` or "/" to retrieve the root directory
        :return: :obj:`GFile` instance of requested file, null if not found.
        :rtype: GFile
        :raises IOException: if IO error when looking up file.
        """

    @typing.overload
    def lookup(self, path: typing.Union[java.lang.String, str], nameComp: java.util.Comparator[java.lang.String]) -> GFile:
        """
        Retrieves a :obj:`GFile` from this filesystem based on its full path and filename, using
        the specified name comparison logic (eg. case sensitive vs insensitive).
        
        :param java.lang.String or str path: string path and filename of a file located in this filesystem.  Use 
        ``null`` or "/" to retrieve the root directory
        :param java.util.Comparator[java.lang.String] nameComp: string comparator used to compare filenames.  Use ``null`` to specify
        the file system's native comparison logic.
        :return: :obj:`GFile` instance of requested file, null if not found.
        :rtype: GFile
        :raises IOException: if IO error when looking up file.
        """

    def resolveSymlinks(self, file: GFile) -> GFile:
        """
        Converts the specified (symlink) file into it's destination, or if not a symlink,
        returns the original file unchanged.
        
        :param GFile file: symlink file to follow
        :return: destination of symlink, or original file if not a symlink
        :rtype: GFile
        :raises IOException: if error following symlink path, typically outside of the hosting
        file system
        """

    @property
    def static(self) -> jpype.JBoolean:
        ...

    @property
    def refManager(self) -> FileSystemRefManager:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def fSRL(self) -> FSRLRoot:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def rootDir(self) -> GFile:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def type(self) -> java.lang.String:
        ...

    @property
    def listing(self) -> java.util.List[GFile]:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...


class GFileSystemIterator(java.util.Iterator[GFile]):
    """
    Iterates over the :obj:`GFile`s in a :obj:`GFileSystem` depth-first
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fs: GFileSystem):
        """
        Creates a new :obj:`GFileSystemIterator` at the root of the given :obj:`GFileSystem`
        
        :param GFileSystem fs: The :obj:`GFileSystem` to iterate over
        """

    @typing.overload
    def __init__(self, dir: GFile):
        """
        Creates a new :obj:`GFileSystemIterator` at the given :obj:`directory <GFile>`
        
        :param GFile dir: The :obj:`directory <GFile>` to start the iteration at
        :raises UncheckedIOException: if ``dir`` is not a directory
        """

    @typing.overload
    def __init__(self, dir: GFile, fileFilter: java.util.function.Predicate[GFile]):
        """
        Creates a new :obj:`GFileSystemIterator` at the given :obj:`directory <GFile>`
        
        :param GFile dir: The :obj:`directory <GFile>` to start the iteration at
        :param java.util.function.Predicate[GFile] fileFilter: A filter to apply to the :obj:`files <GFile>` iterated over
        :raises UncheckedIOException: if ``dir`` is not a directory
        """


class RefdByteProvider(ghidra.app.util.bin.ByteProvider):
    """
    A :obj:`ByteProvider` along with a :obj:`FileSystemRef` to keep the filesystem pinned
    in memory.
     
    
    The caller is responsible for :meth:`closing <.close>` this object, which releases
    the FilesystemRef.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fsRef: FileSystemRef, provider: ghidra.app.util.bin.ByteProvider, fsrl: FSRL):
        """
        Creates a RefdByteProvider instance, taking ownership of the supplied FileSystemRef.
        
        :param FileSystemRef fsRef: :obj:`FileSystemRef` that contains the specified ByteProvider
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider` inside the filesystem held open by the ref
        :param FSRL fsrl: :obj:`FSRL` identity of this new ByteProvider
        """


class GFile(java.lang.Object):
    """
    Represents a file in a :obj:`filesystem <GFileSystem>`.
     
    
    Only valid while the :meth:`owning filesystem <.getFilesystem>` object is still open and not
    :meth:`closed <GFileSystem.close>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFSRL(self) -> FSRL:
        """
        The :obj:`FSRL` of this file.
        
        :return: :obj:`FSRL` of this file.
        :rtype: FSRL
        """

    def getFilesystem(self) -> GFileSystem:
        """
        The :obj:`GFileSystem` that owns this file.
        
        :return: :obj:`GFileSystem` that owns this file.
        :rtype: GFileSystem
        """

    def getLength(self) -> int:
        """
        Returns the length of this file, or -1 if not known.
        
        :return: number of bytes in this file.
        :rtype: int
        """

    def getListing(self) -> java.util.List[GFile]:
        """
        Returns a listing of files in this sub-directory.
        
        :return: :obj:`List` of :obj:`GFile` instances.
        :rtype: java.util.List[GFile]
        :raises IOException: if not a directory or error when accessing files.
        """

    def getName(self) -> str:
        """
        The name of this file.
        
        :return: name of this file.
        :rtype: str
        """

    def getParentFile(self) -> GFile:
        """
        The parent directory of this file.
        
        :return: parent :obj:`GFile` directory of this file.
        :rtype: GFile
        """

    def getPath(self) -> str:
        """
        The path and filename of this file, relative to its owning filesystem.
        
        :return: path and filename of this file, relative to its owning filesystem.
        :rtype: str
        """

    def isDirectory(self) -> bool:
        """
        Returns true if this is a directory.
        
        :return: boolean true if this file is a directory, false otherwise.
        :rtype: bool
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def parentFile(self) -> GFile:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def fSRL(self) -> FSRL:
        ...

    @property
    def listing(self) -> java.util.List[GFile]:
        ...

    @property
    def directory(self) -> jpype.JBoolean:
        ...

    @property
    def filesystem(self) -> GFileSystem:
        ...


class GFileSystemBase(GFileSystem):
    """
    This is the original GFileSystem implementation abstract base class, with most of the
    initially implemented filesystem types extending this class.
     
    
    The new GFileSystem interface is being retro-fitted into this equation to support
    better probing and factory syntax, and new implementations should be based on
    the interface instead of extending this abstract class.
     
    
    NOTE:
    ALL GFileSystem sub-CLASSES MUST END IN "FileSystem".
    If not, the ClassSearcher will not find them.
    Yes, it is an implementation detail.
     
    
    GFileSystemBase instances are constructed when probing a container file and are queried
    with :meth:`isValid(TaskMonitor) <.isValid>` to determine if the container file is handled
    by the GFileSystemBase subclass.
    
    The :obj:`ByteProvider` given to the constructor is not considered 'owned' by
    the GFileSystemBase instance until after it passes the :meth:`isValid <.isValid>`
    check and is :meth:`opened <.open>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def close(self):
        """
        Closes the file system.
        All resources should be released. (programs, temporary files, etc.)
        
        :raises IOException: if an I/O error occurs
        """

    def getName(self) -> str:
        """
        Returns the name of this file system.
        
        :return: the name of this file system
        :rtype: str
        """

    def isValid(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if this file system implementation
        can handle the bytes provided.
        This method should perform the minimal amount of
        checks required to determine validity.
        Keep it quick and tight!
        
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :return: true if valid for the byte provider
        :rtype: bool
        :raises IOException: if an I/O error occurs
        """

    def open(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Opens the file system.
        
        :raises IOException: if an I/O error occurs
        :raises CryptoException: if an encryption error occurs
        """

    def setFSRL(self, fsrl: FSRLRoot):
        ...

    def setFilesystemService(self, fsService: FileSystemService):
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class LocalFileSystem(GFileSystem, GFileHashProvider):
    """
    A :obj:`GFileSystem` implementation giving access to the user's operating system's
    local file system.
     
    
    This implementation does not have a :obj:`GFileSystemFactory` as
    this class will be used as the single root filesystem.
     
    
    Closing() this filesystem does nothing.
    """

    @typing.type_check_only
    class FileFingerprintRec(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def length(self) -> int:
            ...

        def path(self) -> str:
            ...

        def timestamp(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    FSTYPE: typing.Final = "file"

    def getFileAttributes(self, f: jpype.protocol.SupportsPath) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes:
        """
        Create a :obj:`FileAttributes` container with info about the specified local file.
        
        :param jpype.protocol.SupportsPath f: :obj:`File` to query
        :return: :obj:`FileAttributes` instance
        :rtype: ghidra.formats.gfilesystem.fileinfo.FileAttributes
        """

    def getLocalFSRL(self, f: jpype.protocol.SupportsPath) -> FSRL:
        """
        Converts a :obj:`File` into a :obj:`FSRL`.
         
        
        NOTE: The given :obj:`File`'s absolute path will be used.
        
        :param jpype.protocol.SupportsPath f: The :obj:`File` to convert to an :obj:`FSRL`
        :return: The :obj:`FSRL`
        :rtype: FSRL
        """

    def getLocalFile(self, fsrl: FSRL) -> java.io.File:
        """
        Convert a FSRL that points to this file system into a java :obj:`File`.
        
        :param FSRL fsrl: :obj:`FSRL`
        :return: :obj:`File`
        :rtype: java.io.File
        :raises IOException: if FSRL does not point to this file system
        """

    def getSubFileSystem(self, fsrl: FSRL) -> LocalFileSystemSub:
        """
        Creates a new file system instance that is a sub-view limited to the specified directory.
        
        :param FSRL fsrl: :obj:`FSRL` that must be a directory in this local filesystem
        :return: new :obj:`LocalFileSystemSub` instance
        :rtype: LocalFileSystemSub
        :raises IOException: if bad FSRL
        """

    def isLocalSubdir(self, fsrl: FSRL) -> bool:
        """
        Returns true if the :obj:`FSRL` is a local filesystem subdirectory.
        
        :param FSRL fsrl: :obj:`FSRL` to test.
        :return: boolean true if local filesystem directory.
        :rtype: bool
        """

    @staticmethod
    def lookupFile(baseDir: jpype.protocol.SupportsPath, path: typing.Union[java.lang.String, str], nameComp: java.util.Comparator[java.lang.String]) -> java.io.File:
        """
        Looks up a file, by its string path, using a custom comparator.
         
        
        If any element of the path, or the filename are not found, returns a null.
         
        
        A null custom comparator avoids testing each element of the directory path and instead
        relies on the native local file system's name matching.
        
        :param jpype.protocol.SupportsPath baseDir: optional directory to start lookup at
        :param java.lang.String or str path: String path
        :param java.util.Comparator[java.lang.String] nameComp: optional :obj:`Comparator` that will compare filenames, or ``null`` 
        to use native local file system lookup (eg. case-insensitive on windows)
        :return: File that points to the requested path, or null if file was not present on the
        local filesystem (because it doesn't exist, or the name comparison function rejected it)
        :rtype: java.io.File
        """

    @staticmethod
    def makeGlobalRootFS() -> LocalFileSystem:
        """
        Create a new instance
        
        :return: new :obj:`LocalFileSystem` instance using :obj:`.FSTYPE` as its FSRL type.
        :rtype: LocalFileSystem
        """

    @property
    def localFSRL(self) -> FSRL:
        ...

    @property
    def localFile(self) -> java.io.File:
        ...

    @property
    def fileAttributes(self) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes:
        ...

    @property
    def localSubdir(self) -> jpype.JBoolean:
        ...

    @property
    def subFileSystem(self) -> LocalFileSystemSub:
        ...


class FileSystemRefManager(java.lang.Object):
    """
    A threadsafe helper class that manages creating and releasing :obj:`FileSystemRef` instances
    and broadcasting events to :obj:`FileSystemEventListener` listeners.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fs: GFileSystem):
        """
        Creates a new :obj:`FileSystemRefManager` pointing at the specified :obj:`GFileSystem`.
        
        :param GFileSystem fs: :obj:`GFileSystem` to manage.
        """

    def addListener(self, listener: FileSystemEventListener):
        """
        Adds a :obj:`listener <FileSystemEventListener>` that will be called when
        this filesystem is :meth:`closed <FileSystemEventListener.onFilesystemClose>`
        or when :meth:`refs change <FileSystemEventListener.onFilesystemRefChange>`.
        
        :param FileSystemEventListener listener: :obj:`FileSystemEventListener` to receive callbacks, weakly refd and
        automagically removed if a reference isn't held to the listener somewhere else.
        """

    def canClose(self, callersRef: FileSystemRef) -> bool:
        """
        Returns true if the only :obj:`FileSystemRef` pinning this filesystem is the
        caller's ref.
        
        :param FileSystemRef callersRef: :obj:`FileSystemRef` to test
        :return: boolean true if the tested :obj:`FileSystemRef` is the only ref pinning
        the filesystem.
        :rtype: bool
        """

    def create(self) -> FileSystemRef:
        """
        Creates a new :obj:`FileSystemRef` that points at the owning :obj:`filesystem <GFileSystem>`.
        
        :return: new :obj:`FileSystemRef` pointing at the filesystem, never null.
        :rtype: FileSystemRef
        """

    def getLastUsedTimestamp(self) -> int:
        ...

    def onClose(self):
        """
        Called from the :meth:`GFileSystem.close() <GFileSystem.close>` before any destructive changes have
        been made to gracefully shutdown the ref manager.
         
        
        Broadcasts :meth:`FileSystemEventListener.onFilesystemClose(GFileSystem) <FileSystemEventListener.onFilesystemClose>`.
        """

    def release(self, ref: FileSystemRef):
        """
        Releases an existing :obj:`FileSystemRef` and broadcasts
        :meth:`FileSystemEventListener.onFilesystemRefChange(GFileSystem, FileSystemRefManager) <FileSystemEventListener.onFilesystemRefChange>`
        to listeners.
        
        :param FileSystemRef ref: the :obj:`FileSystemRef` to release.
        """

    def removeListener(self, listener: FileSystemEventListener):
        """
        Removes a previously added :obj:`listener <FileSystemEventListener>`.
        
        :param FileSystemEventListener listener: :obj:`FileSystemEventListener` to remove.
        """

    @property
    def lastUsedTimestamp(self) -> jpype.JLong:
        ...


class FSUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SEPARATOR_CHARS: typing.Final = "/\\:"
    SEPARATOR: typing.Final = "/"
    GFILE_NAME_TYPE_COMPARATOR: typing.Final[java.util.Comparator[GFile]]
    """
    Sorts GFiles by type (directories segregated from files) and then by name,
    case-insensitive.
    """


    def __init__(self):
        ...

    @staticmethod
    def appendPath(*paths: typing.Union[java.lang.String, str]) -> str:
        """
        Concats path strings together, taking care to ensure that there is a correct
        path separator character between each part.
         
        
        Handles forward or back slashes as path separator characters in the input, but
        only adds forward slashes when separating the path strings that need a separator.
        
        :param jpype.JArray[java.lang.String] paths: vararg list of path strings, empty or null elements are ok and are skipped.
        :return: null if all params null, "" empty string if all are empty, or
        "path_element[1]/path_element[2]/.../path_element[N]" otherwise.
        :rtype: str
        """

    @staticmethod
    def copyByteProviderToFile(provider: ghidra.app.util.bin.ByteProvider, destFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Copy the contents of a :obj:`ByteProvider` to a file.
        
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider` source of bytes
        :param jpype.protocol.SupportsPath destFile: :obj:`File` destination file
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to update
        :return: number of bytes copied
        :rtype: int
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    @staticmethod
    def displayException(originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], throwable: java.lang.Throwable):
        """
        Displays a filesystem related :obj:`exception <Throwable>` in the most user-friendly manner
        possible, even if we have to do some hacky things with helping the user with
        crypto problems.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.awt.Component parent: a parent component used to center the dialog (or null if you
                    don't have one)
        :param java.lang.String or str title: the title of the pop-up dialog (main subject of message)
        :param java.lang.String or str message: the details of the message
        :param java.lang.Throwable throwable: the Throwable that describes the cause of the error
        """

    @staticmethod
    def escapeDecode(s: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a decoded version of the input stream where "%nn" escape sequences are
        replaced with their actual characters, using UTF-8 decoding rules.
        
        :param java.lang.String or str s: string with escape sequences in the form "%nn", or null.
        :return: string with all escape sequences replaced with native characters, or null if
        original parameter was null.
        :rtype: str
        :raises MalformedURLException: if bad escape sequence format.
        """

    @staticmethod
    def escapeEncode(s: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a copy of the input string with FSRL problematic[1] characters escaped
        as "%nn" sequences, where nn are hexdigits specifying the numeric ascii value
        of that character.
         
        
        Characters that need more than a byte to encode will result in multiple "%nn" values
        that encode the necessary UTF8 codepoints.
         
        
        [1] - non-ascii / unprintable / FSRL portion separation characters.
        
        :param java.lang.String or str s: string, or null.
        :return: string with problematic characters escaped as "%nn" sequences, or null
        if parameter was null.
        :rtype: str
        """

    @staticmethod
    def formatFSTimestamp(d: java.util.Date) -> str:
        """
        Common / unified date formatting for all file system information strings.
        
        :param java.util.Date d: :obj:`Date` to format, or null
        :return: formatted date string, or "NA" if date was null
        :rtype: str
        """

    @staticmethod
    def formatSize(length: typing.Union[java.lang.Long, int]) -> str:
        """
        Common / unified size formatting for all file system information strings.
        
        :param java.lang.Long or int length: :obj:`Long` length, null ok
        :return: pretty'ish length format string, or "NA" if length was null
        :rtype: str
        """

    @staticmethod
    def getExtension(path: typing.Union[java.lang.String, str], extLevel: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the "extension" of the filename part of the path string.
         
        
        Ie. everything after the nth last '.' char in the filename, including that '.' character.
         
        
        Using: "path/filename.ext1.ext2"
         
        
        Gives:
         
        * extLevel 1: ".ext2"
        * extLevel 2: ".ext1.ext2"
        * extLevel 3: null
        
        
        :param java.lang.String or str path: path/filename.ext string
        :param jpype.JInt or int extLevel: number of ext levels; must be greater than 0
        :return: ".ext1" for "path/filename.notext.ext1" level 1, ".ext1.ext2" for
                "path/filename.ext1.ext2" level 2, etc. or null if there was no dot character
        :rtype: str
        :raises IllegalArgumentException: if the given level is less than 1
        """

    @staticmethod
    def getFileMD5(f: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> str:
        """
        Calculate the MD5 of a file.
        
        :param jpype.protocol.SupportsPath f: :obj:`File` to read.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch for cancel
        :return: md5 as a hex encoded string, never null.
        :rtype: str
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    @staticmethod
    def getFileType(f: jpype.protocol.SupportsPath) -> ghidra.formats.gfilesystem.fileinfo.FileType:
        ...

    @staticmethod
    def getFilesystemDescriptionFromClass(clazz: java.lang.Class[typing.Any]) -> str:
        """
        Returns the description value of the :obj:`FileSystemInfo` annotation attached to the
        specified class.
        
        :param java.lang.Class[typing.Any] clazz: Class to query.
        :return: File system description string.
        :rtype: str
        """

    @staticmethod
    def getFilesystemPriorityFromClass(clazz: java.lang.Class[typing.Any]) -> int:
        """
        Returns the priority value of the :obj:`FileSystemInfo` annotation attached to the
        specified class.
        
        :param java.lang.Class[typing.Any] clazz: Class to query.
        :return: File system priority integer.
        :rtype: int
        """

    @staticmethod
    def getFilesystemTypeFromClass(clazz: java.lang.Class[typing.Any]) -> str:
        """
        Returns the type value of the :obj:`FileSystemInfo` annotation attached to the
        specified class.
        
        :param java.lang.Class[typing.Any] clazz: Class to query.
        :return: File system type string.
        :rtype: str
        """

    @staticmethod
    def getLines(byteProvider: ghidra.app.util.bin.ByteProvider) -> java.util.List[java.lang.String]:
        """
        Returns the text lines in the specified ByteProvider.
         
        
        See :meth:`FileUtilities.getLines(InputStream) <FileUtilities.getLines>`
        
        :param ghidra.app.util.bin.ByteProvider byteProvider: :obj:`ByteProvider` to read
        :return: list of text lines
        :rtype: java.util.List[java.lang.String]
        :raises IOException: if error
        """

    @staticmethod
    @typing.overload
    def getMD5(provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor) -> str:
        """
        Calculate the MD5 of a file.
        
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch for cancel
        :return: md5 as a hex encoded string, never null.
        :rtype: str
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    @staticmethod
    @typing.overload
    def getMD5(is_: java.io.InputStream, name: typing.Union[java.lang.String, str], expectedLength: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor) -> str:
        """
        Calculate the hash of an :obj:`InputStream`.
        
        :param java.io.InputStream is: :obj:`InputStream`
        :param java.lang.String or str name: of the inputstream
        :param jpype.JLong or int expectedLength: the length of the inputstream
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to update
        :return: md5 as a hex encoded string, never null
        :rtype: str
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    @staticmethod
    def getSafeFilename(untrustedFilename: typing.Union[java.lang.String, str]) -> str:
        """
        Best-effort of sanitizing an untrusted string that will be used to create
        a file on the user's local filesystem.
        
        :param java.lang.String or str untrustedFilename: filename string with possibly bad / hostile characters or sequences.
        :return: sanitized filename
        :rtype: str
        """

    @staticmethod
    def infoMapToString(info: collections.abc.Mapping) -> str:
        """
        Converts a string-to-string mapping into a "key: value\n" multi-line string.
        
        :param collections.abc.Mapping info: map of string key to string value.
        :return: Multi-line string "key: value" string.
        :rtype: str
        """

    @staticmethod
    def isSameFS(fsrls: java.util.List[FSRL]) -> bool:
        """
        Returns true if all the :obj:`FSRL`s in the specified list are from the filesystem.
        
        :param java.util.List[FSRL] fsrls: :obj:`List` of :obj:`FSRL`s.
        :return: boolean true if all are from same filesystem.
        :rtype: bool
        """

    @staticmethod
    def isSymlink(f: jpype.protocol.SupportsPath) -> bool:
        ...

    @staticmethod
    @deprecated("Use GFileSystem.files(GFile) instead")
    def listFileSystem(fs: GFileSystem, dir: GFile, result: java.util.List[GFile], taskMonitor: ghidra.util.task.TaskMonitor) -> java.util.List[GFile]:
        """
        Returns a list of all files in a GFileSystem.
        
        :param GFileSystem fs: :obj:`GFileSystem` to recursively query for all files.
        :param GFile dir: the :obj:`GFile` directory to recurse into
        :param java.util.List[GFile] result: :obj:`List` of GFiles where the results are accumulated into, or null
        to allocate a new List, returned as the result.
        :param ghidra.util.task.TaskMonitor taskMonitor: :obj:`TaskMonitor` that will be checked for cancel.
        :return: :obj:`List` of accumulated ``result``s
        :rtype: java.util.List[GFile]
        :raises IOException: if io error during listing of directories
        :raises CancelledException: if user cancels
        
        .. deprecated::
        
        Use :meth:`GFileSystem.files(GFile) <GFileSystem.files>` instead
        """

    @staticmethod
    def normalizeNativePath(path: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a copy of the string path that has been fixed to have correct slashes
        and a correct leading root slash '/'.
        
        :param java.lang.String or str path: String forward or backslash path
        :return: String path with all forward slashes and a leading root slash.
        :rtype: str
        """

    @staticmethod
    def readSymlink(f: jpype.protocol.SupportsPath) -> str:
        """
        Returns the destination of a symlink, or null if not a symlink or other error
        
        :param jpype.protocol.SupportsPath f: :obj:`File` that is a symlink
        :return: destination path string of the symlink, or null if not symlink
        :rtype: str
        """

    @staticmethod
    def streamCopy(is_: java.io.InputStream, os: java.io.OutputStream, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Copy a stream while updating a TaskMonitor.
        
        :param java.io.InputStream is: :obj:`InputStream` source of bytes
        :param java.io.OutputStream os: :obj:`OutputStream` destination of bytes
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to update
        :return: number of bytes copied
        :rtype: int
        :raises IOException: if error
        :raises CancelledException: if cancelled
        """

    @staticmethod
    def uncheckedClose(c: java.lang.AutoCloseable, msg: typing.Union[java.lang.String, str]):
        """
        Helper method to invoke close() on a AutoCloseable without having to catch
        an IOException.
        
        :param java.lang.AutoCloseable c: :obj:`AutoCloseable` to close
        :param java.lang.String or str msg: optional msg to log if exception is thrown, null is okay
        """


class FileSystemIndexHelper(java.lang.Object, typing.Generic[METADATATYPE]):
    """
    A helper class used by GFilesystem implementors to track mappings between GFile
    instances and the underlying container filesystem's native file objects.
     
    
    Threadsafe (methods are synchronized).
     
    
    This class also provides filename 'unique-ifying' (per directory) where an auto-incrementing
    number will be added to a file's filename if it is not unique in the directory.
    """

    @typing.type_check_only
    class FileData(java.lang.Object, typing.Generic[METADATATYPE]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fs: GFileSystem, fsFSRL: FSRLRoot):
        """
        Creates a new :obj:`FileSystemIndexHelper` for the specified :obj:`GFileSystem`.
         
        
        A "root" directory GFile will be auto-created for the filesystem.
        
        :param GFileSystem fs: the :obj:`GFileSystem` that this index will be for.
        :param FSRLRoot fsFSRL: the :obj:`fsrl <FSRLRoot>` of the filesystem itself.
        (this parameter is explicitly passed here so there is no possibility of trying to call
        back to the fs's :meth:`GFileSystem.getFSRL() <GFileSystem.getFSRL>` on a half-constructed filesystem.)
        """

    def clear(self):
        """
        Removes all file info from this index.
        """

    def getFileByIndex(self, fileIndex: typing.Union[jpype.JLong, int]) -> GFile:
        """
        Gets the GFile instance that was associated with the filesystem file index.
        
        :param jpype.JLong or int fileIndex: index of the file in its filesystem
        :return: the associated GFile instance, or null if not found
        :rtype: GFile
        """

    def getFileCount(self) -> int:
        """
        Number of files in this index.
        
        :return: number of file in this index
        :rtype: int
        """

    def getListing(self, directory: GFile) -> java.util.List[GFile]:
        """
        Mirrors :meth:`GFileSystem.getListing(GFile) <GFileSystem.getListing>` interface.
        
        :param GFile directory: :obj:`GFile` directory to get the list of child files that have been
        added to this index, null means root directory
        :return: :obj:`List` of GFile files that are in the specified directory, never null
        :rtype: java.util.List[GFile]
        """

    def getMetadata(self, f: GFile) -> METADATATYPE:
        """
        Gets the opaque filesystem specific blob that was associated with the specified file.
        
        :param GFile f: :obj:`GFile` to look for
        :return: Filesystem specific blob associated with the specified file, or null if not found
        :rtype: METADATATYPE
        """

    def getRootDir(self) -> GFile:
        """
        Gets the root :obj:`GFile` object for this filesystem index.
        
        :return: root :obj:`GFile` object.
        :rtype: GFile
        """

    @typing.overload
    def lookup(self, path: typing.Union[java.lang.String, str]) -> GFile:
        """
        Mirrors :meth:`GFileSystem.lookup(String) <GFileSystem.lookup>` interface.
        
        :param java.lang.String or str path: path and filename of a file to find
        :return: :obj:`GFile` instance or null if no file was added to the index at that path
        :rtype: GFile
        """

    @typing.overload
    def lookup(self, baseDir: GFile, path: typing.Union[java.lang.String, str], nameComp: java.util.Comparator[java.lang.String]) -> GFile:
        """
        Mirrors :meth:`GFileSystem.lookup(String) <GFileSystem.lookup>` interface, with additional parameters to
        control the lookup.
        
        :param GFile baseDir: optional starting directory to perform lookup
        :param java.lang.String or str path: path and filename of a file to find
        :param java.util.Comparator[java.lang.String] nameComp: optional :obj:`Comparator` that compares file names.  Suggested values are 
        ``String::compareTo`` or ``String::compareToIgnoreCase`` or ``null`` (also exact).
        :return: :obj:`GFile` instance or null if no file was added to the index at that path
        :rtype: GFile
        """

    def resolveSymlinks(self, file: GFile) -> GFile:
        """
        If supplied file is a symlink, converts the supplied file into the targeted file, otherwise
        just returns the original file.
        
        :param GFile file: :obj:`GFile` to convert
        :return: symlink targeted :obj:`GFile`, or original file it not a symlink, or null if
        symlink path was invalid or reached outside the bounds of this file system
        :rtype: GFile
        :raises IOException: if symlinks are nested too deeply
        """

    def setMetadata(self, f: GFile, metaData: METADATATYPE):
        """
        Sets the associated metadata blob for the specified file.
        
        :param GFile f: GFile to update
        :param METADATATYPE metaData: new metadata blob
        :raises IOException: if unknown file
        """

    def storeFile(self, path: typing.Union[java.lang.String, str], fileIndex: typing.Union[jpype.JLong, int], isDirectory: typing.Union[jpype.JBoolean, bool], length: typing.Union[jpype.JLong, int], metadata: METADATATYPE) -> GFile:
        """
        Creates and stores a file entry into in-memory indexes.
         
        
        The string path will be normalized to forward slashes before being split into
        directory components.
         
        
        Filenames that are not unique in their directory will have a "[nnn]"
        suffix added to the resultant GFile name, where nnn is the file's
        order of occurrence in the container file.
        
        :param java.lang.String or str path: string path and filename of the file being added to the index.  Back
        slashes are normalized to forward slashes
        :param jpype.JLong or int fileIndex: the filesystem specific unique index for this file, or -1
        if not available
        :param jpype.JBoolean or bool isDirectory: boolean true if the new file is a directory
        :param jpype.JLong or int length: number of bytes in the file or -1 if not known or directory
        :param METADATATYPE metadata: opaque blob that will be stored and associated with the new
        GFile instance
        :return: new GFile instance
        :rtype: GFile
        """

    def storeFileWithParent(self, filename: typing.Union[java.lang.String, str], parent: GFile, fileIndex: typing.Union[jpype.JLong, int], isDirectory: typing.Union[jpype.JBoolean, bool], length: typing.Union[jpype.JLong, int], metadata: METADATATYPE) -> GFile:
        """
        Creates and stores a file entry into in-memory indexes.
         
        
        Use this when you already know the parent directory GFile object.
         
        
        Filenames that are not unique in their directory will have a "[nnn]"
        suffix added to the resultant GFile name, where nnn is the file's
        order of occurrence in the container file.
        
        :param java.lang.String or str filename: the new file's name
        :param GFile parent: the new file's parent directory
        :param jpype.JLong or int fileIndex: the filesystem specific unique index for this file, or -1
        if not available
        :param jpype.JBoolean or bool isDirectory: boolean true if the new file is a directory
        :param jpype.JLong or int length: number of bytes in the file or -1 if not known or directory
        :param METADATATYPE metadata: opaque blob that will be stored and associated with the new
        GFile instance
        :return: new GFile instance
        :rtype: GFile
        """

    def storeSymlink(self, path: typing.Union[java.lang.String, str], fileIndex: typing.Union[jpype.JLong, int], symlinkPath: typing.Union[java.lang.String, str], length: typing.Union[jpype.JLong, int], metadata: METADATATYPE) -> GFile:
        """
        Creates and stores a file entry that is a symlink into in-memory indexes.
         
        
        The string path will be normalized to forward slashes before being split into
        directory components.
         
        
        Filenames that are not unique in their directory will have a "[nnn]"
        suffix added to the resultant GFile name, where nnn is the file's
        order of occurrence in the container file.
        
        :param java.lang.String or str path: string path and filename of the file being added to the index.  Back
        slashes are normalized to forward slashes
        :param jpype.JLong or int fileIndex: the filesystem specific unique index for this file, or -1
        if not available
        :param java.lang.String or str symlinkPath: destination of the symlink
        :param jpype.JLong or int length: number of bytes in the file or -1 if not known or directory
        :param METADATATYPE metadata: opaque blob that will be stored and associated with the new
        GFile instance
        :return: new GFile instance
        :rtype: GFile
        """

    def storeSymlinkWithParent(self, filename: typing.Union[java.lang.String, str], parent: GFile, fileIndex: typing.Union[jpype.JLong, int], symlinkPath: typing.Union[java.lang.String, str], length: typing.Union[jpype.JLong, int], metadata: METADATATYPE) -> GFile:
        """
        Creates and stores a file entry that is a symlink into in-memory indexes.
         
        
        Use this when you already know the parent directory GFile object.
         
        
        Filenames that are not unique in their directory will have a "[nnn]"
        suffix added to the resultant GFile name, where nnn is the file's
        order of occurrence in the container file.
        
        :param java.lang.String or str filename: the new file's name
        :param GFile parent: the new file's parent directory
        :param jpype.JLong or int fileIndex: the filesystem specific unique index for this file, or -1
        if not available
        :param java.lang.String or str symlinkPath: destination of the symlink
        :param jpype.JLong or int length: number of bytes in the file or -1 if not known or directory
        :param METADATATYPE metadata: opaque blob that will be stored and associated with the new
        GFile instance
        :return: new GFile instance
        :rtype: GFile
        """

    def updateFSRL(self, file: GFile, newFSRL: FSRL):
        """
        Updates the FSRL of a file already in the index.
        
        :param GFile file: current :obj:`GFile`
        :param FSRL newFSRL: the new FSRL the new file will be given
        """

    @property
    def metadata(self) -> METADATATYPE:
        ...

    @property
    def rootDir(self) -> GFile:
        ...

    @property
    def listing(self) -> java.util.List[GFile]:
        ...

    @property
    def fileCount(self) -> jpype.JInt:
        ...

    @property
    def fileByIndex(self) -> GFile:
        ...


class FileCache(java.lang.Object):
    """
    File caching implementation.
     
    
    Caches files based on a hash of the contents of the file.
    
    Files are retrieved using the hash string.
    
    Cached files are stored in a file with a name that is the hex encoded value of the hash.
    
    Cached files are obfuscated/de-obfuscated when written/read to/from disk.  See 
    :obj:`ObfuscatedFileByteProvider`, :obj:`ObfuscatedInputStream`, 
    :obj:`ObfuscatedOutputStream`.
    
    Cached files are organized into a nested directory structure to prevent
    overwhelming a single directory with thousands of files.
     
    
    Nested directory structure is based on the file's name:
    
        File: AABBCCDDEEFF... → AA/AABBCCDDEEFF...
     
    
    Cache size is not bounded.
     
    
    Cache maintenance is done during startup if interval since last maintenance has been exceeded.
     
    
    Files are not removed from the cache after being added, except during startup maintenance.
    """

    @typing.type_check_only
    class FileCacheMaintenanceDaemon(java.lang.Thread):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefPinningByteArrayProvider(ghidra.app.util.bin.ByteArrayProvider):
        """
        Helper class, keeps a FileCacheEntry pinned while the ByteProvider is alive.  When
        the ByteProvider is closed, the FileCacheEntry is allowed to be garbage collected
        if there is enough memory pressure to also remove its entry from the :obj:`FileCache.memCache`
        map.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, fce: FileCache.FileCacheEntry, fsrl: FSRL):
            ...


    class FileCacheEntryBuilder(java.io.OutputStream):
        """
        Allows creating :obj:`file cache entries <FileCacheEntry>` at the caller's convenience.
        """

        class_: typing.ClassVar[java.lang.Class]

        def finish(self) -> FileCache.FileCacheEntry:
            """
            Finalizes this builder, pushing the bytes that have been written to it into
            the FileCache.
            
            :return: new :obj:`FileCacheEntry`
            :rtype: FileCache.FileCacheEntry
            :raises IOException: if error
            """


    class FileCacheEntry(java.lang.Object):
        """
        Represents a cached file.  It may be an actual file if :obj:`file <FileCacheEntry.file>`
        is set, or if smaller than :obj:`2Mb'ish <FileCache.MAX_INMEM_FILESIZE>` just an 
        in-memory byte array that is weakly pinned in the :obj:`FileCache.memCache` map.
        """

        class_: typing.ClassVar[java.lang.Class]

        def asByteProvider(self, fsrl: FSRL) -> ghidra.app.util.bin.ByteProvider:
            """
            Returns the contents of this cache entry as a :obj:`ByteProvider`, using the specified
            :obj:`FSRL`.
            
            :param FSRL fsrl: :obj:`FSRL` that the returned :obj:`ByteProvider` should have as its
            identity
            :return: new :obj:`ByteProvider` containing the contents of this cache entry, caller is
            responsible for :meth:`closing <ByteProvider.close>`
            :rtype: ghidra.app.util.bin.ByteProvider
            :raises IOException: if error
            """

        def getMD5(self) -> str:
            """
            Returns the MD5 of this cache entry.
            
            :return: the MD5 (as a string) of this cache entry
            :rtype: str
            """

        def length(self) -> int:
            ...

        @property
        def mD5(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    MAX_INMEM_FILESIZE: typing.Final = 2097152
    """
    Max size of a file that will be kept in :obj:`.memCache` (2Mb)
    """

    MD5_HEXSTR_LEN: typing.Final = 32

    def __init__(self, cacheDir: jpype.protocol.SupportsPath):
        """
        Creates a new :obj:`FileCache` instance where files are stored under the specified
        ``cacheDir``
        
        :param jpype.protocol.SupportsPath cacheDir: where to store the files
        :raises IOException: if there was a problem creating subdirectories under cacheDir or
        when pruning expired files.
        """

    @staticmethod
    @deprecated("Marked as deprecated to ensure this is removed in a few versions after most\n user\'s old-style cache dirs have been cleaned up.")
    def performCacheMaintOnOldDirIfNeeded(oldCacheDir: jpype.protocol.SupportsPath):
        """
        Backwards compatible with previous cache directories to age off the files located
        therein.
        
        :param jpype.protocol.SupportsPath oldCacheDir: the old 2-level cache directory
        
        .. deprecated::
        
        Marked as deprecated to ensure this is removed in a few versions after most
        user's old-style cache dirs have been cleaned up.
        """

    def purge(self):
        """
        Deletes all stored files from this file cache that are under a "NN" two hex digit
        nesting dir.
         
        
        Will cause other processes which are accessing or updating the cache to error.
        """


class GIconProvider(java.lang.Object):
    """
    :obj:`GFileSystem` add-on interface to allow filesystems to override how image files
    are converted into viewable :obj:`Icon` instances.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIcon(self, file: GFile, monitor: ghidra.util.task.TaskMonitor) -> javax.swing.Icon:
        """
        A method that :obj:`file systems <GFileSystem>` can implement if they need to preprocess
        image files so that Ghidra can display them.
        
        :param GFile file: :obj:`GFile` to read and convert into an Icon.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update with progress.
        :return: new :obj:`Icon` instance with contents of the GFile.
        :rtype: javax.swing.Icon
        :raises IOException: if problem reading or converting image.
        :raises CancelledException: if user cancels.
        """

    @staticmethod
    def getIconForFile(file: GFile, monitor: ghidra.util.task.TaskMonitor) -> javax.swing.Icon:
        """
        Helper static method that will get an Icon from a data file.
        
        :param GFile file: :obj:`GFile` to read and convert into an Icon.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update with progress.
        :return: new :obj:`Icon` instance with contents of the GFile, or null if the
        file couldn't be converted into an image.
        :rtype: javax.swing.Icon
        :raises CancelledException: if the user cancels.
        """


class RefdInputStream(java.io.InputStream):
    """
    An :obj:`InputStream` wrapper that keeps a :obj:`FileSystemRef` pinned.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fsRef: FileSystemRef, delegate: java.io.InputStream):
        """
        Creates a new :obj:`RefdInputStream`.
        
        :param FileSystemRef fsRef: :obj:`FileSystemRef`
        :param java.io.InputStream delegate: the wrapped :obj:`InputStream`
        """


class FSRLRoot(FSRL):
    """
    A type of :obj:`FSRL` that is specific to the filesystem's identity.
    
    A FSRL's parent is always a FSRLRoot.
     
    
    A FSRLRoot's parent is always a FSRL (ie. the container the filesystem data is in), or null.
     
    
    Examples of relationship between FSRL and FSRLRoots:
     
    * FSRLRoot [ file:// ]
    "file://"
    * FSRLRoot [ file:// ]  <---- FSRL [ /filename.txt ]
    "file:///filename.txt"
    * FSRLRoot [ file:// ]  <---- FSRL [ /filename.txt ] <--- FSRLRoot [ subfs:// ]
    "file:///filename.txt|subfs://"
    """

    class_: typing.ClassVar[java.lang.Class]

    def getContainer(self) -> FSRL:
        """
        Returns the parent containerfile FSRL, or null if this FSRLRoot specifies
        a root-level filesystem.
        
        :return: :obj:`FSRL` of the container object that this filesystem is nested under.
        :rtype: FSRL
        """

    def getName(self) -> str:
        """
        Always returns null for a FSRLRoot.
        
        :return: null because this is a :obj:`FSRLRoot` instance which never has a path and
        therefore doesn't have a name part of a path.
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Always returns null for a FSRLRoot.
        
        :return: null because this is a :obj:`FSRLRoot` instance which never has paths.
        :rtype: str
        """

    def getProtocol(self) -> str:
        """
        Returns the "protocol" portion of this FSRLRoot, for example, in a FSRLRoot of
        "file://", this method would return "file".
        
        :return: string protocol / filesystem type.
        :rtype: str
        """

    def hasContainer(self) -> bool:
        """
        Returns true if there is a parent containerfile, or false if this FSRLRoot specifies
        a root-level filesystem.
        
        :return: boolean true if this :obj:`FSRLRoot` has a parent container, or false if not.
        :rtype: bool
        """

    @staticmethod
    def makeRoot(protocol: typing.Union[java.lang.String, str]) -> FSRLRoot:
        """
        Creates a :obj:`FSRLRoot` without a parent container, using the supplied
        ``protocol`` string as its type.
        
        :param java.lang.String or str protocol: string protocol name
        :return: new :obj:`FSRLRoot` instance.
        :rtype: FSRLRoot
        """

    @staticmethod
    @typing.overload
    def nestedFS(containerFile: FSRL, fstype: typing.Union[java.lang.String, str]) -> FSRLRoot:
        """
        Creates a :obj:`FSRLRoot` as a child of a container :obj:`FSRL`, using the supplied
        ``protocol`` string as its type.
        
        :param FSRL containerFile: :obj:`FSRL` of the container that contains this nested filesystem.
        :param java.lang.String or str fstype: the filesystem type.
        :return: new :obj:`FSRLRoot` instance with a parent pointing to the specified containerFile.
        :rtype: FSRLRoot
        """

    @staticmethod
    @typing.overload
    def nestedFS(containerFile: FSRL, copyFSRL: FSRLRoot) -> FSRLRoot:
        """
        Create a copy of ``copyFSRL``, but using a different ``containerFile`` parent.
         
        
        (ie. re-parents copyFSRL so its parent is containerFile)
        
        :param FSRL containerFile: :obj:`FSRL` of new parent
        :param FSRLRoot copyFSRL: :obj:`FSRLRoot` that will be copied and re-parented.
        :return: new :obj:`FSRLRoot`
        :rtype: FSRLRoot
        """

    def withPathMD5(self, newPath: typing.Union[java.lang.String, str], newMD5: typing.Union[java.lang.String, str]) -> FSRL:
        """
        Creates a new :obj:`FSRL` as a child of this :obj:`FSRLRoot`, using the supplied
        path and MD5 values.
        
        :param java.lang.String or str newPath: string path and filename of the object inside this filesystem, should
        not be null.
        :param java.lang.String or str newMD5: string md5 of the object inside this filesystem, null ok.
        :return: new :obj:`FSRL` instance which is a child of this :obj:`FSRLRoot`.
        :rtype: FSRL
        """

    @property
    def container(self) -> FSRL:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def protocol(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class GFileSystemProgramProvider(java.lang.Object):
    """
    :obj:`GFileSystem` add-on interface that allows a filesystem publish the fact that
    it supports an import feature allowing the caller to import binaries directly into
    Ghidra without going through a :obj:`Loader`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canProvideProgram(self, file: GFile) -> bool:
        """
        Returns true if this GFileSystem can convert the specified GFile instance into
        a Ghidra Program.
        
        :param GFile file: GFile file or directory instance.
        :return: boolean true if calls to :meth:`getProgram(GFile, LanguageService, TaskMonitor, Object) <.getProgram>`
        will be able to convert the file into a program.
        :rtype: bool
        """

    def getProgram(self, file: GFile, languageService: ghidra.program.model.lang.LanguageService, monitor: ghidra.util.task.TaskMonitor, consumer: java.lang.Object) -> ghidra.program.model.listing.Program:
        """
        NOTE: ONLY OVERRIDE THIS METHOD IF YOU CANNOT PROVIDE AN INPUT STREAM
        TO THE INTERNAL FILES OF THIS FILE SYSTEM!
         
        
        BE SURE TO REGISTER THE GIVEN CONSUMER ON THE PROGRAM.
         
        
        Returns a program for the given file.
         
        
        
        :param GFile file: the file to convert into a program
        :param ghidra.program.model.lang.LanguageService languageService: the language service for locating languages and compiler specifications
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :param java.lang.Object consumer: the consumer for the program to be returned
        :return: a program for the given file
        :rtype: ghidra.program.model.listing.Program
        :raises java.lang.Exception: if errors occur
        """


class AbstractFileSystem(GFileSystem, typing.Generic[METADATATYPE]):
    """
    Default implementation of base file system functionality.
    """

    class_: typing.ClassVar[java.lang.Class]


class FileSystemService(java.lang.Object):
    """
    Provides methods for dealing with GFilesystem files and :obj:`filesystems <GFileSystem>`.
     
    
    Most methods take :obj:`FSRL` references to files as a way to decouple dependencies and
    reduce forced filesystem instantiation.
     
    
    (ie. a :obj:`GFile` instance is only valid if its :obj:`GFileSystem` is open, which
    means that its parent probably also has to be open, recursively, etc, whereas a FSRL
    is always valid and does not force the instantiation of parent objects)
     
    
    :obj:`Filesystems <GFileSystem>` should be used via :obj:`filesystem ref <FileSystemRef>`
    handles that ensure the filesystem is pinned in memory and won't be closed while
    you are using it.
     
    
    If you are working with :obj:`GFile` instances, you should have a
    :obj:`fs ref <FileSystemRef>` that you are using to pin the filesystem.
     
    
    Files written to the ``fscache`` directory are obfuscated to prevent interference from
    virus scanners.  See :obj:`ObfuscatedInputStream` or :obj:`ObfuscatedOutputStream` or 
    :obj:`ObfuscatedFileByteProvider`.
     
     
    Thread-safe.
    """

    class DerivedStreamProducer(java.lang.Object):
        """
        Used by :meth:`getDerivedByteProvider() <FileSystemService.getDerivedByteProvider>`
        to produce a derivative stream from a source file.
         
        
        The :obj:`InputStream` returned from the method needs to supply the bytes of the derived file
        and will be closed by the caller.
         
        
        Example:
        fsService.getDerivedByteProvider(
            containerFSRL, 
            null,
            "the_derived_file",
            -1,
            () -> new MySpecialtyInputstream(),
            monitor);
         
        
        See :meth:`produceDerivedStream() <.produceDerivedStream>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def produceDerivedStream(self) -> java.io.InputStream:
            """
            Callback method intended to be implemented by the caller to
            :meth:`FileSystemService.getDerivedByteProvider(FSRL, FSRL, String, long, DerivedStreamProducer, TaskMonitor) <FileSystemService.getDerivedByteProvider>`
             
            
            The implementation needs to return an :obj:`InputStream` that contains the bytes
            of the derived file.
            
            :return: a new :obj:`InputStream` that will produce all the bytes of the derived file
            :rtype: java.io.InputStream
            :raises IOException: if there is a problem while producing the InputStream
            :raises CancelledException: if the user canceled
            """


    class DerivedStreamPushProducer(java.lang.Object):
        """
        Used by :meth:`getDerivedByteProviderPush() <FileSystemService.getDerivedByteProviderPush>`
        to produce a derivative stream from a source file.
         
        
        The implementation needs to write bytes to the supplied :obj:`OutputStream`.
         
        
        Example:
        fsService.getDerivedByteProviderPush(
            containerFSRL, 
            null,
            "the_derived_file",
            -1,
            os -> FileUtilities.copyStream(my_input_stream, os),
            monitor);
         
        
        See :meth:`push(OutputStream) <.push>`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def push(self, os: java.io.OutputStream):
            """
            Callback method intended to be implemented by the caller to
            :meth:`getDerivedByteProviderPush() <FileSystemService.getDerivedByteProviderPush>`
            
            :param java.io.OutputStream os: :obj:`OutputStream` that the implementor should write the bytes to.  Do
            not close the stream when done
            :raises IOException: if there is a problem while writing to the OutputStream
            :raises CancelledException: if the user canceled
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a FilesystemService instance, using the :obj:`Application`'s default value
        for :meth:`user cache directory <Application.getUserCacheDirectory>` as the
        cache directory.
        """

    @typing.overload
    def __init__(self, fscacheDir: jpype.protocol.SupportsPath):
        """
        Creates a FilesystemService instance, using the supplied directory as its file caching
        root directory.
        
        :param jpype.protocol.SupportsPath fscacheDir: :obj:`Root dir <File>` to use to store files placed into cache.
        """

    def clear(self):
        """
        Forcefully closes all open filesystems and clears caches.
        """

    def closeUnusedFileSystems(self):
        """
        Close unused filesystems.
        """

    def createPlaintextTempFile(self, provider: ghidra.app.util.bin.ByteProvider, filenamePrefix: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> java.io.File:
        """
        Exports the bytes in a :obj:`ByteProvider` into normal :obj:`File` that can be
        used as the caller wishes.
         
        
        This method is labeled as 'plaintext' to differentiate it from the standard obfuscated 
        temp files that are produced by this service.
        
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider` that will be written to a temp file
        :param java.lang.String or str filenamePrefix: filename prefix of the newly created File
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: temporary :obj:`File`
        :rtype: java.io.File
        :raises IOException: if error copying data or if cancelled
        """

    def createTempFile(self, sizeHint: typing.Union[jpype.JLong, int]) -> FileCache.FileCacheEntryBuilder:
        """
        Returns a :obj:`FileCacheEntryBuilder` that will allow the caller to
        write bytes to it.
         
        
        After calling :meth:`finish() <FileCacheEntryBuilder.finish>`,
        the caller will have a :obj:`FileCacheEntry` that can provide access to a
        :obj:`ByteProvider`.
         
        
        Temporary files that are written to disk are obfuscated to avoid interference from
        overzealous virus scanners.  See :obj:`ObfuscatedInputStream` / 
        :obj:`ObfuscatedOutputStream`.
        
        :param jpype.JLong or int sizeHint: the expected size of the file, or -1 if unknown
        :return: :obj:`FileCacheEntryBuilder` that must be finalized by calling 
        :meth:`finish() <FileCacheEntryBuilder.finish>`
        :rtype: FileCache.FileCacheEntryBuilder
        :raises IOException: if error
        """

    def getAllFilesystemNames(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of all detected GFilesystem filesystem names.
         
        
        See :meth:`FileSystemFactoryMgr.getAllFilesystemNames() <FileSystemFactoryMgr.getAllFilesystemNames>`.
        
        :return: :obj:`List` of strings.
        :rtype: java.util.List[java.lang.String]
        """

    def getByteProvider(self, fsrl: FSRL, fullyQualifiedFSRL: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a :obj:`ByteProvider` with the contents of the requested :obj:`file <GFile>`.
         
        
        Never returns null, throws IOException if there was a problem.
         
        
        Caller is responsible for :meth:`closing() <ByteProvider.close>` the ByteProvider
        when finished.
        
        :param FSRL fsrl: :obj:`FSRL` file to wrap
        :param jpype.JBoolean or bool fullyQualifiedFSRL: if true, the returned ByteProvider's FSRL will always have a MD5
        hash
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update
        :return: new :obj:`ByteProvider`
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises CancelledException: if user cancels
        :raises IOException: if IO problem
        """

    def getDerivedByteProvider(self, containerFSRL: FSRL, derivedFSRL: FSRL, derivedName: typing.Union[java.lang.String, str], sizeHint: typing.Union[jpype.JLong, int], producer: FileSystemService.DerivedStreamProducer, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a :obj:`ByteProvider` that contains the
        derived (ie. decompressed or decrypted) contents of the requested file.
         
        
        The resulting ByteProvider will be a cached file, either written to a 
        temporary file, or a in-memory buffer if small enough (see :obj:`FileCache.MAX_INMEM_FILESIZE`).
         
         
        If the file was not present in the cache, the :obj:`producer <DerivedStreamProducer>`
        will be called and it will be responsible for returning an :obj:`InputStream`
        which has the derived contents, which will be added to the file cache for next time.
        
        :param FSRL containerFSRL: :obj:`FSRL` w/hash of the source (or container) file that this 
        derived file is based on
        :param FSRL derivedFSRL: (optional) :obj:`FSRL` to assign to the resulting ByteProvider
        :param java.lang.String or str derivedName: a unique string identifying the derived file inside the source (or container) file
        :param jpype.JLong or int sizeHint: the expected size of the resulting ByteProvider, or -1 if unknown
        :param FileSystemService.DerivedStreamProducer producer: supplies an InputStream if needed.  See :obj:`DerivedStreamProducer`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` that will be monitor for cancel requests and updated
        with file io progress
        :return: a :obj:`ByteProvider` containing the bytes of the requested file, that has the 
        specified derivedFSRL, or a pseudo FSRL if not specified.  Never null
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises CancelledException: if the user cancels
        :raises IOException: if there was an io error
        """

    def getDerivedByteProviderPush(self, containerFSRL: FSRL, derivedFSRL: FSRL, derivedName: typing.Union[java.lang.String, str], sizeHint: typing.Union[jpype.JLong, int], pusher: FileSystemService.DerivedStreamPushProducer, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a :obj:`ByteProvider` that contains the
        derived (ie. decompressed or decrypted) contents of the requested file.
         
        
        The resulting ByteProvider will be a cached file, either written to a 
        temporary file, or a in-memory buffer if small enough (see :obj:`FileCache.MAX_INMEM_FILESIZE`).
         
         
        If the file was not present in the cache, the :obj:`pusher <DerivedStreamPushProducer>`
        will be called and it will be responsible for producing and writing the derived
        file's bytes to a :obj:`OutputStream`, which will be added to the file cache for next time.
        
        :param FSRL containerFSRL: :obj:`FSRL` w/hash of the source (or container) file that this 
        derived file is based on
        :param FSRL derivedFSRL: (optional) :obj:`FSRL` to assign to the resulting ByteProvider
        :param java.lang.String or str derivedName: a unique string identifying the derived file inside the source (or container) file
        :param jpype.JLong or int sizeHint: the expected size of the resulting ByteProvider, or -1 if unknown
        :param FileSystemService.DerivedStreamPushProducer pusher: writes bytes to the supplied OutputStream.  See :obj:`DerivedStreamPushProducer`
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` that will be monitor for cancel requests and updated
        with file io progress
        :return: a :obj:`ByteProvider` containing the bytes of the requested file, that has the 
        specified derivedFSRL, or a pseudo FSRL if not specified.  Never null
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises CancelledException: if the user cancels
        :raises IOException: if there was an io error
        """

    def getFileIfAvailable(self, provider: ghidra.app.util.bin.ByteProvider) -> java.io.File:
        """
        Converts a :obj:`ByteProvider` to the underlying File that contains the contents of
        the ByteProvider.
         
        
        Returns ``null`` if the underlying file is not available.
        
        :param ghidra.app.util.bin.ByteProvider provider: :obj:`ByteProvider`
        :return: a java :obj:`File` that is providing the bytes of the specified ByteProvider,
        or null if there is no available file
        :rtype: java.io.File
        """

    def getFilesystem(self, fsFSRL: FSRLRoot, monitor: ghidra.util.task.TaskMonitor) -> FileSystemRef:
        """
        Returns a filesystem instance for the requested :obj:`FSRLRoot`, either from an already
        loaded instance in the global fscache, or by instantiating the requested filesystem
        from its container file (in a possibly recursive manner, depending on the depth
        of the FSLR)
         
        
        Never returns NULL, instead throws IOException if there is a problem.
         
        
        The caller is responsible for releasing the :obj:`FileSystemRef`.
        
        :param FSRLRoot fsFSRL: :obj:`FSRLRoot` of file system you want a reference to.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to allow the user to cancel.
        :return: a new :obj:`FileSystemRef` that the caller is responsible for closing when
        no longer needed, never ``null``.
        :rtype: FileSystemRef
        :raises IOException: if there was an io problem.
        :raises CancelledException: if the user cancels.
        """

    def getFullyQualifiedFSRL(self, fsrl: FSRL, monitor: ghidra.util.task.TaskMonitor) -> FSRL:
        """
        Returns a cloned copy of the ``FSRL`` that should have MD5 values specified.
        (excluding GFile objects that don't have data streams)
        
        :param FSRL fsrl: :obj:`FSRL` of the file that should be forced to have a MD5
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update with progress.
        :return: possibly new :obj:`FSRL` instance with a MD5 value.
        :rtype: FSRL
        :raises CancelledException: if user cancels.
        :raises IOException: if IO problem.
        """

    @staticmethod
    def getInstance() -> FileSystemService:
        ...

    def getLocalFS(self) -> LocalFileSystem:
        """
        Returns a direct reference to the :obj:`local filesystem <LocalFileSystem>`.
        
        :return: A direct reference to the :obj:`local filesystem <LocalFileSystem>`.
        :rtype: LocalFileSystem
        """

    def getLocalFSRL(self, f: jpype.protocol.SupportsPath) -> FSRL:
        """
        Builds a :obj:`FSRL` of a :obj:`file <File>` located on the local filesystem.
        
        :param jpype.protocol.SupportsPath f: :obj:`File` on the local filesystem
        :return: :obj:`FSRL` pointing to the same file, never null
        :rtype: FSRL
        """

    def getMountedFilesystem(self, fsFSRL: FSRLRoot) -> FileSystemRef:
        """
        Returns a new FilesystemRef handle to an already mounted filesystem.
         
        
        The caller is responsible for releasing the ref.
         
        
        Returns null if there is no filesystem mounted at ``fsFSRL``.
        
        :param FSRLRoot fsFSRL: :obj:`FSRLRoot` of file system to get a :obj:`FileSystemRef` to.
        :return: new :obj:`FileSystemRef` or null if requested file system not mounted.
        :rtype: FileSystemRef
        """

    def getMountedFilesystems(self) -> java.util.List[FSRLRoot]:
        """
        Returns a list of all currently mounted filesystems.
         
        
        As a FSRL is returned, there is no guarantee that the filesystem will still be
        mounted when you later use values from the list.
        
        :return: :obj:`List` of :obj:`FSRLRoot` of currently mounted filesystems.
        :rtype: java.util.List[FSRLRoot]
        """

    def getNamedTempFile(self, tempFileCacheEntry: FileCache.FileCacheEntry, name: typing.Union[java.lang.String, str]) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a :obj:`ByteProvider` for the specified :obj:`FileCacheEntry`, using the
        specified filename.
         
        
        The returned ByteProvider's FSRL will be decorative and does not allow returning to
        the same ByteProvider at a later time.
        
        :param FileCache.FileCacheEntry tempFileCacheEntry: :obj:`FileCacheEntry` (returned by :meth:`createTempFile(long) <.createTempFile>`)
        :param java.lang.String or str name: desired name
        :return: new :obj:`ByteProvider` with decorative :obj:`FSRL`
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises IOException: if io error
        """

    def getRefdFile(self, fsrl: FSRL, monitor: ghidra.util.task.TaskMonitor) -> RefdFile:
        """
        Returns the :obj:`GFile` pointed to by the FSRL, along with a :obj:`FileSystemRef`
        that the caller is responsible for releasing (either explicitly via
        ``result.fsRef.close()`` or via the :meth:`RefdFile.close() <RefdFile.close>`).
        
        :param FSRL fsrl: :obj:`FSRL` of the desired file
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` so the user can cancel
        :return: a :obj:`RefdFile` which contains the resultant :obj:`GFile` and a
        :obj:`FileSystemRef` that needs to be closed, or ``null`` if the filesystem
        does not have the requested file.
        :rtype: RefdFile
        :raises CancelledException: if the user cancels
        :raises IOException: if there was a file io problem
        """

    def hasDerivedFile(self, containerFSRL: FSRL, derivedName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if the specified derived file exists in the file cache.
        
        :param FSRL containerFSRL: :obj:`FSRL` w/hash of the container
        :param java.lang.String or str derivedName: name of the derived file inside of the container
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: boolean true if file exists at time of query, false if file is not in cache
        :rtype: bool
        :raises CancelledException: if user cancels
        :raises IOException: if other IO error
        """

    def isFileFilesystemContainer(self, containerFSRL: FSRL, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if the container file probably holds one of the currently supported
        filesystem types.
        
        :param FSRL containerFSRL: :obj:`FSRL` of the file being queried.
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update progress.
        :return: boolean true if the file probably is a container, false otherwise.
        :rtype: bool
        :raises CancelledException: if user cancels.
        :raises IOException: if IO problem.
        """

    def isFilesystemMountedAt(self, fsrl: FSRL) -> bool:
        """
        Returns true of there is a :obj:`filesystem <GFileSystem>` mounted at the requested
        :obj:`FSRL` location.
        
        :param FSRL fsrl: :obj:`FSRL` container to query for mounted filesystem
        :return: boolean true if filesystem mounted at location.
        :rtype: bool
        """

    @staticmethod
    def isInitialized() -> bool:
        """
        Returns true if this service has been loaded
        
        :return: true if this service has been loaded
        :rtype: bool
        """

    def isLocal(self, fsrl: FSRL) -> bool:
        """
        Returns true if the specified location is a path on the local computer's
        filesystem.
        
        :param FSRL fsrl: :obj:`FSRL` path to query
        :return: true if local, false if the path points to an embedded file in a container.
        :rtype: bool
        """

    def mountSpecificFileSystem(self, containerFSRL: FSRL, fsClass: java.lang.Class[FSTYPE], monitor: ghidra.util.task.TaskMonitor) -> FSTYPE:
        """
        Mount a specific file system (by class) using a specified container file.
         
        
        The newly constructed / mounted file system is not managed by this FileSystemService
        or controlled with :obj:`FileSystemRef`s.
         
        
        The caller is responsible for closing the resultant file system instance when it is
        no longer needed.
        
        :param FSRL containerFSRL: a reference to the file that contains the file system image
        :param java.lang.Class[FSTYPE] fsClass: the GFileSystem derived class that implements the specific file system
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to allow the user to cancel
        :return: new :obj:`GFileSystem` instance, caller is responsible for closing() when done.
        :rtype: FSTYPE
        :raises CancelledException: if user cancels
        :raises IOException: if file io error or wrong file system type.
        """

    def newCryptoSession(self) -> ghidra.formats.gfilesystem.crypto.CryptoSession:
        """
        Returns a new :obj:`CryptoSession` that the caller can use to query for
        passwords and such.  Caller is responsible for closing the instance when done.
         
        
        Later callers to this method will receive a nested CryptoSession that shares it's
        state with the initial CryptoSession, until the initial CryptoSession is closed().
        
        :return: new :obj:`CryptoSession` instance, never null
        :rtype: ghidra.formats.gfilesystem.crypto.CryptoSession
        """

    def openFileSystemContainer(self, containerFSRL: FSRL, monitor: ghidra.util.task.TaskMonitor) -> GFileSystem:
        """
        Open the file system contained at the specified location.
         
        
        The newly constructed / mounted file system is not managed by this FileSystemService
        or controlled with :obj:`FileSystemRef`s.
         
        
        The caller is responsible for closing the resultant file system instance when it is
        no longer needed.
        
        :param FSRL containerFSRL: a reference to the file that contains the file system image
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to allow the user to cancel
        :return: new :obj:`GFileSystem` instance, caller is responsible for closing() when done.
        :rtype: GFileSystem
        :raises CancelledException: if user cancels
        :raises IOException: if file io error or wrong file system type.
        """

    @typing.overload
    def probeFileForFilesystem(self, containerFSRL: FSRL, monitor: ghidra.util.task.TaskMonitor, conflictResolver: FileSystemProbeConflictResolver) -> FileSystemRef:
        """
        Auto-detects a filesystem in the container file pointed to by the FSRL.
         
        
        Returns a filesystem instance for the requested container file, either from an already
        loaded instance in the Global fs cache, or by probing for a filesystem in the container
        file using the :obj:`FileSystemFactoryMgr`.
         
        
        Returns null if no filesystem implementation was found that could handle the container
        file.
        
        :param FSRL containerFSRL: :obj:`FSRL` of the file container
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update progress.
        :param FileSystemProbeConflictResolver conflictResolver: :obj:`FileSystemProbeConflictResolver` to handle choosing
        the correct file system type among multiple results, or null if you want
        :obj:`FileSystemProbeConflictResolver.CHOOSEFIRST` .
        :return: new :obj:`FileSystemRef` or null
        :rtype: FileSystemRef
        :raises CancelledException: if user cancels.
        :raises IOException: if IO problem.
        """

    @typing.overload
    def probeFileForFilesystem(self, containerFSRL: FSRL, monitor: ghidra.util.task.TaskMonitor, conflictResolver: FileSystemProbeConflictResolver, priorityFilter: typing.Union[jpype.JInt, int]) -> FileSystemRef:
        """
        Auto-detects a filesystem in the container file pointed to by the FSRL.
         
        
        Returns a filesystem instance for the requested container file, either from an already
        loaded instance in the Global fs cache, or by probing for a filesystem in the container
        file using a :obj:`FileSystemFactoryMgr`.
         
        
        Returns null if no filesystem implementation was found that could handle the container
        file.
        
        :param FSRL containerFSRL: :obj:`FSRL` of the file container
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to watch and update progress.
        :param FileSystemProbeConflictResolver conflictResolver: :obj:`FileSystemProbeConflictResolver` to handle choosing
        the correct file system type among multiple results, or null if you want
        :obj:`FileSystemProbeConflictResolver.CHOOSEFIRST` .
        :param jpype.JInt or int priorityFilter: minimum filesystem :meth:`FileSystemInfo.priority() <FileSystemInfo.priority>` to allow
        when using file system factories to probe the container.
        :return: new :obj:`FileSystemRef` or null
        :rtype: FileSystemRef
        :raises CancelledException: if user cancels.
        :raises IOException: if IO problem.
        """

    def pushFileToCache(self, file: jpype.protocol.SupportsPath, fsrl: FSRL, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Adds a plaintext (non-obfuscated) file to the cache, consuming it in the process, and returns
        a :obj:`ByteProvider` that contains the contents of the file.
         
        
        NOTE: only use this if you have no other choice and are forced to deal with already
        existing files in the local filesystem.
        
        :param jpype.protocol.SupportsPath file: :obj:`File` to add
        :param FSRL fsrl: :obj:`FSRL` of the file that is being added
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: :obj:`ByteProvider` (hosted in the FileCache) that contains the bytes of the
        specified file
        :rtype: ghidra.app.util.bin.ByteProvider
        :raises CancelledException: if cancelled
        :raises IOException: if error
        """

    def releaseFileCache(self, fsrl: FSRL):
        """
        Allows the resources used by caching the specified file to be released.
        
        :param FSRL fsrl: :obj:`FSRL` file to release cache resources for
        """

    def releaseFileSystemImmediate(self, fsRef: FileSystemRef):
        """
        Releases the specified :obj:`FileSystemRef`, and if no other references remain, removes 
        it from the shared cache of file system instances.
        
        :param FileSystemRef fsRef: the ref to release
        """

    @property
    def localFSRL(self) -> FSRL:
        ...

    @property
    def localFS(self) -> LocalFileSystem:
        ...

    @property
    def filesystemMountedAt(self) -> jpype.JBoolean:
        ...

    @property
    def allFilesystemNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def mountedFilesystem(self) -> FileSystemRef:
        ...

    @property
    def mountedFilesystems(self) -> java.util.List[FSRLRoot]:
        ...

    @property
    def local(self) -> jpype.JBoolean:
        ...

    @property
    def fileIfAvailable(self) -> java.io.File:
        ...


class GFileHashProvider(java.lang.Object):
    """
    GFileSystem add-on interface that provides MD5 hashing for file located within the filesystem
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMD5Hash(self, file: GFile, required: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> str:
        """
        Returns the MD5 hash of the specified file.
        
        :param GFile file: the :obj:`GFile`
        :param jpype.JBoolean or bool required: boolean flag, if true the hash will always be returned, even if it has to
        be calculated.  If false, the hash will be returned if easily available
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: MD5 hash as a string
        :rtype: str
        :raises CancelledException: if cancelled
        :raises IOException: if error
        """


class GFileLocal(GFile):
    """
    :obj:`GFile` implementation that refers to a real java.io.File on the local
    file system.
     
    
    This implementation keeps track of the FSRL and GFile path separately so that
    they can be different, as is the case with LocalFileSystemSub files that
    have real FSRLs but fake relative paths.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, f: jpype.protocol.SupportsPath, path: typing.Union[java.lang.String, str], fsrl: FSRL, fs: GFileSystem, parent: GFile):
        """
        Create new GFileLocal instance.
        
        :param jpype.protocol.SupportsPath f: :obj:`File` on the local filesystem
        :param java.lang.String or str path: String path (including filename) of this instance
        :param FSRL fsrl: :obj:`FSRL` of this instance
        :param GFileSystem fs: :obj:`GFileSystem` that created this file.
        :param GFile parent: Parent directory that contains this file, or null if parent is root.
        """

    def getLocalFile(self) -> java.io.File:
        ...

    @property
    def localFile(self) -> java.io.File:
        ...


class FileSystemProbeConflictResolver(java.lang.Object):
    """
    A callback interface used to choose which filesystem implementation to use when
    multiple filesystem types indicate that they can open a container file.
    """

    class_: typing.ClassVar[java.lang.Class]
    CHOOSEFIRST: typing.Final[FileSystemProbeConflictResolver]
    """
    Conflict handler that chooses the first filesystem in the list.
    """

    GUI_PICKER: typing.Final[FileSystemProbeConflictResolver]
    """
    Conflict handler that allows the user to pick the filesystem to use from a GUI list.
    """


    def chooseFSIR(self, factories: java.util.List[ghidra.formats.gfilesystem.factory.FileSystemInfoRec]) -> ghidra.formats.gfilesystem.factory.FileSystemInfoRec:
        """
        This method should be provided by the actual strategy implementation.
         
        
        This method will only be called if the list contains more than a single item.
        
        :param java.util.List[ghidra.formats.gfilesystem.factory.FileSystemInfoRec] factories: :obj:`List` of :obj:`FileSystemInfoRec`, always more than 1 element.
        :return: the chosen FSIR, or null
        :rtype: ghidra.formats.gfilesystem.factory.FileSystemInfoRec
        """

    def resolveFSIR(self, factories: java.util.List[ghidra.formats.gfilesystem.factory.FileSystemInfoRec]) -> ghidra.formats.gfilesystem.factory.FileSystemInfoRec:
        """
        Picks a single :obj:`FileSystemInfoRec` to use when mounting a filesystem.
        
        :param java.util.List[ghidra.formats.gfilesystem.factory.FileSystemInfoRec] factories: a :obj:`List` of :obj:`FileSystemInfoRec`s.
        :return: the chosen FSIR, or null
        :rtype: ghidra.formats.gfilesystem.factory.FileSystemInfoRec
        """


class FileCacheNameIndex(java.lang.Object):
    """
    A best-effort cache of MD5 values of files, where the file is identified by its parent's
    MD5 combined with the file's path inside its parent's 'namespace'.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, parentMD5: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], fileMD5: typing.Union[java.lang.String, str]):
        """
        Adds a filename mapping to this cache.
        
        :param java.lang.String or str parentMD5: the md5 string of the parent object
        :param java.lang.String or str name: the name of this object
        :param java.lang.String or str fileMD5: the md5 string of this object
        :raises IOException: if missing or bad md5 values.
        """

    def clear(self):
        ...

    def get(self, parentMD5: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> str:
        """
        Retrieves a filename mapping from this cache.
        
        :param java.lang.String or str parentMD5: the md5 string of the parent object
        :param java.lang.String or str name: the name of the requested object.
        :return: the md5 string of the requested object, or null if not in cache.
        :rtype: str
        :raises IOException: if missing or bad parent md5 values.
        """


class AbstractFileExtractorTask(ghidra.util.task.Task):
    """
    Common base class for tasks that need to extract files from a GFileSystem location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], canCancel: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], rootOutputDir: jpype.protocol.SupportsPath):
        """
        See :meth:`Task.Task(String, boolean, boolean, boolean) <Task.Task>`.
        
        :param java.lang.String or str title: See :meth:`Task.Task(String, boolean, boolean, boolean) <Task.Task>`
        :param jpype.JBoolean or bool canCancel: See :meth:`Task.Task(String, boolean, boolean, boolean) <Task.Task>`
        :param jpype.JBoolean or bool hasProgress: See :meth:`Task.Task(String, boolean, boolean, boolean) <Task.Task>`
        :param jpype.JBoolean or bool isModal: See :meth:`Task.Task(String, boolean, boolean, boolean) <Task.Task>`
        :param jpype.protocol.SupportsPath rootOutputDir: base directory where files will be extracted to
        """

    def getTotalBytesExportedCount(self) -> int:
        """
        Return the number of bytes that were exported.
        
        :return: the number of bytes that were exported
        :rtype: int
        """

    def getTotalDirsExportedCount(self) -> int:
        """
        Return the number of directories that were exported.
        
        :return: the number of directories that were exported
        :rtype: int
        """

    def getTotalFilesExportedCount(self) -> int:
        """
        Return the number of files that were exported.
        
        :return: the number of files that were exported
        :rtype: int
        """

    @property
    def totalBytesExportedCount(self) -> jpype.JLong:
        ...

    @property
    def totalDirsExportedCount(self) -> jpype.JInt:
        ...

    @property
    def totalFilesExportedCount(self) -> jpype.JInt:
        ...


class FSRL(java.lang.Object):
    """
    A _F_ile _S_ystem _R_esource _L_ocator, (name and string format patterned after URLs)
     
    
    Used to locate a resource (by name) on a "filesystem", in a recursively nested fashion.
     
    
    The string format of FSRLs is ``fstype`` + **"://"** + ``path`` + ``optional_MD5``
    [ + **"|"** pipe + ``FSRL`` ]*
     
    
    See :meth:`fromPartString(FSRL, String) <.fromPartString>` for more format info.
     
    
    Read the string format from right-to-left for easiest understanding... ie.
    "file://z|y://x" reads as "file x inside a filesystem y inside a container file z".
     
    
    FSRL instances are immutable and thread-safe.
     
    
    Examples (pipes shown in red since they are hard to see):
     
    * file://dir/subdir -- simplest example, locates a file on local computer filesystem.
    * file://dir/subdir/example.zip|zip://readme.txt -- points to a file named "readme.txt" in a zip file.
    * file://dir/subdir/example.zip|zip://dir/nested.tar|tar://file.txt -- points to
    a file inside a TAR archive, which is inside a ZIP archive, which is on the local filesystem.
    * file://dir/subdir/example.zip?MD5=1234567|zip://readme.txt?MD5=987654 --
    points to a file named "readme.txt" (with a MD5 hash) in a zip file (that has another
    MD5 hash).
    
     
    
    See :obj:`FSRLRoot` for examples of how FSRL and FSRLRoot's are related.
     
    
    FSRL's can be created either piecemeal, from the bottom up, starting with a root filesystem
    FSRL and calling :meth:`appendPath(String) <.appendPath>` or :meth:`FSRLRoot.nestedFS(FSRL, String) <FSRLRoot.nestedFS>` methods
    to create deeper and deeper nested FSRLs,
     
    
    or
     
    
    FSRL's can be created from strings using :meth:`fromString(String) <.fromString>`.
     
    
    FSRLs that have a MD5 value are :meth:`"fully qualified" <FileSystemService.getFullyQualifiedFSRL>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    PARAM_MD5: typing.Final = "MD5"
    FSRL_OPTION_NAME: typing.Final = "FSRL"

    def appendPath(self, relPath: typing.Union[java.lang.String, str]) -> FSRL:
        """
        Creates a new :obj:`FSRL` instance, using the same :obj:`FSRLRoot` as this instance,
        combining the current :meth:`path <.getPath>` with the ``relPath`` value.
        
        :param java.lang.String or str relPath: relative path string to append, '/'s will be automatically added
        :return: new :obj:`FSRL` instance with additional path appended.
        :rtype: FSRL
        """

    @staticmethod
    def convertRootToContainer(fsrl: FSRL) -> FSRL:
        """
        Ensures that a FSRL instance is a file type reference by converting any FSRLRoots
        into the container file that hosts the FSRLRoot.
        
        :param FSRL fsrl: FSRL or FSRLRoot instance to possibly convert
        :return: original FSRL if already a normal FSRL, or the container if it was a FSRLRoot
        :rtype: FSRL
        """

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> FSRL:
        """
        Returns the :obj:`FSRL` stored in a :obj:`Program`'s properties, or null if not present
        or malformed.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :return: :obj:`FSRL` from program's properties, or null if not present or invalid
        :rtype: FSRL
        """

    @staticmethod
    @typing.overload
    def fromString(fsrlStr: typing.Union[java.lang.String, str]) -> FSRL:
        """
        Creates a :obj:`FSRL` from a raw string.  The parent portions of the FSRL
        are not intern()'d so will not be shared with other FSRL instances.
         
        
        See :meth:`fromPartString(FSRL, String) <.fromPartString>` for details of character encoding fixups.
        
        :param java.lang.String or str fsrlStr: something like "fstype://path/path|fs2type://path2/path2|etc://etc/etc"
        :return: new :obj:`FSRL` instance, never null
        :rtype: FSRL
        :raises MalformedURLException: if empty string or bad format
        """

    @staticmethod
    @typing.overload
    def fromString(parent: FSRL, fsrlStr: typing.Union[java.lang.String, str]) -> FSRL:
        """
        Creates a :obj:`FSRL` from a raw string.
         
        
        See :meth:`fromPartString(FSRL, String) <.fromPartString>` for details of character encoding fixups.
        
        :param FSRL parent: Parent :obj:`FSRL`
        :param java.lang.String or str fsrlStr: something like "fstype://path/path|fs2type://path2/path2|etc://etc/etc"
        :return: new :obj:`FSRL` instance, never null
        :rtype: FSRL
        :raises MalformedURLException: if empty string or bad format
        """

    def getFS(self) -> FSRLRoot:
        """
        Returns the :obj:`FSRLRoot` object that represents the entire
        :obj:`filesystem <GFileSystem>` for this FSRL.
         
        
        Never returns NULL, and calling getFS() on a :obj:`FSRLRoot` object
        returns itself.
        
        :return: :obj:`FSRLRoot` instance that is the parent of this :obj:`FSRL`, never
        null.
        :rtype: FSRLRoot
        """

    def getMD5(self) -> str:
        """
        Returns the MD5 string associated with this file.
         
        
        NULL if no MD5 value present.
        
        :return: md5 string associated with this file object, or null if not present.
        :rtype: str
        """

    @typing.overload
    def getName(self) -> str:
        """
        Returns the name portion of this FSRL's path, everything after the last '/'
         
        
        "file://path/name.ext" returns "name.ext"
        
        :return: name portion of this FSRL path, or null if path is null also.
        :rtype: str
        """

    @typing.overload
    def getName(self, nestedDepth: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the name portion of the FSRL part at parent depth ``nestedDepth``, where 0
        is ourself (equiv to just calling :meth:`getName() <.getName>`, 1 is the parent
        container's name, etc.
        
        :param jpype.JInt or int nestedDepth: relative parent index of FSRL part to query, 0 == this instance.
        :return: name portion of the path of the specified FSRL part.
        :rtype: str
        :raises IOException: if nestedDepth is larger than number of FSRL parent parts.
        """

    def getNestingDepth(self) -> int:
        """
        Returns the number of :obj:`FSRLRoot`s there are in this :obj:`FSRL`.
         
        
        A single level FSRL such as "file://path" will return 1.
        
        A two level FSRL such as "file://path|subfs://path2" will return 2.
        
        etc.
        
        
        :return: number of levels in this FSRL, min value returned is 1.
        :rtype: int
        """

    def getPath(self) -> str:
        """
        Returns the full path/filename of this FSRL.  Does not include parent filesystem path
        or info.
         
        
        "file://path|subfs://subpath/blah" returns "/subpath/blah"
         
        
        May return null if this instance is a :obj:`FSRLRoot`.
        
        :return: string path and filename of this object.  Null if this :obj:`FSRL` is a
        :obj:`FSRLRoot`.
        :rtype: str
        """

    def isDescendantOf(self, potentialParent: FSRL) -> bool:
        """
        Returns ``true`` if this object is a child or descendant of the
        specified ``potentialParent`` parameter.
        
        :param FSRL potentialParent: :obj:`FSRL` to test against
        :return: boolean true if the specified :obj:`FSRL` is a parent (ignoring md5 hashes)
        of this instance.
        :rtype: bool
        """

    @typing.overload
    def isEquivalent(self, fsrlStr: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the two FSRLs are the same, excluding any MD5 values.
        
        :param java.lang.String or str fsrlStr: string-ified :obj:`FSRL`
        :return: boolean true if this instance is the same as the specified string-ified fsrl,
        ignoring any md5 values.
        :rtype: bool
        """

    @typing.overload
    def isEquivalent(self, other: FSRL) -> bool:
        """
        Returns true if the two :obj:`FSRL`s are the same, excluding any MD5 values.
        
        :param FSRL other: :obj:`FSRL` to compare with
        :return: boolean true if this instance is the same as the specified FSRL, ignoring
        any md5 values.
        :rtype: bool
        """

    def isMD5Equal(self, otherMD5: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests specified MD5 value against MD5 in this FSRL.
        
        :param java.lang.String or str otherMD5: md5 in a hex string
        :return: boolean true if equal, or that both are null, false otherwise
        :rtype: bool
        """

    def makeNested(self, fstype: typing.Union[java.lang.String, str]) -> FSRLRoot:
        """
        Creates a new :obj:`FSRLRoot` instance that is a child of this FSRL.
         
        
        See :meth:`FSRLRoot.nestedFS(FSRL, FSRLRoot) <FSRLRoot.nestedFS>` and :meth:`FSRLRoot.nestedFS(FSRL, String) <FSRLRoot.nestedFS>`.
        
        :param java.lang.String or str fstype: file system type string.
        :return: new :obj:`FSRLRoot` instance
        :rtype: FSRLRoot
        """

    def split(self) -> java.util.List[FSRL]:
        """
        Splits a :obj:`FSRL` into a :obj:`List`, with each element pointing to
        each level of the full FSRL.
         
        
        Example: "file://path|subfs://blah|subfs2://blah2"
         
        
        Produces a list of 3 elements:
        
        "file://path"
        
        "file://path|subfs://blah"
        
        "file://path|subfs://blah|subfs2://blah2"
        
        :return: :obj:`List` of :obj:`FSRL` elements pointing to each level of this FSRL.
        :rtype: java.util.List[FSRL]
        """

    def toPrettyFullpathString(self) -> str:
        """
        Returns a string containing the full FSRL, without FS "fstype://" portions
         
        
        Example:
         
        
        ``"fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile"``
         
        
        will result in
         
        
        ``"path/filename|subpath/subfile"``.
        
        :return: formatted string such as: "path/filename|subpath/subfile"
        :rtype: str
        """

    def toPrettyString(self) -> str:
        """
        Returns a string containing the full FSRL, excluding MD5 portions.
        
        :return: string with full FSRL, excluding MD5 portions.
        :rtype: str
        """

    def toString(self) -> str:
        """
        Returns a string containing the full FSRL.
         
        
        Example: "file://path|subfs://blah?MD5=1234567"
        
        :return: string with full FSRL
        :rtype: str
        """

    def toStringPart(self) -> str:
        """
        Returns a string containing just the current :obj:`FSRL` protocol and path.
         
        
        Example: "file://path|subfs://blah?MD5=123456" returns "subfs://blah?MD5=123456"
        
        :return: string containing just the current :obj:`FSRL` protocol and path.
        :rtype: str
        """

    def withMD5(self, newMD5: typing.Union[java.lang.String, str]) -> FSRL:
        """
        Creates a new :obj:`FSRL` instance, using the same information as this instance,
        but with a new :meth:`MD5 <.getMD5>` value.
        
        :param java.lang.String or str newMD5: string md5
        :return: new :obj:`FSRL` instance with the same path and the specified md5 value,
                or if newMD5 is same as existing, returns this
        :rtype: FSRL
        """

    @typing.overload
    def withPath(self, newpath: typing.Union[java.lang.String, str]) -> FSRL:
        """
        Creates a new :obj:`FSRL` instance, using the same :obj:`FSRLRoot` as this instance,
        but with a new path.
         
        
        See also :meth:`appendPath(String) <.appendPath>`.
        
        :param java.lang.String or str newpath: string path
        :return: new :obj:`FSRL` instance with the specified path.
        :rtype: FSRL
        """

    @typing.overload
    def withPath(self, copyPath: FSRL) -> FSRL:
        """
        Creates a new :obj:`FSRL` instance using the same path and other metadata
        present in the ``copyPath`` instance.
         
        
        Used when re-root'ing a FSRL path onto another parent object (usually during intern()'ing)
        
        :param FSRL copyPath: another FSRL to copy path and md5 from
        :return: new FSRL instance
        :rtype: FSRL
        """

    @staticmethod
    def writeToProgramInfo(program: ghidra.program.model.listing.Program, fsrl: FSRL):
        """
        Writes a FSRL value to a :obj:`Program`'s properties.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param FSRL fsrl: :obj:`FSRL` to write
        """

    @property
    def nestingDepth(self) -> jpype.JInt:
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def descendantOf(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def mD5Equal(self) -> jpype.JBoolean:
        ...

    @property
    def fS(self) -> FSRLRoot:
        ...

    @property
    def mD5(self) -> java.lang.String:
        ...


class GFileImpl(GFile):
    """
    Base implementation of file in a :obj:`filesystem <GFileSystem>`.
     
    
    Only valid while the owning filesystem object is still open and not
    :meth:`closed <GFileSystem.close>`.
     
    
    See :obj:`GFile`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def fromFSRL(fileSystem: GFileSystem, parent: GFile, fsrl: FSRL, isDirectory: typing.Union[jpype.JBoolean, bool], length: typing.Union[jpype.JLong, int]) -> GFileImpl:
        """
        Creates a GFile for a filesystem using the information in a FSRL as the file's name
        and as a child of the specified parent.
        
        :param GFileSystem fileSystem: the :obj:`GFileSystem` that owns this file
        :param GFile parent: the parent of the new GFile or null if child-of-root.
        :param FSRL fsrl: :obj:`FSRL` to assign to the file.
        :param jpype.JBoolean or bool isDirectory: boolean flag to indicate that this is a directory
        :param jpype.JLong or int length: length of the file (use -1 if not know or specified).
        :return: a new :obj:`GFileImpl`
        :rtype: GFileImpl
        """

    @staticmethod
    def fromFilename(fileSystem: GFileSystem, parent: GFile, filename: typing.Union[java.lang.String, str], isDirectory: typing.Union[jpype.JBoolean, bool], length: typing.Union[jpype.JLong, int], fsrl: FSRL) -> GFileImpl:
        """
        Creates a GFile for a filesystem using a simple name (not a path)
        and as a child of the specified parent.
         
        
        The filename is accepted without checking or validation.
        
        :param GFileSystem fileSystem: the :obj:`GFileSystem` that owns this file
        :param GFile parent: the parent of the new GFile or null if child-of-root.
        :param java.lang.String or str filename: the file's name, not used if FSRL param specified.
        :param jpype.JBoolean or bool isDirectory: boolean flag to indicate that this is a directory
        :param jpype.JLong or int length: length of the file (use -1 if not know or specified).
        :param FSRL fsrl: :obj:`FSRL` to assign to the file, NULL if an auto-created FSRL is ok.
        :return: a new :obj:`GFileImpl`
        :rtype: GFileImpl
        """

    @staticmethod
    @typing.overload
    def fromPathString(fileSystem: GFileSystem, path: typing.Union[java.lang.String, str], fsrl: FSRL, isDirectory: typing.Union[jpype.JBoolean, bool], length: typing.Union[jpype.JLong, int]) -> GFileImpl:
        """
        Creates a GFile for a filesystem using a string
        path (ie. "dir/subdir/filename"), with the path starting at the root of the
        filesystem.
         
        
        The parents of this GFile are created fresh from any directory names
        in the path string.  It is better to use the
        :meth:`fromFilename(GFileSystem, GFile, String, boolean, long, FSRL) <.fromFilename>` method
        to create GFile instances if you can supply the parent value as that will
        allow reuse of the parent objects instead of duplicates of them being created
        for each file with the same parent path.
        
        :param GFileSystem fileSystem: the :obj:`GFileSystem` that owns this file
        :param java.lang.String or str path: forward slash '/' separated path and filename string.
        :param FSRL fsrl: :obj:`FSRL` to assign to the file, NULL if an auto-created FSRL is ok.
        :param jpype.JBoolean or bool isDirectory: boolean flag to indicate that this is a directory
        :param jpype.JLong or int length: length of the file (use -1 if not know or specified).
        :return: a new :obj:`GFileImpl`
        :rtype: GFileImpl
        """

    @staticmethod
    @typing.overload
    def fromPathString(fileSystem: GFileSystem, parent: GFile, path: typing.Union[java.lang.String, str], fsrl: FSRL, isDirectory: typing.Union[jpype.JBoolean, bool], length: typing.Union[jpype.JLong, int]) -> GFileImpl:
        """
        Creates a GFile for a specific owning filesystem using a string
        path (ie. "dir/subdir/filename"), with the path starting at the supplied
        ``parent`` directory.
         
        
        The parents of this GFile are created fresh from any directory names
        in the path string.  It is better to use the
        :meth:`fromFilename(GFileSystem, GFile, String, boolean, long, FSRL) <.fromFilename>` method
        to create GFile instances if you can supply the parent value as that will
        allow reuse of the parent objects instead of duplicates of them being created
        for each file with the same parent path.
        
        :param GFileSystem fileSystem: the :obj:`GFileSystem` that owns this file
        :param GFile parent: the parent of the new GFile or null if child-of-root.
        :param java.lang.String or str path: forward slash '/' separated path and filename string.
        :param FSRL fsrl: :obj:`FSRL` to assign to the file, NULL if an auto-created FSRL is ok.
        :param jpype.JBoolean or bool isDirectory: boolean flag to indicate that this is a directory
        :param jpype.JLong or int length: length of the file (use -1 if not know or specified).
        :return: a new :obj:`GFileImpl`
        :rtype: GFileImpl
        """

    def setLength(self, length: typing.Union[jpype.JLong, int]):
        ...


class RefdFile(java.io.Closeable):
    """
    A :obj:`GFile` along with a :obj:`FileSystemRef` to keep the filesystem pinned
    in memory.
     
    
    The caller is responsible for :meth:`closing <.close>` this object, which releases
    the FilesystemRef.
    """

    class_: typing.ClassVar[java.lang.Class]
    fsRef: typing.Final[FileSystemRef]
    file: typing.Final[GFile]

    def __init__(self, fsRef: FileSystemRef, file: GFile):
        """
        Creates a RefdFile instance, taking ownership of the supplied fsRef.
        
        :param FileSystemRef fsRef: :obj:`FileSystemRef` that pins the filesystem open
        :param GFile file: GFile file inside the specified filesystem
        """



__all__ = ["SingleFileSystemIndexHelper", "FileSystemInstanceManager", "FileSystemEventListener", "FileSystemRef", "LocalFileSystemSub", "GFileSystem", "GFileSystemIterator", "RefdByteProvider", "GFile", "GFileSystemBase", "LocalFileSystem", "FileSystemRefManager", "FSUtilities", "FileSystemIndexHelper", "FileCache", "GIconProvider", "RefdInputStream", "FSRLRoot", "GFileSystemProgramProvider", "AbstractFileSystem", "FileSystemService", "GFileHashProvider", "GFileLocal", "FileSystemProbeConflictResolver", "FileCacheNameIndex", "AbstractFileExtractorTask", "FSRL", "GFileImpl", "RefdFile"]
