from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db.buffers
import ghidra.framework
import ghidra.util.exception
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


class FileIDFactory(java.lang.Object):
    """
    Factory class for generating unique file ID's.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createFileID() -> str:
        ...


class DataFileHandle(java.lang.Object):
    """
    ``DataFileHandle`` provides a random-access handle to a file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def close(self):
        """
        Closes this random access file stream and releases any system 
        resources associated with the stream. A closed random access 
        file cannot perform input or output operations and cannot be 
        reopened.
        
        :raises IOException: if an I/O error occurs.
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if this data file handle is open read-only.
        
        :raises IOException: if an I/O error occurs.
        """

    def length(self) -> int:
        """
        Returns the length of this file.
        
        :return: the length of this file, measured in bytes.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte]):
        """
        Reads ``b.length`` bytes from this file into the byte 
        array, starting at the current file pointer. This method reads 
        repeatedly from the file until the requested number of bytes are 
        read. This method blocks until the requested number of bytes are 
        read, the end of the stream is detected, or an exception is thrown.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which the data is read.
        :raises java.io.EOFException: if this file reaches the end before reading
                    all the bytes.
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        """
        Reads exactly ``len`` bytes from this file into the byte 
        array, starting at the current file pointer. This method reads 
        repeatedly from the file until the requested number of bytes are 
        read. This method blocks until the requested number of bytes are 
        read, the end of the stream is detected, or an exception is thrown.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which the data is read.
        :param jpype.JInt or int off: the start offset of the data.
        :param jpype.JInt or int len: the number of bytes to read.
        :raises java.io.EOFException: if this file reaches the end before reading
                    all the bytes.
        :raises IOException: if an I/O error occurs.
        """

    def seek(self, pos: typing.Union[jpype.JLong, int]):
        """
        Sets the file-pointer offset, measured from the beginning of this 
        file, at which the next read or write occurs.  The offset may be 
        set beyond the end of the file. Setting the offset beyond the end 
        of the file does not change the file length.  The file length will 
        change only by writing after the offset has been set beyond the end 
        of the file.
        
        :param jpype.JLong or int pos: the offset position, measured in bytes from the 
                        beginning of the file, at which to set the file 
                        pointer.
        :raises IOException: if ``pos`` is less than 
                                ``0`` or if an I/O error occurs.
        """

    def setLength(self, newLength: typing.Union[jpype.JLong, int]):
        """
        Sets the length of this file.
        
         
        If the present length of the file as returned by the
        ``length`` method is greater than the ``newLength``
        argument then the file will be truncated.  In this case, if the file
        offset as returned by the ``getFilePointer`` method is greater
        then ``newLength`` then after this method returns the offset
        will be equal to ``newLength``.
        
         
        If the present length of the file as returned by the
        ``length`` method is smaller than the ``newLength``
        argument then the file will be extended.  In this case, the contents of
        the extended portion of the file are not defined.
        
        :param jpype.JLong or int newLength: The desired length of the file
        :raises IOException: If an I/O error occurs
        """

    def skipBytes(self, n: typing.Union[jpype.JInt, int]) -> int:
        """
        Attempts to skip over ``n`` bytes of input discarding the 
        skipped bytes. 
         
        
         
        This method may skip over some smaller number of bytes, possibly zero. 
        This may result from any of a number of conditions; reaching end of 
        file before ``n`` bytes have been skipped is only one 
        possibility. This method never throws an ``EOFException``. 
        The actual number of bytes skipped is returned.  If ``n`` 
        is negative, no bytes are skipped.
        
        :param jpype.JInt or int n: the number of bytes to be skipped.
        :return: the actual number of bytes skipped.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: typing.Union[jpype.JInt, int]):
        """
        Writes the specified byte to this file. The write starts at 
        the current file pointer.
        
        :param jpype.JInt or int b: the ``byte`` to be written.
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte]):
        """
        Writes ``b.length`` bytes from the specified byte array 
        to this file, starting at the current file pointer.
        
        :param jpype.JArray[jpype.JByte] b: the data.
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        """
        Writes ``len`` bytes from the specified byte array 
        starting at offset ``off`` to this file.
        
        :param jpype.JArray[jpype.JByte] b: the data.
        :param jpype.JInt or int off: the start offset in the data.
        :param jpype.JInt or int len: the number of bytes to write.
        :raises IOException: if an I/O error occurs.
        """

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...


class FileSystemInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def run(self):
        ...


class Version(java.io.Serializable):
    """
    ``Version`` provides immutable information about a specific version of an item.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self, version: typing.Union[jpype.JInt, int], createTime: typing.Union[jpype.JLong, int], user: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param jpype.JInt or int version: file version number
        :param jpype.JLong or int createTime: time version was created
        :param java.lang.String or str user: name of user who created version
        :param java.lang.String or str comment: version comment
        """

    def getComment(self) -> str:
        """
        Returns version comment.
        """

    def getCreateTime(self) -> int:
        """
        Returns time at which version was created.
        """

    def getUser(self) -> str:
        """
        Returns name of user who created version.
        """

    def getVersion(self) -> int:
        """
        Returns version number.
        """

    @property
    def createTime(self) -> jpype.JLong:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def user(self) -> java.lang.String:
        ...


class LockException(ghidra.util.exception.UsrException):
    """
    Indicates a failure to obtain a required lock.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Construct a new LockException with the given message
        
        :param java.lang.String or str msg: the exception message
        """


class ItemCheckoutStatus(java.io.Serializable):
    """
    ``ItemCheckoutStatus`` provides immutable status information for a 
    checked-out item.  This class is serializable so that it may be passed 
    to a remote client.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self, checkoutId: typing.Union[jpype.JLong, int], checkoutType: CheckoutType, user: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], time: typing.Union[jpype.JLong, int], projectPath: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param jpype.JLong or int checkoutId: unique checkout ID
        :param CheckoutType checkoutType: type of checkout
        :param java.lang.String or str user: user name
        :param jpype.JInt or int version: version of file which was checked-out
        :param jpype.JLong or int time: time when checkout was completed.
        """

    def getCheckoutDate(self) -> java.util.Date:
        """
        Returns the time at which the checkout was completed.
        
        :return: 
        :rtype: java.util.Date
        """

    def getCheckoutId(self) -> int:
        """
        Returns the unique ID for the associated checkout.
        """

    def getCheckoutTime(self) -> int:
        """
        Returns the time at which the checkout was completed.
        """

    def getCheckoutType(self) -> CheckoutType:
        """
        Returns the checkout type
        
        :return: checkout type
        :rtype: CheckoutType
        """

    def getCheckoutVersion(self) -> int:
        """
        Returns the file version which was checked-out.
        """

    def getProjectLocation(self) -> str:
        """
        Return a Project location which corresponds to the projectPath 
        or null if one can not be constructed.
        
        :return: project location
        :rtype: str
        """

    def getProjectName(self) -> str:
        """
        Return a Project location which corresponds to the projectPath 
        or null if one can not be constructed.
        
        :return: project location
        :rtype: str
        """

    @typing.overload
    def getProjectPath(self) -> str:
        """
        Returns user's local project path if known.
        """

    @staticmethod
    @typing.overload
    def getProjectPath(projectPath: typing.Union[java.lang.String, str], isTransient: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get project path string suitable for checkout requests
        
        :param java.lang.String or str projectPath: 
        :param jpype.JBoolean or bool isTransient: true if project is transient
        :return: project location path
        :rtype: str
        """

    def getUser(self) -> str:
        """
        Returns the user name for the associated checkout.
        """

    def getUserHostName(self) -> str:
        """
        Returns the user's hostname associated with the original checkout
        
        :return: host name or null
        :rtype: str
        """

    @property
    def projectLocation(self) -> java.lang.String:
        ...

    @property
    def userHostName(self) -> java.lang.String:
        ...

    @property
    def checkoutDate(self) -> java.util.Date:
        ...

    @property
    def projectPath(self) -> java.lang.String:
        ...

    @property
    def checkoutVersion(self) -> jpype.JInt:
        ...

    @property
    def projectName(self) -> java.lang.String:
        ...

    @property
    def checkoutTime(self) -> jpype.JLong:
        ...

    @property
    def checkoutId(self) -> jpype.JLong:
        ...

    @property
    def user(self) -> java.lang.String:
        ...

    @property
    def checkoutType(self) -> CheckoutType:
        ...


class CheckoutType(java.lang.Enum[CheckoutType]):
    """
    ``ChecoutType`` identifies the type of checkout
    """

    class_: typing.ClassVar[java.lang.Class]
    NORMAL: typing.Final[CheckoutType]
    """
    Checkout is a normal non-exclusive checkout
    """

    EXCLUSIVE: typing.Final[CheckoutType]
    """
    Checkout is a persistent exclusive checkout which 
    ensures no other checkout can occur while this checkout
    persists.
    """

    TRANSIENT: typing.Final[CheckoutType]
    """
    Similar to an EXCLUSIVE checkout, this checkout only 
    persists while the associated client-connection is
    alive.  This checkout is only permitted for remote
    versioned file systems which support its use.
    """

    serialVersionUID: typing.Final = 1
    """
    Rely on standard Java serialization for enum
    If the above enum naming/order is changed, the server
    interface version must be changed
    
    
    .. seealso::
    
        | :obj:`GhidraServerHandle`
    """


    @staticmethod
    def getCheckoutType(typeID: typing.Union[jpype.JInt, int]) -> CheckoutType:
        """
        Get the CheckoutType whose name corresponds to the specified ID
        
        :param jpype.JInt or int typeID: checkout type ID
        :return: CheckoutType of null if ID is invalid
        :rtype: CheckoutType
        """

    def getID(self) -> int:
        """
        Get the abbreviated/short name for this checkout type
        for use with serialization.
        
        :return: short name
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CheckoutType:
        ...

    @staticmethod
    def values() -> jpype.JArray[CheckoutType]:
        ...

    @property
    def iD(self) -> jpype.JInt:
        ...


class FileSystem(java.lang.Object):
    """
    ``FileSystem`` provides a hierarchical view and management of a 
    set of files and folders.
    """

    class_: typing.ClassVar[java.lang.Class]
    SEPARATOR_CHAR: typing.Final = '/'
    """
    Character used to separate folder and item names within a path string.
    """

    SEPARATOR: typing.Final[java.lang.String]

    def addFileSystemListener(self, listener: FileSystemListener):
        """
        Adds the given listener to be notified of file system changes.
        
        :param FileSystemListener listener: the listener to be added.
        """

    def createDataFile(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], istream: java.io.InputStream, comment: typing.Union[java.lang.String, str], contentType: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> DataFileItem:
        """
        Creates a new empty data file within the specified parent folder.
        
        :param java.lang.String or str parentPath: folder path of parent
        :param java.lang.String or str name: new data file name
        :param java.io.InputStream istream: source data
        :param java.lang.String or str comment: version comment (used for versioned file system only)
        :param java.lang.String or str contentType: application defined content type
        :param ghidra.util.task.TaskMonitor monitor: progress monitor (used for cancel support, 
        progress not used since length of input stream is unknown)
        :return: new data file
        :rtype: DataFileItem
        :raises DuplicateFileException: Thrown if a folderItem with that name already exists.
        :raises InvalidNameException: if the name has illegal characters.
        all alphanumerics
        :raises IOException: if an IO error occurs.
        :raises CancelledException: if cancelled by monitor
        """

    @typing.overload
    def createDatabase(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str], bufferFile: db.buffers.BufferFile, comment: typing.Union[java.lang.String, str], contentType: typing.Union[java.lang.String, str], resetDatabaseId: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor, user: typing.Union[java.lang.String, str]) -> DatabaseItem:
        """
        Create a new database item within the specified parent folder using the contents
        of the specified BufferFile.
        
        :param java.lang.String or str parentPath: folder path of parent
        :param java.lang.String or str name: new database name
        :param java.lang.String or str fileID: file ID to be associated with new database or null
        :param db.buffers.BufferFile bufferFile: data source
        :param java.lang.String or str comment: version comment (used for versioned file system only)
        :param java.lang.String or str contentType: application defined content type
        :param jpype.JBoolean or bool resetDatabaseId: if true database ID will be reset for new Database
        :param ghidra.util.task.TaskMonitor monitor: allows the database copy to be monitored and cancelled.
        :param java.lang.String or str user: name of user creating item (required for versioned item)
        :return: new DatabaseItem
        :rtype: DatabaseItem
        :raises FileNotFoundException: thrown if parent folder does not exist.
        :raises DuplicateFileException: if a folder item exists with this name
        :raises InvalidNameException: if the name does not have
        all alphanumerics
        :raises IOException: if an IO error occurs.
        :raises CancelledException: if cancelled by monitor
        """

    @typing.overload
    def createDatabase(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str], contentType: typing.Union[java.lang.String, str], bufferSize: typing.Union[jpype.JInt, int], user: typing.Union[java.lang.String, str], projectPath: typing.Union[java.lang.String, str]) -> db.buffers.ManagedBufferFile:
        """
        Create a new empty database item within the specified parent folder. 
        If this is a versioned file-system, the associated item is checked-out.
        The resulting checkoutId can be obtained from the returned buffer file.
        
        :param java.lang.String or str parentPath: folder path of parent
        :param java.lang.String or str name: new database name
        :param java.lang.String or str fileID: file ID to be associated with new database or null
        :param java.lang.String or str contentType: application defined content type
        :param jpype.JInt or int bufferSize: buffer size.  If copying an existing BufferFile, the buffer 
        size must be the same as the source file.
        :param java.lang.String or str user: name of user creating item (required for versioned item)
        :param java.lang.String or str projectPath: path of project in which database is checked-out (required for versioned item)
        :return: an empty BufferFile open for read-write.
        :rtype: db.buffers.ManagedBufferFile
        :raises FileNotFoundException: thrown if parent folder does not exist.
        :raises DuplicateFileException: if a folder item exists with this name
        :raises InvalidNameException: if the name does not have
        all alphanumerics
        :raises IOException: if an IO error occurs.
        """

    def createFile(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], packedFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor, user: typing.Union[java.lang.String, str]) -> FolderItem:
        """
        Creates a new file item from a packed file.
        The content/item type must be determined from the input stream.
        
        :param java.lang.String or str parentPath: folder path of parent
        :param java.lang.String or str name: new data file name
        :param jpype.protocol.SupportsPath packedFile: packed file data
        :param ghidra.util.task.TaskMonitor monitor: progress monitor (used for cancel support, 
        progress not used since length of input stream is unknown)
        :param java.lang.String or str user: name of user creating item (required for versioned item)
        :return: new item
        :rtype: FolderItem
        :raises InvalidNameException: if the name has illegal characters.
        all alphanumerics
        :raises IOException: if an IO error occurs.
        :raises CancelledException: if cancelled by monitor
        """

    def createFolder(self, parentPath: typing.Union[java.lang.String, str], folderName: typing.Union[java.lang.String, str]):
        """
        Creates a new subfolder within the specified parent folder.
        
        :param java.lang.String or str parentPath: folder path of parent
        :param java.lang.String or str folderName: name of new subfolder
        :raises DuplicateFileException: if a folder exists with this name
        :raises InvalidNameException: if the name does not have
        all alphanumerics
        :raises IOException: thrown if an IO error occurs.
        """

    def deleteFolder(self, folderPath: typing.Union[java.lang.String, str]):
        """
        Delete the specified folder.
        
        :param java.lang.String or str folderPath: path of folder to be deleted
        :raises FolderNotEmptyException: Thrown if the folder is not empty.
        :raises FileNotFoundException: if there is no folder with the given path name.
        :raises IOException: if error occurred during delete.
        """

    def dispose(self):
        """
        Cleanup and release resources
        """

    def fileExists(self, folderPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the file exists
        
        :param java.lang.String or str folderPath: the folderPath of the folder that may contain the file.
        :param java.lang.String or str name: the name of the file to check for existence.
        :raises IOException: if an IO error occurs.
        """

    def folderExists(self, folderPath: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the folder specified by the path exists.
        
        :param java.lang.String or str folderPath: the name of the folder to check for existence.
        :return: true if the folder exists.
        :rtype: bool
        :raises IOException: if an IO error occurs.
        """

    def getFolderNames(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Return a list of subfolders (by name) that are stored within the specified folder path.
        
        :raises FileNotFoundException: if folder path does not exist.
        :raises IOException: if IO error occurs.
        """

    @typing.overload
    def getItem(self, folderPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> FolderItem:
        """
        Returns the FolderItem in the given folder with the given name
        
        :param java.lang.String or str folderPath: the folder path containing the item.
        :param java.lang.String or str name: the name of the item.
        :return: the FolderItem with the given folderPath and name, or null if it doesn't exist.
        :rtype: FolderItem
        :raises IOException: if IO error occurs.
        """

    @typing.overload
    def getItem(self, fileID: typing.Union[java.lang.String, str]) -> FolderItem:
        """
        Returns the FolderItem specified by its unique File-ID
        
        :param java.lang.String or str fileID: the items unique file ID
        :return: the FolderItem with the given folderPath and name, or null if it doesn't exist.
        :rtype: FolderItem
        :raises IOException: if IO error occurs.
        :raises java.lang.UnsupportedOperationException: if file-system does not support this operation
        """

    def getItemCount(self) -> int:
        """
        Returns the number of folder items contained within this file-system.
        
        :raises IOException: 
        :raises java.lang.UnsupportedOperationException: if file-system does not support this operation
        """

    def getItemNames(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of the folder item names contained in the given folder.
        
        :param java.lang.String or str folderPath: the path of the folder.
        :return: a list of folder item names.
        :rtype: jpype.JArray[java.lang.String]
        :raises IOException:
        """

    def getItems(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[FolderItem]:
        """
        Returns a list of the folder items contained in the given folder.
        
        :param java.lang.String or str folderPath: the path of the folder.
        :return: a list of folder items.  Null items may exist if index contained item name
        while storage was not found.  An :obj:`UnknownFolderItem` may be returned if unsupported
        item storage encountered.
        :rtype: jpype.JArray[FolderItem]
        :raises IOException:
        """

    def getUserName(self) -> str:
        """
        Get user name associated with this filesystem.  In the case of a remote filesystem
        this will correspond to the name used during login/authentication.  A null value may 
        be returned if user name unknown.
        """

    def isOnline(self) -> bool:
        """
        Returns true if file-system is on-line.
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if file-system is read-only.
        
        :raises IOException:
        """

    def isShared(self) -> bool:
        """
        Returns true if this file system is shared
        """

    def isVersioned(self) -> bool:
        """
        Returns true if the file-system requires check-outs when
        modifying folder items.
        """

    def moveFolder(self, parentPath: typing.Union[java.lang.String, str], folderName: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str]):
        """
        Move the specified folder to the path specified by newFolderPath. 
        The moved folder must not be an ancestor of the new Parent.
        
        :param java.lang.String or str parentPath: path of parent folder that the moving folder currently resides in.
        :param java.lang.String or str folderName: name of the folder within the parentPath to be moved.
        :param java.lang.String or str newParentPath: path to where the folder is to be moved.
        :raises FileNotFoundException: if the moved folder does not exist.
        :raises DuplicateFileException: if folder with the same name exists within the new parent folder
        :raises FileInUseException: if any file within this folder or its descendants are in-use or checked-out
        :raises IOException: if an IO error occurs.
        :raises InvalidNameException: if the new FolderPath contains an illegal file name.
        :raises IllegalArgumentException: if new Parent is invalid.
        """

    def moveItem(self, folderPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], newFolderPath: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Moves the specified item to a new folder.
        
        :param java.lang.String or str folderPath: path of folder containing the item.
        :param java.lang.String or str name: name of the item to be moved.
        :param java.lang.String or str newFolderPath: path of folder where item is to be moved.
        :raises FileNotFoundException: if the item does not exist.
        :raises DuplicateFileException: if item with the same name exists within the new parent folder.
        :raises FileInUseException: if the item is in-use or checked-out
        :raises IOException: if an IO error occurs.
        :raises InvalidNameException: if the newName is invalid
        """

    def removeFileSystemListener(self, listener: FileSystemListener):
        """
        Removes the listener from being notified of file system changes.
        
        :param FileSystemListener listener:
        """

    def renameFolder(self, parentPath: typing.Union[java.lang.String, str], folderName: typing.Union[java.lang.String, str], newFolderName: typing.Union[java.lang.String, str]):
        """
        Renames the specified folder to a new name.
        
        :param java.lang.String or str parentPath: the parent folder of the folder to be renamed.
        :param java.lang.String or str folderName: the current name of the folder to be renamed.
        :param java.lang.String or str newFolderName: the name the folder to be renamed to.
        :raises FileNotFoundException: if the folder to be renamed does not exist.
        :raises DuplicateFileException: if folder with the new name already exists.
        :raises FileInUseException: if any file within this folder or its descendants are in-use or checked-out
        :raises IOException: if an IO error occurs.
        :raises InvalidNameException: if the new FolderName contains an illegal file name.
        """

    @property
    def shared(self) -> jpype.JBoolean:
        ...

    @property
    def item(self) -> FolderItem:
        ...

    @property
    def versioned(self) -> jpype.JBoolean:
        ...

    @property
    def folderNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def online(self) -> jpype.JBoolean:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...

    @property
    def items(self) -> jpype.JArray[FolderItem]:
        ...

    @property
    def itemNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def itemCount(self) -> jpype.JInt:
        ...


class DataFileItem(FolderItem):
    """
    ``DataFileItem`` corresponds to a private serialized
    data file within a FileSystem.  Methods are provided for opening
    the underlying file as an input or output stream.
     
    
    NOTE: The use of DataFile is not encouraged and is not fully
    supported.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getInputStream(self) -> java.io.InputStream:
        """
        Open the current version of this item for reading.
        
        :return: input stream
        :rtype: java.io.InputStream
        :raises FileNotFoundException:
        """

    @typing.overload
    def getInputStream(self, version: typing.Union[jpype.JInt, int]) -> java.io.InputStream:
        """
        Open a specific version of this item for reading.
        
        :return: input stream
        :rtype: java.io.InputStream
        :raises FileNotFoundException:
        """

    def getOutputStream(self) -> java.io.OutputStream:
        """
        Open a new version of this item for writing.
        
        :return: output stream.
        :rtype: java.io.OutputStream
        :raises FileNotFoundException:
        """

    @property
    def inputStream(self) -> java.io.InputStream:
        ...

    @property
    def outputStream(self) -> java.io.OutputStream:
        ...


class FolderNotEmptyException(java.io.IOException):
    """
    ``FolderNotEmptyException`` is thrown when an attempt is
    made to remove a Folder which is not empty.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str msg: error message
        """


class FileSystemSynchronizer(java.lang.Object):
    """
    This class is essentially a global flag used to track the long running file system synchronizing
    operation.   This class is a workaround to avoid rewriting the complicated file system locking.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def isSynchronizing() -> bool:
        """
        Returns true the underlying file system is going through a long-running synchronization 
        operation while holding the ``filesystem`` lock.   Calling this method allows clients
        in the Swing thread to avoid  calling methods that require a file system lock, which would
        cause the UI to lock during the synchronizing operation.
        
        :return: true if synchronizing
        :rtype: bool
        """

    @staticmethod
    def setSynchronizing(b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the synchronizing operation is running.
        
        :param jpype.JBoolean or bool b: true if synchronizing
        """


class DatabaseItem(FolderItem):
    """
    ``DatabaseItem`` corresponds to a private or versioned 
    database within a FileSystem.  Methods are provided for opening
    the underlying database as a BufferFile.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def open(self, version: typing.Union[jpype.JInt, int], minChangeDataVer: typing.Union[jpype.JInt, int]) -> db.buffers.ManagedBufferFile:
        """
        Open a specific version of the stored database for non-update use.
        Historical change data from minChangeDataVer through version is available.
        The returned BufferFile does not support the BufferMgr's Save operation.
        
        :param jpype.JInt or int version: database version
        :param jpype.JInt or int minChangeDataVer: indicates the oldest change data version to be
        included in change set.  A -1 indicates only the last change data buffer file is applicable.
        :return: buffer file
        :rtype: db.buffers.ManagedBufferFile
        :raises FileInUseException: thrown if unable to obtain the required database lock(s).
        :raises IOException: thrown if IO error occurs.
        
        .. seealso::
        
            | :obj:`ManagedBufferFile.getNextChangeDataFile(boolean)`
        """

    @typing.overload
    def open(self, version: typing.Union[jpype.JInt, int]) -> db.buffers.ManagedBufferFile:
        """
        Open a specific version of the stored database for non-update use.
        Change data will not be available.
        The returned BufferFile does not support the BufferMgr's Save operation.
        
        :param jpype.JInt or int version: database version
        :return: buffer file
        :rtype: db.buffers.ManagedBufferFile
        :raises FileInUseException: thrown if unable to obtain the required database lock(s).
        :raises IOException: thrown if IO error occurs.
        """

    @typing.overload
    def open(self) -> db.buffers.ManagedBufferFile:
        """
        Open the current version of the stored database for non-update use.
        Change data will not be available.
        The returned BufferFile does not support the BufferMgr's Save operation.
        
        :raises IOException: thrown if IO error occurs.
        """

    def openForUpdate(self, checkoutId: typing.Union[jpype.JLong, int]) -> db.buffers.ManagedBufferFile:
        """
        Open the current version of the stored database for update use.
        The returned BufferFile supports the Save operation.
        If this item is on a shared file-system, this method initiates an
        item checkin.  If a changeSet is specified, it will be filled with 
        all change data since the check-out version.  Change data will be 
        read into the change set starting oldest to newest.
        
        :param jpype.JLong or int checkoutId: the associated checkoutId if this item is stored
        on a versioned file-system, otherwise DEFAULT_CHECKOUT_ID can be 
        specified.
        :return: buffer file
        :rtype: db.buffers.ManagedBufferFile
        :raises FileInUseException: thrown if unable to obtain the required database lock(s).
        :raises IOException: thrown if IO error occurs.
        """


class FileSystemEventManager(FileSystemListener):
    """
    ``FileSystemListenerList`` maintains a list of FileSystemListener's.
    This class, acting as a FileSystemListener, simply relays each callback to
    all FileSystemListener's within its list.  Employs either a synchronous 
    and asynchronous notification mechanism. Once disposed event dispatching will 
    discontinue.
    """

    @typing.type_check_only
    class ThreadState(java.lang.Enum[FileSystemEventManager.ThreadState]):

        class_: typing.ClassVar[java.lang.Class]
        STOPPED: typing.Final[FileSystemEventManager.ThreadState]
        RUNNING: typing.Final[FileSystemEventManager.ThreadState]
        DISPOSED: typing.Final[FileSystemEventManager.ThreadState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FileSystemEventManager.ThreadState:
            ...

        @staticmethod
        def values() -> jpype.JArray[FileSystemEventManager.ThreadState]:
            ...


    @typing.type_check_only
    class FileSystemEventProcessingThread(java.lang.Thread):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FileSystemEvent(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ItemMovedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ItemRenamedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ItemDeletedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FolderMovedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FolderRenamedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FolderDeletedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ItemCreatedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FolderCreatedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ItemChangedEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SynchronizeEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MarkerEvent(FileSystemEventManager.FileSystemEvent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, enableAsynchronousDispatching: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param jpype.JBoolean or bool enableAsynchronousDispatching: if true a separate dispatch thread will be used
        to notify listeners.  If false, blocking notification will be performed.  Events are 
        immediately discarded in the absence of any listener(s).
        """

    def add(self, listener: FileSystemListener):
        """
        Add a listener to this list.
        
        :param FileSystemListener listener: the listener
        """

    def dispose(self):
        """
        Discontinue event dispatching and terminate dispatch thread if it exists.
        """

    def flushEvents(self, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit) -> bool:
        """
        Blocks until all current events have been processed.
         
        
        Note: clients should only use this method when :meth:`isAsynchronous() <.isAsynchronous>` returns true, since
        this class cannot track when non-threaded events have finished broadcasting to listeners.
        In a synchronous use case, any test that needs to know when client events have been processed
        must use some other mechanism to know when event processing is finished.
        
        :param jpype.JLong or int timeout: the maximum time to wait
        :param java.util.concurrent.TimeUnit unit: the time unit of the ``time`` argument
        :return: true if the events were processed in the given timeout.  A false value will be
        returned if either a timeout occured
        :rtype: bool
        """

    def isAsynchronous(self) -> bool:
        """
        Return true if asynchornous event processing is enabled.
        
        :return: true if asynchornous event processing is enabled, else false
        :rtype: bool
        """

    def remove(self, listener: FileSystemListener):
        """
        Remove a listener from this list.
        
        :param FileSystemListener listener: the listener
        """

    @property
    def asynchronous(self) -> jpype.JBoolean:
        ...


class ExclusiveCheckoutException(java.io.IOException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...


class FileSystemListener(java.lang.Object):
    """
    ``FileSystemListener`` provides a listener the ability 
    to be notified of folder and file changes within a FileSystem.
    """

    class_: typing.ClassVar[java.lang.Class]

    def folderCreated(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Notification that a new folder was created.
        
        :param java.lang.String or str parentPath: the path of the folder that contains the new folder
        :param java.lang.String or str name: the name of the new folder
        """

    def folderDeleted(self, parentPath: typing.Union[java.lang.String, str], folderName: typing.Union[java.lang.String, str]):
        """
        Notification that a folder was deleted.
        
        :param java.lang.String or str parentPath: the path of the folder that contained the deleted folder.
        :param java.lang.String or str folderName: the name of the folder that was deleted.
        """

    def folderMoved(self, parentPath: typing.Union[java.lang.String, str], folderName: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str]):
        """
        Notification that a folder was moved.
        
        :param java.lang.String or str parentPath: the path of the folder that used to contain the moved folder.
        :param java.lang.String or str folderName: the name of the folder that was moved.
        :param java.lang.String or str newParentPath: the path of the folder that now contains the moved folder.
        """

    def folderRenamed(self, parentPath: typing.Union[java.lang.String, str], oldFolderName: typing.Union[java.lang.String, str], newFolderName: typing.Union[java.lang.String, str]):
        """
        Notification that a folder was renamed.
        
        :param java.lang.String or str parentPath: the path of the folder containing the folder that was renamed.
        :param java.lang.String or str oldFolderName: the old name of the folder.
        :param java.lang.String or str newFolderName: the new name of the folder.
        """

    def itemChanged(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]):
        """
        Notfication that an item's state has changed.
        
        :param java.lang.String or str parentPath: the path of the folder containing the item.
        :param java.lang.String or str itemName: the name of the item that has changed.
        """

    def itemCreated(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Notification that a new folder item was created.
        
        :param java.lang.String or str parentPath: the path of the folder that contains the new item.
        :param java.lang.String or str name: the name of the new item.
        """

    def itemDeleted(self, folderPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]):
        """
        Notification that a folder item was deleted.
        
        :param java.lang.String or str folderPath: the path of the folder that contained the deleted item.
        :param java.lang.String or str itemName: the name of the item that was deleted.
        """

    def itemMoved(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Notification that an item was moved.
        
        :param java.lang.String or str parentPath: the path of the folder that used to contain the item.
        :param java.lang.String or str name: the name of the item that was moved.
        :param java.lang.String or str newParentPath: the path of the folder that the item was moved to.
        :param java.lang.String or str newName: the new name of the item.
        """

    def itemRenamed(self, folderPath: typing.Union[java.lang.String, str], oldItemName: typing.Union[java.lang.String, str], newItemName: typing.Union[java.lang.String, str]):
        """
        Notification that an item was renamed.
        
        :param java.lang.String or str folderPath: the path of the folder that contains the renamed item
        :param java.lang.String or str oldItemName: the old name of the item.
        :param java.lang.String or str newItemName: the new name of the item.
        """

    def syncronize(self):
        """
        Perform a full refresh / synchronization
        """


class FolderItem(java.lang.Object):
    """
    ``FolderItem`` represents an individual file
    contained within a FileSystem and is uniquely identified 
    by a path string.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN_FILE_TYPE: typing.Final = -1
    """
    Underlying file is an unknown/unsupported type.
    """

    DATABASE_FILE_TYPE: typing.Final = 0
    """
    Underlying file is a Database
    """

    DATAFILE_FILE_TYPE: typing.Final = 1
    """
    Underlying file is serialized data file
    """

    DEFAULT_CHECKOUT_ID: typing.Final = -1
    """
    Default checkout ID used when a checkout is not applicable.
    """

    LATEST_VERSION: typing.Final = -1
    """
    Default file version number used to indicate the latest/current version.
    """


    def canRecover(self) -> bool:
        """
        Returns true if unsaved file changes can be recovered.
        """

    def checkout(self, checkoutType: CheckoutType, user: typing.Union[java.lang.String, str], projectPath: typing.Union[java.lang.String, str]) -> ItemCheckoutStatus:
        """
        Checkout this folder item.
        
        :param CheckoutType checkoutType: type of checkout
        :param java.lang.String or str user: user requesting checkout
        :param java.lang.String or str projectPath: path of project where checkout was made
        :return: checkout status or null if exclusive checkout request failed
        :rtype: ItemCheckoutStatus
        :raises IOException: if an IO error occurs or this item is not versioned
        """

    def clearCheckout(self):
        """
        Clears the checkout data associated with this non-shared file.
        NOTE: This method is only valid for a local non-versioned file-system.
        
        :raises IOException:
        """

    def delete(self, version: typing.Union[jpype.JInt, int], user: typing.Union[java.lang.String, str]):
        """
        Deletes the item or a specific version.  If a specific version 
        is specified, it must either be the oldest or latest (i.e., current).
        
        :param jpype.JInt or int version: specific version to be deleted, or -1 to remove
        all versions.
        :param java.lang.String or str user: user name
        :raises IOException: if an IO error occurs, including the inability 
        to delete a version because this item is checked-out, the user does
        not have permission, or the specified version is not the oldest or
        latest.
        """

    def getCheckout(self, checkoutId: typing.Union[jpype.JLong, int]) -> ItemCheckoutStatus:
        """
        Get the checkout status which corresponds to the specified checkout ID.
        
        :param jpype.JLong or int checkoutId: checkout ID
        :return: checkout status or null if checkout ID not found.
        :rtype: ItemCheckoutStatus
        :raises IOException: if an IO error occurs or this item is not versioned
        """

    def getCheckoutId(self) -> int:
        """
        Returns the checkoutId for this file.  A value of -1 indicates 
        a private item.
        NOTE: This method is only valid for a local non-versioned file-system.
        
        :raises IOException: if an IO error occurs
        """

    def getCheckoutVersion(self) -> int:
        """
        Returns the item version which was checked-out.  A value of -1 indicates 
        a private item. 
        NOTE: This method is only valid for a local non-versioned file-system.
        
        :raises IOException:
        """

    def getCheckouts(self) -> jpype.JArray[ItemCheckoutStatus]:
        """
        Get all current checkouts for this item.
        
        :return: array of checkouts
        :rtype: jpype.JArray[ItemCheckoutStatus]
        :raises IOException: if an IO error occurs or this item is not versioned
        """

    def getContentType(self) -> str:
        """
        Return The content type name for this item.
        """

    def getContentTypeVersion(self) -> int:
        """
        Returns the version of content type.  Note this is the version of the structure/storage
        for the content type, Not the users version of their data.
        """

    def getCurrentVersion(self) -> int:
        """
        Return the latest/current version.
        """

    def getFileID(self) -> str:
        """
        Return the file ID if one has been established or null
        """

    def getLocalCheckoutVersion(self) -> int:
        """
        Returns the local item version at the time the checkout was
        completed.  A value of -1 indicates a private item.  
        NOTE: This method is only valid for a local non-versioned file-system.
        """

    def getName(self) -> str:
        """
        Return The display name for this item.
        """

    def getParentPath(self) -> str:
        """
        Returns the path of the parent folder.
        """

    def getPathName(self) -> str:
        """
        Return The concatenation of the pathname and the basename
        which can be used to uniquely identify a folder item.
        """

    def getVersions(self) -> jpype.JArray[Version]:
        """
        Returns list of all available versions or null
        if item is not versioned.
        
        :raises IOException: thrown if an IO error occurs.
        """

    def hasCheckouts(self) -> bool:
        """
        Returns true if this item is versioned and has one or more checkouts.
        
        :raises IOException: if an IO error occurs
        """

    def isCheckedOut(self) -> bool:
        """
        Returns true if this item is a checked-out copy from a versioned file system.
        """

    def isCheckedOutExclusive(self) -> bool:
        """
        Returns true if this item is a checked-out copy with exclusive access from a versioned file system.
        """

    def isCheckinActive(self) -> bool:
        """
        Returns true if this item is versioned and has a checkin in-progress.
        
        :raises IOException: if an IO error occurs
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if item can be overwritten/deleted.
        """

    def isVersioned(self) -> bool:
        """
        Return true if this is a versioned item, else false
        
        :raises IOException: thrown if an IO error occurs.
        """

    def lastModified(self) -> int:
        """
        Return The time that this item was last modified.
        """

    def length(self) -> int:
        """
        Returns the length of this domain file.  This size is the minimum disk space
        used for storing this file, but does not account for additional storage space
        used to tracks changes, etc.
        
        :return: file length
        :rtype: int
        :raises IOException: thrown if IO or access error occurs
        """

    def output(self, outputFile: jpype.protocol.SupportsPath, version: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Serialize (i.e., pack) this item into the specified outputFile.
        
        :param jpype.protocol.SupportsPath outputFile: packed output file to be created
        :param jpype.JInt or int version: if this item is versioned, specifies the version to be output, otherwise
        -1 should be specified.
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises IOException: 
        :raises CancelledException: if monitor cancels operation
        """

    def refresh(self) -> FolderItem:
        """
        Returns this instance after refresh or null if item no longer exists
        """

    def resetFileID(self) -> str:
        """
        Assign a new file-ID to this local non-versioned file.
        NOTE: This method is only valid for a local non-versioned file-system.
        
        :return: new file-ID
        :rtype: str
        :raises IOException: thrown if IO or access error occurs
        """

    def setCheckout(self, checkoutId: typing.Union[jpype.JLong, int], exclusive: typing.Union[jpype.JBoolean, bool], checkoutVersion: typing.Union[jpype.JInt, int], localVersion: typing.Union[jpype.JInt, int]):
        """
        Set the checkout data associated with this non-shared file.
        NOTE: This method is only valid for a local non-versioned file-system.
        
        :param jpype.JLong or int checkoutId: checkout ID (provided by ItemCheckoutStatus).
        :param jpype.JBoolean or bool exclusive: true if checkout is exclusive
        :param jpype.JInt or int checkoutVersion: the item version which was checked-out (provided
        by ItemCheckoutStatus).
        :param jpype.JInt or int localVersion: the local item version at the time the checkout was
        completed.
        :raises IOException: if an IO error occurs or item is 
        stored on a shared file-system
        """

    def setContentTypeVersion(self, version: typing.Union[jpype.JInt, int]):
        """
        Sets the version for the content type. This will change whenever the domain objects
        are upgraded.
        
        :param jpype.JInt or int version: the new version for the content type.
        :raises IOException: if an IO error occurs or item is 
        stored on a shared file-system
        """

    def setReadOnly(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Set the state of the read-only indicator for this non-shared item.
        
        :param jpype.JBoolean or bool state: read-only state
        :raises IOException: if an IO error occurs or item is 
        stored on a shared file-system
        """

    def terminateCheckout(self, checkoutId: typing.Union[jpype.JLong, int], notify: typing.Union[jpype.JBoolean, bool]):
        """
        Terminates a checkout.  The checkout ID becomes invalid, therefore the 
        associated checkout copy should either be removed or converted to a
        private file.
        
        :param jpype.JLong or int checkoutId: checkout ID
        :param jpype.JBoolean or bool notify: if true item change notification will be sent
        :raises IOException: if an IO error occurs or this item is not versioned
        """

    def updateCheckoutVersion(self, checkoutId: typing.Union[jpype.JLong, int], checkoutVersion: typing.Union[jpype.JInt, int], user: typing.Union[java.lang.String, str]):
        """
        Update the checkout version associated with this versioned item.
        
        :param jpype.JLong or int checkoutId: id corresponding to an existing checkout
        :param jpype.JInt or int checkoutVersion: 
        :param java.lang.String or str user: 
        :raises IOException: if an IO error occurs.
        """

    @property
    def checkedOut(self) -> jpype.JBoolean:
        ...

    @property
    def pathName(self) -> java.lang.String:
        ...

    @property
    def checkouts(self) -> jpype.JArray[ItemCheckoutStatus]:
        ...

    @property
    def checkedOutExclusive(self) -> jpype.JBoolean:
        ...

    @property
    def parentPath(self) -> java.lang.String:
        ...

    @property
    def contentTypeVersion(self) -> jpype.JInt:
        ...

    @contentTypeVersion.setter
    def contentTypeVersion(self, value: jpype.JInt):
        ...

    @property
    def localCheckoutVersion(self) -> jpype.JInt:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @readOnly.setter
    def readOnly(self, value: jpype.JBoolean):
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...

    @property
    def versions(self) -> jpype.JArray[Version]:
        ...

    @property
    def versioned(self) -> jpype.JBoolean:
        ...

    @property
    def checkoutVersion(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def checkinActive(self) -> jpype.JBoolean:
        ...

    @property
    def checkoutId(self) -> jpype.JLong:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...

    @property
    def fileID(self) -> java.lang.String:
        ...



__all__ = ["FileIDFactory", "DataFileHandle", "FileSystemInitializer", "Version", "LockException", "ItemCheckoutStatus", "CheckoutType", "FileSystem", "DataFileItem", "FolderNotEmptyException", "FileSystemSynchronizer", "DatabaseItem", "FileSystemEventManager", "ExclusiveCheckoutException", "FileSystemListener", "FolderItem"]
