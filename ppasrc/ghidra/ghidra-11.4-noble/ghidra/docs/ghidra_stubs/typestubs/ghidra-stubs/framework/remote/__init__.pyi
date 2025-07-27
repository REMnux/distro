from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db.buffers
import ghidra.framework.store
import java.io # type: ignore
import java.lang # type: ignore
import java.rmi # type: ignore
import java.security # type: ignore
import javax.security.auth # type: ignore
import javax.security.auth.callback # type: ignore


class RemoteRepositoryHandle(RepositoryHandle, java.rmi.Remote):
    """
    ``RepositoryHandle`` provides access to a remote repository via RMI.
     
    
    Methods from :obj:`RepositoryHandle` **must** be re-declared here
    so they may be properly marshalled for remote invocation via RMI.  
    This became neccessary with an OpenJDK 11.0.6 change made to 
    :obj:`RemoteObjectInvocationHandler`.
    """

    class_: typing.ClassVar[java.lang.Class]


class GhidraPrincipal(java.security.Principal, java.io.Serializable):
    """
    ``GhidraPrincipal`` specifies a Ghidra user as a Principal
    for use with server login/authentication.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self, username: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str username: user id/name
        """

    @staticmethod
    def getGhidraPrincipal(subj: javax.security.auth.Subject) -> GhidraPrincipal:
        """
        Returns the GhidraPrincipal object contained within a Subject, or null if
        not found.
        
        :param javax.security.auth.Subject subj: user subject
        :return: GhidraPrincipal or null
        :rtype: GhidraPrincipal
        """

    def getName(self) -> str:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class RepositoryItem(java.io.Serializable):
    """
    ``RepositoryItemStatus`` provides status information for a 
    repository folder item.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 2
    FILE: typing.Final = 1
    DATABASE: typing.Final = 2

    def __init__(self, folderPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str], itemType: typing.Union[jpype.JInt, int], contentType: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], versionTime: typing.Union[jpype.JLong, int]):
        """
        Constructor.
        
        :param java.lang.String or str folderPath: path of folder containing item.
        :param java.lang.String or str itemName: name of item
        :param java.lang.String or str fileID: unique file ID
        :param jpype.JInt or int itemType: type of item (FILE or DATABASE)
        :param java.lang.String or str contentType: content type associated with item
        :param jpype.JInt or int version: repository item version or -1 if versioning not supported
        :param jpype.JLong or int versionTime: version creation time
        """

    def getContentType(self) -> str:
        """
        Returns content class
        """

    def getFileID(self) -> str:
        ...

    def getItemType(self) -> int:
        """
        Returns type of item.
        """

    def getName(self) -> str:
        """
        Returns the item name.
        """

    def getParentPath(self) -> str:
        """
        Returns path of the parent folder containing this item.
        """

    def getPathName(self) -> str:
        """
        Returns the folder item path within the repository.
        """

    def getVersion(self) -> int:
        """
        Returns the current version of the item or 
        -1 if versioning not supported.
        """

    def getVersionTime(self) -> int:
        """
        Returns the time (UTC milliseconds) when the current version was created.
        """

    @property
    def pathName(self) -> java.lang.String:
        ...

    @property
    def itemType(self) -> jpype.JInt:
        ...

    @property
    def versionTime(self) -> jpype.JLong:
        ...

    @property
    def parentPath(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def contentType(self) -> java.lang.String:
        ...

    @property
    def fileID(self) -> java.lang.String:
        ...


class RepositoryHandle(java.lang.Object):
    """
    ``RepositoryHandle`` provides access to a repository.
    """

    class_: typing.ClassVar[java.lang.Class]
    CLIENT_CHECK_PERIOD: typing.Final[jpype.JInt]

    def anonymousAccessAllowed(self) -> bool:
        """
        
        
        :return: true if anonymous access allowed by this repository
        :rtype: bool
        :raises IOException: if an IO error occurs
        """

    def checkout(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutType: ghidra.framework.store.CheckoutType, projectPath: typing.Union[java.lang.String, str]) -> ghidra.framework.store.ItemCheckoutStatus:
        """
        Perform a checkout on the specified item.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :param ghidra.framework.store.CheckoutType checkoutType: checkout type.  If exclusive or transient, checkout is only successful 
        if no other checkouts exist.  No new checkouts of item will be permitted while an 
        exclusive/transient checkout is active.
        :param java.lang.String or str projectPath: path of user's project
        :return: checkout data
        :rtype: ghidra.framework.store.ItemCheckoutStatus
        :raises IOException: if an IO error occurs
        """

    def close(self):
        """
        Notification to server that client is dropping handle.
        
        :raises IOException: if error occurs
        """

    def createDatabase(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str], bufferSize: typing.Union[jpype.JInt, int], contentType: typing.Union[java.lang.String, str], projectPath: typing.Union[java.lang.String, str]) -> db.buffers.ManagedBufferFileHandle:
        """
        Create a new empty database item within the repository.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: new item name
        :param java.lang.String or str fileID: unique file ID
        :param jpype.JInt or int bufferSize: buffer file buffer size
        :param java.lang.String or str contentType: application content type
        :param java.lang.String or str projectPath: path of user's project
        :return: initial buffer file open for writing
        :rtype: db.buffers.ManagedBufferFileHandle
        :raises UserAccessException: if user does not have adequate permission within the repository.
        :raises DuplicateFileException: item path already exists within repository
        :raises IOException: if an IO error occurs
        :raises InvalidNameException: if itemName or parentPath contains invalid characters
        """

    def deleteItem(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int]):
        """
        Delete the specified version of an item.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :param jpype.JInt or int version: oldest or latest version of item to be deleted, or -1
        to delete the entire item.  User must be Admin or owner of version to be
        deleted.
        :raises IOException: if an IO error occurs
        """

    def fileExists(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified item exists.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :raises IOException: if an IO error occurs
        """

    def folderExists(self, folderPath: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified folder path exists.
        
        :param java.lang.String or str folderPath: folder path
        :raises IOException: if an IO error occurs
        """

    def getCheckout(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int]) -> ghidra.framework.store.ItemCheckoutStatus:
        """
        Returns specific checkout data for an item.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :param jpype.JLong or int checkoutId: checkout ID
        :return: checkout data
        :rtype: ghidra.framework.store.ItemCheckoutStatus
        :raises IOException: if an IO error occurs
        """

    def getCheckouts(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]:
        """
        Get a list of all checkouts for an item.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :return: checkout data list
        :rtype: jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]
        :raises FileNotFoundException: if folder item not found
        :raises IOException: if an IO error occurs
        """

    def getEvents(self) -> jpype.JArray[RepositoryChangeEvent]:
        """
        Get pending change events.  Call will block until an event is available.
        
        :return: array of events
        :rtype: jpype.JArray[RepositoryChangeEvent]
        :raises IOException: if error occurs.
        """

    @typing.overload
    def getItem(self, parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> RepositoryItem:
        """
        Returns the RepositoryItem in the given folder with the given name
        
        :param java.lang.String or str parentPath: folder path
        :param java.lang.String or str name: item name
        :return: item or null if not found
        :rtype: RepositoryItem
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def getItem(self, fileID: typing.Union[java.lang.String, str]) -> RepositoryItem:
        """
        Returns the RepositoryItem with the given unique file ID
        
        :param java.lang.String or str fileID: unique file ID
        :return: item or null if not found
        :rtype: RepositoryItem
        :raises IOException: if an IO error occurs
        :raises UnsupportedOperationException: if file-system does not support this operation
        """

    def getItemCount(self) -> int:
        """
        Returns the number of folder items contained within this file-system.
        
        :raises IOException: if an IO error occurs
        :raises UnsupportedOperationException: if file-system does not support this operation
        """

    def getItemList(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[RepositoryItem]:
        """
        Get of all items found within the specified parent folder path.
        
        :param java.lang.String or str folderPath: parent folder path
        :return: list of items contained within specified parent folder
        :rtype: jpype.JArray[RepositoryItem]
        :raises UserAccessException: 
        :raises FileNotFoundException: if parent folder not found
        :raises IOException: if an IO error occurs
        """

    def getLength(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the length of this domain file.  This size is the minimum disk space
        used for storing this file, but does not account for additional storage space
        used to tracks changes, etc.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :return: file length
        :rtype: int
        :raises IOException: if an IO error occurs
        """

    def getName(self) -> str:
        """
        Returns the name of this repository.
        
        :raises IOException: if an IO error occurs
        """

    def getServerUserList(self) -> jpype.JArray[java.lang.String]:
        """
        Convenience method for obtaining a list of all users
        known to the server.
        
        :return: list of user names.
        :rtype: jpype.JArray[java.lang.String]
        :raises IOException: if an IO error occurs
        
        .. seealso::
        
            | :obj:`RemoteRepositoryServerHandle.getAllUsers`
        """

    def getSubfolderList(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Get list of subfolders contained within the specified parent folder.
        
        :param java.lang.String or str folderPath: parent folder path
        :return: list of subfolder names
        :rtype: jpype.JArray[java.lang.String]
        :raises UserAccessException: if user does not have adequate permission within the repository.
        :raises FileNotFoundException: if specified parent folder path not found
        :raises IOException: if an IO error occurs
        """

    def getUser(self) -> User:
        """
        Returns user object associated with this handle.
        
        :raises IOException: if an IO error occurs
        """

    def getUserList(self) -> jpype.JArray[User]:
        """
        Returns a list of users authorized for this repository.
        
        :raises UserAccessException: 
        :raises IOException: if an IO error occurs
        """

    def getVersions(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.framework.store.Version]:
        """
        Returns a list of all versions for the specified item.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :return: version list
        :rtype: jpype.JArray[ghidra.framework.store.Version]
        :raises IOException: if an IO error occurs
        """

    def hasCheckouts(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified item has one or more checkouts.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        """

    def isCheckinActive(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified item has an active checkin.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        """

    def moveFolder(self, oldParentPath: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], oldFolderName: typing.Union[java.lang.String, str], newFolderName: typing.Union[java.lang.String, str]):
        """
        Move an entire folder
        
        :param java.lang.String or str oldParentPath: current parent folder path
        :param java.lang.String or str newParentPath: new parent folder path
        :param java.lang.String or str oldFolderName: current folder name
        :param java.lang.String or str newFolderName: new folder name
        :raises InvalidNameException: if newFolderName is invalid
        :raises DuplicateFileException: if target folder already exists
        :raises IOException: if an IO error occurs
        """

    def moveItem(self, oldParentPath: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], oldItemName: typing.Union[java.lang.String, str], newItemName: typing.Union[java.lang.String, str]):
        """
        Move an item to another folder
        
        :param java.lang.String or str oldParentPath: current parent folder path
        :param java.lang.String or str newParentPath: new parent folder path
        :param java.lang.String or str oldItemName: current item name
        :param java.lang.String or str newItemName: new item name
        :raises InvalidNameException: if newItemName is invalid
        :raises DuplicateFileException: if target item already exists
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def openDatabase(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], minChangeDataVer: typing.Union[jpype.JInt, int]) -> db.buffers.ManagedBufferFileHandle:
        """
        Open an existing version of a database buffer file for non-update read-only use.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of existing data file
        :param jpype.JInt or int version: existing version of data file (-1 = latest version)
        :param jpype.JInt or int minChangeDataVer: indicates the oldest change data buffer file to be
        included.  A -1 indicates only the last change data buffer file is applicable.
        :return: remote buffer file for non-update read-only use
        :rtype: db.buffers.ManagedBufferFileHandle
        :raises UserAccessException: if user does not have adequate permission within the repository.
        :raises FileNotFoundException: if database version not found
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def openDatabase(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int]) -> db.buffers.ManagedBufferFileHandle:
        """
        Open the current version for checkin of new version.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of existing data file
        :param jpype.JLong or int checkoutId: checkout ID
        :return: remote buffer file for updateable read-only use
        :rtype: db.buffers.ManagedBufferFileHandle
        :raises UserAccessException: if user does not have adequate permission within the repository.
        :raises FileNotFoundException: if database version not found
        :raises IOException: if an IO error occurs
        """

    def setUserList(self, users: jpype.JArray[User], anonymousAccessAllowed: typing.Union[jpype.JBoolean, bool]):
        """
        Set the list of authorized users for this repository.
        
        :param jpype.JArray[User] users: list of user and access permissions.
        :param jpype.JBoolean or bool anonymousAccessAllowed: true if anonymous access should be permitted to
        this repository
        :raises UserAccessException: 
        :raises IOException: if an IO error occurs
        """

    def terminateCheckout(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int], notify: typing.Union[jpype.JBoolean, bool]):
        """
        Terminate an existing item checkout.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :param jpype.JLong or int checkoutId: checkout ID
        :param jpype.JBoolean or bool notify: notify listeners of item status change
        :raises IOException: if an IO error occurs
        """

    def updateCheckoutVersion(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int], checkoutVersion: typing.Union[jpype.JInt, int]):
        """
        Update checkout data for an item following an update of a local checkout file.
        
        :param java.lang.String or str parentPath: parent folder path
        :param java.lang.String or str itemName: name of item
        :param jpype.JLong or int checkoutId: checkout ID
        :param jpype.JInt or int checkoutVersion: item version used for update
        :raises IOException: if error occurs
        """

    @property
    def item(self) -> RepositoryItem:
        ...

    @property
    def userList(self) -> jpype.JArray[User]:
        ...

    @property
    def subfolderList(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def itemList(self) -> jpype.JArray[RepositoryItem]:
        ...

    @property
    def serverUserList(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def user(self) -> User:
        ...

    @property
    def events(self) -> jpype.JArray[RepositoryChangeEvent]:
        ...

    @property
    def itemCount(self) -> jpype.JInt:
        ...


class SSHSignatureCallback(javax.security.auth.callback.Callback, java.io.Serializable):
    """
    ``SSHSignatureCallback`` provides a Callback implementation used
    to perform SSH authentication.  This callback is instantiated
    by the server with a random token which must be signed using the 
    user's SSH private key.
     
    
    It is the responsibility of the callback handler to invoke the 
    sign method and return this object in response
    to the callback.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self, token: jpype.JArray[jpype.JByte], serverSignature: jpype.JArray[jpype.JByte]):
        """
        Construct callback with a random token to be signed by the client.
        
        :param jpype.JArray[jpype.JByte] token: random bytes to be signed
        :param jpype.JArray[jpype.JByte] serverSignature: server signature of token (using server PKI)
        """

    def getServerSignature(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the server signature of token (using server PKI)
        
        :return: the server's signature of the token bytes.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getSignature(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        :return: signed token bytes set by callback handler.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getToken(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        :return: token to be signed using user certificate.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def isSigned(self) -> bool:
        """
        
        
        :return: true if callback has been signed
        :rtype: bool
        """

    def sign(self, privateKeyParameters: java.lang.Object):
        """
        Sign this challenge with the specified SSH private key.
        
        :param java.lang.Object privateKeyParameters: SSH private key parameters 
                (:obj:`RSAKeyParameters` or :obj:`RSAKeyParameters`)
        :raises IOException: if signature generation failed
        """

    @property
    def signature(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def signed(self) -> jpype.JBoolean:
        ...

    @property
    def serverSignature(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def token(self) -> jpype.JArray[jpype.JByte]:
        ...


class RepositoryChangeEvent(java.io.Serializable):
    """
    Repository change event (used by server only).
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1
    REP_NULL_EVENT: typing.Final = -1
    REP_FOLDER_CREATED: typing.Final = 0
    REP_ITEM_CREATED: typing.Final = 1
    REP_FOLDER_DELETED: typing.Final = 2
    REP_FOLDER_MOVED: typing.Final = 3
    REP_FOLDER_RENAMED: typing.Final = 4
    REP_ITEM_DELETED: typing.Final = 5
    REP_ITEM_RENAMED: typing.Final = 6
    REP_ITEM_MOVED: typing.Final = 7
    REP_ITEM_CHANGED: typing.Final = 8
    REP_OPEN_HANDLE_COUNT: typing.Final = 9
    type: typing.Final[jpype.JInt]
    parentPath: typing.Final[java.lang.String]
    name: typing.Final[java.lang.String]
    newParentPath: typing.Final[java.lang.String]
    newName: typing.Final[java.lang.String]

    def __init__(self, type: typing.Union[jpype.JInt, int], parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Constructor.
        Parameters not applicable to the specified type may be null.
        
        :param jpype.JInt or int type: event type
        :param java.lang.String or str parentPath: parent folder path for repository item or folder
        :param java.lang.String or str name: repository item or folder name
        :param java.lang.String or str newParentPath: new parent folder path for repository item or folder
        :param java.lang.String or str newName: new repository item or folder name
        """


class AnonymousCallback(javax.security.auth.callback.Callback, java.io.Serializable):

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self):
        ...

    def anonymousAccessRequested(self) -> bool:
        """
        
        
        :return: true if anonymous access requested
        :rtype: bool
        """

    def setAnonymousAccessRequested(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        If state set to true anonymous read-only access will be requested
        
        :param jpype.JBoolean or bool state: true to request anonymous access
        """


class User(java.lang.Comparable[User], java.io.Serializable):
    """
    Container class for the user name and the permission type: READ_ONLY,
    WRITE, or ADMIN.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 2
    ANONYMOUS_USERNAME: typing.Final = "-anonymous-"
    """
    Name associated with anonymous user
    """

    READ_ONLY: typing.Final = 0
    """
    Value corresponding to Read-only permission for a repository user.
    """

    WRITE: typing.Final = 1
    """
    Value corresponding to Write permission for a repository user.
    """

    ADMIN: typing.Final = 2
    """
    Value corresponding to Administrative permission for a repository user.
    """


    def __init__(self, name: typing.Union[java.lang.String, str], permission: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param java.lang.String or str name: user id/name
        :param jpype.JInt or int permission: permission value (READ_ONLY, WRITE or ADMIN)
        """

    def getName(self) -> str:
        """
        Returns user id/name
        """

    def getPermissionType(self) -> int:
        """
        Returns the permission value assigned this user.
        """

    def hasWritePermission(self) -> bool:
        """
        Return true if this user has permission of WRITE or ADMIN.
        """

    def isAdmin(self) -> bool:
        """
        Returns true if permission is ADMIN.
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if permission is READ_ONLY.
        """

    @property
    def permissionType(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def admin(self) -> jpype.JBoolean:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...


class RemoteRepositoryServerHandle(RepositoryServerHandle, java.rmi.Remote):
    """
    ``RepositoryServerHandle`` provides access to a remote repository server via RMI.
     
    
    Methods from :obj:`RepositoryServerHandle` **must** be re-declared here 
    so they may be properly marshalled for remote invocation via RMI.  
    This became neccessary with an OpenJDK 11.0.6 change made to 
    :obj:`RemoteObjectInvocationHandler`.
    """

    class_: typing.ClassVar[java.lang.Class]


class RMIServerPortFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, basePort: typing.Union[jpype.JInt, int]):
        """
        Construct port factory using specified basePort
        """

    def getRMIRegistryPort(self) -> int:
        """
        Returns RMI Registry port
        """

    def getRMISSLPort(self) -> int:
        """
        Returns the SSL-protected RMI port.
        """

    def getStreamPort(self) -> int:
        """
        Returns the SSL Stream port
        """

    @property
    def rMISSLPort(self) -> jpype.JInt:
        ...

    @property
    def rMIRegistryPort(self) -> jpype.JInt:
        ...

    @property
    def streamPort(self) -> jpype.JInt:
        ...


class GhidraServerHandle(java.rmi.Remote):
    """
    ``GhidraServerHandle`` provides access to a remote server.
    This remote interface facilitates user login/authentication, providing
    a more useful handle to the associated repository server.
    """

    class_: typing.ClassVar[java.lang.Class]
    INTERFACE_VERSION: typing.Final = 11
    """
    The collective interface version for all Ghidra Server remote interfaces.
    If any remote interface is modified, this value should be incremented.
     
    Version Change History:
    1: Original Version
    2: Changed API to support NAT and firewalls
    3: Allow user to login with alternate user ID
    4: Added additional checkout data and database ID support (4.2)
    5: Added support for quick update of checkout file following merged check-in on server,
        also added alternate authentication via password file (4.4)
    6: Refactored BufferFile related classes creating a ManagedBufferFile which
        supports all the version-control capabilities. (5.2)
    7: Added support for SSH authentication callback, anonymous user access (5.4)
    8: Added salted local passwords, added LocalIndexedFilesystem V1 with ability to obtain file count (6.1)
    9: Added support for transient checkouts (7.2)
    10: Added BlockStreamServer (7.4)
    11: Revised password hash to SHA-256 (9.0)
        - version 9.1 switched to using SSL/TLS for RMI registry connection preventing
            older clients the ability to connect to the server.  Remote interface remained
            unchanged allowing 9.1 clients to connect to 9.0 server.
    """

    MIN_GHIDRA_VERSION: typing.Final = "9.0"
    """
    Minimum version of Ghidra which utilized the current INTERFACE_VERSION
    """

    DEFAULT_PORT: typing.Final = 13100
    """
    Default RMI base port for Ghidra Server
    """

    BIND_NAME_PREFIX: typing.Final = "GhidraServer"
    """
    RMI registry binding name prefix for all versions of the remote GhidraServerHandle object.
    """

    BIND_NAME: typing.Final = "GhidraServer9.0"
    """
    RMI registry binding name for the supported version of the remote GhidraServerHandle object.
    """


    def checkCompatibility(self, serverInterfaceVersion: typing.Union[jpype.JInt, int]):
        """
        Check server interface compatibility
        
        :param jpype.JInt or int serverInterfaceVersion: client/server interface version
        :raises RemoteException: 
        
        .. seealso::
        
            | :obj:`.INTERFACE_VERSION`
        """

    def getAuthenticationCallbacks(self) -> jpype.JArray[javax.security.auth.callback.Callback]:
        """
        Returns user authentication proxy object.
        
        :raises RemoteException: 
        :return: authentication callbacks which must be satisfied or null if authentication not
        required.
        :rtype: jpype.JArray[javax.security.auth.callback.Callback]
        """

    def getRepositoryServer(self, user: javax.security.auth.Subject, authCallbacks: jpype.JArray[javax.security.auth.callback.Callback]) -> RemoteRepositoryServerHandle:
        """
        Get a handle to the repository server.
        
        :param javax.security.auth.Subject user: user subject containing GhidraPrincipal
        :param jpype.JArray[javax.security.auth.callback.Callback] authCallbacks: valid authentication callback objects which have been satisfied, or
        null if server does not require authentication.
        :return: repository server handle.
        :rtype: RemoteRepositoryServerHandle
        :raises LoginException: if user authentication fails
        :raises RemoteException: 
        
        .. seealso::
        
            | :obj:`.getAuthenticationCallbacks()`
        """

    @property
    def authenticationCallbacks(self) -> jpype.JArray[javax.security.auth.callback.Callback]:
        ...


class RepositoryServerHandle(java.lang.Object):
    """
    ``RepositoryServerHandle`` provides access to a repository server.
    """

    class_: typing.ClassVar[java.lang.Class]

    def anonymousAccessAllowed(self) -> bool:
        """
        
        
        :return: true if server allows anonymous access.
        Individual repositories must grant anonymous access separately.
        :rtype: bool
        :raises IOException: if an IO error occurs
        """

    def canSetPassword(self) -> bool:
        """
        Returns true if the user's password can be changed.
        
        :raises IOException: if an IO error occurs
        """

    def connected(self):
        """
        Verify that server is alive and connected.
        
        :raises IOException: if connection verification fails
        """

    def createRepository(self, name: typing.Union[java.lang.String, str]) -> RepositoryHandle:
        """
        Create a new repository on the server.  The newly created RepositoryHandle will contain 
        a unique project ID for the client.
        
        :param java.lang.String or str name: repository name.
        This ID will be used to identify and maintain checkout data.
        :return: handle to new repository.
        :rtype: RepositoryHandle
        :raises DuplicateFileException: 
        :raises UserAccessException: 
        :raises IOException: if an IO error occurs
        """

    def deleteRepository(self, name: typing.Union[java.lang.String, str]):
        """
        Delete a repository.
        
        :param java.lang.String or str name: repository name.
        :raises UserAccessException: if user does not have permission to delete repository
        :raises IOException: if an IO error occurs
        """

    def getAllUsers(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of all known users.
        
        :raises IOException: if an IO error occurs
        """

    def getPasswordExpiration(self) -> int:
        """
        Returns the amount of time in milliseconds until the 
        user's password will expire.
        
        :return: time until expiration or -1 if it will not expire
        :rtype: int
        :raises IOException: if an IO error occurs
        """

    def getRepository(self, name: typing.Union[java.lang.String, str]) -> RepositoryHandle:
        """
        Get a handle to an existing repository.
        
        :param java.lang.String or str name: repository name.
        :return: repository handle or null if repository does not exist.
        :rtype: RepositoryHandle
        :raises UserAccessException: if user does not have permission to access repository
        :raises IOException: if an IO error occurs
        """

    def getRepositoryNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of all repository names which are accessable by the current user.
        
        :raises IOException: if an IO error occurs
        """

    def getUser(self) -> str:
        """
        Returns current user for which this handle belongs.
        
        :raises IOException: if an IO error occurs
        """

    def isReadOnly(self) -> bool:
        """
        
        
        :return: true if user has restricted read-only access to server (e.g., anonymous user)
        :rtype: bool
        :raises IOException: if an IO error occurs
        """

    def setPassword(self, saltedSHA256PasswordHash: jpype.JArray[jpype.JChar]) -> bool:
        """
        Set the password for the user.
        
        :param jpype.JArray[jpype.JChar] saltedSHA256PasswordHash: SHA256 salted password hash
        :return: true if password changed
        :rtype: bool
        :raises IOException: if an IO error occurs
        
        .. seealso::
        
            | :obj:`ghidra.util.HashUtilities.getSaltedHash(String, char[])`HashUtilities.getSaltedHash("SHA-256", char[])
        """

    @property
    def passwordExpiration(self) -> jpype.JLong:
        ...

    @property
    def allUsers(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def repositoryNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def repository(self) -> RepositoryHandle:
        ...

    @property
    def user(self) -> java.lang.String:
        ...


class SignatureCallback(javax.security.auth.callback.Callback, java.io.Serializable):
    """
    ``SignatureCallback`` provides a Callback implementation used
    to perform PKI authentication.  This callback is instantiated
    by the server with a random token which must be signed using the 
    user's certificate which contains one of the recognizedAuthorities
    within it certificate chain.
     
    
    It is the responsibility of the callback handler to invoke the 
    sign(X509Certificate[], byte[]) and return this object in response
    to the callback.
    """

    class_: typing.ClassVar[java.lang.Class]
    serialVersionUID: typing.Final = 1

    def __init__(self, recognizedAuthorities: jpype.JArray[javax.security.auth.x500.X500Principal], token: jpype.JArray[jpype.JByte], serverSignature: jpype.JArray[jpype.JByte]):
        """
        Construct callback with a random token to be signed by the client.
        
        :param jpype.JArray[javax.security.auth.x500.X500Principal] recognizedAuthorities: list of CA's from which one must occur
        within the certificate chain of the signing certificate.
        :param jpype.JArray[jpype.JByte] token: random bytes to be signed
        """

    def getCertificateChain(self) -> jpype.JArray[java.security.cert.X509Certificate]:
        """
        Returns certificate chain used to sign token.
        """

    def getRecognizedAuthorities(self) -> jpype.JArray[java.security.Principal]:
        """
        Returns list of approved certificate authorities.
        """

    def getServerSignature(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the server's signature of the token bytes.
        """

    def getSigAlg(self) -> str:
        ...

    def getSignature(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns signed token bytes set by callback handler.
        """

    def getToken(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns token to be signed using user certificate.
        """

    def sign(self, sigCertChain: jpype.JArray[java.security.cert.X509Certificate], certSignature: jpype.JArray[jpype.JByte]):
        """
        Set token signature data.  Method must be invoked by 
        callback handler.
        
        :param jpype.JArray[java.security.cert.X509Certificate] sigCertChain: certificate chain used to sign token.
        :param jpype.JArray[jpype.JByte] certSignature: token signature
        """

    @property
    def certificateChain(self) -> jpype.JArray[java.security.cert.X509Certificate]:
        ...

    @property
    def signature(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def recognizedAuthorities(self) -> jpype.JArray[java.security.Principal]:
        ...

    @property
    def serverSignature(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def token(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def sigAlg(self) -> java.lang.String:
        ...



__all__ = ["RemoteRepositoryHandle", "GhidraPrincipal", "RepositoryItem", "RepositoryHandle", "SSHSignatureCallback", "RepositoryChangeEvent", "AnonymousCallback", "User", "RemoteRepositoryServerHandle", "RMIServerPortFactory", "GhidraServerHandle", "RepositoryServerHandle", "SignatureCallback"]
