from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db.buffers
import docking.widgets
import ghidra.framework.model
import ghidra.framework.remote
import ghidra.framework.store
import ghidra.security
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import javax.security.auth.callback # type: ignore


class RemoteAdapterListener(java.lang.Object):
    """
    ``RemoteAdapterListener`` provides a listener interface 
    which facilitates notifcation when the connection
    state of a remote server/repository adapter changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def connectionStateChanged(self, adapter: java.lang.Object):
        """
        Callback notification indicating the remote object
        connection state has changed.
        
        :param java.lang.Object adapter: remote interface adapter (e.g., RepositoryServerAdapter).
        """


class HeadlessClientAuthenticator(ClientAuthenticator):
    """
    ``HeadlessClientAuthenticator`` provides the ability to install a Ghidra Server 
    authenticator needed when operating in a headless mode.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def installHeadlessClientAuthenticator(username: typing.Union[java.lang.String, str], keystorePath: typing.Union[java.lang.String, str], allowPasswordPrompt: typing.Union[jpype.JBoolean, bool]):
        """
        Install headless client authenticator for Ghidra Server and when http/https 
        connections require authentication and have not specified user information.
        
        :param java.lang.String or str username: optional username to be used with a Ghidra Server which
        allows username to be specified.  If null, :meth:`ClientUtil.getUserName() <ClientUtil.getUserName>` 
        will be used.
        :param java.lang.String or str keystorePath: optional PKI or SSH keystore path.  May also be specified
        as resource path for SSH key.
        :param jpype.JBoolean or bool allowPasswordPrompt: if true the user may be prompted for passwords
        via the console (stdin).  Please note that the Java console will echo 
        the password entry to the terminal which may be undesirable.
        :raises IOException: if error occurs while opening specified keystorePath
        """


class ClientAuthenticator(ghidra.security.KeyStorePasswordProvider):

    class_: typing.ClassVar[java.lang.Class]

    def getAuthenticator(self) -> java.net.Authenticator:
        """
        Get a standard Java authenticator for HTTP and other standard network connections
        
        :return: authenticator object
        :rtype: java.net.Authenticator
        """

    def getNewPassword(self, parent: java.awt.Component, serverInfo: typing.Union[java.lang.String, str], username: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JChar]:
        """
        Get new user password
        
        :param java.awt.Component parent: dialog parent component or null if not applicable
        :param java.lang.String or str serverInfo: server host info
        :param java.lang.String or str username: 
        :return: new password or null if password should not be changed, 
        if not null array will be cleared by caller
        :rtype: jpype.JArray[jpype.JChar]
        """

    def isSSHKeyAvailable(self) -> bool:
        """
        
        
        :return: true if SSH private key is available for authentication
        :rtype: bool
        """

    def processPasswordCallbacks(self, title: typing.Union[java.lang.String, str], serverType: typing.Union[java.lang.String, str], serverName: typing.Union[java.lang.String, str], allowUserNameEntry: typing.Union[jpype.JBoolean, bool], nameCb: javax.security.auth.callback.NameCallback, passCb: javax.security.auth.callback.PasswordCallback, choiceCb: javax.security.auth.callback.ChoiceCallback, anonymousCb: ghidra.framework.remote.AnonymousCallback, loginError: typing.Union[java.lang.String, str]) -> bool:
        """
        Process password authentication callbacks.
        
        :param java.lang.String or str title: password prompt title if GUI is used
        :param java.lang.String or str serverType: type of server (label associated with serverName)
        :param java.lang.String or str serverName: name of server
        :param jpype.JBoolean or bool allowUserNameEntry: if true user ID entry will be supported if nameCb is not null.
        :param javax.security.auth.callback.NameCallback nameCb: provides storage for user login name.  A null indicates
        that the default user name will be used, @see ClientUtil#getUserName()
        :param javax.security.auth.callback.PasswordCallback passCb: provides storage for user password, @see PasswordCallback#setPassword(char[])
        :param javax.security.auth.callback.ChoiceCallback choiceCb: specifies choice between NT Domain authentication (index=0) and local password
        file authentication (index=1).  Set selected index to specify authenticator to be used,
        :param ghidra.framework.remote.AnonymousCallback anonymousCb: may be used to request anonymous read-only access to 
        the server.  A null is specified if anonymous access has not been enabed on the server.
        :param java.lang.String or str loginError: previous login error message or null for first attempt
        :return: true if password provided, false if entry cancelled
        :rtype: bool
        
        .. seealso::
        
            | :obj:`ChoiceCallback.setSelectedIndex(int)`A null is specified if no choice is available (password authenticator determined by server configuration).
        
            | :obj:`AnonymousCallback.setAnonymousAccessRequested(boolean)`
        """

    def processSSHSignatureCallbacks(self, serverName: typing.Union[java.lang.String, str], nameCb: javax.security.auth.callback.NameCallback, sshCb: ghidra.framework.remote.SSHSignatureCallback) -> bool:
        """
        Process Ghidra Server SSH authentication callbacks.
        
        :param java.lang.String or str serverName: name of server
        :param javax.security.auth.callback.NameCallback nameCb: provides storage for user login name.  A null indicates
        that the default user name will be used, @see ClientUtil#getUserName().
        :param ghidra.framework.remote.SSHSignatureCallback sshCb: provides authentication token to be signed with private key, @see SSHAuthenticationCallback#sign(SSHPrivateKey)
        :return: 
        :rtype: bool
        """

    def promptForReconnect(self, parent: java.awt.Component, message: typing.Union[java.lang.String, str]) -> bool:
        """
        Prompt user for reconnect
        
        :param java.awt.Component parent: dialog parent component or null if not applicable
        :param java.lang.String or str message: 
        :return: return true if reconnect should be attempted
        :rtype: bool
        """

    @property
    def sSHKeyAvailable(self) -> jpype.JBoolean:
        ...

    @property
    def authenticator(self) -> java.net.Authenticator:
        ...


class PasswordClientAuthenticator(ClientAuthenticator):
    """
    ``PasswordClientAuthenticator`` provides a fixed username/password 
    authentication response when connecting to any Ghidra Server or accessing
    a protected PKI keystore.  The use of this authenticator is intended for
    headless applications in which the user is unable to respond to such
    prompts.  SSH authentication is not currently supported.  Anonymous user
    access is not supported.
     
    
    If a PKI certificate has been installed, a password may be required 
    to access the certificate keystore independent of any other password which may be required
    for accessing SSH keys or server password authentication.  In such headless situations,
    the PKI certificate path/password should be specified via a property since it is unlikely
    that the same password will apply.
    
    
    .. seealso::
    
        | :obj:`ApplicationKeyManagerFactory`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, password: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, username: typing.Union[java.lang.String, str], password: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class RepositoryChangeDispatcher(java.lang.Runnable):

    class_: typing.ClassVar[java.lang.Class]

    def setFileChangeListener(self, changeListener: ghidra.framework.store.FileSystemListener):
        ...

    def start(self):
        ...

    def stop(self):
        ...


class RepositoryServerAdapter(java.lang.Object):
    """
    ``RepositoryServerAdapter`` provides a persistent wrapper for a 
    ``RepositoryServerHandle`` which may become invalid if the 
    remote connection were to fail.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addListener(self, listener: RemoteAdapterListener):
        """
        Add a listener to this remote adapter
        
        :param RemoteAdapterListener listener:
        """

    def anonymousAccessAllowed(self) -> bool:
        """
        
        
        :return: true if server allows anonymous access.
        Individual repositories must grant anonymous access separately.
        :rtype: bool
        :raises IOException: 
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.anonymousAccessAllowed()`
        """

    def canSetPassword(self) -> bool:
        """
        Returns true if this server allows the user to change their password.
        
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.canSetPassword()`
        """

    def connect(self) -> bool:
        """
        Attempt to connect or re-connect to the server.
        
        :return: true if connect successful, false if cancelled by user
        :rtype: bool
        :raises NotConnectedException: if connect failed (error will be displayed to user)
        """

    def createRepository(self, name: typing.Union[java.lang.String, str]) -> RepositoryAdapter:
        """
        Create a new repository on the server.
        
        :param java.lang.String or str name: repository name.
        :return: handle to new repository.
        :rtype: RepositoryAdapter
        :raises DuplicateNameException: 
        :raises UserAccessException: 
        :raises IOException: 
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.createRepository(String)`
        """

    def deleteRepository(self, name: typing.Union[java.lang.String, str]):
        """
        Delete a repository.
        
        :param java.lang.String or str name: repository name.
        :raises UserAccessException: 
        :raises IOException: 
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.deleteRepository(java.lang.String)`
        """

    def disconnect(self):
        """
        Force disconnect with server
        """

    def getAllUsers(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of all known users.
        
        :raises IOException: 
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.getAllUsers()`
        """

    def getLastConnectError(self) -> java.lang.Throwable:
        """
        Returns the last error associated with a failed connection attempt.
        
        :return: last connect error or null
        :rtype: java.lang.Throwable
        """

    def getRepository(self, name: typing.Union[java.lang.String, str]) -> RepositoryAdapter:
        """
        Get a handle to an existing repository.  The repository adapter is
        initially disconnected - the connect() method or another repository 
        action method must be invoked to establish a repository connection.
        
        :param java.lang.String or str name: repository name.
        :return: repository handle or null if repository not found.
        :rtype: RepositoryAdapter
        """

    def getRepositoryNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of all repository names defined to the server.
        
        :raises IOException: 
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.getRepositoryNames()`
        """

    def getServerInfo(self) -> ghidra.framework.model.ServerInfo:
        """
        Returns server information.  May be null if using fixed RepositoryServerHandle.
        """

    def getUser(self) -> str:
        """
        Returns user's server login identity
        """

    def isCancelled(self) -> bool:
        """
        Returns true if the connection was cancelled by the user.
        
        :return: try if cancelled by user
        :rtype: bool
        """

    def isConnected(self) -> bool:
        """
        Returns true if connected.
        """

    def isReadOnly(self) -> bool:
        """
        
        
        :return: true if user has restricted read-only access to server (e.g., anonymous user)
        :rtype: bool
        :raises IOException: 
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.isReadOnly()`
        """

    def removeListener(self, listener: RemoteAdapterListener):
        """
        Remove a listener from this remote adapter
        
        :param RemoteAdapterListener listener:
        """

    def setPassword(self, saltedSHA256PasswordHash: jpype.JArray[jpype.JChar]) -> bool:
        """
        Set the simple password for the user.
        
        :param jpype.JArray[jpype.JChar] saltedSHA256PasswordHash: hex character representation of salted SHA256 hash of the password
        :return: true if password changed
        :rtype: bool
        :raises IOException: if user data can't be written to file
        :raises NotConnectedException: if server connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryServerHandle.setPassword(char[])`
        
            | :obj:`ghidra.util.HashUtilities.getSaltedHash(String, char[])`HashUtilities.getSaltedHash("SHA-256", char[])
        """

    @property
    def connected(self) -> jpype.JBoolean:
        ...

    @property
    def serverInfo(self) -> ghidra.framework.model.ServerInfo:
        ...

    @property
    def allUsers(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def repositoryNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def lastConnectError(self) -> java.lang.Throwable:
        ...

    @property
    def repository(self) -> RepositoryAdapter:
        ...

    @property
    def user(self) -> java.lang.String:
        ...


class RepositoryAdapter(RemoteAdapterListener):
    """
    ``RepositoryAdapter`` provides a persistent wrapper for a remote RepositoryHandle 
    which may become invalid if the remote connection were to fail.  Connection recovery is provided 
    by any method call which must communicate with the server.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverAdapter: RepositoryServerAdapter, name: typing.Union[java.lang.String, str]):
        """
        Construct.
        
        :param RepositoryServerAdapter serverAdapter: persistent server adapter
        :param java.lang.String or str name: repository name
        """

    def addListener(self, listener: RemoteAdapterListener):
        """
        Add a listener to this remote adapter
        
        :param RemoteAdapterListener listener:
        """

    def anonymousAccessAllowed(self) -> bool:
        """
        
        
        :return: true if anonymous access allowed by this repository
        :rtype: bool
        :raises IOException:
        """

    def checkout(self, folderPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutType: ghidra.framework.store.CheckoutType, projectPath: typing.Union[java.lang.String, str]) -> ghidra.framework.store.ItemCheckoutStatus:
        ...

    def connect(self):
        """
        Attempt to connect to the server.
        
        :raises RepositoryNotFoundException: if named repository does not exist
        :raises IOException: if IO error occurs
        """

    def connectionStateChanged(self, adapter: java.lang.Object):
        """
        Notification callback when server connection state changes.
        
        
        .. seealso::
        
            | :obj:`ghidra.framework.client.RemoteAdapterListener.connectionStateChanged(java.lang.Object)`
        """

    def createDataFile(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]):
        ...

    def createDatabase(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], bufferSize: typing.Union[jpype.JInt, int], contentType: typing.Union[java.lang.String, str], fileID: typing.Union[java.lang.String, str], projectPath: typing.Union[java.lang.String, str]) -> db.buffers.ManagedBufferFileAdapter:
        """
        
        
        
        .. seealso::
        
            | :obj:`RepositoryHandle.createDatabase(String, String, String, int, String, String)`
        """

    def deleteItem(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int]):
        ...

    def disconnect(self):
        ...

    def fileExists(self, folderPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def folderExists(self, folderPath: typing.Union[java.lang.String, str]) -> bool:
        ...

    def getCheckout(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int]) -> ghidra.framework.store.ItemCheckoutStatus:
        ...

    def getCheckouts(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.framework.store.ItemCheckoutStatus]:
        ...

    @typing.overload
    def getItem(self, folderPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> ghidra.framework.remote.RepositoryItem:
        ...

    @typing.overload
    def getItem(self, fileID: typing.Union[java.lang.String, str]) -> ghidra.framework.remote.RepositoryItem:
        ...

    def getItemCount(self) -> int:
        ...

    def getItemList(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.framework.remote.RepositoryItem]:
        ...

    def getLength(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> int:
        ...

    def getName(self) -> str:
        """
        Returns repository name
        """

    def getOpenFileHandleCount(self) -> int:
        ...

    def getServer(self) -> RepositoryServerAdapter:
        """
        Returns server adapter
        """

    def getServerInfo(self) -> ghidra.framework.model.ServerInfo:
        """
        Returns server information
        """

    def getServerUserList(self) -> jpype.JArray[java.lang.String]:
        """
        Returns list of all users known to server.
        
        :raises IOException: 
        :raises UserAccessException: user no longer has any permission to use repository.
        :raises NotConnectedException: if server/repository connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`RemoteRepositoryHandle.getServerUserList()`
        """

    def getSubfolderList(self, folderPath: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        ...

    def getUser(self) -> ghidra.framework.remote.User:
        """
        Returns repository user object.
        
        :raises UserAccessException: user no longer has any permission to use repository.
        :raises NotConnectedException: if server/repository connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`ghidra.framework.remote.RemoteRepositoryHandle.getUser()`
        """

    def getUserList(self) -> jpype.JArray[ghidra.framework.remote.User]:
        """
        Returns list of repository users.
        
        :raises IOException: 
        :raises UserAccessException: user no longer has any permission to use repository.
        :raises NotConnectedException: if server/repository connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`RemoteRepositoryHandle.getUserList()`
        """

    def getVersions(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.framework.store.Version]:
        ...

    def hadUnexpectedDisconnect(self) -> bool:
        """
        Returns true if connection recently was lost unexpectedly
        """

    def hasCheckouts(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def isCheckinActive(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def isConnected(self) -> bool:
        """
        Returns true if connected.
        """

    def moveFolder(self, oldParentPath: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], oldFolderName: typing.Union[java.lang.String, str], newFolderName: typing.Union[java.lang.String, str]):
        ...

    def moveItem(self, oldParentPath: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], oldItemName: typing.Union[java.lang.String, str], newItemName: typing.Union[java.lang.String, str]):
        ...

    def openDataFile(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int]) -> ghidra.framework.store.DataFileHandle:
        ...

    @typing.overload
    def openDatabase(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], minChangeDataVer: typing.Union[jpype.JInt, int]) -> db.buffers.ManagedBufferFileAdapter:
        ...

    @typing.overload
    def openDatabase(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int]) -> db.buffers.ManagedBufferFileAdapter:
        ...

    def removeListener(self, listener: RemoteAdapterListener):
        """
        Remove a listener from this remote adapter
        
        :param RemoteAdapterListener listener:
        """

    def setFileSystemListener(self, fsListener: ghidra.framework.store.FileSystemListener):
        """
        Set the file system listener associated with the remote repository.
        
        :param ghidra.framework.store.FileSystemListener fsListener: file system listener
        """

    def setUserList(self, users: jpype.JArray[ghidra.framework.remote.User], anonymousAccessAllowed: typing.Union[jpype.JBoolean, bool]):
        """
        Set the list of authorized users for this repository.
        
        :param jpype.JArray[ghidra.framework.remote.User] users: list of user and access permissions.
        :param jpype.JBoolean or bool anonymousAccessAllowed: true to permit anonymous access (also requires anonymous
        access to be enabled for server)
        :raises UserAccessException: 
        :raises IOException: 
        :raises NotConnectedException: if server/repository connection is down (user already informed)
        
        .. seealso::
        
            | :obj:`RemoteRepositoryHandle.setUserList(User[], boolean)`
        """

    def terminateCheckout(self, folderPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int], notify: typing.Union[jpype.JBoolean, bool]):
        ...

    def updateCheckoutVersion(self, parentPath: typing.Union[java.lang.String, str], itemName: typing.Union[java.lang.String, str], checkoutId: typing.Union[jpype.JLong, int], checkoutVersion: typing.Union[jpype.JInt, int]):
        ...

    def verifyConnection(self) -> bool:
        """
        Verify that the connection is still valid.
        
        :return: true if the connection is valid; false if the connection needs to be reestablished
        :rtype: bool
        """

    @property
    def connected(self) -> jpype.JBoolean:
        ...

    @property
    def server(self) -> RepositoryServerAdapter:
        ...

    @property
    def item(self) -> ghidra.framework.remote.RepositoryItem:
        ...

    @property
    def userList(self) -> jpype.JArray[ghidra.framework.remote.User]:
        ...

    @property
    def serverInfo(self) -> ghidra.framework.model.ServerInfo:
        ...

    @property
    def subfolderList(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def openFileHandleCount(self) -> jpype.JInt:
        ...

    @property
    def itemList(self) -> jpype.JArray[ghidra.framework.remote.RepositoryItem]:
        ...

    @property
    def serverUserList(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def user(self) -> ghidra.framework.remote.User:
        ...

    @property
    def itemCount(self) -> jpype.JInt:
        ...


class DefaultClientAuthenticator(docking.widgets.PopupKeyStorePasswordProvider, ClientAuthenticator):

    @typing.type_check_only
    class ServerPasswordPrompt(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getMinimalURL(url: java.net.URL) -> java.net.URL:
        """
        Produce minimal URL (i.e., protocol, host and port)
        
        :param java.net.URL url: request URL
        :return: minimal URL
        :rtype: java.net.URL
        """


class NotConnectedException(java.io.IOException):
    """
    ``NotConnectedException`` indicates that the server connection
    is down.  When this exception is thrown, the current operation should be
    aborted.  At the time this exception is thrown, the user has already been
    informed of a server error condition.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str msg: error message
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


@typing.type_check_only
class ServerConnectTask(ghidra.util.task.Task):
    """
    Task for connecting to server with Swing thread.
    """

    @typing.type_check_only
    class ConnectCancelledListener(ghidra.util.task.CancelledListener, java.io.Closeable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FastConnectionFailSocket(java.net.Socket):
        """
        Socket implementation with very short connect timeout
        """

        class_: typing.ClassVar[java.lang.Class]

        def connect(self, endpoint: java.net.SocketAddress):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getGhidraServerHandle(server: ghidra.framework.model.ServerInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.framework.remote.GhidraServerHandle:
        """
        Obtain a remote instance of the Ghidra Server Handle object
        
        :param ghidra.framework.model.ServerInfo server: server information
        :param ghidra.util.task.TaskMonitor monitor: cancellable monitor
        :return: Ghidra Server Handle object
        :rtype: ghidra.framework.remote.GhidraServerHandle
        :raises IOException: if a connection error occurs
        :raises CancelledException: if connection attempt was cancelled
        """

    def run(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Completes and necessary authentication and obtains a repository handle.
        If a connection error occurs, an exception will be stored (:meth:`getException() <.getException>`.
        
        :raises CancelledException: if task cancelled
        
        .. seealso::
        
            | :obj:`ghidra.util.task.Task.run(ghidra.util.task.TaskMonitor)`
        """


class ClientUtil(java.lang.Object):
    """
    ``ClientUtil`` allows a user to connect to a Repository Server and obtain its handle.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def changePassword(parent: java.awt.Component, handle: ghidra.framework.remote.RepositoryServerHandle, serverInfo: typing.Union[java.lang.String, str]):
        """
        Prompt user and change password on server (not initiated by user).
        
        :param java.awt.Component parent: dialog parent
        :param ghidra.framework.remote.RepositoryServerHandle handle: server handle
        :param java.lang.String or str serverInfo: server information
        :raises IOException: if error occurs while updating password
        """

    @staticmethod
    def checkGhidraServer(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Connect to a Ghidra Server and verify compatibility.  This method can be used
        to effectively "ping" the Ghidra Server to verify the ability to connect.
        NOTE: Use of this method when PKI authentication is enabled is not supported.
        
        :param java.lang.String or str host: server hostname
        :param jpype.JInt or int port: first Ghidra Server port (0=use default)
        :param ghidra.util.task.TaskMonitor monitor: cancellable monitor
        :raises IOException: thrown if an IO Error occurs (e.g., server not found).
        :raises RemoteException: if server interface is incompatible or another server-side
        error occurs.
        :raises CancelledException: if connection attempt was cancelled
        """

    @staticmethod
    def clearRepositoryAdapter(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int]):
        """
        Eliminate the specified repository server from the connection cache
        
        :param java.lang.String or str host: host name or IP address
        :param jpype.JInt or int port: port (0: use default port)
        """

    @staticmethod
    def getClientAuthenticator() -> ClientAuthenticator:
        """
        Get the currently installed client authenticator.  If one has not been
        installed, this will trigger the installation of a default instance.
        
        :return: current client authenticator
        :rtype: ClientAuthenticator
        """

    @staticmethod
    @typing.overload
    def getRepositoryServer(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int]) -> RepositoryServerAdapter:
        """
        Connect to a Repository Server and obtain a handle to it.
        Based upon the server authentication requirements, the user may be
        prompted for a password via a Swing dialog.  If a previous connection
        attempt to this server failed, the adapter may be returned in a
        disconnected state.
        
        :param java.lang.String or str host: server name or address
        :param jpype.JInt or int port: server port, 0 indicates that default port should be used.
        :return: repository server adapter
        :rtype: RepositoryServerAdapter
        """

    @staticmethod
    @typing.overload
    def getRepositoryServer(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], forceConnect: typing.Union[jpype.JBoolean, bool]) -> RepositoryServerAdapter:
        """
        Connect to a Repository Server and obtain a handle to it.
        Based upon the server authentication requirements, the user may be
        prompted for a password via a Swing dialog.
        
        :param java.lang.String or str host: server name or address
        :param jpype.JInt or int port: server port, 0 indicates that default port should be used.
        :param jpype.JBoolean or bool forceConnect: if true and the server adapter is disconnected, an
        attempt will be made to reconnect.
        :return: repository server handle
        :rtype: RepositoryServerAdapter
        """

    @staticmethod
    def getUserName() -> str:
        """
        Returns default user login name.  Actual user name used by repository
        should be obtained from RepositoryServerAdapter.getUser
        
        :return: default user name
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def handleException(repository: RepositoryAdapter, exc: java.lang.Exception, operation: typing.Union[java.lang.String, str], mustRetry: typing.Union[jpype.JBoolean, bool], parent: java.awt.Component):
        """
        Displays an error dialog appropriate for the given exception. If the exception is a
        ConnectException or NotConnectedException, a prompt to reconnect to the Ghidra Server
        is displayed.
        
        :param RepositoryAdapter repository: may be null if the exception is not a RemoteException
        :param java.lang.Exception exc: exception that occurred
        :param java.lang.String or str operation: operation that was being done when the exception occurred; this string
        is be used in the message for the error dialog if one should be displayed
        :param jpype.JBoolean or bool mustRetry: true if the message should state that the user should retry the operation
        because it may not have succeeded (if the exception was because a RemoteException); there
        may be cases where the operation succeeded; as a result of the operation, a bad connection
        to the server was detected (e.g., save a file). Note: this parameter is ignored if the
        exception is not a ConnectException or NotConnectedException.
        :param java.awt.Component parent: parent of the error dialog
        """

    @staticmethod
    @typing.overload
    def handleException(repository: RepositoryAdapter, exc: java.lang.Exception, operation: typing.Union[java.lang.String, str], parent: java.awt.Component):
        """
        Displays an error dialog appropriate for the given exception. If the exception is a
        ConnectException or NotConnectedException, a prompt to reconnect to the Ghidra Server
        is displayed. The message states that the operation may have to be retried due to the
        failed connection.
        
        :param RepositoryAdapter repository: may be null if the exception is not a RemoteException
        :param java.lang.Exception exc: exception that occurred
        :param java.lang.String or str operation: operation that was being done when the exception occurred; this string
        is be used in the message for the error dialog if one should be displayed
        :param java.awt.Component parent: parent of the error dialog
        """

    @staticmethod
    def isConnected(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determine if a connected :obj:`RepositoryServerAdapter` already exists for the specified server.
        
        :param java.lang.String or str host: server name or address
        :param jpype.JInt or int port: server port, 0 indicates that default port applies.
        :return: true if connection already exists, else false
        :rtype: bool
        """

    @staticmethod
    def isSSHKeyAvailable() -> bool:
        ...

    @staticmethod
    def promptForReconnect(repository: RepositoryAdapter, parent: java.awt.Component):
        """
        Prompt the user to reconnect to the Ghidra Server.
        
        :param RepositoryAdapter repository: repository to connect to
        :param java.awt.Component parent: parent of the dialog
        """

    @staticmethod
    def setClientAuthenticator(authenticator: ClientAuthenticator):
        """
        Set client authenticator
        
        :param ClientAuthenticator authenticator: client authenticator instance
        """


class RepositoryNotFoundException(java.io.IOException):
    """
    ``RepositoryNotFoundException`` thrown when a failed connection occurs to a
    non-existing repository.  A valid server connection is required to make this 
    determination.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...



__all__ = ["RemoteAdapterListener", "HeadlessClientAuthenticator", "ClientAuthenticator", "PasswordClientAuthenticator", "RepositoryChangeDispatcher", "RepositoryServerAdapter", "RepositoryAdapter", "DefaultClientAuthenticator", "NotConnectedException", "ServerConnectTask", "ClientUtil", "RepositoryNotFoundException"]
