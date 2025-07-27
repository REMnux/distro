from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.client
import ghidra.framework.data
import ghidra.framework.model
import ghidra.util.classfinder
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore


class GhidraProtocolConnector(java.lang.Object):
    """
    ``GhidraProtocolConnector`` provides an abtract implementation to access Ghidra 
    repositories using various underlying communication protocols.  The common requirement 
    for all implementations is the ability to derive a repository URL from any folder or file
    URL.
    """

    class_: typing.ClassVar[java.lang.Class]

    def connect(self, readOnly: typing.Union[jpype.JBoolean, bool]) -> GhidraURLConnection.StatusCode:
        """
        Connect to the resource specified by the associated URL.  This method should only be invoked
        once, a second attempt may result in an IOException.
        
        :param jpype.JBoolean or bool readOnly: if resource should be requested for write access.
        :return: connection status code
        :rtype: GhidraURLConnection.StatusCode
        :raises IOException: if a connection error occurs
        """

    def getFolderItemName(self) -> str:
        """
        Gets the repository folder item name associated with the URL.
        If an ambiguous path has been specified, the folder item name may become null
        after a connection is established (e.g., folder item name will be appended 
        to folder path and item name will become null if item turns out to
        be a folder).
        
        :return: folder item name or null
        :rtype: str
        """

    def getFolderPath(self) -> str:
        """
        Gets the repository folder path associated with the URL.
        If an ambiguous path has been specified, the folder path may change
        after a connection is established (e.g., folder item name will be appended 
        to folder path and item name will become null if item turns out to
        be a folder).
        
        :return: repository folder path or null
        :rtype: str
        """

    def getRepositoryAdapter(self) -> ghidra.framework.client.RepositoryAdapter:
        """
        Get the RepositoryAdapter associated with a URL which specifies a repository.
        
        :return: repository adapter or null if a project locator is supplied instead
        :rtype: ghidra.framework.client.RepositoryAdapter
        """

    def getRepositoryName(self) -> str:
        """
        Gets the repository name associated with the URL.  If a local URL is used this will
        correspond to the project name.
        
        :return: the repository name or null if URL does not identify a specific repository
        :rtype: str
        """

    def getRepositoryServerAdapter(self) -> ghidra.framework.client.RepositoryServerAdapter:
        """
        Get the RepositoryServerAdapter associated with a URL which specifies a repository or
        repository server.
        
        :return: repository server adapter or null if a project locator is supplied instead
        :rtype: ghidra.framework.client.RepositoryServerAdapter
        """

    def getStatusCode(self) -> GhidraURLConnection.StatusCode:
        """
        Gets the status code from a Ghidra URL connect attempt.
        
        :return: the Ghidra status code or null if not yet connected
        :rtype: GhidraURLConnection.StatusCode
        
        .. seealso::
        
            | :obj:`.connect(boolean)`
        """

    def isReadOnly(self) -> bool:
        """
        Determines the read-only nature of a connected resource
        
        :return: true if read-only, false if write access allowed
        :rtype: bool
        :raises NotConnectedException: if connect has not yet been performed
        """

    @property
    def folderPath(self) -> java.lang.String:
        ...

    @property
    def folderItemName(self) -> java.lang.String:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def repositoryName(self) -> java.lang.String:
        ...

    @property
    def repositoryServerAdapter(self) -> ghidra.framework.client.RepositoryServerAdapter:
        ...

    @property
    def repositoryAdapter(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    @property
    def statusCode(self) -> GhidraURLConnection.StatusCode:
        ...


class DefaultGhidraProtocolHandler(GhidraProtocolHandler):
    """
    ``DefaultGhidraProtocolHandler`` provides the default protocol 
    handler which corresponds to the original RMI-based Ghidra Server
    and local file-based Ghidra projects.
    ghidra://host/repo/... or ghidra:/path/projectName/...
    See :obj:`DefaultGhidraProtocolConnector` and :obj:`DefaultLocalGhidraProtocolConnector`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TransientProjectData(ghidra.framework.data.DefaultProjectData):

    class_: typing.ClassVar[java.lang.Class]

    def incrementInstanceUseCount(self):
        ...


class RepositoryInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, repositoryURL: java.net.URL, repositoryName: typing.Union[java.lang.String, str], readOnly: typing.Union[jpype.JBoolean, bool]):
        ...

    def getURL(self) -> java.net.URL:
        """
        Get the Ghidra URL which corresponds to the repository
        
        :return: repository URL
        :rtype: java.net.URL
        """

    def toShortString(self) -> str:
        ...

    @property
    def uRL(self) -> java.net.URL:
        ...


class GhidraURLResultHandlerAdapter(GhidraURLResultHandler):
    """
    :obj:`GhidraURLResultHandlerAdapter` provides a basic result handler for 
    :obj:`GhidraURLQuery`.  All uses of this adapter should override one or
    both of the processing methods :meth:`processResult(DomainFile, URL, TaskMonitor) <.processResult>`
    and :meth:`processResult(DomainFolder, URL, TaskMonitor) <.processResult>`.  For any process method
    not overriden the default behavior is reporting *Unsupported Content*.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct adapter.  If :meth:`handleError(String, String, URL, IOException) <.handleError>`
        is not overriden all errors are reported via 
        :meth:`Msg.showError(Object, java.awt.Component, String, Object) <Msg.showError>`.
        """

    @typing.overload
    def __init__(self, throwErrorByDefault: typing.Union[jpype.JBoolean, bool]):
        """
        Construct adapter with preferred error handling.  There is no need to use this constructor
        if :meth:`handleError(String, String, URL, IOException) <.handleError>` is override.
        
        :param jpype.JBoolean or bool throwErrorByDefault: if true all errors will be thrown as an :obj:`IOException`,
        otherwise error is reported via :meth:`Msg.showError(Object, java.awt.Component, String, Object) <Msg.showError>`.
        """


class GhidraURLResultHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def handleError(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], url: java.net.URL, cause: java.io.IOException):
        """
        Handle error which occurs during query operation.
        
        :param java.lang.String or str title: error title
        :param java.lang.String or str message: error detail
        :param java.net.URL url: URL which was used for query
        :param java.io.IOException cause: cause of error (may be null)
        :raises IOException: may be thrown if handler decides to propogate error
        """

    def handleUnauthorizedAccess(self, url: java.net.URL):
        """
        Handle authorization error. 
        This condition is generally logged and user notified via GUI during connection processing.
        This method does not do anything by default but is provided to flag failure if needed since
        :meth:`handleError(String, String, URL, IOException) <.handleError>` will not be invoked.
        
        :param java.net.URL url: connection URL
        :raises IOException: may be thrown if handler decides to propogate error
        """

    @typing.overload
    def processResult(self, domainFile: ghidra.framework.model.DomainFile, url: java.net.URL, monitor: ghidra.util.task.TaskMonitor):
        """
        Process the specified ``domainFile`` query result. 
        Dissemination of the ``domainFile`` instance should be restricted and any use of it 
        completed before the call to this method returns.  Upon return from this method call the 
        underlying connection will be closed and at which time the ``domainFile`` instance 
        will become invalid.
        
        :param ghidra.framework.model.DomainFile domainFile: :obj:`DomainFile` to which the URL refers.
        :param java.net.URL url: URL which was used to retrieve the specified ``domainFile``
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO error occurs
        :raises CancelledException: if task is cancelled
        """

    @typing.overload
    def processResult(self, domainFolder: ghidra.framework.model.DomainFolder, url: java.net.URL, monitor: ghidra.util.task.TaskMonitor):
        """
        Process the specified ``domainFolder`` query result.
        Dissemination of the ``domainFolder`` instance should be restricted and any use of it 
        completed before the call to this method returns.  Upon return from this method call the 
        underlying connection will be closed and at which time the ``domainFolder`` instance 
        will become invalid.
        
        :param ghidra.framework.model.DomainFolder domainFolder: :obj:`DomainFolder` to which the URL refers.
        :param java.net.URL url: URL which was used to retrieve the specified ``domainFolder``
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO error occurs
        :raises CancelledException: if task is cancelled
        """


class DefaultLocalGhidraProtocolConnector(GhidraProtocolConnector):
    """
    ``DefaultLocalGhidraProtocolConnector`` provides support for the
    Ghidra URL protocol which specifies a local Ghidra project without extension.
    This connector is responsible for producing a suitable :obj:`ProjectLocator`
    for accessing the project files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLocalProjectLocator(self) -> ghidra.framework.model.ProjectLocator:
        """
        Get the ProjectLocator associated with a local project URL.
        
        :return: project locator object or null if URL supplies a RepositoryAdapter and/or 
        RepositoryServerAdapter.
        :rtype: ghidra.framework.model.ProjectLocator
        """

    @property
    def localProjectLocator(self) -> ghidra.framework.model.ProjectLocator:
        ...


class GhidraURLWrappedContent(java.lang.Object):
    """
    ``GhidraURLWrappedContent`` provides controlled access to a Ghidra folder/file
    associated with a Ghidra URL.  It is important to note the issuance of this object does
    not guarantee existence of the requested resource.  Any object obtained via the getContent
    method must be released via the release method.  The following rules should be followed
    when using domain folder and files obtained.
     
    1. The getContent method may only be invoked once per consumer
    2. The content must be released when no longer in-use, however it should not be released
    until any derivative domain folders and files are no longer in use as well.
    3. A read-only or immutable domain object may remain open while the associated domain 
    file/folder is released.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, c: GhidraURLConnection):
        ...

    def getContent(self, consumer: java.lang.Object) -> java.lang.Object:
        """
        Get the domain folder or file associated with the Ghidra URL.
        The consumer is responsible for releasing the content object via the release method 
        when it is no longer in use (see :meth:`release(Object, Object) <.release>`}).
        
        :param java.lang.Object consumer: object which is responsible for releasing the content
        :return: domain file or folder
        :rtype: java.lang.Object
        :raises IOException: if an IO error occurs
        :raises FileNotFoundException: if the Ghidra URL does no correspond to a folder or file
        within the Ghidra repository/project.
        
        .. seealso::
        
            | :obj:`.release(Object, Object)`
        """

    def release(self, content: java.lang.Object, consumer: java.lang.Object):
        """
        Indicates the content object previously obtained from this wrapper is
        no longer in-use and the underlying connection may be closed.  A read-only 
        or immutable domain object may remain open and in-use after its associated
        domain folder/file has been released.
        
        :param java.lang.Object content: object obtained via :meth:`getContent(Object) <.getContent>`
        :param java.lang.Object consumer: object consumer which was specified to :meth:`getContent(Object) <.getContent>`
        """

    @property
    def content(self) -> java.lang.Object:
        ...


class Handler(java.net.URLStreamHandler):
    """
    ``Handler`` provides a "ghidra" URL protocol handler which
    corresponds to the ``GhidraURLConnection`` implementation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def isSupportedURL(url: java.net.URL) -> bool:
        """
        Determine if the specified url is supported and that any required 
        protocol extensions are recognized.
        
        :param java.net.URL url: 
        :return: true if support ghidra URL
        :rtype: bool
        """

    @staticmethod
    def registerHandler():
        """
        Register the "ghidra" URL protocol Handler.
        Alternatively, the protocol handler can be explicitly used when instantiating 
        a ghidra URL:
         
        URL url = new URL(null, "ghidra://myGhidraServer/Test", new ghidra.framework.protocol.ghidra.Handler());
         
        It is also important that a ``ClientAuthenticator`` also be registered.
        
        
        .. seealso::
        
            | :obj:`ClientUtil.setClientAuthenticator(ghidra.framework.client.ClientAuthenticator)`
        """


class GhidraURL(java.lang.Object):
    """
    Supported URL forms include:
     
    * ghidra://<host>:<port>/<repository-name>[/<folder-path>]/[<folderItemName>[#ref]]
    * ghidra:/[X:/]<project-path>/<project-name>[?[/<folder-path>]/[<folderItemName>[#ref]]]
    """

    class_: typing.ClassVar[java.lang.Class]
    PROTOCOL: typing.Final = "ghidra"
    MARKER_FILE_EXTENSION: typing.Final = ".gpr"
    PROJECT_DIRECTORY_EXTENSION: typing.Final = ".rep"

    @staticmethod
    def getDisplayString(url: java.net.URL) -> str:
        """
        Generate preferred display string for Ghidra URLs.
        Form can be parsed by the toURL method.
        
        :param java.net.URL url: ghidra URL
        :return: formatted URL display string
        :rtype: str
        
        .. seealso::
        
            | :obj:`.toURL(String)`
        """

    @staticmethod
    def getFolderURL(ghidraUrl: java.net.URL) -> java.net.URL:
        """
        Force the specified URL to specify a folder.  This may be neccessary when only folders
        are supported since Ghidra permits both a folder and file to have the same name within
        its parent folder.  This method simply ensures that the URL path ends with a ``/`` 
        character if needed.
        
        :param java.net.URL ghidraUrl: ghidra URL
        :return: ghidra folder URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: if specified URL is niether a 
        :meth:`valid remote server URL <.isServerRepositoryURL>`
        or :meth:`local project URL <.isLocalProjectURL>`.
        """

    @staticmethod
    def getNormalizedURL(url: java.net.URL) -> java.net.URL:
        """
        Get a normalized URL which eliminates use of host names and optional URL ref
        which may prevent direct comparison.
        
        :param java.net.URL url: ghidra URL
        :return: normalized url
        :rtype: java.net.URL
        """

    @staticmethod
    def getProjectPathname(ghidraUrl: java.net.URL) -> str:
        """
        Get the project pathname referenced by the specified Ghidra file/folder URL.
        If path is missing root folder is returned.
        
        :param java.net.URL ghidraUrl: ghidra file/folder URL (server-only URL not permitted)
        :return: pathname of file or folder
        :rtype: str
        """

    @staticmethod
    def getProjectStorageLocator(localProjectURL: java.net.URL) -> ghidra.framework.model.ProjectLocator:
        """
        Get the project locator which corresponds to the specified local project URL.
        Confirm local project URL with :meth:`isLocalProjectURL(URL) <.isLocalProjectURL>` prior to method use.
        
        :param java.net.URL localProjectURL: local Ghidra project URL
        :return: project locator or null if invalid path specified
        :rtype: ghidra.framework.model.ProjectLocator
        :raises IllegalArgumentException: URL is not a valid 
        :meth:`local project URL <.isLocalProjectURL>`.
        """

    @staticmethod
    def getProjectURL(ghidraUrl: java.net.URL) -> java.net.URL:
        """
        Get Ghidra URL which corresponds to the local-project or repository with any 
        file path or query details removed.
        
        :param java.net.URL ghidraUrl: ghidra file/folder URL (server-only URL not permitted)
        :return: local-project or repository URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: if URL does not specify the ``ghidra`` protocol
        or does not properly identify a remote repository or local project.
        """

    @staticmethod
    def getRepositoryName(url: java.net.URL) -> str:
        """
        Get the shared repository name associated with a repository URL or null
        if not applicable.  For ghidra URL extensions it is assumed that the first path element
        corresponds to the repository name.
        
        :param java.net.URL url: ghidra URL for shared project resource
        :return: repository name or null if not applicable to URL
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def isGhidraURL(str: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified string appears to be a possible ghidra URL
        (starts with "ghidra:/").
        
        :param java.lang.String or str str: string to be checked
        :return: true if string is possible ghidra URL
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isGhidraURL(url: java.net.URL) -> bool:
        """
        Tests if the given url is using the Ghidra protocol
        
        :param java.net.URL url: the url to test
        :return: true if the url is using the Ghidra protocol
        :rtype: bool
        """

    @staticmethod
    def isLocalGhidraURL(str: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if URL string uses a local format (e.g., ``ghidra:/path...``).
        Extensive validation is not performed.  This method is intended to differentiate
        from a server URL only.
        
        :param java.lang.String or str str: URL string
        :return: true if string appears to be local Ghidra URL, else false
        :rtype: bool
        """

    @staticmethod
    def isLocalProjectURL(url: java.net.URL) -> bool:
        """
        Determine if the specified URL is a local project URL.
        No checking is performed as to the existence of the project.
        
        :param java.net.URL url: ghidra URL
        :return: true if specified URL refers to a local 
        project (ghidra:/path/projectName...)
        :rtype: bool
        """

    @staticmethod
    def isServerRepositoryURL(url: java.net.URL) -> bool:
        """
        Determine if the specified URL is any type of server "repository" URL.
        No checking is performed as to the existence of the server or repository.
        NOTE: ghidra protocol extensions are not currently supported (e.g., ghidra:http://...).
        
        :param java.net.URL url: ghidra URL
        :return: true if specified URL refers to a Ghidra server 
        repository (ghidra://host/repositoryNAME/path...)
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isServerURL(str: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if URL string uses a remote server format (e.g., ``ghidra://host...``).
        Extensive validation is not performed.  This method is intended to differentiate
        from a local URL only.
        
        :param java.lang.String or str str: URL string
        :return: true if string appears to be remote server Ghidra URL, else false
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isServerURL(url: java.net.URL) -> bool:
        """
        Determine if the specified URL is any type of supported server Ghidra URL.
        No checking is performed as to the existence of the server or repository.
        
        :param java.net.URL url: ghidra URL
        :return: true if specified URL refers to a Ghidra server 
        repository (ghidra://host/repositoryNAME/path...)
        :rtype: bool
        """

    @staticmethod
    def localProjectExists(url: java.net.URL) -> bool:
        """
        Determine if the specified URL refers to a local project and
        it exists.
        
        :param java.net.URL url: ghidra URL
        :return: true if specified URL refers to a local project and
        it exists.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def makeURL(dirPath: typing.Union[java.lang.String, str], projectName: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project
        
        :param java.lang.String or str dirPath: absolute path of project location directory
        :param java.lang.String or str projectName: name of project
        :return: local Ghidra project URL
        :rtype: java.net.URL
        """

    @staticmethod
    @typing.overload
    def makeURL(projectLocator: ghidra.framework.model.ProjectLocator) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project
        
        :param ghidra.framework.model.ProjectLocator projectLocator: absolute project location
        :return: local Ghidra project URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: if ``projectLocator`` does not have an absolute location
        """

    @staticmethod
    @typing.overload
    def makeURL(projectLocation: typing.Union[java.lang.String, str], projectName: typing.Union[java.lang.String, str], projectFilePath: typing.Union[java.lang.String, str], ref: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project with optional project file and ref
        
        :param java.lang.String or str projectLocation: absolute path of project location directory
        :param java.lang.String or str projectName: name of project
        :param java.lang.String or str projectFilePath: file path (e.g., /a/b/c, may be null)
        :param java.lang.String or str ref: location reference (may be null)
        :return: local Ghidra project URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: if an absolute projectLocation path is not specified
        """

    @staticmethod
    @typing.overload
    def makeURL(projectLocator: ghidra.framework.model.ProjectLocator, projectFilePath: typing.Union[java.lang.String, str], ref: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project with optional project file and ref
        
        :param ghidra.framework.model.ProjectLocator projectLocator: local project locator
        :param java.lang.String or str projectFilePath: file path (e.g., /a/b/c, may be null)
        :param java.lang.String or str ref: location reference (may be null)
        :return: local Ghidra project URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: if invalid ``projectFilePath`` specified or if URL 
        instantion fails.
        """

    @staticmethod
    @typing.overload
    def makeURL(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], repositoryName: typing.Union[java.lang.String, str], repositoryPath: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository content.  Path may correspond 
        to either a file or folder.
        
        :param java.lang.String or str host: server host name/address
        :param jpype.JInt or int port: optional server port (a value <= 0 refers to the default port)
        :param java.lang.String or str repositoryName: repository name
        :param java.lang.String or str repositoryPath: absolute folder or file path within repository.
        Folder paths should end with a '/' character.
        :return: Ghidra Server repository content URL
        :rtype: java.net.URL
        """

    @staticmethod
    @typing.overload
    def makeURL(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], repositoryName: typing.Union[java.lang.String, str], repositoryPath: typing.Union[java.lang.String, str], ref: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository content.  Path may correspond 
        to either a file or folder.
        
        :param java.lang.String or str host: server host name/address
        :param jpype.JInt or int port: optional server port (a value <= 0 refers to the default port)
        :param java.lang.String or str repositoryName: repository name
        :param java.lang.String or str repositoryPath: absolute folder or file path within repository.
        :param java.lang.String or str ref: ref or null 
        Folder paths should end with a '/' character.
        :return: Ghidra Server repository content URL
        :rtype: java.net.URL
        """

    @staticmethod
    @typing.overload
    def makeURL(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], repositoryName: typing.Union[java.lang.String, str], repositoryFolderPath: typing.Union[java.lang.String, str], fileName: typing.Union[java.lang.String, str], ref: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository content.  Path may correspond 
        to either a file or folder.
        
        :param java.lang.String or str host: server host name/address
        :param jpype.JInt or int port: optional server port (a value <= 0 refers to the default port)
        :param java.lang.String or str repositoryName: repository name
        :param java.lang.String or str repositoryFolderPath: absolute folder path within repository.
        :param java.lang.String or str fileName: name of a file or folder contained within the specified ``repositoryFolderPath``
        :param java.lang.String or str ref: optional URL ref or null
        Folder paths should end with a '/' character.
        :return: Ghidra Server repository content URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: if required arguments are blank or invalid
        """

    @staticmethod
    @typing.overload
    def makeURL(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], repositoryName: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository and its root folder
        
        :param java.lang.String or str host: server host name/address
        :param jpype.JInt or int port: optional server port (a value <= 0 refers to the default port)
        :param java.lang.String or str repositoryName: repository name
        :return: Ghidra Server repository URL
        :rtype: java.net.URL
        """

    @staticmethod
    def toURL(projectPathOrURL: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Create a Ghidra URL from a string form of Ghidra URL or local project path.
        This method can consume strings produced by the getDisplayString method.
        
        :param java.lang.String or str projectPathOrURL: project path (<absolute-directory>/<project-name>) or 
        string form of Ghidra URL.
        :return: local Ghidra project URL
        :rtype: java.net.URL
        :raises IllegalArgumentException: invalid path or URL specified
        
        .. seealso::
        
            | :obj:`.getDisplayString(URL)`
        """


class GhidraProtocolHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    ``GhidraProtocolHandler`` provides the extension point for 
    Ghidra protocol extensions.  A Ghidra protocol extension will be identified 
    within by the optional *extProtocolName* appearing within a Ghidra URL:
    ghidra:[<extProtocolName>:]/... In the absence of a protocol extension
    the :obj:`DefaultGhidraProtocolHandler` will be used.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getConnector(self, ghidraUrl: java.net.URL) -> GhidraProtocolConnector:
        """
        Get the Ghidra protocol connector for a Ghidra URL which requires this
        extension.
        
        :param java.net.URL ghidraUrl: Ghidra protocol URL
        :return: Ghidra protocol connector
        :rtype: GhidraProtocolConnector
        :raises MalformedURLException: if URL is invalid
        """

    def isExtensionSupported(self, extProtocolName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if this protocol handler is responsible for handling the
        specified named protocol extension.  One handler may support multiple
        protocol extension names (e.g., http and https).
        
        :param java.lang.String or str extProtocolName: protocol extension name
        :return: true if this handler supports the specified protocol extension name
        :rtype: bool
        """

    @property
    def connector(self) -> GhidraProtocolConnector:
        ...

    @property
    def extensionSupported(self) -> jpype.JBoolean:
        ...


class GhidraURLQuery(java.lang.Object):
    """
    :obj:`GhidraURLQuery` performs remote Ghidra repository and read-only local project
    queries for processing either a :obj:`DomainFile` or :obj:`DomainFolder` that a 
    Ghidra URL may reference.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def queryRepositoryUrl(ghidraUrl: java.net.URL, readOnly: typing.Union[jpype.JBoolean, bool], resultHandler: GhidraURLResultHandler, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform query using specified GhidraURL and process result.
        Both local project and remote repository URLs are supported.
        This method is intended to be invoked from within a :obj:`Task` or for headless operations.
        
        :param java.net.URL ghidraUrl: local or remote Ghidra URL
        :param jpype.JBoolean or bool readOnly: allows update/commit (false) or read-only (true) access.
        :param GhidraURLResultHandler resultHandler: query result handler
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO error occurs which was re-thrown by ``resultHandler``
        :raises CancelledException: if task is cancelled
        """

    @staticmethod
    def queryUrl(ghidraUrl: java.net.URL, resultHandler: GhidraURLResultHandler, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform read-only query using specified GhidraURL and process result.
        Both local project and remote repository URLs are supported.
        This method is intended to be invoked from within a :obj:`Task` or for headless operations.
        
        :param java.net.URL ghidraUrl: local or remote Ghidra URL
        :param GhidraURLResultHandler resultHandler: query result handler
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO error occurs which was re-thrown by ``resultHandler``
        :raises CancelledException: if task is cancelled
        """


class GhidraURLConnection(java.net.URLConnection):

    class StatusCode(java.lang.Enum[GhidraURLConnection.StatusCode]):
        """
        Connection status codes
        """

        class_: typing.ClassVar[java.lang.Class]
        OK: typing.Final[GhidraURLConnection.StatusCode]
        UNAUTHORIZED: typing.Final[GhidraURLConnection.StatusCode]
        """
        Ghidra Status-Code 401: Unauthorized.
        This status code occurs when repository access is denied.
        """

        NOT_FOUND: typing.Final[GhidraURLConnection.StatusCode]
        """
        Ghidra Status-Code 404: Not Found.
        This status code occurs when repository or project does not exist.
        """

        LOCKED: typing.Final[GhidraURLConnection.StatusCode]
        """
        Ghidra Status-Code 423: Locked.
        This status code occurs when project is locked (i.e., in use).
        """

        UNAVAILABLE: typing.Final[GhidraURLConnection.StatusCode]
        """
        Ghidra Status-Code 503: Unavailable.
        This status code includes a variety of connection errors
        which are reported/logged by the Ghidra Server support code.
        """


        def getCode(self) -> int:
            ...

        def getDescription(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GhidraURLConnection.StatusCode:
            ...

        @staticmethod
        def values() -> jpype.JArray[GhidraURLConnection.StatusCode]:
            ...

        @property
        def code(self) -> jpype.JInt:
            ...

        @property
        def description(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    GHIDRA_WRAPPED_CONTENT: typing.Final = "GhidraWrappedContent"
    """
    Ghidra content type - domain folder/file wrapped within GhidraURLWrappedContent object.
    
    
    .. seealso::
    
        | :obj:`GhidraURLWrappedContent`
    """

    REPOSITORY_SERVER_CONTENT: typing.Final = "RepositoryServer"
    """
    Ghidra content type - repository server in the form of a RepositoryAdapter
    
    
    .. seealso::
    
        | :obj:`RepositoryAdapter`
    """


    @typing.overload
    def __init__(self, ghidraUrl: java.net.URL):
        """
        Construct a Ghidra URL connection which uses the default handler without
        any extension protocol.
        
        :param java.net.URL ghidraUrl: ghidra protocol URL (e.g., ghidra://server/repo)
        :raises MalformedURLException: if URL is invalid
        """

    @typing.overload
    def __init__(self, url: java.net.URL, protocolHandler: GhidraProtocolHandler):
        """
        Construct a Ghidra URL connection which requires an Ghidra protocol extension
        
        :param java.net.URL url: extension URL without the ghidra protocol prefix (e.g., http://server/repo)
        :param GhidraProtocolHandler protocolHandler: Ghidra protocol extension handler
        :raises MalformedURLException: if URL is invalid
        """

    def getContent(self) -> java.lang.Object:
        """
        Get content associated with the URL
        
        :return: URL content generally in the form of GhidraURLWrappedContent, although other
        special cases may result in different content (Example: a server-only URL could result in
        content class of RepositoryServerAdapter).
        :rtype: java.lang.Object
        :raises IOException: if an IO error occurs
        """

    def getFolderItemName(self) -> str:
        """
        Gets the repository folder item name associated with this connection.
        If an ambiguous path has been specified, the folder item name may become null
        after a connection is established (e.g., folder item name will be appended 
        to folder path and item name will become null if item turns out to
        be a folder).
        
        :return: folder item name or null
        :rtype: str
        """

    def getFolderPath(self) -> str:
        """
        Gets the repository folder path associated with this connection.
        If an ambiguous path has been specified, the folder path may change
        after a connection is established (e.g., folder item name will be appended 
        to folder path and item name will become null if item turns out to
        be a folder).
        
        :return: repository folder path or null
        :rtype: str
        """

    def getProjectData(self) -> ghidra.framework.model.ProjectData:
        """
        If URL connects and corresponds to a valid repository or local project, this method
        may be used to obtain the associated ProjectData object.  The caller is
        responsible for properly :meth:`closing <ProjectData.close>` the returned project data 
        instance when no longer in-use, failure to do so may prevent release of repository handle 
        to server until process exits.  It is important that :meth:`ProjectData.close() <ProjectData.close>` is
        invoked once, and only once, per call to this method to ensure project "use" tracking 
        is properly maintained.  Improperly invoking the close method on a shared transient 
        :obj:`ProjectData` instance may cause the underlying storage to be prematurely
        disposed.
        
        :return: project data which corresponds to this connection or null if unavailable
        :rtype: ghidra.framework.model.ProjectData
        :raises IOException: if an IO error occurs
        """

    def getRepositoryName(self) -> str:
        """
        Gets the repository name associated with this ``GhidraURLConnection``.
        
        :return: the repository name or null if URL does not identify a specific repository
        :rtype: str
        """

    def getStatusCode(self) -> GhidraURLConnection.StatusCode:
        """
        Gets the status code from a Ghidra URL connect attempt.
        
        :raises IOException: if an error occurred connecting to the server.
        :return: the Ghidra connection status code or null
        :rtype: GhidraURLConnection.StatusCode
        """

    def isReadOnly(self) -> bool:
        """
        Connection was opened as read-only
        
        :return: true if read-only connection
        :rtype: bool
        """

    def setReadOnly(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Set the read-only state for this connection prior to connecting or getting content.  
        The default access is read-only.  Extreme care must be taken when setting the state to false 
        for local projects without the use of a ProjectLock.
         
        
        **NOTE:** Local project URL connections only support read-only access.
        
        :param jpype.JBoolean or bool state: read-only if true, otherwise read-write
        :raises UnsupportedOperationException: if an attempt is made to enable write access for
        a local project URL.
        :raises IllegalStateException: if already connected
        """

    @property
    def projectData(self) -> ghidra.framework.model.ProjectData:
        ...

    @property
    def folderPath(self) -> java.lang.String:
        ...

    @property
    def folderItemName(self) -> java.lang.String:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @readOnly.setter
    def readOnly(self, value: jpype.JBoolean):
        ...

    @property
    def repositoryName(self) -> java.lang.String:
        ...

    @property
    def content(self) -> java.lang.Object:
        ...

    @property
    def statusCode(self) -> GhidraURLConnection.StatusCode:
        ...


class DefaultGhidraProtocolConnector(GhidraProtocolConnector):
    """
    ``DefaultGhidraProtocolConnector`` provides support for the
    Ghidra URL protocol without extension for accessing the legacy Ghidra Server 
    over an RMI interface.
    """

    class_: typing.ClassVar[java.lang.Class]


class ContentTypeQueryTask(GhidraURLQueryTask):
    """
    A blocking/modal Ghidra URL content type discovery task
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ghidraUrl: java.net.URL):
        """
        Construct a Ghidra URL content type query task
        
        :param java.net.URL ghidraUrl: Ghidra URL (local or remote)
        :raises IllegalArgumentException: if specified URL is not a Ghidra URL
        (see :obj:`GhidraURL`).
        """

    def getContentType(self) -> str:
        """
        Get the discovered content type (e.g., "Program")
        
        :return: content type or null if error occured or unsupported URL content
        :rtype: str
        :raises IllegalStateException: if task has not completed execution
        """

    @property
    def contentType(self) -> java.lang.String:
        ...


class TransientProjectManager(java.lang.Object):

    @typing.type_check_only
    class TransientProjectStorageLocator(ghidra.framework.model.ProjectLocator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Force disposal of all transient projects associated with remote Ghidra URL
        connections. WARNING: This method intended for testing only.
        """

    def getActiveProjectCount(self) -> int:
        """
        Get the number of active transient project data instances
        
        :return: number of active transient project data instances
        :rtype: int
        """

    @staticmethod
    def getTransientProjectManager() -> TransientProjectManager:
        """
        Get the ``TransientProjectManager`` singleton instance for the JVM
        
        :return: ``TransientProjectManager`` singleton instance
        :rtype: TransientProjectManager
        """

    @property
    def activeProjectCount(self) -> jpype.JInt:
        ...


class GhidraURLQueryTask(ghidra.util.task.Task, GhidraURLResultHandler):
    """
    :obj:`GhidraURLQueryTask` provides an abstract Task which performs remote Ghidra 
    repository and read-only local project queries for processing either a :obj:`DomainFile` 
    or :obj:`DomainFolder` that a Ghidra URL may reference.
     
    
    All implementations of this Task should override one or
    both of the processing methods :meth:`processResult(DomainFile, URL, TaskMonitor) <.processResult>`
    and :meth:`processResult(DomainFolder, URL, TaskMonitor) <.processResult>`.  For any process method
    not overriden the default behavior is reporting *Unsupported Content*.
     
    
    If :meth:`handleError(String, String, URL, IOException) <.handleError>`
    is not overriden all errors are reported via 
    :meth:`Msg.showError(Object, java.awt.Component, String, Object) <Msg.showError>`.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["GhidraProtocolConnector", "DefaultGhidraProtocolHandler", "TransientProjectData", "RepositoryInfo", "GhidraURLResultHandlerAdapter", "GhidraURLResultHandler", "DefaultLocalGhidraProtocolConnector", "GhidraURLWrappedContent", "Handler", "GhidraURL", "GhidraProtocolHandler", "GhidraURLQuery", "GhidraURLConnection", "DefaultGhidraProtocolConnector", "ContentTypeQueryTask", "TransientProjectManager", "GhidraURLQueryTask"]
