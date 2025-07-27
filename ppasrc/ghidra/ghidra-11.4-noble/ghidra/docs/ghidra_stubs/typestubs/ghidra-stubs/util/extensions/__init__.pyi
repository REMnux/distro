from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


class ExtensionUtils(java.lang.Object):
    """
    Utilities for finding extensions.
     
    
    Extension searching is cached.  Use :meth:`reload() <.reload>` to update the cache.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROPERTIES_FILE_NAME: typing.ClassVar[java.lang.String]
    PROPERTIES_FILE_NAME_UNINSTALLED: typing.ClassVar[java.lang.String]

    def __init__(self):
        ...

    @staticmethod
    def clearCache():
        """
        Clears any cached extensions.
        """

    @staticmethod
    def createExtensionDetailsFromArchive(resourceFile: generic.jar.ResourceFile) -> ExtensionDetails:
        ...

    @staticmethod
    def createExtensionFromProperties(file: jpype.protocol.SupportsPath) -> ExtensionDetails:
        ...

    @staticmethod
    def getActiveInstalledExtensions() -> java.util.Set[ExtensionDetails]:
        ...

    @staticmethod
    def getAllInstalledExtensions() -> Extensions:
        ...

    @staticmethod
    def getArchiveExtensions() -> java.util.Set[ExtensionDetails]:
        """
        Returns all archive extensions. These are all the extensions found in
        :obj:`ApplicationLayout.getExtensionArchiveDir`.   This are added to an installation as
        part of the build processes.
         
        
        Archived extensions may be zip files and directories.
        
        :return: set of archive extensions
        :rtype: java.util.Set[ExtensionDetails]
        """

    @staticmethod
    @typing.overload
    def getExtension(path: typing.Union[java.lang.String, str]) -> ExtensionDetails:
        ...

    @staticmethod
    @typing.overload
    def getExtension(file: jpype.protocol.SupportsPath, quiet: typing.Union[jpype.JBoolean, bool]) -> ExtensionDetails:
        ...

    @staticmethod
    def getInstalledExtensions() -> java.util.Set[ExtensionDetails]:
        """
        Returns all installed extensions. These are all the extensions found in
        :obj:`ApplicationLayout.getExtensionInstallationDirs`.
        
        :return: set of installed extensions
        :rtype: java.util.Set[ExtensionDetails]
        """

    @staticmethod
    def initializeExtensions():
        """
        Performs extension maintenance.  This should be called at startup, before any plugins or
        extension points are loaded.
        """

    @staticmethod
    def install(extension: ExtensionDetails, file: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> bool:
        ...

    @staticmethod
    def isExtension(file: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given file or directory is a valid ghidra extension.
         
        
        Note: This means that the zip or directory contains an extension.properties file.
        
        :param jpype.protocol.SupportsPath file: the zip or directory to inspect
        :return: true if the given file represents a valid extension
        :rtype: bool
        """

    @staticmethod
    def reload():
        """
        Clears any cached extensions and searches for extensions.
        """


class ExtensionDetails(java.lang.Comparable[ExtensionDetails]):
    """
    Representation of a Ghidra extension. This class encapsulates all information required to
    uniquely identify an extension and where (or if) it has been installed.
     
    
    Note that hashCode and equals have been implemented for this. Two extension
    descriptions are considered equal if they have the same :obj:`.name` attribute; all other
    fields are unimportant except for display purposes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], author: typing.Union[java.lang.String, str], createdOn: typing.Union[java.lang.String, str], version: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param java.lang.String or str name: unique name of the extension; cannot be null
        :param java.lang.String or str description: brief explanation of what the extension does; can be null
        :param java.lang.String or str author: creator of the extension; can be null
        :param java.lang.String or str createdOn: creation date of the extension, can be null
        :param java.lang.String or str version: the extension version
        """

    def clearMarkForUninstall(self) -> bool:
        """
        A companion method for :meth:`markForUninstall() <.markForUninstall>` that allows extensions marked for cleanup 
        to be restored to the installed state.
         
        
        Specifically, the following will be renamed:
         
        * Module.manifest.uninstalled to Module.manifest
        * extension.properties.uninstalled to extension.properties
        
        
        :return: true if successful
        :rtype: bool
        """

    def getArchivePath(self) -> str:
        """
        Returns the location where the extension archive is located.  The extension archive concept
        is not used for all extensions, but is used for delivering extensions as part of a 
        distribution.
        
        :return: the archive path, or null
        :rtype: str
        
        .. seealso::
        
            | :obj:`ApplicationLayout.getExtensionArchiveDir()`
        """

    def getAuthor(self) -> str:
        ...

    def getCreatedOn(self) -> str:
        ...

    def getDescription(self) -> str:
        ...

    def getInstallDir(self) -> java.io.File:
        ...

    def getInstallPath(self) -> str:
        """
        Returns the location where this extension is installed. If the extension is not installed 
        this will be null.
        
        :return: the extension path, or null
        :rtype: str
        """

    def getLibraries(self) -> java.util.Set[java.net.URL]:
        """
        Returns URLs for all jar files living in the {extension dir}/lib directory for an installed
        extension.
        
        :return: the URLs
        :rtype: java.util.Set[java.net.URL]
        """

    def getName(self) -> str:
        ...

    def getVersion(self) -> str:
        ...

    def isFromArchive(self) -> bool:
        ...

    def isInstalled(self) -> bool:
        """
        An extension is known to be installed if it has a valid installation path AND that path
        contains a Module.manifest file.   Extensions that are :meth:`isPendingUninstall() <.isPendingUninstall>` are 
        still on the filesystem, may be in use by the tool, but will be removed upon restart.
         
        
        Note: The module manifest file is a marker that indicates several things; one of which is
        the installation status of an extension. When a user marks an extension to be uninstalled via
        the UI, the only thing that is done is to remove this manifest file, which tells the tool to 
        remove the entire extension directory on the next launch.
        
        :return: true if the extension is installed.
        :rtype: bool
        """

    def isInstalledInInstallationFolder(self) -> bool:
        """
        Returns true if this extension is installed under an installation folder or inside of a 
        source control repository folder.
        
        :return: true if this extension is installed under an installation folder or inside of a 
        source control repository folder.
        :rtype: bool
        """

    def isPendingUninstall(self) -> bool:
        """
        Returns true if this extension is marked to be uninstalled.  The contents of the extension
        still exist and the tool may still be using the extension, but on restart, the extension will
        be removed.
        
        :return: true if marked for uninstall
        :rtype: bool
        """

    def markForUninstall(self) -> bool:
        """
        Converts the module manifest and extension properties file that are in an installed state to 
        an uninstalled state.
         
        Specifically, the following will be renamed:
         
        * Module.manifest to Module.manifest.uninstalled
        * extension.properties = extension.properties.uninstalled
        
        
        :return: false if any renames fail
        :rtype: bool
        """

    def setArchivePath(self, path: typing.Union[java.lang.String, str]):
        ...

    def setAuthor(self, author: typing.Union[java.lang.String, str]):
        ...

    def setCreatedOn(self, date: typing.Union[java.lang.String, str]):
        ...

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        ...

    def setInstallDir(self, installDir: jpype.protocol.SupportsPath):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setVersion(self, version: typing.Union[java.lang.String, str]):
        ...

    @property
    def installed(self) -> jpype.JBoolean:
        ...

    @property
    def installPath(self) -> java.lang.String:
        ...

    @property
    def author(self) -> java.lang.String:
        ...

    @author.setter
    def author(self, value: java.lang.String):
        ...

    @property
    def libraries(self) -> java.util.Set[java.net.URL]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @description.setter
    def description(self, value: java.lang.String):
        ...

    @property
    def archivePath(self) -> java.lang.String:
        ...

    @archivePath.setter
    def archivePath(self, value: java.lang.String):
        ...

    @property
    def version(self) -> java.lang.String:
        ...

    @version.setter
    def version(self, value: java.lang.String):
        ...

    @property
    def createdOn(self) -> java.lang.String:
        ...

    @createdOn.setter
    def createdOn(self, value: java.lang.String):
        ...

    @property
    def pendingUninstall(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def fromArchive(self) -> jpype.JBoolean:
        ...

    @property
    def installDir(self) -> java.io.File:
        ...

    @installDir.setter
    def installDir(self, value: java.io.File):
        ...

    @property
    def installedInInstallationFolder(self) -> jpype.JBoolean:
        ...


class ExtensionModuleClassLoader(java.net.URLClassLoader):
    """
    A class loader used with Ghidra extensions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, extensionDir: ExtensionDetails):
        ...


class Extensions(java.lang.Object):
    """
    A collection of all extensions found.  This class provides methods processing duplicates and
    managing extensions marked for removal.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMatchingExtensions(self, e: ExtensionDetails) -> java.util.List[ExtensionDetails]:
        """
        Returns all extensions matching the given details
        
        :param ExtensionDetails e: the extension details to match
        :return: all matching extensions
        :rtype: java.util.List[ExtensionDetails]
        """

    @property
    def matchingExtensions(self) -> java.util.List[ExtensionDetails]:
        ...



__all__ = ["ExtensionUtils", "ExtensionDetails", "ExtensionModuleClassLoader", "Extensions"]
