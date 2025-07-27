from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra
import ghidra.framework
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class ApplicationSettings(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getUserApplicationSettingsDirectory() -> java.io.File:
        """
        Returns the directory into which application settings are stored per user, per 
        application version.
        
        :return: the directory into which application settings are stored per user, per 
        application version.
        :rtype: java.io.File
        """


class DummyApplicationLayout(ApplicationLayout):
    """
    The dummy application layout defines the customizable elements of a dummy application's 
    directory structure.  A dummy application only has a name, an installation/root dir, and
    a user temp directory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs a new dummy application layout object.
        
        :param java.lang.String or str name: the application name
        :raises IOException: if there was a problem getting a user directory.
        """


class AppCleaner(ghidra.GhidraLaunchable):
    """
    Interactive utility to discover and delete artifacts that Ghidra lays down on the filesystem
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def launch(self, layout: ghidra.GhidraApplicationLayout, args: jpype.JArray[java.lang.String]):
        """
        Launches the :obj:`AppCleaner`
        
        :param ghidra.GhidraApplicationLayout layout: The application layout to use for the launch
        :param jpype.JArray[java.lang.String] args: One argument is expected: the name of the application to clean.  All other
        arguments are ignored.
        :raises java.lang.Exception: if there was a problem with the launch
        """


class ApplicationLayout(java.lang.Object):
    """
    The Application Layout base class defines the customizable elements of the application's
    directory structure.  Create a subclass to define a custom layout.
     
    
    If a layout changes in a significant way, the
    :obj:`ApplicationProperties.APPLICATION_LAYOUT_VERSION_PROPERTY` should be incremented so
    external things like Eclipse GhidraDev know to look in different places for things.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getApplicationInstallationDir(self) -> generic.jar.ResourceFile:
        """
        Gets the application installation directory from the application layout.
        
        :return: The application installation directory (or null if not set).
        :rtype: generic.jar.ResourceFile
        """

    def getApplicationProperties(self) -> ghidra.framework.ApplicationProperties:
        """
        Gets the application properties from the application layout
        
        :return: The application properties.  Should never be null.
        :rtype: ghidra.framework.ApplicationProperties
        """

    def getApplicationRootDirs(self) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Gets the application root directories from the application layout.
        
        :return: A collection of application root directories (or null if not set).
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    def getExtensionArchiveDir(self) -> generic.jar.ResourceFile:
        """
        Returns the directory where archived application Extensions are stored.  This directory may
        contain both zip files and subdirectories.   This directory is only used inside of an
        installation; development mode does not use this directory.   This directory is used to ship 
        pre-built Ghidra extensions as part of a distribution.
         
        
        This should be at the following location:
        
         
        * {install dir}/Extensions/Ghidra
        
        
        :return: the application Extensions archive directory.  Could be null if the
        :obj:`ApplicationLayout` does not support application Extensions.
        :rtype: generic.jar.ResourceFile
        """

    def getExtensionInstallationDirs(self) -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a prioritized :obj:`ordered list <List>` of the application Extensions installation 
        directories.   Typically, the values may be any of the following locations:
        
         
        * [user settings dir]/Extensions
        * [application install dir]/Ghidra/Extensions (Release Mode)
        * ghidra/Ghidra/Extensions (Development Mode)
        
        
        :return: an :obj:`ordered list <List>` of the application Extensions installation directories.
        Could be empty if the :obj:`ApplicationLayout` does not support application Extensions.
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    def getModules(self) -> java.util.Map[java.lang.String, ghidra.framework.GModule]:
        """
        Gets the application's modules from the application layout.
        
        :return: The application's modules as a map (mapping module name to module for convenience).
        :rtype: java.util.Map[java.lang.String, ghidra.framework.GModule]
        """

    def getPatchDir(self) -> generic.jar.ResourceFile:
        """
        Returns the location of the application patch directory.  The patch directory can be
        used to modify existing code within a distribution.
        
        :return: the patch directory; may be null
        :rtype: generic.jar.ResourceFile
        """

    def getUserCacheDir(self) -> java.io.File:
        """
        Gets the user cache directory from the application layout.
        
        :return: The user cache directory (or null if not set).
        :rtype: java.io.File
        """

    def getUserSettingsDir(self) -> java.io.File:
        """
        Gets the user settings directory from the application layout.
        
        :return: The user settings directory (or null if not set).
        :rtype: java.io.File
        """

    def getUserTempDir(self) -> java.io.File:
        """
        Gets the user temp directory from the application layout.
        
        :return: The user temp directory (or null if not set).
        :rtype: java.io.File
        """

    def inSingleJarMode(self) -> bool:
        """
        Checks whether or not the application is using a "single jar" layout.  Custom application
        layouts that extend this class can override this method once they determine they are in
        single jar mode.
        
        :return: true if the application is using a "single jar" layout; otherwise, false.
        :rtype: bool
        """

    @property
    def patchDir(self) -> generic.jar.ResourceFile:
        ...

    @property
    def applicationInstallationDir(self) -> generic.jar.ResourceFile:
        ...

    @property
    def extensionArchiveDir(self) -> generic.jar.ResourceFile:
        ...

    @property
    def userCacheDir(self) -> java.io.File:
        ...

    @property
    def extensionInstallationDirs(self) -> java.util.List[generic.jar.ResourceFile]:
        ...

    @property
    def applicationRootDirs(self) -> java.util.Collection[generic.jar.ResourceFile]:
        ...

    @property
    def applicationProperties(self) -> ghidra.framework.ApplicationProperties:
        ...

    @property
    def userSettingsDir(self) -> java.io.File:
        ...

    @property
    def userTempDir(self) -> java.io.File:
        ...

    @property
    def modules(self) -> java.util.Map[java.lang.String, ghidra.framework.GModule]:
        ...


class ApplicationUtilities(java.lang.Object):
    """
    Utility class for default application things.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROPERTY_TEMP_DIR: typing.Final = "application.tempdir"
    """
    Name of system property used to override the location of the user temporary directory
    """

    PROPERTY_CACHE_DIR: typing.Final = "application.cachedir"
    """
    Name of system property used to override the location of the user cache directory
    """

    PROPERTY_SETTINGS_DIR: typing.Final = "application.settingsdir"
    """
    Name of system property used to override the location of the user settings directory
    """


    def __init__(self):
        ...

    @staticmethod
    def findDefaultApplicationRootDirs() -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Searches for default application root directories.
        
        :return: A collection of discovered application root directories (could be empty).
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    def getDefaultUserCacheDir(applicationProperties: ghidra.framework.ApplicationProperties) -> java.io.File:
        """
        Gets the application's default user cache directory.
         
        
        NOTE: This method creates the directory if it does not exist.
        
        :param ghidra.framework.ApplicationProperties applicationProperties: The application properties.
        :return: The application's default user cache directory. The returned :obj:`File` will 
        represent an absolute path.
        :rtype: java.io.File
        :raises FileNotFoundException: if the absolute path of the user cache directory could not be 
        determined.
        :raises IOException: if the user cache directory could not be created.
        """

    @staticmethod
    def getDefaultUserSettingsDir(applicationProperties: ghidra.framework.ApplicationProperties, installationDirectory: generic.jar.ResourceFile) -> java.io.File:
        """
        Gets the application's default user settings directory.
         
        
        NOTE: This method creates the directory if it does not exist.
        
        :param ghidra.framework.ApplicationProperties applicationProperties: The application properties.
        :param generic.jar.ResourceFile installationDirectory: The application installation directory.
        :return: The application's default user settings directory. The returned :obj:`File` will
        represent an absolute path.
        :rtype: java.io.File
        :raises FileNotFoundException: if the absolute path of the user settings directory could not 
        be determined.
        :raises IOException: if the user settings directory could not be created.
        """

    @staticmethod
    def getDefaultUserTempDir(applicationName: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Gets the application's default user temp directory.
         
        
        NOTE: This method creates the directory if it does not exist.
        
        :param java.lang.String or str applicationName: The application name.
        :return: The application's default user temp directory. The returned :obj:`File` will 
        represent an absolute path.
        :rtype: java.io.File
        :raises FileNotFoundException: if the absolute path of the user temp directory could not be 
        determined.
        :raises IOException: if the user temp directory could not be created.
        """

    @staticmethod
    def getLegacyUserSettingsDir(applicationProperties: ghidra.framework.ApplicationProperties, installationDirectory: generic.jar.ResourceFile) -> java.io.File:
        """
        Gets the application's legacy (pre-Ghida 11.1) user settings directory.
         
        
        NOTE: This method does not create the directory.
        
        :param ghidra.framework.ApplicationProperties applicationProperties: The application properties.
        :param generic.jar.ResourceFile installationDirectory: The application installation directory.
        :return: The application's legacy user settings directory. The returned :obj:`File` will 
        represent an absolute path.
        :rtype: java.io.File
        :raises FileNotFoundException: if the absolute path of the legacy user settings directory 
        could not be determined.
        """

    @staticmethod
    def normalizeApplicationName(applicationName: typing.Union[java.lang.String, str]) -> str:
        """
        Normalizes the application name by removing spaces and converting to lower case
        
        :param java.lang.String or str applicationName: The application name
        :return: The normalized application name
        :rtype: str
        """


class XdgUtils(java.lang.Object):
    """
    Class to support the "XDG Base Directory Specification"
     
    
    Based off version 0.8
    
    
    .. seealso::
    
        | `basedir-spec-0.8.html <https://specifications.freedesktop.org/basedir-spec/basedir-spec-0.8.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    XDG_DATA_HOME: typing.Final = "XDG_DATA_HOME"
    """
    $XDG_DATA_HOME defines the base directory relative to which user-specific data files should 
    be stored. If $XDG_DATA_HOME is either not set or empty, a default equal to 
    $HOME/.local/share should be used.
    """

    XDG_CONFIG_HOME: typing.Final = "XDG_CONFIG_HOME"
    """
    $XDG_CONFIG_HOME defines the base directory relative to which user-specific configuration 
    files should be stored. If $XDG_CONFIG_HOME is either not set or empty, a default equal to 
    $HOME/.config should be used.
    """

    XDG_STATE_HOME: typing.Final = "XDG_STATE_HOME"
    """
    $XDG_STATE_HOME defines the base directory relative to which user-specific state files should
    be stored. If $XDG_STATE_HOME is either not set or empty, a default equal to 
    $HOME/.local/state should be used.
    """

    XDG_DATA_DIRS: typing.Final = "XDG_DATA_DIRS"
    """
    $XDG_DATA_DIRS defines the preference-ordered set of base directories to search for data 
    files in addition to the $XDG_DATA_HOME base directory. The directories in $XDG_DATA_DIRS 
    should be separated with a colon ':'.
    """

    XDG_CONFIG_DIRS: typing.Final = "XDG_CONFIG_DIRS"
    """
    $XDG_CONFIG_DIRS defines the preference-ordered set of base directories to search for 
    configuration files in addition to the $XDG_CONFIG_HOME base directory. The directories in 
    $XDG_CONFIG_DIRS should be separated with a colon ':'.
    """

    XDG_CACHE_HOME: typing.Final = "XDG_CACHE_HOME"
    """
    $XDG_CACHE_HOME defines the base directory relative to which user-specific non-essential 
    data files should be stored. If $XDG_CACHE_HOME is either not set or empty, a default equal 
    to $HOME/.cache should be used.
    """

    XDG_RUNTIME_DIR: typing.Final = "XDG_RUNTIME_DIR"
    """
    $XDG_RUNTIME_DIR defines the base directory relative to which user-specific non-essential 
    runtime files and other file objects (such as sockets, named pipes, ...) should be stored. 
    The directory MUST be owned by the user, and he MUST be the only one having read and write 
    access to it. Its Unix access mode MUST be 0700.
    """


    def __init__(self):
        ...



__all__ = ["ApplicationSettings", "DummyApplicationLayout", "AppCleaner", "ApplicationLayout", "ApplicationUtilities", "XdgUtils"]
