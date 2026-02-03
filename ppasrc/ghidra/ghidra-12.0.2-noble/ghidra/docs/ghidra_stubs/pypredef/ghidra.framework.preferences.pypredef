from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


class Preferences(java.lang.Object):
    """
    Uses Properties to manage user preferences as name/value pairs.  All methods
    are static.
    """

    class_: typing.ClassVar[java.lang.Class]
    APPLICATION_PREFERENCES_FILENAME: typing.Final = "preferences"
    """
    The ``APPLICATION_PREFERENCES_FILENAME`` is the default name for the user preferences file.
    
    
    .. seealso::
    
        | :obj:`ghidra.framework.preferences.Preferences`
    """

    LAST_OPENED_ARCHIVE_DIRECTORY: typing.Final = "LastOpenedArchiveDirectory"
    """
    Preference name for the last opened archive directory.
    """

    PROJECT_DIRECTORY: typing.Final = "ProjectDirectory"
    """
    Preference name for the project directory.
    """

    LAST_TOOL_IMPORT_DIRECTORY: typing.Final = "LastToolImportDirectory"
    """
    Preference name for import directory that was last accessed for tools.
    """

    LAST_TOOL_EXPORT_DIRECTORY: typing.Final = "LastToolExportDirectory"
    """
    Preference name for export directory that was last accessed for tools.
    """

    LAST_NEW_PROJECT_DIRECTORY: typing.Final = "LastNewProjectDirectory"
    """
    Preference name for directory last selected for creating a new project.
    """

    LAST_PATH_DIRECTORY: typing.Final = "LastPathDirectory"
    """
    Preference name for the last chosen directory for path related items.
    """

    LAST_IMPORT_FILE: typing.Final = "LastImportFile"
    """
    Preference name for the import directory that was last accessed for domain files.
    """

    LAST_EXPORT_DIRECTORY: typing.Final = "LastExportDirectory"
    """
    Preference name for the export directory that was last accessed.
    """


    @staticmethod
    def clear():
        """
        Clears all properties in this Preferences object.
         
        
        **Warning: **Save any changes pending before calling this method, as this call will
        erase any changes not written do disk via :meth:`store() <.store>`
        """

    @staticmethod
    def getFilename() -> str:
        """
        Get the filename that will be used in the store() method.
        
        :return: the filename
        :rtype: str
        """

    @staticmethod
    def getPluginPaths() -> jpype.JArray[java.lang.String]:
        """
        Return the paths in the UserPluginPath property.
        Return zero length array if this property is not set.
        
        :return: the paths
        :rtype: jpype.JArray[java.lang.String]
        """

    @staticmethod
    @typing.overload
    def getProperty(name: typing.Union[java.lang.String, str]) -> str:
        """
        Get the property with the given name.
         
        
        Note: all ``getProperty(...)`` methods will check :meth:`System.getProperty(String) <System.getProperty>`
        for a value first.  This allows users to override preferences from the command-line.
        
        :param java.lang.String or str name: the property name
        :return: the current property value; null if not set
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getProperty(name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Get the property with the given name; if there is no property, return the defaultValue.
         
        
        Note: all ``getProperty(...)`` methods will check :meth:`System.getProperty(String) <System.getProperty>`
        for a value first.  This allows users to override preferences from the command-line.
        
        :param java.lang.String or str name: the property name
        :param java.lang.String or str defaultValue: the default value
        :return: the property value; default value if not set
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getProperty(String, String, boolean)`
        """

    @staticmethod
    @typing.overload
    def getProperty(name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str], useHistoricalValue: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get the property with the given name; if there is no property, return the defaultValue.
         
        
        This version of ``getProperty`` will, when ``useHistoricalValue`` is true, look
        for the given preference value in the last used installation of the application.
         
        
        Note: all ``getProperty(...)`` methods will check :meth:`System.getProperty(String) <System.getProperty>`
        for a value first.  This allows users to override preferences from the command-line.
        
        :param java.lang.String or str name: The name of the property for which to get a value
        :param java.lang.String or str defaultValue: The value to use if there is no value yet set for the given name
        :param jpype.JBoolean or bool useHistoricalValue: True signals to check the last used application installation for a 
                value for the given name **if that value has not yet been set**.
        :return: the property with the given name; if there is no property,
                return the defaultValue.
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getProperty(String)`
        
            | :obj:`.getProperty(String, String)`
        """

    @staticmethod
    def getPropertyNames() -> java.util.List[java.lang.String]:
        """
        Get an array of known property names.
        
        :return: if there are no properties, return a zero-length array
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def removeProperty(name: typing.Union[java.lang.String, str]) -> str:
        """
        Removes the given preference from this preferences object.
        
        :param java.lang.String or str name: the name of the preference key to remove.
        :return: the value that was stored with the given key.
        :rtype: str
        """

    @staticmethod
    def setFilename(name: typing.Union[java.lang.String, str]):
        """
        Set the filename so that when the store() method is called, the
        preferences are written to this file.
        
        :param java.lang.String or str name: the filename
        """

    @staticmethod
    def setPluginPaths(paths: jpype.JArray[java.lang.String]):
        """
        Set the paths to be used as the UserPluginPath property.
        
        :param jpype.JArray[java.lang.String] paths: the paths
        """

    @staticmethod
    def setProperty(name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Set the property value.  If a null value is passed, then the property is removed from 
        this collection of preferences.
        
        :param java.lang.String or str name: property name
        :param java.lang.String or str value: value for property
        """

    @staticmethod
    def store() -> bool:
        """
        Store the preferences in a file for the current filename.
        
        :return: true if the file was written
        :rtype: bool
        :raises RuntimeException: if the preferences filename was not set
        """



__all__ = ["Preferences"]
