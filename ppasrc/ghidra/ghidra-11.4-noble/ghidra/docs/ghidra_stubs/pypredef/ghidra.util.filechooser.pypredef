from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import utility.function


class GhidraFileChooserModel(java.lang.Object):
    """
    Interface for the GhidraFileChooser data model.
    This allows the GhidraFileChooser to operate
    on files from different sources, other than
    just the local file system.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createDirectory(self, directory: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Creates a directory in the specified directory with the specified
        name.
        
        :param jpype.protocol.SupportsPath directory: the directory in which to create the new directory
        :param java.lang.String or str name: the name of the directory
        :return: true if the new directory was create.
        :rtype: bool
        """

    def getDescription(self, file: jpype.protocol.SupportsPath) -> str:
        """
        Returns a description for the specified file.
        
        :param jpype.protocol.SupportsPath file: the file
        :return: a description for the specified file
        :rtype: str
        """

    def getDesktopDirectory(self) -> java.io.File:
        """
        Returns the user's desktop directory, as defined by their operating system and/or their windowing environment, or
        null if there is no desktop directory.
        
        Example: "/home/the_user/Desktop" or "c:/Users/the_user/Desktop"
        
        :return: desktop directory
        :rtype: java.io.File
        """

    def getDownloadsDirectory(self) -> java.io.File:
        """
        Returns the user's downloads directory, as defined by their operating system and/or their windowing environment, or
        null if there is no downloads directory.
        
        Example: "/home/the_user/Downloads" or "c:/Users/the_user/Downloads"
        
        :return: downloads directory
        :rtype: java.io.File
        """

    def getHomeDirectory(self) -> java.io.File:
        """
        Returns the home directory.
        
        :return: the home directory
        :rtype: java.io.File
        """

    def getIcon(self, file: jpype.protocol.SupportsPath) -> javax.swing.Icon:
        """
        Returns an icon for the specified file.
        
        :param jpype.protocol.SupportsPath file: the file
        :return: an icon for the specified file
        :rtype: javax.swing.Icon
        """

    def getListing(self, directory: jpype.protocol.SupportsPath, filter: java.io.FileFilter) -> java.util.List[java.io.File]:
        """
        Returns an array of the files that 
        exist in the specified directory.
        
        :param jpype.protocol.SupportsPath directory: the directory
        :param java.io.FileFilter filter: the file filter; may be null
        :return: list of files
        :rtype: java.util.List[java.io.File]
        """

    def getRoots(self, forceUpdate: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.io.File]:
        """
        Returns a list of the root drives/directories.
         
        
        On windows, "C:\", "D:\", etc.
         
        
        On linux, "/".
        
        :param jpype.JBoolean or bool forceUpdate: if true, request a fresh listing, if false allow a cached result
        :return: the root drives
        :rtype: java.util.List[java.io.File]
        """

    def getSeparator(self) -> str:
        """
        Returns the file separator char.
        On windows, '\'
        On linux, '/'.
        
        :return: the file separator char
        :rtype: str
        """

    def isAbsolute(self, file: jpype.protocol.SupportsPath) -> bool:
        """
        Tests whether this abstract pathname is absolute.  The definition of
        absolute pathname is system dependent.  On UNIX systems, a pathname is
        absolute if its prefix is ``"/"``.  On Microsoft Windows systems, a
        pathname is absolute if its prefix is a drive specifier followed by
        ``"\\"``, or if its prefix is ``"\\"``.
        
        :param jpype.protocol.SupportsPath file: the file
        :return: ``true`` if this abstract pathname is absolute,
                ``false`` otherwise
        :rtype: bool
        """

    def isDirectory(self, file: jpype.protocol.SupportsPath) -> bool:
        """
        Tests whether the file denoted by this abstract pathname is a directory.
        
        :param jpype.protocol.SupportsPath file: the file
        :return: ``true`` if and only if the file denoted by this
                abstract pathname exists *and* is a directory;
                ``false`` otherwise
        :rtype: bool
        """

    def renameFile(self, src: jpype.protocol.SupportsPath, dest: jpype.protocol.SupportsPath) -> bool:
        """
        Renames the src file to the destination file.
        
        :param jpype.protocol.SupportsPath src: the file to be renamed
        :param jpype.protocol.SupportsPath dest: the new file
        :return: true if the file was renamed
        :rtype: bool
        """

    def setModelUpdateCallback(self, callback: utility.function.Callback):
        """
        Set the model update callback.
        
        :param utility.function.Callback callback: the new model update callback handler
        """

    @property
    def homeDirectory(self) -> java.io.File:
        ...

    @property
    def absolute(self) -> jpype.JBoolean:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def roots(self) -> java.util.List[java.io.File]:
        ...

    @property
    def desktopDirectory(self) -> java.io.File:
        ...

    @property
    def directory(self) -> jpype.JBoolean:
        ...

    @property
    def separator(self) -> jpype.JChar:
        ...

    @property
    def downloadsDirectory(self) -> java.io.File:
        ...


class GhidraFileFilter(java.lang.Object):
    """
    A interface that filters out all files 
    except for those type extensions that it knows about.
    Extensions are of the type ".foo", which is typically found on
    Windows and Unix boxes, but not on Macinthosh. Case is ignored.
    """

    class_: typing.ClassVar[java.lang.Class]
    ALL: typing.Final[GhidraFileFilter]
    """
    A default implementation that shows all files.
    """


    def accept(self, pathname: jpype.protocol.SupportsPath, model: GhidraFileChooserModel) -> bool:
        """
        Tests whether or not the specified abstract pathname should be
        included in a pathname list.
        
        :param jpype.protocol.SupportsPath pathname: The abstract pathname to be tested
        :param GhidraFileChooserModel model: The underlying file chooser model
        :return: ``true`` if and only if ``pathname``
                should be included
        :rtype: bool
        """

    def getDescription(self) -> str:
        """
        Returns the description of this filter.
        
        :return: the description of this filter
        :rtype: str
        """

    @property
    def description(self) -> java.lang.String:
        ...


class ExtensionFileFilter(GhidraFileFilter):
    """
    A convenience implementation of FileFilter that filters out
    all files except for those type extensions that it knows about.
     
    
    Extensions are of the type "foo" (no leading dot). Case is ignored.
     
    
    Example - create a new filter that filters out all files
    but gif and jpg image files:
     
        GhidraFileChooser chooser = new GhidraFileChooser();
        chooser.addFileFilter(ExtensionFilFilter.forExtensions("JPEG and GIF Images", "gif", "jpg"));
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, extension: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        """
        Creates a file filter that accepts the given file type.
        Example: new ExtensionFileFilter("jpg", "JPEG Images");
        
        :param java.lang.String or str extension: file extension to match, without leading dot
        :param java.lang.String or str description: descriptive string of the filter
        """

    @typing.overload
    def __init__(self, filters: jpype.JArray[java.lang.String], description: typing.Union[java.lang.String, str]):
        """
        Creates a file filter from the given string array and description.
        Example: new ExtensionFileFilter(String {"gif", "jpg"}, "Gif and JPG Images");
        
        :param jpype.JArray[java.lang.String] filters: array of file name extensions, each without a leading dot
        :param java.lang.String or str description: descriptive string of the filter
        """

    def accept(self, f: jpype.protocol.SupportsPath, model: GhidraFileChooserModel) -> bool:
        """
        Return true if this file should be shown in the directory pane,
        false if it shouldn't.
        
        Files that begin with "." are ignored.
        
        
        .. seealso::
        
            | :obj:`FileFilter.accept`
        """

    @staticmethod
    def forExtensions(description: typing.Union[java.lang.String, str], *exts: typing.Union[java.lang.String, str]) -> ExtensionFileFilter:
        """
        Creates a :obj:`ExtensionFileFilter` in a varargs friendly way.
        
        :param java.lang.String or str description: String description of this set of file extensions.
        :param jpype.JArray[java.lang.String] exts: variable length list of file extensions, without leading dot.
        :return: new :obj:`ExtensionFileFilter` instance.
        :rtype: ExtensionFileFilter
        """



__all__ = ["GhidraFileChooserModel", "GhidraFileFilter", "ExtensionFileFilter"]
