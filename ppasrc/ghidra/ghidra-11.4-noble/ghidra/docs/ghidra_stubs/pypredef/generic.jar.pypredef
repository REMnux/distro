from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.jar # type: ignore


class ApplicationModule(java.lang.Comparable[ApplicationModule]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, applicationRoot: jpype.protocol.SupportsPath, moduleDir: jpype.protocol.SupportsPath):
        ...

    def excludeFromGhidraJar(self) -> bool:
        ...

    def getApplicationRoot(self) -> java.io.File:
        ...

    def getModuleDir(self) -> java.io.File:
        ...

    def getName(self) -> str:
        ...

    def getRelativePath(self) -> str:
        ...

    def isConfiguration(self) -> bool:
        ...

    def isDebug(self) -> bool:
        ...

    def isExtension(self) -> bool:
        ...

    def isFeature(self) -> bool:
        ...

    def isFramework(self) -> bool:
        ...

    def isGPL(self) -> bool:
        ...

    def isProcessor(self) -> bool:
        ...

    @property
    def gPL(self) -> jpype.JBoolean:
        ...

    @property
    def extension(self) -> jpype.JBoolean:
        ...

    @property
    def framework(self) -> jpype.JBoolean:
        ...

    @property
    def debug(self) -> jpype.JBoolean:
        ...

    @property
    def feature(self) -> jpype.JBoolean:
        ...

    @property
    def configuration(self) -> jpype.JBoolean:
        ...

    @property
    def applicationRoot(self) -> java.io.File:
        ...

    @property
    def relativePath(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def processor(self) -> jpype.JBoolean:
        ...

    @property
    def moduleDir(self) -> java.io.File:
        ...


class ResourceFileFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def accept(self, file: ResourceFile) -> bool:
        ...


class JarResource(Resource):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, jarFile: jpype.protocol.SupportsPath, filter: JarEntryFilter):
        ...

    @typing.overload
    def __init__(self, parent: JarResource, path: typing.Union[java.lang.String, str]):
        ...


class JarEntryRootNode(JarEntryNode):

    @typing.type_check_only
    class DefaultFilter(JarEntryFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, filter: JarEntryFilter):
        ...

    def toURL(self) -> java.net.URL:
        ...


class ResourceFile(java.lang.Comparable[ResourceFile]):
    """
    Class for representing file object regardless of whether they are actual files in the file system or
    or files stored inside of a jar file.  This class provides most all the same capabilities as the
    File class.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Construct a ResourceFile that represents a normal file in the file system.
        
        :param jpype.protocol.SupportsPath file: the file in the file system.
        """

    @typing.overload
    def __init__(self, resourceFile: ResourceFile, path: typing.Union[java.lang.String, str]):
        """
        Construct a new ResourceFile from a parent file and a relative child path.
        
        :param ResourceFile resourceFile: the parent file
        :param java.lang.String or str path: the child path.
        """

    @typing.overload
    def __init__(self, absolutePath: typing.Union[java.lang.String, str]):
        """
        Constructs a Resource file from string path that can be either a file path or a jar url.
        
        :param java.lang.String or str absolutePath: the path to the file.
        """

    @typing.overload
    def __init__(self, absolutePath: typing.Union[java.lang.String, str], filter: JarEntryFilter):
        """
        Constructs a Resource file from string path that can be either a file path or a jar url.
        
        :param java.lang.String or str absolutePath: the path to the file.
        :param JarEntryFilter filter: The filter used to exclude files from being loaded
        """

    def canWrite(self) -> bool:
        """
        Returns true if this file can be written to.
        
        :return: true if this file can be written to.
        :rtype: bool
        """

    def containsPath(self, otherFile: ResourceFile) -> bool:
        """
        Returns true if this file's path contains the entire path of the given file.
        
        :param ResourceFile otherFile: the other file to check
        :return: true if this file's path contains the entire path of the given file.
        :rtype: bool
        """

    def delete(self) -> bool:
        """
        Attempts to delete the file.  Not supported (returns false) for files within a jar file.
        
        :return: true if the file was deleted, false otherwise.
        :rtype: bool
        """

    def exists(self) -> bool:
        """
        Returns true if the file exists.
        
        :return: true if the file exists.
        :rtype: bool
        """

    def getAbsolutePath(self) -> str:
        """
        Returns the absolute file path for this file.
        
        :return: the absolute file path for this file.
        :rtype: str
        """

    def getCanonicalFile(self) -> ResourceFile:
        """
        Returns the canonicalFile for this file.
        
        :return: the canonicalFile for this file.
        :rtype: ResourceFile
        """

    def getCanonicalPath(self) -> str:
        """
        Returns the canonical file path for this file.
        
        :return: the absolute file path for this file.
        :rtype: str
        :raises IOException: if an exception is thrown getting the canonical path
        """

    def getFile(self, copyIfNeeded: typing.Union[jpype.JBoolean, bool]) -> java.io.File:
        """
        Returns a File object.  If this ResourceFile represents a standard filesystem, then no
        copy is necessary to return a file.  If this ResourceFile represents a compressed 
        filesystem, then a copy from that filesystem to the real filesystem is needed to create
        a File object.  ``copyIfNeeded`` allows you to dictate whether a copy should take 
        place, if needed.
         
        
        If you just want the contents of a file, then call :meth:`getInputStream() <.getInputStream>`.
        
        :param jpype.JBoolean or bool copyIfNeeded: true to copy the file when embedded in a compressed filesystem; false
                            to return null in that case.
        :return: a File object or null if not a file and copyIfNeeded was false
        :rtype: java.io.File
        """

    def getFileSystemRoot(self) -> java.io.File:
        """
        Returns the root file for this file.
        
        :return: the root file for this file.
        :rtype: java.io.File
        """

    def getInputStream(self) -> java.io.InputStream:
        """
        If this file exists and is not a directory, it will return an InputStream for the file's 
        contents.
        
        :return: an InputStream for the file's contents.
        :rtype: java.io.InputStream
        :raises FileNotFoundException: if the file does not exist.
        :raises IOException: if an exception occurs creating the input stream
        """

    def getName(self) -> str:
        """
        Returns the simple name of the file.
        
        :return: the simple name of the file.
        :rtype: str
        """

    def getOutputStream(self) -> java.io.OutputStream:
        """
        Returns an OutputStream if the file can be opened for writing.
        
        :return: an OutputStream if the file can be opened for writing.
        :rtype: java.io.OutputStream
        :raises FileNotFoundException: if the file can't be created or opened for writing.
        """

    def getParentFile(self) -> ResourceFile:
        """
        Returns the parent of this ResourceFile or null if it is a root.
        
        :return: the parent of this ResourceFile or null if it is a root.
        :rtype: ResourceFile
        """

    def isDirectory(self) -> bool:
        """
        Returns true if this Resource file exists and is a directory.
        
        :return: true if this Resource file exists and is a directory.
        :rtype: bool
        """

    def isFile(self) -> bool:
        """
        Returns true if this file exists and is not a directory.
        
        :return: true if this file exists and is not a directory.
        :rtype: bool
        """

    def lastModified(self) -> int:
        """
        Returns the time that this file was last modified.
        
        :return: the time that this file was last modified.
        :rtype: int
        """

    def length(self) -> int:
        """
        Returns the size of this file.
        
        :return: the size of the file.
        :rtype: int
        """

    @typing.overload
    def listFiles(self) -> jpype.JArray[ResourceFile]:
        """
        Returns a array of ResourceFiles if this ResourceFile is a directory. Otherwise return null.
        
        :return: the child ResourceFiles if this is a directory, null otherwise.
        :rtype: jpype.JArray[ResourceFile]
        """

    @typing.overload
    def listFiles(self, filter: ResourceFileFilter) -> jpype.JArray[ResourceFile]:
        """
        Returns a array of ResourceFiles if this ResourceFile is a directory. Otherwise return null.
        
        :param ResourceFileFilter filter: a filter to restrict the array of files returned.
        :return: the child ResourceFiles if this is a directory, null otherwise.
        :rtype: jpype.JArray[ResourceFile]
        """

    def mkdir(self) -> bool:
        """
        Creates a directory for the path represented by this file.
        
        :return: true if a new directory was created.
        :rtype: bool
        """

    @staticmethod
    def openJarResourceFile(jarFile: jpype.protocol.SupportsPath, filter: JarEntryFilter) -> ResourceFile:
        """
        Creates a new Root ResourceFile for a given jar file.
        
        :param jpype.protocol.SupportsPath jarFile: the jar file to open.
        :param JarEntryFilter filter: JarEntryFilter that will filter out unwanted jar entries.
        :return: A Resource file that represents the root of the jarfile file system.
        :rtype: ResourceFile
        :raises IOException: if the jar file can't be read.
        """

    def toURI(self) -> java.net.URI:
        """
        Returns a URI for this file object.
        
        :return: a URI for this file object.
        :rtype: java.net.URI
        """

    def toURL(self) -> java.net.URL:
        """
        Returns a URL that represents this file object.
        
        :return: a URL that represents this file object.
        :rtype: java.net.URL
        :raises MalformedURLException: if a URL can't be formed for this file.
        """

    @property
    def parentFile(self) -> ResourceFile:
        ...

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def fileSystemRoot(self) -> java.io.File:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def canonicalPath(self) -> java.lang.String:
        ...

    @property
    def inputStream(self) -> java.io.InputStream:
        ...

    @property
    def absolutePath(self) -> java.lang.String:
        ...

    @property
    def outputStream(self) -> java.io.OutputStream:
        ...

    @property
    def directory(self) -> jpype.JBoolean:
        ...

    @property
    def canonicalFile(self) -> ResourceFile:
        ...


class ClassModuleTree(java.lang.Object):

    @typing.type_check_only
    class FileNode(java.lang.Comparable[ClassModuleTree.FileNode]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parent: ClassModuleTree.FileNode, name: typing.Union[java.lang.String, str]):
            ...

        def createNode(self, nodeName: typing.Union[java.lang.String, str]) -> ClassModuleTree.FileNode:
            ...

        def getChild(self, childName: typing.Union[java.lang.String, str]) -> ClassModuleTree.FileNode:
            ...

        def getChildren(self) -> java.util.List[ClassModuleTree.FileNode]:
            ...

        def getCount(self) -> int:
            ...

        def getPath(self) -> str:
            ...

        def setModule(self, moduleName: typing.Union[java.lang.String, str]):
            ...

        def trim(self) -> str:
            ...

        @property
        def path(self) -> java.lang.String:
            ...

        @property
        def children(self) -> java.util.List[ClassModuleTree.FileNode]:
            ...

        @property
        def count(self) -> jpype.JInt:
            ...

        @property
        def child(self) -> ClassModuleTree.FileNode:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, treeFile: ResourceFile):
        ...

    def addNode(self, path: typing.Union[java.lang.String, str], moduleName: typing.Union[java.lang.String, str]):
        ...

    def getModuleName(self, className: typing.Union[java.lang.String, str]) -> str:
        ...

    def getNodeCount(self) -> int:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def printRecursively(self):
        ...

    def saveFile(self, outputFile: jpype.protocol.SupportsPath):
        ...

    def trim(self):
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...

    @property
    def nodeCount(self) -> jpype.JInt:
        ...


class FileResource(Resource):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath):
        ...


class JarEntryNode(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getChildren(self) -> java.util.List[JarEntryNode]:
        ...

    def getInputStream(self) -> java.io.InputStream:
        ...

    def getName(self) -> str:
        ...

    @typing.overload
    def getNode(self, childName: typing.Union[java.lang.String, str]) -> JarEntryNode:
        ...

    @typing.overload
    def getNode(self, path: jpype.JArray[java.lang.String]) -> JarEntryNode:
        ...

    def getParent(self) -> JarEntryNode:
        ...

    def isDirectory(self) -> bool:
        ...

    def isFile(self) -> bool:
        ...

    def lastModified(self) -> int:
        ...

    def length(self) -> int:
        ...

    @property
    def parent(self) -> JarEntryNode:
        ...

    @property
    def node(self) -> JarEntryNode:
        ...

    @property
    def file(self) -> jpype.JBoolean:
        ...

    @property
    def children(self) -> java.util.List[JarEntryNode]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def inputStream(self) -> java.io.InputStream:
        ...

    @property
    def directory(self) -> jpype.JBoolean:
        ...


class Resource(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def canWrite(self) -> bool:
        ...

    def delete(self) -> bool:
        ...

    def exists(self) -> bool:
        ...

    def getAbsolutePath(self) -> str:
        ...

    def getCanonicalPath(self) -> str:
        ...

    def getCanonicalResource(self) -> Resource:
        ...

    def getFile(self) -> java.io.File:
        ...

    def getFileSystemRoot(self) -> java.io.File:
        ...

    def getInputStream(self) -> java.io.InputStream:
        ...

    def getName(self) -> str:
        ...

    def getOutputStream(self) -> java.io.OutputStream:
        ...

    def getParent(self) -> Resource:
        ...

    def getResource(self, name: typing.Union[java.lang.String, str]) -> Resource:
        ...

    def getResourceAsFile(self, resourceFile: ResourceFile) -> java.io.File:
        ...

    def isDirectory(self) -> bool:
        ...

    def isFile(self) -> bool:
        ...

    def lastModified(self) -> int:
        ...

    def length(self) -> int:
        ...

    @typing.overload
    def listFiles(self) -> jpype.JArray[ResourceFile]:
        ...

    @typing.overload
    def listFiles(self, filter: ResourceFileFilter) -> jpype.JArray[ResourceFile]:
        ...

    def mkdir(self) -> bool:
        ...

    def toURI(self) -> java.net.URI:
        ...

    def toURL(self) -> java.net.URL:
        ...

    @property
    def parent(self) -> Resource:
        ...

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def resource(self) -> Resource:
        ...

    @property
    def fileSystemRoot(self) -> java.io.File:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def canonicalPath(self) -> java.lang.String:
        ...

    @property
    def inputStream(self) -> java.io.InputStream:
        ...

    @property
    def canonicalResource(self) -> Resource:
        ...

    @property
    def absolutePath(self) -> java.lang.String:
        ...

    @property
    def outputStream(self) -> java.io.OutputStream:
        ...

    @property
    def resourceAsFile(self) -> java.io.File:
        ...

    @property
    def directory(self) -> jpype.JBoolean:
        ...


class GClassLoader(java.net.URLClassLoader):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, moduleDirs: java.util.List[java.io.File]):
        ...


class JarEntryFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def accepts(self, jarEntry: java.util.jar.JarEntry) -> bool:
        ...



__all__ = ["ApplicationModule", "ResourceFileFilter", "JarResource", "JarEntryRootNode", "ResourceFile", "ClassModuleTree", "FileResource", "JarEntryNode", "Resource", "GClassLoader", "JarEntryFilter"]
