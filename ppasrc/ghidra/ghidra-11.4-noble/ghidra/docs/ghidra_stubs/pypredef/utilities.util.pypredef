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
import java.lang.annotation # type: ignore
import java.lang.reflect # type: ignore
import java.net # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class AnnotationUtilities(java.lang.Enum[AnnotationUtilities]):
    """
    Some utilities for reflection using annotations
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def collectAnnotatedMethods(annotCls: java.lang.Class[java.lang.annotation.Annotation], cls: java.lang.Class[typing.Any]) -> java.util.Set[java.lang.reflect.Method]:
        """
        Collect from among the given class, its superclasses, and its interfaces all methods
        annotated with the given annotation type.
        
        :param java.lang.Class[java.lang.annotation.Annotation] annotCls: the annotation type
        :param java.lang.Class[typing.Any] cls: the class whose methods to examine
        :return: the set of all methods having the given annotation type
        :rtype: java.util.Set[java.lang.reflect.Method]
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AnnotationUtilities:
        ...

    @staticmethod
    def values() -> jpype.JArray[AnnotationUtilities]:
        ...


class FileUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    IO_BUFFER_SIZE: typing.Final = 32768

    @staticmethod
    def checkedMkdir(dir: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Ensures the specified leaf directory exists.
         
        
        Throws an :obj:`IOException` if there is any problem while creating the directory.
         
        
        Does not create any missing parent directories.  See :meth:`checkedMkdirs(File) <.checkedMkdirs>` instead.
         
        
        Takes into account race conditions with external threads/processes
        creating the same directory at the same time.
        
        :param jpype.protocol.SupportsPath dir: The directory to create.
        :return: a reference to the same :obj:`File` instance that was passed in.
        :rtype: java.io.File
        :raises IOException: if there was a failure when creating the directory (ie. the
        parent directory did not exist or other issue).
        """

    @staticmethod
    def checkedMkdirs(dir: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Ensures the specified full directory path exists, creating any missing
        directories as needed.
         
        
        Throws an :obj:`IOException` if there is any problem while creating the directory.
         
        
        Uses :meth:`createDir(File) <.createDir>` to create new directories (which handles
        race conditions if other processes are also trying to create the same directory).
        
        :param jpype.protocol.SupportsPath dir: directory path to be created
        :return: a reference to the same :obj:`File` instance that was passed in.
        :rtype: java.io.File
        :raises IOException: if there was a failure when creating a directory.
        """

    @staticmethod
    @typing.overload
    def copyDir(originalDir: jpype.protocol.SupportsPath, copyDir: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        This is the same as calling :meth:`copyDir(File, File, FileFilter, TaskMonitor) <.copyDir>` with
        a :obj:`FileFilter` that accepts all files.
        
        :param jpype.protocol.SupportsPath originalDir: the source dir
        :param jpype.protocol.SupportsPath copyDir: the destination dir
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the number of filed copied
        :rtype: int
        :raises IOException: if there is an issue copying the files
        :raises CancelledException: if the operation is cancelled
        """

    @staticmethod
    @typing.overload
    def copyDir(originalDir: jpype.protocol.SupportsPath, copyDir: jpype.protocol.SupportsPath, filter: java.io.FileFilter, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Copies the contents of ``originalDir`` to ``copyDir``.  If the ``originalDir``
        does not exist, then this method will do nothing.  If ``copyDir`` does not exist, then
        it will be created as necessary.
        
        :param jpype.protocol.SupportsPath originalDir: The directory from which to extract contents
        :param jpype.protocol.SupportsPath copyDir: The directory in which the extracted contents will be placed
        :param java.io.FileFilter filter: a filter to apply against the directory's contents
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the number of filed copied
        :rtype: int
        :raises IOException: if there was a problem accessing the files
        :raises CancelledException: if the copy is cancelled
        """

    @staticmethod
    @typing.overload
    def copyFile(fromFile: jpype.protocol.SupportsPath, toFile: jpype.protocol.SupportsPath, append: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Copy the fromFile contents to the toFile.  The toFile will be overwritten or created.
        
        :param jpype.protocol.SupportsPath fromFile: source file
        :param jpype.protocol.SupportsPath toFile: destination file
        :param jpype.JBoolean or bool append: if true and the file exists, the fromFile contents will be
        appended to the toFile.
        :param ghidra.util.task.TaskMonitor monitor: if specified the progress will be reset and will advance to
        100% when the copy is complete.
        :return: number of bytes copied from source file to destination file
        :rtype: int
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    @typing.overload
    def copyFile(fromFile: generic.jar.ResourceFile, toFile: jpype.protocol.SupportsPath, append: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Copy the fromFile contents to the toFile.
        
        :param generic.jar.ResourceFile fromFile: source file
        :param jpype.protocol.SupportsPath toFile: destination file
        :param jpype.JBoolean or bool append: if true and the file exists, the fromFile contents will be
                        appended to the toFile.
        :param ghidra.util.task.TaskMonitor monitor: if specified the progress will be reset and will advance to
                        100% when the copy is complete.
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    @typing.overload
    def copyFile(fromFile: generic.jar.ResourceFile, toFile: generic.jar.ResourceFile, monitor: ghidra.util.task.TaskMonitor):
        """
        Copy the fromFile contents to the toFile.  The toFile will be overwritten or created.
        
        :param generic.jar.ResourceFile fromFile: source file
        :param generic.jar.ResourceFile toFile: destination file
        :param ghidra.util.task.TaskMonitor monitor: if specified the progress will be reset and will advance to
                        100% when the copy is complete.
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    def copyFileToStream(fromFile: jpype.protocol.SupportsPath, out: java.io.OutputStream, monitor: ghidra.util.task.TaskMonitor):
        """
        Copy the contents of the specified fromFile to the out stream.
        
        :param jpype.protocol.SupportsPath fromFile: file data source
        :param java.io.OutputStream out: destination stream
        :param ghidra.util.task.TaskMonitor monitor: if specified the progress will be reset and will advance to
        100% when the copy is complete.
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    def copyStreamToFile(in_: java.io.InputStream, toFile: jpype.protocol.SupportsPath, append: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Copy the in stream to the toFile.  The toFile will be overwritten or created.
        
        :param java.io.InputStream in: source input stream
        :param jpype.protocol.SupportsPath toFile: destination file
        :param jpype.JBoolean or bool append: if true and the file exists, the fromFile contents will be
        appended to the toFile.
        :param ghidra.util.task.TaskMonitor monitor: if specified the progress will be reset and will advance to
        100% when the copy is complete.
        :return: number of bytes copied from source file to destination file
        :rtype: int
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    def copyStreamToStream(in_: java.io.InputStream, out: java.io.OutputStream, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Copy the ``in`` stream to the ``out`` stream.  The output stream will
        **not** be closed when the copy operation is finished.
        
        :param java.io.InputStream in: source input stream
        :param java.io.OutputStream out: the destination output stream
        :param ghidra.util.task.TaskMonitor monitor: if specified the progress will be reset and will advance to
                        100% when the copy is complete.
        :return: the number of bytes copied from the input stream to the output stream.
        :rtype: int
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    def createDir(dir: jpype.protocol.SupportsPath) -> bool:
        """
        Ensures the specified leaf directory exists.
         
        
        Does not create any missing parent directories.  See :meth:`mkdirs(File) <.mkdirs>` instead.
         
        
        Takes into account race conditions with external threads/processes
        creating the same directory at the same time.
        
        :param jpype.protocol.SupportsPath dir: The directory to create.
        :return: True If the directory exists when this method completes; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def deleteDir(dir: jpype.protocol.SupportsPath) -> bool:
        """
        Delete a file or directory and all of its contents
        
        :param jpype.protocol.SupportsPath dir: the directory to delete
        :return: true if delete was successful. If false is returned, a partial
                delete may have occurred.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def deleteDir(dir: jpype.protocol.SupportsPath) -> bool:
        """
        Delete a file or directory and all of its contents
        
        :param jpype.protocol.SupportsPath dir: the dir to delete
        :return: true if delete was successful. If false is returned, a partial
                delete may have occurred.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def deleteDir(dir: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Delete a directory and all of its contents
        
        :param jpype.protocol.SupportsPath dir: the dir to delete
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if delete was successful. If false is returned, a partial
                delete may have occurred.
        :rtype: bool
        :raises CancelledException: if the operation is cancelled
        """

    @staticmethod
    def directoryExistsAndIsNotEmpty(directory: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the give file is not null, exists, is a directory and contains files.
        
        :param jpype.protocol.SupportsPath directory: the directory to test
        :return: true if the give file is not null, exists, is a directory and contains files.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.directoryIsEmpty(File)`
        """

    @staticmethod
    def directoryIsEmpty(directory: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given file is not null, exits, is a directory and has no files.
        
        :param jpype.protocol.SupportsPath directory: the directory to test for emptiness
        :return: true if the given file is a directory and has not files.
        :rtype: bool
        """

    @staticmethod
    def exists(uri: java.net.URI) -> bool:
        ...

    @staticmethod
    @typing.overload
    def existsAndIsCaseDependent(file: jpype.protocol.SupportsPath) -> FileResolutionResult:
        """
        Returns true if a file exists on disk and has a case that matches the filesystem.
        This method is handy for
        comparing file paths provided externally (like from a user or a config file) to
        determine if the case of the file path matches the case of the file on the filesystem.
        
        :param jpype.protocol.SupportsPath file: the file to be tested
        :return: a result object that reports the status of the file
        :rtype: FileResolutionResult
        """

    @staticmethod
    @typing.overload
    def existsAndIsCaseDependent(file: generic.jar.ResourceFile) -> FileResolutionResult:
        """
        Returns true if a file exists on disk and has a case that matches the filesystem.
        This method is handy for
        comparing file paths provided externally (like from a user or a config file) to
        determine if the case of the file path matches the case of the file on the filesystem.
        
        :param generic.jar.ResourceFile file: the file to be tested
        :return: a result object that reports the status of the file
        :rtype: FileResolutionResult
        """

    @staticmethod
    @typing.overload
    def forEachFile(path: jpype.protocol.SupportsPath, consumer: java.util.function.Consumer[java.nio.file.Path]):
        """
        A convenience method to list the contents of the given directory path and pass each to the
        given consumer.  If the given path does not represent a directory, nothing will happen.
         
         
        This method handles closing resources by using the try-with-resources construct on 
        :meth:`Files.list(Path) <Files.list>`
        
        :param jpype.protocol.SupportsPath path: the directory
        :param java.util.function.Consumer[java.nio.file.Path] consumer: the consumer of each child in the given directory
        :raises IOException: if there is any problem reading the directory contents
        """

    @staticmethod
    @typing.overload
    def forEachFile(resourceFile: jpype.protocol.SupportsPath, consumer: java.util.function.Consumer[java.io.File]):
        """
        A convenience method to list the contents of the given directory path and pass each to the
        given consumer.  If the given path does not represent a directory, nothing will happen.
        
        :param jpype.protocol.SupportsPath resourceFile: the directory
        :param java.util.function.Consumer[java.io.File] consumer: the consumer of each child in the given directory
        """

    @staticmethod
    @typing.overload
    def forEachFile(resourceFile: generic.jar.ResourceFile, consumer: java.util.function.Consumer[generic.jar.ResourceFile]):
        """
        A convenience method to list the contents of the given directory path and pass each to the
        given consumer.  If the given path does not represent a directory, nothing will happen.
        
        :param generic.jar.ResourceFile resourceFile: the directory
        :param java.util.function.Consumer[generic.jar.ResourceFile] consumer: the consumer of each child in the given directory
        """

    @staticmethod
    def formatLength(length: typing.Union[jpype.JLong, int]) -> str:
        """
        Returns a human readable string representing the length of something in bytes.
         
        
        Larger sizes are represented in rounded off kilo and mega bytes.
         
        
        TODO: why is the method using 1000 vs. 1024 for K?
        
        :param jpype.JLong or int length: the length to format
        :return: pretty string - "1.1KB", "5.0MB"
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getBytesFromFile(sourceFile: jpype.protocol.SupportsPath) -> jpype.JArray[jpype.JByte]:
        """
        Return an array of bytes read from the given file.
        
        :param jpype.protocol.SupportsPath sourceFile: the source file
        :return: the bytes
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if the file could not be accessed
        """

    @staticmethod
    @typing.overload
    def getBytesFromFile(sourceFile: jpype.protocol.SupportsPath, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        """
        Return an array of bytes read from the sourceFile, starting at the
        given offset
        
        :param jpype.protocol.SupportsPath sourceFile: file to read from
        :param jpype.JLong or int offset: offset into the file to begin reading
        :param jpype.JLong or int length: size of returned array of bytes
        :return: array of bytes, size length
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: thrown if there was a problem accessing the file or if there weren't
        at least ``length`` bytes read.
        """

    @staticmethod
    @typing.overload
    def getBytesFromFile(sourceFile: generic.jar.ResourceFile) -> jpype.JArray[jpype.JByte]:
        """
        Return an array of bytes read from the given file.
        
        :param generic.jar.ResourceFile sourceFile: the source file
        :return: the bytes
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if the file could not be accessed
        """

    @staticmethod
    @typing.overload
    def getBytesFromFile(sourceFile: generic.jar.ResourceFile, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        """
        Return an array of bytes read from the sourceFile, starting at the
        given offset
        
        :param generic.jar.ResourceFile sourceFile: file to read from
        :param jpype.JLong or int offset: offset into the file to begin reading
        :param jpype.JLong or int length: size of returned array of bytes
        :return: array of bytes, size length
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: thrown if there was a problem accessing the file or if there weren't
        at least ``length`` bytes read.
        """

    @staticmethod
    @typing.overload
    def getBytesFromStream(is_: java.io.InputStream) -> jpype.JArray[jpype.JByte]:
        """
        Reads the bytes from the stream into a byte array
        
        :param java.io.InputStream is: the input stream to read
        :return: a byte[] containing the bytes from the stream.
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if an I/O error occurs reading
        """

    @staticmethod
    @typing.overload
    def getBytesFromStream(inputStream: java.io.InputStream, expectedLength: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Reads the number of bytes indicated by the expectedLength from the input stream and returns
        them in a byte array.
        
        :param java.io.InputStream inputStream: the input stream
        :param jpype.JInt or int expectedLength: the number of bytes to be read
        :return: an array of bytes, that is the expectedLength, that was read from the stream.
        :rtype: jpype.JArray[jpype.JByte]
        :raises IOException: if the "expectedLength" number of bytes can't be read from the input stream.
        """

    @staticmethod
    @typing.overload
    def getLines(file: jpype.protocol.SupportsPath) -> java.util.List[java.lang.String]:
        """
        Returns all of the lines in the file without any newline characters
        
        :param jpype.protocol.SupportsPath file: The file to read in
        :return: a list of file lines
        :rtype: java.util.List[java.lang.String]
        :raises IOException: if an error occurs reading the file
        """

    @staticmethod
    @typing.overload
    def getLines(file: generic.jar.ResourceFile) -> java.util.List[java.lang.String]:
        """
        Returns all of the lines in the file without any newline characters.
         
        
        The file is treated as UTF-8 encoded.
        
        :param generic.jar.ResourceFile file: The text file to read in
        :return: a list of file lines
        :rtype: java.util.List[java.lang.String]
        :raises IOException: if an error occurs reading the file
        """

    @staticmethod
    @typing.overload
    def getLines(url: java.net.URL) -> java.util.List[java.lang.String]:
        """
        Returns all of the lines in the BufferedReader without any newline characters.
         
        
        The file is treated as UTF-8 encoded.
        
        :param java.net.URL url: the input stream from which to read
        :return: a list of file lines
        :rtype: java.util.List[java.lang.String]
        :raises IOException: thrown if there was a problem accessing the files
        """

    @staticmethod
    @typing.overload
    def getLines(is_: java.io.InputStream) -> java.util.List[java.lang.String]:
        """
        Returns all of the lines in the given :obj:`InputStream` without any newline characters.
        
        :param java.io.InputStream is: the input stream from which to read
        :return: a :obj:`List` of strings representing the text lines of the file
        :rtype: java.util.List[java.lang.String]
        :raises IOException: if there are any issues reading the file
        """

    @staticmethod
    @typing.overload
    def getLines(in_: java.io.BufferedReader) -> java.util.List[java.lang.String]:
        """
        Returns all of the lines in the :obj:`BufferedReader` without any newline characters.
        
        :param java.io.BufferedReader in: BufferedReader to read lines from. The caller is responsible for closing the reader
        :return: a :obj:`List` of strings representing the text lines of the file
        :rtype: java.util.List[java.lang.String]
        :raises IOException: if there are any issues reading the file
        """

    @staticmethod
    def getLinesQuietly(file: generic.jar.ResourceFile) -> java.util.List[java.lang.String]:
        """
        Returns all of the lines in the file without any newline characters.  This method
        is the same as :meth:`getLines(ResourceFile) <.getLines>`, except that it handles the exception
        that is thrown by that method.
        
        :param generic.jar.ResourceFile file: The file to read in
        :return: a list of file lines
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getPrettySize(file: jpype.protocol.SupportsPath) -> str:
        """
        Returns the size of the given file as a human readable String.
         
        
        See :meth:`formatLength(long) <.formatLength>`
        
        :param jpype.protocol.SupportsPath file: the file for which to get size
        :return: the pretty string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getText(is_: java.io.InputStream) -> str:
        """
        Returns all of the text in the given :obj:`InputStream`.
         
        
        EOL characters are normalized to simple '\n's.
        
        :param java.io.InputStream is: the input stream from which to read
        :return: the content as a String
        :rtype: str
        :raises IOException: if there are any issues reading the file
        """

    @staticmethod
    @typing.overload
    def getText(f: jpype.protocol.SupportsPath) -> str:
        """
        Returns all of the text in the given :obj:`File`.
         
        
        See :meth:`getText(InputStream) <.getText>`
        
        :param jpype.protocol.SupportsPath f: the file to read
        :return: the content as a String
        :rtype: str
        :raises IOException: if there are any issues reading the file or file is too large.
        """

    @staticmethod
    def isEmpty(f: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given file:
         
        1.  is null, or  
        2. :meth:`File.isFile() <File.isFile>` is true, 
        3. and :meth:`File.length() <File.length>` is == 0.
        
        
        :param jpype.protocol.SupportsPath f: the file to check
        :return: true if the file is not empty
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isPathContainedWithin(potentialParentFile: jpype.protocol.SupportsPath, otherFile: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given ``potentialParentFile`` is the parent path of
        the given ``otherFile``, or if the two file paths point to the same path.
        
        :param jpype.protocol.SupportsPath potentialParentFile: The file that may be the parent
        :param jpype.protocol.SupportsPath otherFile: The file that may be the child
        :return: boolean true if otherFile's path is within potentialParentFile's path
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isPathContainedWithin(potentialParents: collections.abc.Sequence, otherFile: generic.jar.ResourceFile) -> bool:
        """
        Returns true if any of the given ``potentialParents`` is the parent path of or has
        the same path as the given ``otherFile``.
        
        :param collections.abc.Sequence potentialParents: The files that may be the parent
        :param generic.jar.ResourceFile otherFile: The file that may be the child
        :return: boolean true if otherFile's path is within any of the potentialParents' paths
        :rtype: bool
        """

    @staticmethod
    def mkdirs(dir: jpype.protocol.SupportsPath) -> bool:
        """
        Make all directories in the full directory path specified. This is a
        replacement for the File.mkdirs() which fails due to a problem with the
        File.exists() method with remote file systems on Windows. After renaming
        a directory, the exists() method frequently reports the old directory as
        still existing. In the case of File.mkdirs() the recreation of the old
        directory would fail. The File.mkdir() method does not perform this
        check.
        
        :param jpype.protocol.SupportsPath dir: directory path to be created
        :return: True If the directory exists when this method completes; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def openNative(file: jpype.protocol.SupportsPath):
        """
        Uses the :obj:`Desktop` API to open the specified file using the user's operating
        system's native widgets (ie. Windows File Explorer, Mac Finder, etc).
         
        
        If the specified file is a directory, a file explorer will tend to be opened.
         
        
        If the specified file is a file, the operating system will decide what to do based
        on the contents or name of the file.
         
        
        If the :obj:`Desktop` API isn't support in the current env (unknown when
        this will actually happen) an error dialog will be displayed.
        
        :param jpype.protocol.SupportsPath file: :obj:`File` ref to a directory or file on the local filesystem.
        :raises IOException: if the OS doesn't know what to do with the file.
        """

    @staticmethod
    def pathToParts(path: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        ...

    @staticmethod
    @typing.overload
    def relativizePath(f1: jpype.protocol.SupportsPath, f2: jpype.protocol.SupportsPath) -> str:
        """
        Returns the portion of the second file that trails the full path of the first file.  If
        the paths are the same or unrelated, then null is returned.
        
         
        For example, given, in this order, two files with these paths
        ``/a/b`` and ``/a/b/c``, this method will return 'c'.
        
        :param jpype.protocol.SupportsPath f1: the parent file
        :param jpype.protocol.SupportsPath f2: the child file
        :return: the portion of the second file that trails the full path of the first file; null as
        described above
        :rtype: str
        :raises IOException: if there is an error canonicalizing the path
        """

    @staticmethod
    @typing.overload
    def relativizePath(f1: generic.jar.ResourceFile, f2: generic.jar.ResourceFile) -> str:
        """
        Return the relative path string of one resource file in another. If no path can be 
        constructed or the files are the same, then null is returned.
         
        Note: unlike :meth:`relativizePath(File, File) <.relativizePath>`, this function does not resolve symbolic 
        links.
        
         
        For example, given, in this order, two files with these paths
        ``/a/b`` and ``/a/b/c``, this method will return 'c'.
        
        :param generic.jar.ResourceFile f1: the parent resource file
        :param generic.jar.ResourceFile f2: the child resource file
        :return: the relative path of ``f2`` in ``f1``; null if f1 is not a parent of f2
        :rtype: str
        """

    @staticmethod
    def resolveFileCaseInsensitive(f: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Ensures the specified :obj:`File` points to a valid existing file,
        regardless of case match of the file's name.
         
        
        Does not fixup any case-mismatching of the parent directories of the specified
        file.
         
        
        If the exact filename already exists, it is returned unchanged, otherwise
        an all-lowercase version of the filename is probed, and then an all-uppercase
        version of the filename is probed, returning it if found.
         
        
        Finally, the entire parent directory of the specified file is listed, and the first
        file that matches, case-insensitively to the target file, is returned.
         
        
        If no file is found that matches, the original File instance is returned.
         
        
        See also :meth:`existsAndIsCaseDependent(ResourceFile) <.existsAndIsCaseDependent>`.
        
        :param jpype.protocol.SupportsPath f: File instance
        :return: File instance pointing to a case-insensitive match of the File parameter
        :rtype: java.io.File
        """

    @staticmethod
    def resolveFileCaseSensitive(caseSensitiveFile: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Ensures that the specified :obj:`File` param points to a file on the filesystem with a
        filename that has the exact same character case as the filename portion of the
        specified File.
         
        
        This does not ensure that the path components are case-sensitive.
         
        
        If the specified File and filesystem file do not match case a NULL is returned,
        otherwise the original File parameter is returned.
         
        
        This method is useful on OS's that have filesystems that are case-insensitive and allow
        using File("A") to open real file "a", and you do not wish to allow this.
         
        
        If the specified file being queried is a symbolic link to a file with a different name,
        no case sensitivity checks are done and the original specified File param is returned
        unchanged.
         
        
        (Put another way: symlink "FILE1" -> "../path/file2", no case sensitive enforcing can be done,
        but symlink "FILE1" -> "../path/file1" will be enforced by this method.)
         
        
        Querying a filepath that does not exist will result in a 'success' and the caller will
        receive the non-existent File instance back.
        
        :param jpype.protocol.SupportsPath caseSensitiveFile: :obj:`File` to enforce case-sensitive-ness of the name portion
        :return: the same :obj:`File` instance if it points to a file on the filesystem with
        the same case, or a NULL if the case does not match.
        :rtype: java.io.File
        """

    @staticmethod
    def setOwnerOnlyPermissions(f: jpype.protocol.SupportsPath):
        """
        Sets the given file (or directory) to readable and writable by only the owner.
        
        :param jpype.protocol.SupportsPath f: The file (or directory) to set the permissions of.
        """

    @staticmethod
    def writeBytes(file: jpype.protocol.SupportsPath, bytes: jpype.JArray[jpype.JByte]):
        """
        Writes an array of bytes to a file.
        
        :param jpype.protocol.SupportsPath file: the file to write to
        :param jpype.JArray[jpype.JByte] bytes: the array of bytes to write
        :raises FileNotFoundException: thrown if the file path is invalid
        :raises IOException: thrown if the file can't be written to.
        """

    @staticmethod
    def writeLinesToFile(file: jpype.protocol.SupportsPath, lines: java.util.List[java.lang.String]):
        """
        Writes the given list of Strings to the file, separating each by a newline character.
         
        
        **
        This will overwrite the contents of the given file!
        **
        
        :param jpype.protocol.SupportsPath file: the file to which the lines will be written
        :param java.util.List[java.lang.String] lines: the lines to write
        :raises IOException: if there are any issues writing to the file
        """

    @staticmethod
    def writeStringToFile(file: jpype.protocol.SupportsPath, s: typing.Union[java.lang.String, str]):
        """
        Writes the given String to the specified :obj:`File`.
        
        :param jpype.protocol.SupportsPath file: :obj:`File` to write to.
        :param java.lang.String or str s: String to write to the file.
        :raises IOException: if there were any issues while writing to the file.
        """


class FileResolutionResult(java.lang.Object):
    """
    A simple class that holds info relating to the result of verifying a file's existence and
    proper usage of case.
    """

    class FileResolutionStatus(java.lang.Enum[FileResolutionResult.FileResolutionStatus]):

        class_: typing.ClassVar[java.lang.Class]
        OK: typing.Final[FileResolutionResult.FileResolutionStatus]
        FileDoesNotExist: typing.Final[FileResolutionResult.FileResolutionStatus]
        NotProperlyCaseDependent: typing.Final[FileResolutionResult.FileResolutionStatus]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FileResolutionResult.FileResolutionStatus:
            ...

        @staticmethod
        def values() -> jpype.JArray[FileResolutionResult.FileResolutionStatus]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createDoesNotExistResult() -> FileResolutionResult:
        ...

    @staticmethod
    def doesNotExist(file: generic.jar.ResourceFile) -> FileResolutionResult:
        ...

    def getMessage(self) -> str:
        ...

    def getStatus(self) -> FileResolutionResult.FileResolutionStatus:
        ...

    def isOk(self) -> bool:
        ...

    @staticmethod
    def notCaseDependent(canonicalPath: typing.Union[java.lang.String, str], userPath: typing.Union[java.lang.String, str]) -> FileResolutionResult:
        ...

    @staticmethod
    def ok() -> FileResolutionResult:
        ...

    @property
    def message(self) -> java.lang.String:
        ...

    @property
    def status(self) -> FileResolutionResult.FileResolutionStatus:
        ...



__all__ = ["AnnotationUtilities", "FileUtilities", "FileResolutionResult"]
