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


class Pair(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]):
        ...

    def getEnd(self) -> int:
        ...

    def getStart(self) -> int:
        ...

    def setEnd(self, end: typing.Union[jpype.JLong, int]):
        ...

    def setStart(self, start: typing.Union[jpype.JLong, int]):
        ...

    @property
    def start(self) -> jpype.JLong:
        ...

    @start.setter
    def start(self, value: jpype.JLong):
        ...

    @property
    def end(self) -> jpype.JLong:
        ...

    @end.setter
    def end(self, value: jpype.JLong):
        ...


class ReverseLineReader(java.lang.Object):
    """
    Reads in a single line of text from a given input file, in reverse order. 
     
    CONOPS:
        1. Start at a given position in the file and read BUFFER_SIZE bytes into a byte array
    2. From the end of the array, read a character
    3. If the character represents a newline (or carriage return), the line is finished, so return.
    4. If not, continue reading.
    """

    class_: typing.ClassVar[java.lang.Class]
    raf: java.io.RandomAccessFile

    def __init__(self, encoding: typing.Union[java.lang.String, str], raf: java.io.RandomAccessFile):
        """
        
        
        :param java.lang.String or str encoding: 
        :param java.io.RandomAccessFile raf: 
        :raises IOException:
        """

    def readLine(self) -> str:
        """
        Reads a single line from the current file pointer position, in reverse.  To do this we do
        the following:
         
        1. Read a 'large enough' number of bytes into a buffer (enough to guarantee a full line of
            text.
        2. Move backwards through the bytes just read until a newline or carriage return is found.
        3. Throw away the rest of the bytes and return the line found.
        
        :return: 
        :rtype: str
        :raises IOException:
        """

    def setFilePos(self, position: typing.Union[jpype.JLong, int]):
        """
        Moves the file pointer to the given byte location.
        
        :param jpype.JLong or int position:
        """


class ChunkReader(java.lang.Object):
    """
    This class handles reading data from the input file, in the form of :obj:`Chunk` objects.  Each
    chunk is stored in the :obj:`ChunkModel` and represents a single block of text that is 
    displayed in the :obj:`FVTable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, model: ChunkModel):
        """
        
        
        :param jpype.protocol.SupportsPath file: 
        :param ChunkModel model: 
        :raises IOException:
        """

    def getFile(self) -> java.io.File:
        """
        Returns the file being read.
        
        :return: 
        :rtype: java.io.File
        """

    def getFileSize(self) -> int:
        """
        Returns the number of bytes in the input file.
        
        :return: number of bytes
        :rtype: int
        :raises IOException:
        """

    def getStartOfNextLine(self, startByte: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the start of the next line after the given byte. To do this, simply read 
        backwards from the given point until a newline or carriage return is found.
        
        :param jpype.JLong or int startByte: 
        :return: 
        :rtype: int
        :raises IOException:
        """

    def readBytes(self, startByte: typing.Union[jpype.JLong, int], endByte: typing.Union[jpype.JLong, int]) -> java.util.List[jpype.JArray[jpype.JByte]]:
        """
        Reads all bytes from the given byte to the end byte. If the amount of bytes to be read is
        greater than the size of an INT, we will have to read this in several chunks, hence the
        need to return a list of arrays, and not just a single byte array.
        
        :param jpype.JLong or int startByte: 
        :param jpype.JLong or int endByte: 
        :return: a map of all the bytes read in (index 0 is first chunk, 1 is next, etc...).
        :rtype: java.util.List[jpype.JArray[jpype.JByte]]
        :raises IOException:
        """

    def readLastChunk(self) -> java.util.List[java.lang.String]:
        """
        Reads one chunk from the end of the file. This is useful when scrolling to the bottom of
        the viewport.
        
        :return: the last chunk, or an empty list
        :rtype: java.util.List[java.lang.String]
        :raises IOException:
        """

    def readNextChunk(self) -> java.util.List[java.lang.String]:
        """
        Reads the next chunk in the file past the last one specified in the :obj:`ChunkModel`.
        
        :return: the lines of text read
        :rtype: java.util.List[java.lang.String]
        :raises FileNotFoundException: 
        :raises IOException:
        """

    def readNextChunkFrom(self, startByte: typing.Union[jpype.JLong, int]) -> java.util.List[java.lang.String]:
        """
        Reads a chunk of data from the given location in the file.  To ensure we're always reading
        full lines, take the given start position and move forward to the next full line before
        reading.
        
        :param jpype.JLong or int startByte: the position to start reading from
        :return: the lines of text read
        :rtype: java.util.List[java.lang.String]
        :raises IOException:
        """

    def readPreviousChunk(self) -> java.util.List[java.lang.String]:
        """
        Reads the chunk immediately before the first visible one.
        
        :return: the previous chunk, or an empty list
        :rtype: java.util.List[java.lang.String]
        :raises IOException:
        """

    def reload(self):
        ...

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def fileSize(self) -> jpype.JLong:
        ...

    @property
    def startOfNextLine(self) -> jpype.JLong:
        ...


class ChunkModel(java.lang.Iterable[Chunk]):
    """
    Stores all chunks read-in by the :obj:`ChunkReader`. The model is responsible for handling all
    interaction with the list of chunks.
    """

    class_: typing.ClassVar[java.lang.Class]
    selectedByteStart: jpype.JLong
    selectedByteEnd: jpype.JLong
    NUM_LINES: typing.Final = 250
    MAX_VISIBLE_CHUNKS: typing.Final = 3

    def __init__(self):
        ...

    @typing.overload
    def add(self, chunk: Chunk):
        """
        Adds the given chunk to the model.
        
        :param Chunk chunk:
        """

    @typing.overload
    def add(self, index: typing.Union[jpype.JInt, int], chunk: Chunk):
        """
        Adds a chunk at the given index to the model.
        
        :param jpype.JInt or int index: 
        :param Chunk chunk:
        """

    def clear(self):
        """
        Clears all chunks from the model.
        """

    def get(self, index: typing.Union[jpype.JInt, int]) -> Chunk:
        """
        Returns the chunk at the given index.
        
        :param jpype.JInt or int index: 
        :return: 
        :rtype: Chunk
        """

    def getFilePositionForRow(self, row: typing.Union[jpype.JInt, int]) -> Pair:
        """
        Returns the start/end byte positions within the input file for the given row.
         
        To do this we have to loop over all chunks in the :obj:`ChunkModel` and count the number 
        of lines in each chunk until we get to the line (row) we're looking for. We then grab the 
        correct value from the byteMap for that chunk line, which is the starting byte for it.
        
        :param jpype.JInt or int row: 
        :return: the byte position in the file this row corresponds to
        :rtype: Pair
        """

    def getNumChunks(self) -> int:
        """
        
        
        :return: 
        :rtype: int
        """

    def getRowForBytePos(self, selectedByte: typing.Union[jpype.JLong, int]) -> int:
        """
        Searches the visible chunks to see if any of them contain the given byte. If so, returns
        the row in the table where it resides. Returns -1 otherwise.
        
        :param jpype.JLong or int selectedByte: 
        :return: 
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Returns the number of chunks in the model.
        
        :return: 
        :rtype: int
        """

    def remove(self, index: typing.Union[jpype.JInt, int]) -> Chunk:
        """
        Removes the chunk at the given index from the model.
        
        :param jpype.JInt or int index:
        """

    @property
    def rowForBytePos(self) -> jpype.JInt:
        ...

    @property
    def numChunks(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def filePositionForRow(self) -> Pair:
        ...


class Chunk(java.lang.Object):
    """
    A chunk represents the basic unit of text that is displayed in the :obj:`FVTable`. This does
    NOT contain the actual text being displayed; rather it contains metadata describing the 
    text (start/end byte positions, number of lines in the chunk, etc...).
     
    It should be noted that chunks are transient - they are created and destroyed as different
    sections of the file are required for display.
    """

    class_: typing.ClassVar[java.lang.Class]
    start: jpype.JLong
    end: jpype.JLong
    rowToFilePositionMap: java.util.Map[java.lang.Integer, Pair]
    linesInChunk: jpype.JInt

    def __init__(self):
        ...



__all__ = ["Pair", "ReverseLineReader", "ChunkReader", "ChunkModel", "Chunk"]
