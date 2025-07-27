from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


class AbstractAddMemoryBlockCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Base command class for adding memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setArtificial(self, a: typing.Union[jpype.JBoolean, bool]):
        """
        Prior to command execution the block's artificial attribute state may be specified
        and will be applied to the new memory block.
        
        :param jpype.JBoolean or bool a: block artificial attribute state
        """


class MoveBlockTask(ghidra.program.util.ProgramTask):
    """
    Command that runs in the background to move a memory block, as the move may
    be a time consuming operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, currentStart: ghidra.program.model.address.Address, newStart: ghidra.program.model.address.Address, listener: MoveBlockListener):
        """
        Creates a background command for moving memory blocks. The memory block
        is moved from its current start address to its new start address. After
        the command has completed, getStatus() can be called to check the
        success. If unsuccessful, getStatusMsg() can be called to get a message
        indicating why the command failed.
        
        :param ghidra.program.model.listing.Program program: the program whose memory map is being modified
        :param ghidra.program.model.address.Address currentStart: the start address of the block before the move.
        :param ghidra.program.model.address.Address newStart: the start address of the block after the move.
        :param MoveBlockListener listener: listener that will be notified when the move block has
                    completed.
        """

    def getStatusMessage(self) -> str:
        ...

    def isCancelled(self) -> bool:
        ...

    def wasSuccessful(self) -> bool:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...


class AddBitMappedMemoryBlockCmd(AbstractAddMemoryBlockCmd):
    """
    Command for adding Bit-mapped memory blocks.
    The resulting mapped block will derive its' byte values (1 or 0) from the mapped source bits.
    Example: 8 bytes in the resulting block will be derived from 1-byte
    in the underlying source region.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool], isVolatile: typing.Union[jpype.JBoolean, bool], mappedAddress: ghidra.program.model.address.Address, isOverlay: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new AddBitMappedMemoryBlockCmd
        
        :param java.lang.String or str name: the name for the new memory block.
        :param java.lang.String or str comment: the comment for the block
        :param java.lang.String or str source: indicates what is creating the block
        :param ghidra.program.model.address.Address start: the start address for the block
        :param jpype.JLong or int length: the length of the new block in number of bits to be mapped
        :param jpype.JBoolean or bool read: sets the block's read permission flag
        :param jpype.JBoolean or bool write: sets the block's write permission flag
        :param jpype.JBoolean or bool execute: sets the block's execute permission flag
        :param jpype.JBoolean or bool isVolatile: sets the block's volatile flag
        :param ghidra.program.model.address.Address mappedAddress: the address in memory that will serve as the bytes source for the block
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay address space.
        """


class DeleteBlockListener(java.lang.Object):
    """
    Listener that is notified when the DeleteBlockCmd completes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def deleteBlockCompleted(self, cmd: DeleteBlockCmd):
        """
        Notification that the delete block command completed
        
        :param DeleteBlockCmd cmd: command that was completed; the command has the 
        status as to whether the delete was successful
        """


class AddByteMappedMemoryBlockCmd(AbstractAddMemoryBlockCmd):
    """
    Command for adding byte-mapped memory blocks
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool], isVolatile: typing.Union[jpype.JBoolean, bool], mappedAddress: ghidra.program.model.address.Address, byteMappingScheme: ghidra.program.database.mem.ByteMappingScheme, isOverlay: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new AddByteMappedMemoryBlockCmd with a specified byte mapping scheme.
        Byte mapping scheme is specified by two values schemeDestByteCount and schemeSrcByteCount which
        may be viewed as a ratio of number of destination bytes to number of mapped source bytes. 
        When the destination consumes bytes from the mapped source it consume schemeDestByteCount bytes then 
        skips (schemeSrcByteCount - schemeDestByteCount) bytes before repeating the mapping sequence over 
        the extent of the destination block.  The block start address and source mappedAddress must
        be chosen carefully as they relate to the mapping scheme when it is anything other than 1:1.
        
        :param java.lang.String or str name: the name for the new memory block.
        :param java.lang.String or str comment: the comment for the block
        :param java.lang.String or str source: indicates what is creating the block
        :param ghidra.program.model.address.Address start: the start address for the block
        :param jpype.JLong or int length: the length of the new block
        :param jpype.JBoolean or bool read: sets the block's read permission flag
        :param jpype.JBoolean or bool write: sets the block's write permission flag
        :param jpype.JBoolean or bool execute: sets the block's execute permission flag
        :param jpype.JBoolean or bool isVolatile: sets the block's volatile flag
        :param ghidra.program.model.address.Address mappedAddress: the address in memory that will serve as the bytes source for the block
        :param ghidra.program.database.mem.ByteMappingScheme byteMappingScheme: byte mapping scheme (may be null for 1:1 mapping)
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay address space.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool], isVolatile: typing.Union[jpype.JBoolean, bool], mappedAddress: ghidra.program.model.address.Address, isOverlay: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new AddByteMappedMemoryBlockCmd with 1:1 byte mapping scheme
        
        :param java.lang.String or str name: the name for the new memory block.
        :param java.lang.String or str comment: the comment for the block
        :param java.lang.String or str source: indicates what is creating the block
        :param ghidra.program.model.address.Address start: the start address for the block
        :param jpype.JLong or int length: the length of the new block
        :param jpype.JBoolean or bool read: sets the block's read permission flag
        :param jpype.JBoolean or bool write: sets the block's write permission flag
        :param jpype.JBoolean or bool execute: sets the block's execute permission flag
        :param jpype.JBoolean or bool isVolatile: sets the block's volatile flag
        :param ghidra.program.model.address.Address mappedAddress: the address in memory that will serve as the bytes source for the block
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay address space.
        """


class AddInitializedMemoryBlockCmd(AbstractAddMemoryBlockCmd):
    """
    Command for adding a new memory block initialized with a specific byte.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool], isVolatile: typing.Union[jpype.JBoolean, bool], initialValue: typing.Union[jpype.JByte, int], isOverlay: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new AddFileBytesMemoryBlockCmd
        
        :param java.lang.String or str name: the name for the new memory block.
        :param java.lang.String or str comment: the comment for the block
        :param java.lang.String or str source: indicates what is creating the block
        :param ghidra.program.model.address.Address start: the start address for the block
        :param jpype.JLong or int length: the length of the new block
        :param jpype.JBoolean or bool read: sets the block's read permission flag
        :param jpype.JBoolean or bool write: sets the block's write permission flag
        :param jpype.JBoolean or bool execute: sets the block's execute permission flag
        :param jpype.JBoolean or bool isVolatile: sets the block's volatile flag
        :param jpype.JByte or int initialValue: the bytes value to use throught the new block.
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay address space.
        """


class AddUninitializedMemoryBlockCmd(AbstractAddMemoryBlockCmd):
    """
    Command for adding uninitialized memory blocks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool], isVolatile: typing.Union[jpype.JBoolean, bool], isOverlay: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new AddUninitializedMemoryBlockCmd
        
        :param java.lang.String or str name: the name for the new memory block.
        :param java.lang.String or str comment: the comment for the block
        :param java.lang.String or str source: indicates what is creating the block
        :param ghidra.program.model.address.Address start: the start address for the block
        :param jpype.JLong or int length: the length of the new block
        :param jpype.JBoolean or bool read: sets the block's read permission flag
        :param jpype.JBoolean or bool write: sets the block's write permission flag
        :param jpype.JBoolean or bool execute: sets the block's execute permission flag
        :param jpype.JBoolean or bool isVolatile: sets the block's volatile flag
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay address space.
        """


class DeleteBlockCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command that runs in the background to delete a memory block, as 
    the delete may be a time consuming operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, blockAddresses: jpype.JArray[ghidra.program.model.address.Address], listener: DeleteBlockListener):
        """
        Creates a background command for deleting memory blocks. Each address in
        the array of block addresses indicates that the block containing that
        address should be removed.
        After the command has completed, getStatus() can be called to check the success.
        If unsuccessful, getStatusMsg() can be called to get a message 
        indicating why the command failed.
        
        :param jpype.JArray[ghidra.program.model.address.Address] blockAddresses: addresses indicating each block to be removed.
        :param DeleteBlockListener listener: listener that will be notified when the delete block has completed.
        """

    def getStatus(self) -> bool:
        """
        Return whether the delete block was successful.
        
        :return: true if the block was deleted
        :rtype: bool
        """

    @property
    def status(self) -> jpype.JBoolean:
        ...


class AddFileBytesMemoryBlockCmd(AbstractAddMemoryBlockCmd):
    """
    Command for adding a new memory block using bytes from an imported :obj:`FileBytes` object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool], isVolatile: typing.Union[jpype.JBoolean, bool], fileBytes: ghidra.program.database.mem.FileBytes, offset: typing.Union[jpype.JLong, int], isOverlay: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new AddFileBytesMemoryBlockCmd
        
        :param java.lang.String or str name: the name for the new memory block.
        :param java.lang.String or str comment: the comment for the block
        :param java.lang.String or str source: indicates what is creating the block
        :param ghidra.program.model.address.Address start: the start address for the block
        :param jpype.JLong or int length: the length of the new block
        :param jpype.JBoolean or bool read: sets the block's read permission flag
        :param jpype.JBoolean or bool write: sets the block's write permission flag
        :param jpype.JBoolean or bool execute: sets the block's execute permission flag
        :param jpype.JBoolean or bool isVolatile: sets the block's volatile flag
        :param ghidra.program.database.mem.FileBytes fileBytes: the :obj:`FileBytes` object that provides the byte source for this block.
        :param jpype.JLong or int offset: the offset into the :obj:`FileBytes` object for the first byte in this block.
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay address space.
        """


class MoveBlockListener(java.lang.Object):
    """
    Listener that is notified when a move block completed or some state
    has changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def moveBlockCompleted(self, cmd: MoveBlockTask):
        """
        Notification that the move block completed.
        
        :param MoveBlockTask cmd: the command that was executed to move the block; the
        command has the status of whether the block was moved
        successfully
        """

    def stateChanged(self):
        """
        Notification that something has changed.
        """



__all__ = ["AbstractAddMemoryBlockCmd", "MoveBlockTask", "AddBitMappedMemoryBlockCmd", "DeleteBlockListener", "AddByteMappedMemoryBlockCmd", "AddInitializedMemoryBlockCmd", "AddUninitializedMemoryBlockCmd", "DeleteBlockCmd", "AddFileBytesMemoryBlockCmd", "MoveBlockListener"]
