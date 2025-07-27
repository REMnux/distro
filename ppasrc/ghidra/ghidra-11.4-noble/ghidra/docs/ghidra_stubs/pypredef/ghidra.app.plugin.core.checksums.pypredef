from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.mem
import ghidra.util.classfinder
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class SHA256DigestChecksumAlgorithm(DigestChecksumAlgorithm):
    """
    This class is used for the computation of the SHA-256 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the SHA-256 checksum algorithm.
        
        :raises NoSuchAlgorithmException: If MessageDigest does not support this algorithm.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


class Checksum8ChecksumAlgorithm(BasicChecksumAlgorithm):
    """
    This class is used for the computation of the basic 8-bit checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the basic 8-bit checksum algorithm.
        """


class ChecksumAlgorithm(ghidra.util.classfinder.ExtensionPoint):
    """
    This abstract class is used for the computation and formatting of various checksum algorithms.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs a new checksum algorithm with the given name.
        
        :param java.lang.String or str name: The name of the checksum algorithm.
        """

    @staticmethod
    def format(checksum: jpype.JArray[jpype.JByte], hex: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Formats the checksum as a string.
        
        :param jpype.JArray[jpype.JByte] checksum: The checksum to format as a string.
        :param jpype.JBoolean or bool hex: True if the checksum should be formatted as hex; false if decimal. 
                    Note: if formatting as decimal is not possible, hex will be used instead.
        :return: The formatted checksum.
        :rtype: str
        """

    def getChecksum(self) -> jpype.JArray[jpype.JByte]:
        """
        Gets the last computed checksum.
        
        :return: The last computed checksum, or null if the checksum has never been generated.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getName(self) -> str:
        """
        Gets the name of the checksum algorithm.
        
        :return: The name of the checksum algorithm.
        :rtype: str
        """

    def reset(self):
        ...

    def supportsDecimal(self) -> bool:
        """
        Checks whether or not this algorithm supports showing its result in decimal format.
        
        :return: True if this algorithm supports showing its result in decimal format; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def toArray(l: typing.Union[jpype.JLong, int], numBytes: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Converts a long to a little-endian array.
        
        :param jpype.JLong or int l: The long to convert.
        :param jpype.JInt or int numBytes: The desired size of the resulting array.  Result is truncated or padded if 
                        numBytes is smaller or larger than size of long.
        :return: The little-endian array.
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, provider: ComputeChecksumsProvider):
        """
        Updates (or generates) the checksum for this algorithm over the given address range.
        
        :param ghidra.program.model.mem.Memory memory: The memory over which to generate the checksum.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor.
        :param ComputeChecksumsProvider provider: An optional checksum provider that has options used for generating the
        checksum.  Could be null.
        :raises MemoryAccessException: If there was a problem accessing the specified memory.
        :raises CancelledException: If checksum generation was cancelled.
        """

    @typing.overload
    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Updates (or generates) the checksum for this algorithm over the given address range.
        
        :param ghidra.program.model.mem.Memory memory: The memory over which to generate the checksum.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor.
        :raises MemoryAccessException: If there was a problem accessing the specified memory.
        :raises CancelledException: If checksum generation was cancelled.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def checksum(self) -> jpype.JArray[jpype.JByte]:
        ...


class Checksum16ChecksumAlgorithm(BasicChecksumAlgorithm):
    """
    This class is used for the computation of the basic 16-bit checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the basic 16-bit checksum algorithm.
        """


class SHA1DigestChecksumAlgorithm(DigestChecksumAlgorithm):
    """
    This class is used for the computation of the SHA-1 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the SHA-1 checksum algorithm.
        
        :raises NoSuchAlgorithmException: If MessageDigest does not support this algorithm.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


class SHA384DigestChecksumAlgorithm(DigestChecksumAlgorithm):
    """
    This class is used for the computation of the SHA-384 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the SHA-384 checksum algorithm.
        
        :raises NoSuchAlgorithmException: If MessageDigest does not support this algorithm.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


class SHA512DigestChecksumAlgorithm(DigestChecksumAlgorithm):
    """
    This class is used for the computation of the SHA-512 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the SHA-512 checksum algorithm.
        
        :raises NoSuchAlgorithmException: If MessageDigest does not support this algorithm.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


class MD2DigestChecksumAlgorithm(DigestChecksumAlgorithm):
    """
    This class is used for the computation of the MD2 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the MD2 checksum algorithm.
        
        :raises NoSuchAlgorithmException: If MessageDigest does not support this algorithm.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


class ChecksumTableModel(docking.widgets.table.GDynamicColumnTableModel[ChecksumAlgorithm, java.lang.Object]):
    """
    This class is used to model the table in the ComputeChecksumsProvider.
    """

    @typing.type_check_only
    class ChecksumNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ChecksumAlgorithm, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ChecksumValueColumn(docking.widgets.table.AbstractDynamicTableColumn[ChecksumAlgorithm, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CaseInsensitiveComparator(java.util.Comparator[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME_COL: typing.Final = 0
    VALUE_COL: typing.Final = 1

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, checksumAlgorithms: java.util.List[ChecksumAlgorithm]):
        """
        Constructor for the table model.
        
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: The service provider
        :param java.util.List[ChecksumAlgorithm] checksumAlgorithms: The list of checksum algorithms to use in the table
        """


class CRC32ChecksumAlgorithm(ChecksumAlgorithm):
    """
    This class is used for the computation of the CRC-32 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the CRC-32 checksum algorithm.
        """

    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, onesComp: typing.Union[jpype.JBoolean, bool], twosComp: typing.Union[jpype.JBoolean, bool]):
        """
        Computes the checksum with the given options.
        
        :param ghidra.program.model.mem.Memory memory: The memory to generate the checksum from.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor to cancel the computation.
        :param jpype.JBoolean or bool onesComp: True if the checksum should be complemented with a ones complement.
        :param jpype.JBoolean or bool twosComp: True if the checksum should be complemented with a twos complement.
        :raises MemoryAccessException: If there was a problem reading the memory.
        :raises CancelledException: If the user cancels the task.
        """


class ComputeChecksumsPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor for the ComputeChecksumsPlugin.
        
        :param ghidra.framework.plugintool.PluginTool tool:
        """


class CRC16CCITTChecksumAlgorithm(ChecksumAlgorithm):
    """
    This class is used for the computation of the CRC-16 CCITT checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the CRC-16 CCITT checksum algorithm.
        """

    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, onesComp: typing.Union[jpype.JBoolean, bool], twosComp: typing.Union[jpype.JBoolean, bool]):
        """
        Computes the checksum with the given options.
        
        :param ghidra.program.model.mem.Memory memory: The memory to generate the checksum from.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor to cancel the computation.
        :param jpype.JBoolean or bool onesComp: True if the checksum should be complemented with a ones complement.
        :param jpype.JBoolean or bool twosComp: True if the checksum should be complemented with a twos complement.
        :raises MemoryAccessException: If there was a problem reading the memory.
        :raises CancelledException: If the user cancels the task.
        """


class CRC16ChecksumAlgorithm(ChecksumAlgorithm):
    """
    This class is used for the computation of the CRC-16 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the CRC-16 checksum algorithm.
        """

    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, onesComp: typing.Union[jpype.JBoolean, bool], twosComp: typing.Union[jpype.JBoolean, bool]):
        """
        Computes the checksum with the given options.
        
        :param ghidra.program.model.mem.Memory memory: The memory to generate the checksum from.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor to cancel the computation.
        :param jpype.JBoolean or bool onesComp: True if the checksum should be complemented with a ones complement.
        :param jpype.JBoolean or bool twosComp: True if the checksum should be complemented with a twos complement.
        :raises MemoryAccessException: If there was a problem accessing the specified memory.
        :raises CancelledException: If checksum generation was cancelled.
        """


class ComputeChecksumTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ComputeChecksumsProvider, memory: ghidra.program.model.mem.Memory, set: ghidra.program.model.address.AddressSetView):
        ...


class DigestChecksumAlgorithm(ChecksumAlgorithm):
    """
    This class is used for the computation of various digest checksums that are provided 
    by java. These checksums do not have options associated with them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: typing.Union[java.lang.String, str]):
        """
        Constructor for the digest checksum.
        
        :param java.lang.String or str type: The type of digest checksum to create.
        :raises NoSuchAlgorithmException: If MessageDigest does not support the type.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


@typing.type_check_only
class MemoryInputStream(java.io.InputStream):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ComputeChecksumsProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Provider to invoke computation of various checksums and display them in a table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ComputeChecksumsPlugin):
        """
        Constructor for the provider.
        
        :param ComputeChecksumsPlugin plugin: The plugin that created the provider.
        """

    def isCarry(self) -> bool:
        """
        Returns true if the toggle action for 'carry' is selected.
        
        :return: true if the toggle action for 'carry' is selected.
        :rtype: bool
        """

    def isOnes(self) -> bool:
        """
        Returns true if the toggle action for 'one's complement' is selected.
        
        :return: true if the toggle action for 'one's complement' is selected.
        :rtype: bool
        """

    def isTwos(self) -> bool:
        """
        Returns true if the toggle action for 'two's complement' is selected.
        
        :return: true if the toggle action for 'two's complement' is selected.
        :rtype: bool
        """

    def isXor(self) -> bool:
        """
        Returns true if the toggle action for 'xor' is selected.
        
        :return: true if the toggle action for 'xor' is selected.
        :rtype: bool
        """

    @property
    def twos(self) -> jpype.JBoolean:
        ...

    @property
    def ones(self) -> jpype.JBoolean:
        ...

    @property
    def xor(self) -> jpype.JBoolean:
        ...

    @property
    def carry(self) -> jpype.JBoolean:
        ...


class Adler32ChecksumAlgorithm(ChecksumAlgorithm):
    """
    This class is used for the computation of the Adler-32 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the Adler-32 checksums algorithm.
        """

    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, onesComp: typing.Union[jpype.JBoolean, bool], twosComp: typing.Union[jpype.JBoolean, bool]):
        """
        Computes the checksum with the given options.
        
        :param ghidra.program.model.mem.Memory memory: The memory to generate the checksum from.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor to cancel the computation.
        :param jpype.JBoolean or bool onesComp: True if the checksum should be complemented with a ones complement.
        :param jpype.JBoolean or bool twosComp: True if the checksum should be complemented with a twos complement.
        :raises MemoryAccessException: If there was a problem accessing the specified memory.
        :raises CancelledException: If checksum generation was cancelled.
        """


class MD5DigestChecksumAlgorithm(DigestChecksumAlgorithm):
    """
    This class is used for the computation of the MD5 checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the MD5 checksum algorithm.
        
        :raises NoSuchAlgorithmException: If MessageDigest does not support this algorithm.
        
        .. seealso::
        
            | :obj:`MessageDigest.getInstance(String)`
        """


class BasicChecksumAlgorithm(ChecksumAlgorithm):
    """
    This class is used for the computation of various basic checksums.
    """

    class SupportedByteSize(java.lang.Enum[BasicChecksumAlgorithm.SupportedByteSize]):
        """
        The byte sizes that are supported by the basic checksum algorithm.
        """

        class_: typing.ClassVar[java.lang.Class]
        CHECKSUM8: typing.Final[BasicChecksumAlgorithm.SupportedByteSize]
        CHECKSUM16: typing.Final[BasicChecksumAlgorithm.SupportedByteSize]
        CHECKSUM32: typing.Final[BasicChecksumAlgorithm.SupportedByteSize]

        def getNumBytes(self) -> int:
            """
            Gets the number of bytes supported by this entry.
            
            :return: The number of bytes supported by this entry.
            :rtype: int
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BasicChecksumAlgorithm.SupportedByteSize:
            ...

        @staticmethod
        def values() -> jpype.JArray[BasicChecksumAlgorithm.SupportedByteSize]:
            ...

        @property
        def numBytes(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, size: BasicChecksumAlgorithm.SupportedByteSize):
        """
        Constructor for the basic checksum.
        
        :param BasicChecksumAlgorithm.SupportedByteSize size: The size in bytes of the basic checksum.
        """

    def updateChecksum(self, memory: ghidra.program.model.mem.Memory, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, xor: typing.Union[jpype.JBoolean, bool], carry: typing.Union[jpype.JBoolean, bool], onesComp: typing.Union[jpype.JBoolean, bool], twosComp: typing.Union[jpype.JBoolean, bool]):
        """
        Computes the checksum with the given options.
        
        :param ghidra.program.model.mem.Memory memory: The memory to generate the checksum from.
        :param ghidra.program.model.address.AddressSetView addrSet: The addresses over which to generate the checksum.
        :param ghidra.util.task.TaskMonitor monitor: Cancelable task monitor to cancel the computation.
        :param jpype.JBoolean or bool xor: True if the checksum should allow xor operations.
        :param jpype.JBoolean or bool carry: True if the checksum should allow carry operations.
        :param jpype.JBoolean or bool onesComp: True if the checksum should be complemented with a ones complement.
        :param jpype.JBoolean or bool twosComp: True if the checksum should be complemented with a twos complement.
        :raises MemoryAccessException: If there was a problem accessing the specified memory.
        :raises CancelledException: If checksum generation was cancelled.
        """


class Checksum32ChecksumAlgorithm(BasicChecksumAlgorithm):
    """
    This class is used for the computation of the basic 32-bit checksum algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for the basic 32-bit checksum algorithm.
        """



__all__ = ["SHA256DigestChecksumAlgorithm", "Checksum8ChecksumAlgorithm", "ChecksumAlgorithm", "Checksum16ChecksumAlgorithm", "SHA1DigestChecksumAlgorithm", "SHA384DigestChecksumAlgorithm", "SHA512DigestChecksumAlgorithm", "MD2DigestChecksumAlgorithm", "ChecksumTableModel", "CRC32ChecksumAlgorithm", "ComputeChecksumsPlugin", "CRC16CCITTChecksumAlgorithm", "CRC16ChecksumAlgorithm", "ComputeChecksumTask", "DigestChecksumAlgorithm", "MemoryInputStream", "ComputeChecksumsProvider", "Adler32ChecksumAlgorithm", "MD5DigestChecksumAlgorithm", "BasicChecksumAlgorithm", "Checksum32ChecksumAlgorithm"]
