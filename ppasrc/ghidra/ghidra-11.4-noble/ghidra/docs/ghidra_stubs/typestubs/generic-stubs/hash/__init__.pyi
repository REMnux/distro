from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.lang # type: ignore


class FNV1a32MessageDigestFactory(MessageDigestFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SimpleCRC32(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    crc32tab: typing.Final[jpype.JArray[jpype.JInt]]

    def __init__(self):
        ...

    @staticmethod
    def hashOneByte(hashcode: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int]) -> int:
        ...


class FNV1a64MessageDigestFactory(MessageDigestFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MessageDigest(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def digest(self) -> jpype.JArray[jpype.JByte]:
        """
        Completes the hash computation by performing final operations such as
        padding.  The digest is reset after this call is made.
        
        :return: the array of bytes for the resulting hash value
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def digest(self, buf: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Completes the hash computation by performing final operations such as
        padding.  The digest is reset after this call is made.
        
        :param jpype.JArray[jpype.JByte] buf: output buffer for the computed digest
        :param jpype.JInt or int offset: offset into the output buffer to begin storing the digest
        :param jpype.JInt or int len: number of bytes within buf allocated for the digest
        :return: the number of bytes placed into buf
        :rtype: int
        """

    def digestLong(self) -> int:
        """
        Completes the hash computation by performing final operations such as
        padding, and returns (up to) the first 8 bytes as a big-endian long
        value.  The digest is reset after this call is made.
        
        :return: the digest value as a long value
        :rtype: int
        """

    def getAlgorithm(self) -> str:
        """
        Returns a string that identifies the algorithm, independent of
        implementation details.
        
        :return: the name of the algorithm
        :rtype: str
        """

    def getDigestLength(self) -> int:
        """
        Returns the length of the digest in bytes.
        
        :return: the digest length in bytes
        :rtype: int
        """

    def reset(self):
        """
        Resets the digest for further use.
        """

    @typing.overload
    def update(self, input: typing.Union[jpype.JByte, int]):
        """
        Updates the digest using the specified byte.
        
        :param jpype.JByte or int input: the byte with which to update the digest
        """

    @typing.overload
    def update(self, input: typing.Union[jpype.JShort, int]):
        """
        Updates the digest using the specified short.
        
        :param jpype.JShort or int input: the short with which to update the digest (big endian)
        """

    @typing.overload
    def update(self, input: typing.Union[jpype.JInt, int]):
        """
        Updates the digest using the specified int.
        
        :param jpype.JInt or int input: the int with which to update the digest (big endian)
        """

    @typing.overload
    def update(self, input: typing.Union[jpype.JLong, int]):
        """
        Updates the digest using the specified long.
        
        :param jpype.JLong or int input: the long with which to update the digest (big endian)
        """

    @typing.overload
    def update(self, input: jpype.JArray[jpype.JByte]):
        """
        Updates the digest using the specified array of bytes. Do not use a monitor
        
        :param jpype.JArray[jpype.JByte] input: the array of bytes
        """

    @typing.overload
    def update(self, input: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        """
        Updates the digest using the specified array of bytes, starting at the
        specified offset (and for the specified length). Do not use a monitor.
        
        :param jpype.JArray[jpype.JByte] input: the array of bytes
        :param jpype.JInt or int offset: the offset to start from in the array of bytes
        :param jpype.JInt or int len: the number of bytes to use, starting at offset
        """

    @typing.overload
    def update(self, input: jpype.JArray[jpype.JByte], monitor: ghidra.util.task.TaskMonitor):
        """
        Updates the digest using the specified array of bytes.
        
        :param jpype.JArray[jpype.JByte] input: the array of bytes
        :param ghidra.util.task.TaskMonitor monitor: the monitor to check during loops
        :raises CancelledException:
        """

    @typing.overload
    def update(self, input: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Updates the digest using the specified array of bytes, starting at the
        specified offset (and for the specified length).
        
        :param jpype.JArray[jpype.JByte] input: the array of bytes
        :param jpype.JInt or int offset: the offset to start from in the array of bytes
        :param jpype.JInt or int len: the number of bytes to use, starting at offset
        :param ghidra.util.task.TaskMonitor monitor: the monitor to check during loops
        :raises CancelledException:
        """

    @property
    def digestLength(self) -> jpype.JInt:
        ...

    @property
    def algorithm(self) -> java.lang.String:
        ...


class MessageDigestFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def createDigest(self) -> MessageDigest:
        ...


class FNV1a32MessageDigest(AbstractMessageDigest):

    class_: typing.ClassVar[java.lang.Class]
    FNV_32_OFFSET_BASIS: typing.Final = -2128831035
    FNV_32_PRIME: typing.Final = 16777619

    @typing.overload
    def __init__(self, initialVector: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...


class FNV1a64MessageDigest(AbstractMessageDigest):

    class_: typing.ClassVar[java.lang.Class]
    FNV_64_OFFSET_BASIS: typing.Final = -3750763034362895579
    FNV_64_PRIME: typing.Final = 1099511628211

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, initialVector: typing.Union[jpype.JLong, int]):
        ...


class AbstractMessageDigest(MessageDigest):

    class_: typing.ClassVar[java.lang.Class]
    algorithm: typing.Final[java.lang.String]
    digestLength: typing.Final[jpype.JInt]

    @typing.overload
    def update(self, input: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        """
        You REALLY want to override this method.
        """

    @typing.overload
    def update(self, input: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        You REALLY want to override this method too.
        
        :raises CancelledException:
        """



__all__ = ["FNV1a32MessageDigestFactory", "SimpleCRC32", "FNV1a64MessageDigestFactory", "MessageDigest", "MessageDigestFactory", "FNV1a32MessageDigest", "FNV1a64MessageDigest", "AbstractMessageDigest"]
