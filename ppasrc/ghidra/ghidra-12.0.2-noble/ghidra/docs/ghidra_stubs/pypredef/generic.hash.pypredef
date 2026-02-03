from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


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


class HashUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MD5_ALGORITHM: typing.ClassVar[java.lang.String]
    SHA256_ALGORITHM: typing.ClassVar[java.lang.String]
    SALT_LENGTH: typing.Final = 4
    MD5_UNSALTED_HASH_LENGTH: typing.Final = 32
    MD5_SALTED_HASH_LENGTH: typing.Final = 36
    SHA256_UNSALTED_HASH_LENGTH: typing.Final = 64
    SHA256_SALTED_HASH_LENGTH: typing.Final = 68

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate hash in a hex character representation
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: hex hash value in text format
        :rtype: jpype.JArray[jpype.JChar]
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], in_: java.io.InputStream) -> str:
        """
        Generate message digest hash for specified input stream.  Stream will be read
        until EOF is reached.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param java.io.InputStream in: input stream
        :return: message digest hash
        :rtype: str
        :raises IOException: if reading input stream produces an error
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], file: jpype.protocol.SupportsPath) -> str:
        """
        Generate message digest hash for specified file contents.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.protocol.SupportsPath file: file to be read
        :return: message digest hash
        :rtype: str
        :raises IOException: if opening or reading file produces an error
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], values: java.util.List[java.lang.String]) -> str:
        """
        Generate combined message digest hash for all values in the 
        specified values list.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param java.util.List[java.lang.String] values: list of text strings
        :return: message digest hash
        :rtype: str
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], values: jpype.JArray[jpype.JByte]) -> str:
        """
        Generate combined message digest hash for the bytes in the specified array.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JByte] values: array of bytes to hash
        :return: message digest hash
        :rtype: str
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getSaltedHash(algorithm: typing.Union[java.lang.String, str], salt: jpype.JArray[jpype.JChar], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate salted hash for specified message.  Supplied salt is 
        returned as prefix to returned hash.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JChar] salt: digest salt (use empty string for no salt)
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: salted hash using specified salt which is
        returned as a prefix to the hash
        :rtype: jpype.JArray[jpype.JChar]
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getSaltedHash(algorithm: typing.Union[java.lang.String, str], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate salted hash for specified message using random salt.  
        First 4-characters of returned hash correspond to the salt data.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: salted hash using randomly generated salt which is
        returned as a prefix to the hash
        :rtype: jpype.JArray[jpype.JChar]
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    def hexDump(data: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JChar]:
        """
        Convert binary data to a sequence of hex characters.
        
        :param jpype.JArray[jpype.JByte] data: binary data
        :return: hex character representation of data
        :rtype: jpype.JArray[jpype.JChar]
        """


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



__all__ = ["FNV1a32MessageDigestFactory", "SimpleCRC32", "FNV1a64MessageDigestFactory", "MessageDigest", "MessageDigestFactory", "FNV1a32MessageDigest", "FNV1a64MessageDigest", "HashUtilities", "AbstractMessageDigest"]
