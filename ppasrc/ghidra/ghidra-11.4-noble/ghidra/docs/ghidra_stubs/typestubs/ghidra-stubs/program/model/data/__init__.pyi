from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import generic.jar
import ghidra
import ghidra.app.merge
import ghidra.docking.settings
import ghidra.framework.model
import ghidra.program.database
import ghidra.program.database.data
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.exception
import ghidra.util.filechooser
import ghidra.util.task
import ghidra.xml
import java.awt.datatransfer # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.nio # type: ignore
import java.nio.charset # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.imageio.stream # type: ignore
import javax.sound.midi # type: ignore
import javax.sound.sampled # type: ignore
import javax.swing # type: ignore
import utility.function


E = typing.TypeVar("E")
T = typing.TypeVar("T")


class Float2DataType(AbstractFloatDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Float2DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Undefined3DataType(Undefined):
    """
    Provides an implementation of a byte that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined3DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Constructs a new Undefined1 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class WideChar16DataType(BuiltIn, ArrayStringable, DataTypeWithCharset):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[WideChar16DataType]
    """
    A statically defined WideCharDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class GIFResource(java.lang.Object):
    """
    Class for determining the size of a GIF image. It loads just enough of the GIF information to 
    follow the data block links and read the bytes until the terminator is hit.  The amount of
    bytes read indicate the number of bytes the GIF data type is consume.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buf: ghidra.program.model.mem.MemBuffer):
        ...

    def getLength(self) -> int:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class AlignmentDataType(BuiltIn, Dynamic):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class StringDataInstance(java.lang.Object):
    """
    Represents an instance of a string in a :obj:`MemBuffer`.
     
    
    This class handles all the details of detecting a terminated string's length, converting the
    bytes in the membuffer into a java native String, and converting the raw String into a formatted
    human-readable version, according to the various :obj:`SettingsDefinition`s attached to the
    string data location.
    """

    class StaticStringInstance(StringDataInstance):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, fakeStr: typing.Union[java.lang.String, str], fakeLen: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class AdjustedCharsetInfo(java.lang.Object):
        """
        Simple class to hold tuple of (detected_charset_name,bom_bytes_to_skip,detected_endianness).
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, charsetName: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    NULL_INSTANCE: typing.Final[StringDataInstance]
    """
    A :obj:`StringDataInstance` that represents a non-existent string.
     
    
    Methods on this instance generally return null.
    """

    MAX_STRING_LENGTH: typing.Final = 16384
    DEFAULT_CHARSET_NAME: typing.Final = "US-ASCII"
    UNKNOWN: typing.Final = "??"
    UNKNOWN_DOT_DOT_DOT: typing.Final = "??..."

    @typing.overload
    def __init__(self, dataType: DataType, settings: ghidra.docking.settings.Settings, buf: ghidra.program.model.mem.MemBuffer, length: typing.Union[jpype.JInt, int]):
        """
        Creates a string instance using the data in the :obj:`MemBuffer` and the settings pulled
        from the :obj:`string data type <AbstractStringDataType>`.
        
        :param DataType dataType: :obj:`DataType` of the string, either a :obj:`AbstractStringDataType`
                    derived type or an :obj:`ArrayStringable` element-of-char-array type.
        :param ghidra.docking.settings.Settings settings: :obj:`Settings` attached to the data location.
        :param ghidra.program.model.mem.MemBuffer buf: :obj:`MemBuffer` containing the data.
        :param jpype.JInt or int length: Length passed from the caller to the datatype. -1 indicates a 'probe' trying to
                    detect the length of an unknown string, otherwise it will be the length of the
                    containing field of the data instance.
        """

    @typing.overload
    def __init__(self, dataType: DataType, settings: ghidra.docking.settings.Settings, buf: ghidra.program.model.mem.MemBuffer, length: typing.Union[jpype.JInt, int], isArrayElement: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a string instance using the data in the :obj:`MemBuffer` and the settings pulled
        from the :obj:`string data type <AbstractStringDataType>`.
        
        :param DataType dataType: :obj:`DataType` of the string, either a :obj:`AbstractStringDataType`
                    derived type or an :obj:`ArrayStringable` element-of-char-array type.
        :param ghidra.docking.settings.Settings settings: :obj:`Settings` attached to the data location.
        :param ghidra.program.model.mem.MemBuffer buf: :obj:`MemBuffer` containing the data.
        :param jpype.JInt or int length: Length passed from the caller to the datatype. -1 indicates a 'probe' trying to
                    detect the length of an unknown string, otherwise it will be the length of the
                    containing field of the data instance.
        :param jpype.JBoolean or bool isArrayElement: boolean flag, true indicates that the specified dataType is an element
                    in an array (ie. char[] vs. just a plain char), causing the string layout to be
                    forced to :obj:`StringLayoutEnum.NULL_TERMINATED_BOUNDED`
        """

    def encodeReplacementFromCharRepresentation(self, repr: java.lang.CharSequence) -> jpype.JArray[jpype.JByte]:
        """
        Parse and encode a single character from its representation to replace the current value
        
        :param java.lang.CharSequence repr: the representation of a single character
        :return: the encoded value
        :rtype: jpype.JArray[jpype.JByte]
        :raises StringParseException: if the representation could not be parsed
        :raises UnmappableCharacterException: if a character could not be encoded
        :raises MalformedInputException: if the input contains invalid character sequences
        """

    def encodeReplacementFromCharValue(self, value: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JByte]:
        """
        Encode a single character to replace the current value
        
        :param jpype.JArray[jpype.JChar] value: a single code point to encode
        :return: the encoded value
        :rtype: jpype.JArray[jpype.JByte]
        :raises CharacterCodingException: if the character could not be encoded
        """

    def encodeReplacementFromStringRepresentation(self, repr: java.lang.CharSequence) -> jpype.JArray[jpype.JByte]:
        """
        Parse and encode a string from its representation to replace the current value
        
        :param java.lang.CharSequence repr: the representation of the string
        :return: the encoded value
        :rtype: jpype.JArray[jpype.JByte]
        :raises StringParseException: if the representation could not be parsed
        :raises UnmappableCharacterException: if a character could not be encoded
        :raises MalformedInputException: if the input contains invalid character sequences
        """

    def encodeReplacementFromStringValue(self, value: java.lang.CharSequence) -> jpype.JArray[jpype.JByte]:
        """
        Encode a string to replace the current value
        
        :param java.lang.CharSequence value: the value to encode
        :return: the encoded value
        :rtype: jpype.JArray[jpype.JByte]
        :raises CharacterCodingException: if a character could not be encoded
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the :obj:`MemBuffer`.
        
        :return: :obj:`Address` of the MemBuffer.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getByteOffcut(self, byteOffset: typing.Union[jpype.JInt, int]) -> StringDataInstance:
        """
        Returns a new :obj:`StringDataInstance` that points to the string characters that start at
        ``byteOffset`` from the start of this instance.
         
        
        If the requested offset is not valid, StringDataInstance.NULL_INSTANCE is returned.
        
        :param jpype.JInt or int byteOffset: number of bytes from start of data instance to start new instance.
        :return: new StringDataInstance, or ``StringDataInstance.NULL_INSTANCE`` if 
        offset not valid.
        :rtype: StringDataInstance
        """

    def getCharOffcut(self, offsetChars: typing.Union[jpype.JInt, int]) -> StringDataInstance:
        """
        Create a new :obj:`StringDataInstance` that points to a portion of this instance, starting
        at a character offset (whereever that may be) into the data.
        
        :param jpype.JInt or int offsetChars: number of characters from the beginning of the string to start the new
                    StringDataInstance.
        :return: new :obj:`StringDataInstance` pointing to a subset of characters, or the
                ``this`` instance if there was an error.
        :rtype: StringDataInstance
        """

    @staticmethod
    @typing.overload
    def getCharRepresentation(dataType: DataType, bytes: jpype.JArray[jpype.JByte], settings: ghidra.docking.settings.Settings) -> str:
        """
        Returns a string representation of the character(s) contained in the byte array, suitable for
        display as a single character, or as a sequence of characters.
        
        :param DataType dataType: the :obj:`DataType` of the element containing the bytes (most likely a
                    ByteDataType)
        :param jpype.JArray[jpype.JByte] bytes: the big-endian ordered bytes to convert to a char representation
        :param ghidra.docking.settings.Settings settings: the :obj:`Settings` object for the location where the bytes came from, or
                    null
        :return: formatted string (typically with quotes around the contents): single character: 'a',
                multiple characters: "a\x12bc"
        :rtype: str
        """

    @typing.overload
    def getCharRepresentation(self) -> str:
        """
        Convert a char value (or sequence of char values) in memory into its canonical unicode
        representation, using attached charset and encoding information.
        
        :return: String containing the representation of the char.
        :rtype: str
        """

    def getCharsetName(self) -> str:
        """
        Returns the string name of the charset.
        
        :return: string charset name
        :rtype: str
        """

    def getDataLength(self) -> int:
        """
        Returns the length of this string's data, in bytes.
        
        :return: number of bytes in this string.
        :rtype: int
        """

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getLabel(self, prefixStr: typing.Union[java.lang.String, str], abbrevPrefixStr: typing.Union[java.lang.String, str], defaultStr: typing.Union[java.lang.String, str], options: DataTypeDisplayOptions) -> str:
        ...

    def getOffcutLabelString(self, prefixStr: typing.Union[java.lang.String, str], abbrevPrefixStr: typing.Union[java.lang.String, str], defaultStr: typing.Union[java.lang.String, str], options: DataTypeDisplayOptions, byteOffset: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getStringDataInstance(data: ghidra.program.model.listing.Data) -> StringDataInstance:
        """
        Returns a new :obj:`StringDataInstance` using the bytes in the data codeunit.
        
        :param ghidra.program.model.listing.Data data: :obj:`Data` item
        :return: new :obj:`StringDataInstance`, never NULL. See :obj:`.NULL_INSTANCE`.
        :rtype: StringDataInstance
        """

    @staticmethod
    @typing.overload
    def getStringDataInstance(dataType: DataType, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> StringDataInstance:
        """
        Returns a new :obj:`StringDataInstance` using the bytes in the MemBuffer.
        
        :param DataType dataType: :obj:`DataType` of the bytes in the buffer.
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object
        :param jpype.JInt or int length: the length of the data.
        :return: new :obj:`StringDataInstance`, never NULL. See :obj:`.NULL_INSTANCE`.
        :rtype: StringDataInstance
        """

    def getStringDataTypeGuess(self) -> DataType:
        """
        Maps a :obj:`StringDataInstance` (this type) to the String DataType that best can handle
        this type of data.
         
        
        I dare myself to type Type one more time.
        
        :return: :obj:`DataType`, defaulting to :obj:`StringDataType` if no direct match found.
        :rtype: DataType
        """

    def getStringLength(self) -> int:
        """
        Returns the length, in bytes, of the string data object contained in the :obj:`MemBuffer`,
        or -1 if the length could not be determined.
         
        
        This is not the same as the number of characters in the string, or the number of bytes
        occupied by the characters. For instance, pascal strings have a 1 or 2 byte length field that
        increases the size of the string data object beyond the characters in the string, and null
        terminated strings have don't include the null character, but its presence is included in the
        size of the string object.
         
        
        For length-specified string data types that do not use null-terminators and with a known data
        instance length (ie. not a probe), this method just returns the value specified in the
        constructor ``length`` parameter, otherwise a null-terminator is searched for.
         
        
        When searching for a null-terminator, the constructor ``length`` parameter will be
        respected or ignored depending on the :obj:`StringLayoutEnum`.
         
        
        When the length parameter is ignored (ie. "unbounded" searching), the search is limited to
        :obj:`.MAX_STRING_LENGTH` bytes.
         
        
        The MemBuffer's endian'ness is used to determine which end of the padded character field
        contains our n-bit character which will be tested for null-ness. (not the endian'ness of the
        character set name - ie. "UTF-16BE")
        
        :return: length of the string (INCLUDING null term if null term probe), in bytes, or -1 if
                no terminator found.
        :rtype: int
        """

    @typing.overload
    def getStringRepresentation(self) -> str:
        """
        Returns a formatted version of the string returned by :meth:`getStringValue() <.getStringValue>`.
         
        
        The resulting string will be formatted with quotes around the parts that contain plain ASCII
        alpha characters (and simple escape sequences), and out-of-range byte-ish values listed as
        comma separated hex-encoded values:
         
        
        Example (quotes are part of result): ``"Test\tstring",01,02,"Second\npart",00``
        
        :return: formatted String, or the translated value if present and the "show translated"
        setting is enabled for this string's location
        :rtype: str
        """

    @typing.overload
    def getStringRepresentation(self, originalOrTranslated: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a formatted version of the string returned by :meth:`getStringValue() <.getStringValue>`.
         
        
        The resulting string will be formatted with quotes around the parts that contain plain ASCII
        alpha characters (and simple escape sequences), and out-of-range byte-ish values listed as
        comma separated hex-encoded values:
         
        
        Example (quotes are part of result): ``"Test\tstring",01,02,"Second\npart",00``
        
        :param jpype.JBoolean or bool originalOrTranslated: boolean flag, if true returns the representation of the
        string value, if false returns the representation of the translated value
        :return: formatted String
        :rtype: str
        """

    def getStringValue(self) -> str:
        """
        Returns the string contained in the specified :obj:`MemBuffer`, or null if all the bytes of
        the string could not be read.
         
        
        This method deals in characters of size :obj:`.charSize`, that might be
        :obj:`padded <.paddedCharSize>` to a larger size. The raw n-byte characters are converted into
        a Java String using a Java :obj:`Charset` or by using a custom Ghidra conversion. (see
        convertBytesToStringCustomCharset)
         
        
        The MemBuffer's endian'ness is used to determine which end of the :obj:`padded  <.paddedCharSize>` field contains our :obj:`.charSize` character bytes which will be used to create
        the java String.
        
        :return: String containing the characters in buf or null if unable to read all ``length``
                bytes from the membuffer.
        :rtype: str
        """

    def getTranslatedValue(self) -> str:
        """
        Returns the value of the stored
        :meth:`translated settings <TranslationSettingsDefinition.getTranslatedValue>`
        string.
        
        :return: previously translated string.
        :rtype: str
        """

    def hasTranslatedValue(self) -> bool:
        """
        Returns true if this string has a translated value that could
        be displayed.
        
        :return: boolean true if translated value is present, false if no
        value is present
        :rtype: bool
        """

    @staticmethod
    def isChar(data: ghidra.program.model.listing.Data) -> bool:
        """
        Returns true if the :obj:`Data` instance is one of the many 'char' data types.
        
        :param ghidra.program.model.listing.Data data: :obj:`Data` instance to test, null ok
        :return: boolean true if char data
        :rtype: bool
        """

    def isMissingNullTerminator(self) -> bool:
        """
        Returns true if the string should have a trailing NULL character and doesn't.
        
        :return: boolean true if the trailing NULL character is missing, false if string type doesn't
                need a trailing NULL character or if it is present.
        :rtype: bool
        """

    def isShowTranslation(self) -> bool:
        """
        Returns true if the user should be shown the translated value of the string instead of the
        real value.
        
        :return: boolean true if should show previously translated value.
        :rtype: bool
        """

    @staticmethod
    def isString(data: ghidra.program.model.listing.Data) -> bool:
        """
        Returns true if the :obj:`Data` instance is a 'string'.
        
        :param ghidra.program.model.listing.Data data: :obj:`Data` instance to test, null ok.
        :return: boolean true if string data.
        :rtype: bool
        """

    @staticmethod
    def isStringDataType(dt: DataType) -> bool:
        """
        Returns true if the specified :obj:`DataType` is (or could be) a string.
         
        
        Arrays of char-like elements (see :obj:`ArrayStringable`) are treated as string data types.
        The actual data instance needs to be inspected to determine if the array is an actual string.
        
        :param DataType dt: DataType to test
        :return: boolean true if data type is or could be a string
        :rtype: bool
        """

    @staticmethod
    def makeStringLabel(prefixStr: typing.Union[java.lang.String, str], str: typing.Union[java.lang.String, str], options: DataTypeDisplayOptions) -> str:
        """
        Formats a string value so that it is in the form of a symbol label.
        
        :param java.lang.String or str prefixStr: data type prefix, see :meth:`AbstractStringDataType.getDefaultLabelPrefix() <AbstractStringDataType.getDefaultLabelPrefix>`
        :param java.lang.String or str str: string value
        :param DataTypeDisplayOptions options: display options
        :return: string, suitable to be used as a label
        :rtype: str
        """

    @property
    def charOffcut(self) -> StringDataInstance:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def dataLength(self) -> jpype.JInt:
        ...

    @property
    def translatedValue(self) -> java.lang.String:
        ...

    @property
    def addressRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def stringDataTypeGuess(self) -> DataType:
        ...

    @property
    def charRepresentation(self) -> java.lang.String:
        ...

    @property
    def missingNullTerminator(self) -> jpype.JBoolean:
        ...

    @property
    def stringValue(self) -> java.lang.String:
        ...

    @property
    def byteOffcut(self) -> StringDataInstance:
        ...

    @property
    def showTranslation(self) -> jpype.JBoolean:
        ...

    @property
    def stringRepresentation(self) -> java.lang.String:
        ...

    @property
    def stringLength(self) -> jpype.JInt:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def charsetName(self) -> java.lang.String:
        ...


class CharsetSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    :obj:`SettingsDefinition` for setting the charset of a string instance.
      
    
    Charsets control how raw bytes are converted to native java String instances.
      
    
    :obj:`CharsetInfo` controls the list of character sets that the user is shown.
    """

    class_: typing.ClassVar[java.lang.Class]
    CHARSET: typing.Final[CharsetSettingsDefinition]

    def getCharset(self, settings: ghidra.docking.settings.Settings, defaultValue: typing.Union[java.lang.String, str]) -> str:
        ...

    def setCharset(self, settings: ghidra.docking.settings.Settings, charset: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def setStaticEncodingMappingValues(mappingValues: collections.abc.Mapping):
        """
        Sets a static lookup table that maps from old deprecated (language,encoding) index
        values to a charset name.
         
        
        The old index values were used by old-style MBCS data type.
        
        :param collections.abc.Mapping mappingValues: map of language_id to list of charset names.
        """


class Undefined7DataType(Undefined):
    """
    Provides an implementation of a byte that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined7DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Constructs a new Undefined1 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class Complex32DataType(AbstractComplexDataType):
    """
    Provides a definition of a ``complex`` built-in data type consisting of two 128-bit floating point
    numbers in the IEEE 754 double precision format.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Complex32DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class IconResourceDataType(BitmapResourceDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class PngDataType(BuiltIn, Dynamic, Resource):

    @typing.type_check_only
    class PngDataImage(DataImage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.ClassVar[jpype.JArray[jpype.JByte]]
    MASK: typing.ClassVar[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class AbstractPointerTypedefBuiltIn(BuiltIn, TypeDef):
    """
    ``AbstractPointerTypedefDataType`` provides an abstract :obj:`BuiltIn` datatype 
    implementation for a pointer-typedef datatype.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getUniversalID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def universalID(self) -> ghidra.util.UniversalID:
        ...


class WideCharDataType(BuiltIn, ArrayStringable, DataTypeWithCharset):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[WideCharDataType]
    """
    A statically defined WideCharDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class AlignedStructureInspector(AlignedStructurePacker):
    """
    ``AlignedStructureInspector`` provides a simple instance of a structure 
    member container used to perform alignment operations without forcing modification
    of the actual structure.
    """

    @typing.type_check_only
    class ReadOnlyComponentWrapper(InternalDataTypeComponent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def packComponents(structure: StructureInternal) -> AlignedStructurePacker.StructurePackResult:
        """
        Perform structure component packing in a read-only fashion primarily
        for the purpose of computing external alignment for existing structures.
        
        :param StructureInternal structure: 
        :return: aligned packing result
        :rtype: AlignedStructurePacker.StructurePackResult
        """


class AudioPlayer(Playable, javax.sound.sampled.LineListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        ...


class InvalidDataTypeException(ghidra.util.exception.UsrException):
    """
    Exception thrown if a data type is not valid for the operation being performed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dt: DataType):
        """
        Constructor
        
        :param DataType dt: the data type that is invalid for the operation being performed.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: detailed message explaining exception
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Construct a new InvalidDataTypeException with the given message and cause
        
        :param java.lang.String or str msg: the exception message
        :param java.lang.Throwable cause: the exception cause
        """


class Pointer56DataType(PointerDataType):
    """
    Pointer56 is really a factory for generating 7-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer56DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class UnsignedInteger7DataType(AbstractUnsignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedInteger7DataType]
    """
    A statically defined UnsignedInteger7DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class BadDataType(BuiltIn, Dynamic):
    """
    Provides an implementation of a data type that is not valid (bad) as it is used in
    the program. For example, the class for the underlying data type may no longer be 
    available or the data type may not fit where it has been placed in the program.
      
     
    This field is not meant to be loaded by the :obj:`ClassSearcher`, hence the X in the name.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[BadDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class StructureDataType(CompositeDataTypeImpl, StructureInternal):
    """
    Basic implementation of the structure data type.
    NOTES: 
     
    * Implementation is not thread safe when being modified.
    * For a structure to treated as having a zero-length (see :meth:`isZeroLength() <.isZeroLength>`) it
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        """
        Construct a new structure with the given name and length. The root category will be used.
        NOTE: A constructor form which accepts a :obj:`DataTypeManager` should be used when possible
        since there may be performance benefits during datatype resolution.
        
        :param java.lang.String or str name: the name of the new structure
        :param jpype.JInt or int length: the initial size of the structure in bytes. If 0 is specified the structure
                    will report its length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Construct a new structure with the given name, length and datatype manager which conveys data
        organization. The root category will be used.
        
        :param java.lang.String or str name: the name of the new structure
        :param jpype.JInt or int length: the initial size of the structure in bytes. If 0 is specified the structure
                    will report its length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null. Also, the
                    data type manager may not yet contain this actual data type.
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        """
        Construct a new structure with the given name and length within the specified categry path.
        NOTE: A constructor form which accepts a :obj:`DataTypeManager` should be used when possible
        since there may be performance benefits during datatype resolution.
        
        :param CategoryPath path: the category path indicating where this data type is located.
        :param java.lang.String or str name: the name of the new structure
        :param jpype.JInt or int length: the initial size of the structure in bytes. If 0 is specified the structure
                    will report its length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Construct a new structure with the given name, length and datatype manager within the
        specified categry path.
        
        :param CategoryPath path: the category path indicating where this data type is located.
        :param java.lang.String or str name: the name of the new structure
        :param jpype.JInt or int length: the initial size of the structure in bytes. If 0 is specified the structure
                    will report its length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null. Also, the
                    data type manager may not yet contain this actual data type.
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], universalID: ghidra.util.UniversalID, sourceArchive: SourceArchive, lastChangeTime: typing.Union[jpype.JLong, int], lastChangeTimeInSourceArchive: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        """
        Construct a new structure with the given name and length
        
        :param CategoryPath path: the category path indicating where this data type is located.
        :param java.lang.String or str name: the name of the new structure
        :param jpype.JInt or int length: the initial size of the structure in bytes. If 0 is specified the structure
                    will report its length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        :param ghidra.util.UniversalID universalID: the id for the data type
        :param SourceArchive sourceArchive: the source archive for this data type
        :param jpype.JLong or int lastChangeTime: the last time this data type was changed
        :param jpype.JLong or int lastChangeTimeInSourceArchive: the last time this data type was changed in its source
                    archive.
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null. Also, the
                    data type manager may not yet contain this actual data type.
        """

    def clone(self, dtm: DataTypeManager) -> StructureDataType:
        """
        Create cloned structure for target dtm preserving source archive information. WARNING!
        cloning non-packed structures which contain bitfields can produce invalid results when
        switching endianness due to the differences in packing order.
        
        :param DataTypeManager dtm: target data type manager
        :return: cloned structure
        :rtype: StructureDataType
        """

    def copy(self, dtm: DataTypeManager) -> DataType:
        """
        Create copy of structure for target dtm (source archive information is discarded). 
         
        
        WARNING! copying non-packed structures which contain bitfields can produce invalid results when
        switching endianness due to the differences in packing order.
        
        :param DataTypeManager dtm: target data type manager
        :return: cloned structure
        :rtype: DataType
        """

    def replaceWith(self, dataType: DataType):
        """
        Replaces the internal components of this structure with components of the given structure
        including packing and alignment settings.
        
        :param DataType dataType: the structure to get the component information from.
        :raises IllegalArgumentException: if any of the component data types are not allowed to
                    replace a component in this composite data type. For example, suppose dt1
                    contains dt2. Therefore it is not valid to replace a dt2 component with dt1 since
                    this would cause a cyclic dependency.
        """


class AddressSpaceSettingsDefinition(ghidra.docking.settings.StringSettingsDefinition, TypeDefSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[AddressSpaceSettingsDefinition]


class TerminatedStringDataType(AbstractStringDataType):
    """
    A null-terminated string :obj:`DataType` with a user setable
    :obj:`charset <CharsetSettingsDefinition>` (default ASCII).
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[TerminatedStringDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class WordDataType(AbstractUnsignedIntegerDataType):
    """
    Provides a basic implementation of a word datatype
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[WordDataType]
    """
    A statically defined WordDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class ProgramBasedDataTypeManager(DomainFileBasedDataTypeManager):
    """
    Extends DataTypeManager to include methods specific to a data type manager for
    a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearAllSettings(self, data: ghidra.program.model.listing.Data):
        """
        Clear all settings for the given data.
        
        :param ghidra.program.model.listing.Data data: data code unit
        """

    def clearSetting(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Clear the specified setting for the given data
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: settings name
        :return: true if the settings were cleared
        :rtype: bool
        """

    def deleteAddressRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all settings in the range
        
        :param ghidra.program.model.address.Address startAddr: the first address in the range.
        :param ghidra.program.model.address.Address endAddr: the last address in the range.
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor
        :raises CancelledException: if the user cancelled the operation.
        """

    def getInstanceSettingsNames(self, data: ghidra.program.model.listing.Data) -> jpype.JArray[java.lang.String]:
        """
        Returns all the instance Settings names used for the specified data
        
        :param ghidra.program.model.listing.Data data: data code unit
        :return: the names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getLongSettingsValue(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str]) -> int:
        """
        Get the long value for data instance settings.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: settings name
        :return: null if the named setting was not found
        :rtype: int
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program instance associated with this datatype manager
        
        :return: program instance associated with this datatype manager
        :rtype: ghidra.program.model.listing.Program
        """

    def getSettings(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Gets the value for data instance settings in Object form.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: the name of settings.
        :return: the settings object
        :rtype: java.lang.Object
        """

    def getStringSettingsValue(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str]) -> str:
        """
        Get the String value for data instance settings.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: settings name
        :return: null if the named setting was not found
        :rtype: str
        """

    def isChangeAllowed(self, data: ghidra.program.model.listing.Data, settingsDefinition: ghidra.docking.settings.SettingsDefinition) -> bool:
        """
        Determine if a settings change is permitted for the specified settingsDefinition.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param ghidra.docking.settings.SettingsDefinition settingsDefinition: settings definition
        :return: true if change permitted else false
        :rtype: bool
        """

    def isEmptySetting(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Returns true if no settings are set for the given data
        
        :param ghidra.program.model.listing.Data data: data code unit
        :return: true if not settings
        :rtype: bool
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move the settings in the range to the new start address
        
        :param ghidra.program.model.address.Address fromAddr: start address from where to move
        :param ghidra.program.model.address.Address toAddr: new Address to move to
        :param jpype.JLong or int length: number of addresses to move
        :param ghidra.util.task.TaskMonitor monitor: progress monitor
        :raises CancelledException: if the operation was cancelled
        """

    def setLongSettingsValue(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]) -> bool:
        """
        Set the long value for data instance settings.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: settings name
        :param jpype.JLong or int value: value of setting
        :return: true if the settings actually changed
        :rtype: bool
        """

    def setSettings(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str], value: java.lang.Object) -> bool:
        """
        Set the Object value for data instance settings.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: the name of the settings
        :param java.lang.Object value: the value for the settings, must be either a String, byte[]
                        or Long
        :return: true if the settings were updated
        :rtype: bool
        """

    def setStringSettingsValue(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> bool:
        """
        Set the string value for data instance settings.
        
        :param ghidra.program.model.listing.Data data: data code unit
        :param java.lang.String or str name: settings name
        :param java.lang.String or str value: value of setting
        :return: true if the settings actually changed
        :rtype: bool
        """

    @property
    def emptySetting(self) -> jpype.JBoolean:
        ...

    @property
    def instanceSettingsNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class UnsignedShortDataType(AbstractUnsignedIntegerDataType):
    """
    Basic implementation for a Short Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedShortDataType]
    """
    A statically defined UnsignedShortDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class EndianSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    SettingsDefinition for endianness
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[EndianSettingsDefinition]
    ENDIAN: typing.Final[EndianSettingsDefinition]
    DEFAULT: typing.Final = 0
    LITTLE: typing.Final = 1
    BIG: typing.Final = 2

    def getEndianness(self, settings: ghidra.docking.settings.Settings, defaultValue: ghidra.program.model.lang.Endian) -> ghidra.program.model.lang.Endian:
        ...

    def isBigEndian(self, settings: ghidra.docking.settings.Settings, buf: ghidra.program.model.mem.MemBuffer) -> bool:
        """
        Returns the endianness settings.  First looks in settings, then defaultSettings
        and finally returns a default value if the first two have no value for this definition.
        
        :param ghidra.docking.settings.Settings settings: the instance settings to search for the value
        :param ghidra.program.model.mem.MemBuffer buf: the data context
        :return: a boolean value for the endianness setting
        :rtype: bool
        """

    def setBigEndian(self, settings: ghidra.docking.settings.Settings, isBigEndian: typing.Union[jpype.JBoolean, bool]):
        ...


class CompositeInternal(Composite):
    """
    Interface for common methods in Structure and Union
    """

    class ComponentComparator(java.util.Comparator[DataTypeComponent]):
        """
        ``ComponentComparator`` provides ability to compare two DataTypeComponent objects
        based upon their ordinal. Intended to be used to sort components based upon ordinal.
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[CompositeInternal.ComponentComparator]

        def __init__(self):
            ...


    class OffsetComparator(java.util.Comparator[java.lang.Object]):
        """
        ``OffsetComparator`` provides ability to compare an Integer offset with a
        DataTypeComponent object. The offset will be consider equal (0) if the component contains the
        offset.
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[CompositeInternal.OffsetComparator]

        def __init__(self):
            ...


    class OrdinalComparator(java.util.Comparator[java.lang.Object]):
        """
        ``OrdinalComparator`` provides ability to compare an Integer ordinal with a
        DataTypeComponent object. The ordinal will be consider equal (0) if the component corresponds
        to the specified ordinal.
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[CompositeInternal.OrdinalComparator]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    ALIGN_NAME: typing.Final = "aligned"
    PACKING_NAME: typing.Final = "pack"
    DISABLED_PACKING_NAME: typing.Final = "disabled"
    DEFAULT_PACKING_NAME: typing.Final = ""
    DEFAULT_PACKING: typing.Final = 0
    """
    The stored packing value which corresponds to a composite that will automatically pack
    based upon the alignment requirements of its components.  A positive pack value will
    also pack in a similar fashion but will use the pack value as a maximum alignment
    for each component.
    See :obj:`.getStoredPackingValue`.
    """

    NO_PACKING: typing.Final = -1
    """
    The stored packing value which corresponds to a composite whose packing has been disabled.
    In the case of structures this will permit explicit component placement by
    offset within the structure and undefined filler components will be used.
    This is the initial state of all newly instantiated structures.
    See :meth:`getStoredPackingValue() <.getStoredPackingValue>`.
    """

    DEFAULT_ALIGNMENT: typing.Final = 0
    """
    The stored minimum alignment value which indicates the default alignment
    should be used based upon the packing and component alignment requirements.
    See :obj:`.getStoredMinimumAlignment`.
    """

    MACHINE_ALIGNMENT: typing.Final = -1
    """
    The stored minimum alignment value which indicates the machine alignment
    should be used as the minimum alignment (as defined by the current
    :meth:`DataOrganization.getMachineAlignment() <DataOrganization.getMachineAlignment>`).
    See :meth:`getStoredMinimumAlignment() <.getStoredMinimumAlignment>`.
    """


    @staticmethod
    def getAlignmentAndPackingString(composite: Composite) -> str:
        ...

    @staticmethod
    def getMinAlignmentString(composite: Composite) -> str:
        ...

    @staticmethod
    def getPackingString(composite: Composite) -> str:
        ...

    def getStoredMinimumAlignment(self) -> int:
        """
        Get the minimum alignment setting for this Composite which contributes
        to the actual computed alignment value (see :meth:`getAlignment() <.getAlignment>`.
        
        :return: the minimum alignment setting for this Composite or a reserved value to indicate
        either :obj:`.DEFAULT_ALIGNMENT` or :obj:`.MACHINE_ALIGNMENT`.
        :rtype: int
        """

    def getStoredPackingValue(self) -> int:
        """
        Gets the current packing value (typically a power of 2).  Other special values
        which may be returned include 0 and -1.
        
        :return: the current positive packing value, 0 or -1.
        :rtype: int
        """

    @staticmethod
    def toString(composite: Composite) -> str:
        """
        Dump composite and its components for use in :meth:`Object.toString() <Object.toString>` representation.
        
        :param Composite composite: composite instance to be dumped
        :return: formatted dump as string
        :rtype: str
        """

    @property
    def storedMinimumAlignment(self) -> jpype.JInt:
        ...

    @property
    def storedPackingValue(self) -> jpype.JInt:
        ...


class UnsignedInteger3DataType(AbstractUnsignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedInteger3DataType]
    """
    A statically defined UnsignedInteger3DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class BuiltInDataTypeManager(StandAloneDataTypeManager):
    """
    Data type manager for built in types that do not live anywhere except
    in memory.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getDataTypeManager() -> BuiltInDataTypeManager:
        """
        Returns shared instance of built-in data type manager.
        
        :return: the manager
        :rtype: BuiltInDataTypeManager
        """


class ProjectArchiveBasedDataTypeManager(DomainFileBasedDataTypeManager):
    """
    Extends DataTypeManager to provide methods specific to project data type archives.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeComponentImpl(InternalDataTypeComponent, java.io.Serializable):
    """
    Basic implementation of a DataTypeComponent
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataType: DataType, parent: CompositeDataTypeImpl, length: typing.Union[jpype.JInt, int], ordinal: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], fieldName: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Create a new DataTypeComponent
        
        :param DataType dataType: the dataType for this component
        :param CompositeDataTypeImpl parent: the dataType that this component belongs to
        :param jpype.JInt or int length: the length of the dataType in this component.
        :param jpype.JInt or int ordinal: the index within its parent.
        :param jpype.JInt or int offset: the byte offset within the parent
        :param java.lang.String or str fieldName: the name associated with this component
        :param java.lang.String or str comment: the comment associated with this component
        """

    @typing.overload
    def __init__(self, dataType: DataType, parent: CompositeDataTypeImpl, length: typing.Union[jpype.JInt, int], ordinal: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int]):
        """
        Create a new DataTypeComponent
        
        :param DataType dataType: the dataType for this component
        :param CompositeDataTypeImpl parent: the dataType that this component belongs to
        :param jpype.JInt or int length: the length of the dataType in this component.
        :param jpype.JInt or int ordinal: the index of this component within its parent.
        :param jpype.JInt or int offset: the byte offset within the parent
        """

    @staticmethod
    def checkDefaultFieldName(fieldName: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def getPreferredComponentLength(dataType: DataType, length: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the preferred length for a new component. The length returned will be no
        larger than the specified length.
        
        :param DataType dataType: new component datatype
        :param jpype.JInt or int length: constrained length or -1 to force use of dataType size.
                        Dynamic types such as string must have a positive length
                        specified.
        :return: preferred component length
        :rtype: int
        :raises IllegalArgumentException: if length not specified for a :obj:`Dynamic` dataType.
        """


class SignedLeb128DataType(AbstractLeb128DataType):
    """
    A Signed Little Endian Base 128 integer data type.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[SignedLeb128DataType]
    """
    A statically defined SignedLeb128DataType instance.
    """


    @typing.overload
    def __init__(self):
        """
        Creates a signed little endian base 128 integer data type.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        """
        Creates a signed little endian base 128 integer data type.
        
        :param DataTypeManager dtm: the data type manager to associate with this data type.
        """


class AbstractSignedIntegerDataType(AbstractIntegerDataType):
    """
    Base type for unsigned integer data types.
    """

    class_: typing.ClassVar[java.lang.Class]


class FileDataTypeManager(StandAloneDataTypeManager, FileArchiveBasedDataTypeManager):
    """
    DataTypeManager for a file. Can import categories from a file, or export
    categories to a packed database.
    """

    class_: typing.ClassVar[java.lang.Class]
    EXTENSION: typing.Final = "gdt"
    GDT_FILEFILTER: typing.Final[ghidra.util.filechooser.GhidraFileFilter]
    SUFFIX: typing.Final = ".gdt"
    """
    Suffix for an archive file.
    """


    @staticmethod
    def convertFilename(file: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Convert the filename for the given file to have the packed database
        file extension.
        
        :param jpype.protocol.SupportsPath file: file whose name is to be converted
        :return: file if the filename already ends in the packed database
        file extension, or a new File object that has the packed database
        file extension
        :rtype: java.io.File
        """

    @staticmethod
    @typing.overload
    def createFileArchive(packedDbfile: jpype.protocol.SupportsPath) -> FileDataTypeManager:
        """
        Create a new data-type file archive using the default data organization
        
        :param jpype.protocol.SupportsPath packedDbfile: archive file (filename must end with DataTypeFileManager.SUFFIX)
        :return: data-type manager backed by specified packedDbFile
        :rtype: FileDataTypeManager
        :raises IOException: if an IO error occurs
        """

    @staticmethod
    @typing.overload
    def createFileArchive(packedDbFile: jpype.protocol.SupportsPath, languageId: ghidra.program.model.lang.LanguageID, compilerSpecId: ghidra.program.model.lang.CompilerSpecID) -> FileDataTypeManager:
        """
        Create a new data-type file archive using the default data organization.
        
        :param jpype.protocol.SupportsPath packedDbFile: archive file (filename must end with DataTypeFileManager.SUFFIX)
        :param ghidra.program.model.lang.LanguageID languageId: valid language ID (see appropriate *.ldefs file for defined IDs)
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecId: valid compiler spec ID which corresponds to the language ID.
        :return: data-type manager backed by the specified packedDbFile
        :rtype: FileDataTypeManager
        :raises DuplicateFileException: if ``packedDbFile`` already exists
        :raises LanguageNotFoundException: if specified ``languageId`` not defined.
        :raises CompilerSpecNotFoundException: if specified ``compilerSpecId`` is not defined 
        for the specified language.
        :raises IOException: if an IO error occurs
        """

    @staticmethod
    @typing.overload
    def createFileArchive(packedDbfile: jpype.protocol.SupportsPath, languageId: typing.Union[java.lang.String, str], compilerSpecId: typing.Union[java.lang.String, str]) -> FileDataTypeManager:
        """
        Create a new data-type file archive using the default data organization.
        
        :param jpype.protocol.SupportsPath packedDbfile: archive file (filename must end with DataTypeFileManager.SUFFIX)
        :param java.lang.String or str languageId: valid language ID (see appropriate *.ldefs file for defined IDs).  If null
        invocation will be deferred to :meth:`createFileArchive(File) <.createFileArchive>`.
        :param java.lang.String or str compilerSpecId: valid compiler spec ID which corresponds to the language ID.
        :return: data-type manager backed by the specified packedDbFile
        :rtype: FileDataTypeManager
        :raises LanguageNotFoundException: if specified ``languageId`` not defined.
        :raises CompilerSpecNotFoundException: if specified ``compilerSpecId`` is not defined 
        for the specified language.
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def delete(self):
        ...

    @staticmethod
    @typing.overload
    def delete(packedDbfile: jpype.protocol.SupportsPath):
        ...

    def getFilename(self) -> str:
        """
        Get the filename for the current file.
        
        :return: String filename, or null if there is no current file.
        :rtype: str
        """

    def isClosed(self) -> bool:
        ...

    @staticmethod
    @typing.overload
    def openFileArchive(packedDbfile: jpype.protocol.SupportsPath, openForUpdate: typing.Union[jpype.JBoolean, bool]) -> FileDataTypeManager:
        """
        Open an existing data-type file archive using the default data organization.
         
        
        **NOTE:** If archive has an assigned architecture, issues may arise due to a revised or
        missing :obj:`Language`/:obj:`CompilerSpec` which will result in a warning but not
        prevent the archive from being opened.  Such a warning condition will ne logged and may 
        result in missing or stale information for existing datatypes which have architecture related
        data.  In some case it may be appropriate to 
        :meth:`check for warnings <FileDataTypeManager.getWarning>` on the returned archive
        object prior to its use.
        
        :param jpype.protocol.SupportsPath packedDbfile: archive file (filename must end with DataTypeFileManager.SUFFIX)
        :param jpype.JBoolean or bool openForUpdate: if true archive will be open for update
        :return: data-type manager backed by specified packedDbFile
        :rtype: FileDataTypeManager
        :raises IOException: if an IO error occurs
        """

    @staticmethod
    @typing.overload
    def openFileArchive(packedDbfile: generic.jar.ResourceFile, openForUpdate: typing.Union[jpype.JBoolean, bool]) -> FileDataTypeManager:
        """
        Open an existing data-type file archive using the default data organization.
         
        
        **NOTE:** If archive has an assigned architecture, issues may arise due to a revised or
        missing :obj:`Language`/:obj:`CompilerSpec` which will result in a warning but not
        prevent the archive from being opened.  Such a warning condition will ne logged and may 
        result in missing or stale information for existing datatypes which have architecture related
        data.  In some case it may be appropriate to 
        :meth:`check for warnings <FileDataTypeManager.getWarning>` on the returned archive
        object prior to its use.
        
        :param generic.jar.ResourceFile packedDbfile: archive file (filename must end with DataTypeFileManager.SUFFIX)
        :param jpype.JBoolean or bool openForUpdate: if true archive will be open for update
        :return: data-type manager backed by specified packedDbFile
        :rtype: FileDataTypeManager
        :raises IOException: if an IO error occurs
        """

    def save(self):
        """
        Save the category to source file.
        
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def saveAs(self, saveFile: jpype.protocol.SupportsPath, newUniversalId: ghidra.util.UniversalID):
        """
        Saves the data type manager to the given file with a specific databaseId.
        NOTE: This method is intended for use in transforming one archive database to
        match another existing archive database.
        
        :param jpype.protocol.SupportsPath saveFile: the file to save
        :param ghidra.util.UniversalID newUniversalId: the new id to use
        :raises DuplicateFileException: if save file already exists
        :raises IOException: if IO error occurs
        """

    @typing.overload
    def saveAs(self, saveFile: jpype.protocol.SupportsPath):
        """
        Saves the data type manager to the given file
        
        :param jpype.protocol.SupportsPath saveFile: the file to save
        :raises DuplicateFileException: if save file already exists
        :raises IOException: if IO error occurs
        """

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...


class TerminatedUnicodeDataType(AbstractStringDataType):
    """
    A null-terminated string :obj:`DataType` with a UTF-16 :obj:`charset <CharsetSettingsDefinition>`.
     
    
    
    NOTE: TerminatedUnicodeDataType class was renamed to TerminatedUnicodeStringDataType to
    address problem where this factory data-type may have previously been added to
    composites.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[TerminatedUnicodeDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class RepeatedDynamicDataType(DynamicDataType):
    """
    Template for a repeated Dynamic Data Type.
     
    Base abstract data type for a Dynamic structure data type that contains
    some number of repeated data types.  After each data type, including the header
    there is a terminator value which specifies whether there are any more data structures
    following.  TerminatorValue can be 1,2,4,or 8 bytes.
     
    The dynamic structure looks like this:
     
        RepeatDynamicDataType
        Header
        TerminatorV1
        RepDT1
        TerminatorV2
        RepDT2
        ...
        RepDTN-1
        TerminatorVN  == TerminateValue
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], header: DataType, baseStruct: DataType, terminatorValue: typing.Union[jpype.JLong, int], terminatorSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Construct Repeat Dynamic Data Type Template.
        
        :param java.lang.String or str name: name of this data type
        :param java.lang.String or str description: description of the data type
        :param DataType header: header data type
        :param DataType baseStruct: repeated structure following the data type
        :param jpype.JLong or int terminatorValue: value to terminate repeats on
        :param jpype.JInt or int terminatorSize: size of the value
        """

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class StandAloneDataTypeManager(ghidra.program.database.data.DataTypeManagerDB, java.io.Closeable):
    """
    Basic implementation of the DataTypeManger interface
    """

    class ArchiveWarningLevel(java.lang.Enum[StandAloneDataTypeManager.ArchiveWarningLevel]):

        class_: typing.ClassVar[java.lang.Class]
        INFO: typing.Final[StandAloneDataTypeManager.ArchiveWarningLevel]
        WARN: typing.Final[StandAloneDataTypeManager.ArchiveWarningLevel]
        ERROR: typing.Final[StandAloneDataTypeManager.ArchiveWarningLevel]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> StandAloneDataTypeManager.ArchiveWarningLevel:
            ...

        @staticmethod
        def values() -> jpype.JArray[StandAloneDataTypeManager.ArchiveWarningLevel]:
            ...


    class ArchiveWarning(java.lang.Enum[StandAloneDataTypeManager.ArchiveWarning]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[StandAloneDataTypeManager.ArchiveWarning]
        """
        :obj:`.NONE` indicates a normal archive condition
        """

        UPGRADED_LANGUAGE_VERSION: typing.Final[StandAloneDataTypeManager.ArchiveWarning]
        """
        :obj:`.UPGRADED_LANGUAGE_VERSION` indicates an archive which has been open for update
        was upgraded to a newer language version.  This is expected when the :obj:`Language`
        required by the associated :obj:`ProgramArchitecture` has a major version change 
        which involves significant :obj:`Register` changes.  Sharing an upgraded archive 
        may impact others who do not have access to the updated :obj:`Language` module.
        """

        LANGUAGE_NOT_FOUND: typing.Final[StandAloneDataTypeManager.ArchiveWarning]
        """
        :obj:`.LANGUAGE_NOT_FOUND` indicates the :obj:`Language` or its appropriate version, 
        required by the associated :obj:`ProgramArchitecture`, was not found or encountered
        a problem being loaded.  The :meth:`FileDataTypeManager.getWarningDetail() <FileDataTypeManager.getWarningDetail>` may provide
        additional insight to the underlying cause.
        """

        COMPILER_SPEC_NOT_FOUND: typing.Final[StandAloneDataTypeManager.ArchiveWarning]
        """
        :obj:`.COMPILER_SPEC_NOT_FOUND` indicates the :obj:`CompilerSpec`, 
        required by the associated :obj:`ProgramArchitecture`, was not found or encountered
        a problem being loaded.  The :meth:`FileDataTypeManager.getWarningDetail() <FileDataTypeManager.getWarningDetail>` may provide
        additional insight to the underlying cause.  This condition can only occur if the
        required :obj:`Language` was found.
        """

        LANGUAGE_UPGRADE_REQURED: typing.Final[StandAloneDataTypeManager.ArchiveWarning]
        """
        :obj:`.LANGUAGE_UPGRADE_REQURED` indicates an archive which has been open read-only
        requires an upgraded to a newer language version.  This is expected when the 
        :obj:`Language` required by the associated :obj:`ProgramArchitecture` has a major 
        version change within the current installation.  Major version changes for a 
        :obj:`Language` rarely occur but are required when significant :obj:`Register` 
        or addressing changes have been made.  Upgrading a shared archive may impact others 
        who do not have access to the updated :obj:`Language` module and should be 
        coordinated with others who may be affected.
        """

        DATA_ORG_CHANGED: typing.Final[StandAloneDataTypeManager.ArchiveWarning]
        """
        :obj:`.DATA_ORG_CHANGED` indicates an archive which has been open read-only
        requires an upgraded to adjust for changes in the associated data organization.
        """


        def level(self) -> StandAloneDataTypeManager.ArchiveWarningLevel:
            """
            Get the warning level
            
            :return: warning level
            :rtype: StandAloneDataTypeManager.ArchiveWarningLevel
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> StandAloneDataTypeManager.ArchiveWarning:
            ...

        @staticmethod
        def values() -> jpype.JArray[StandAloneDataTypeManager.ArchiveWarning]:
            ...


    class LanguageUpdateOption(java.lang.Enum[StandAloneDataTypeManager.LanguageUpdateOption]):

        class_: typing.ClassVar[java.lang.Class]
        CLEAR: typing.Final[StandAloneDataTypeManager.LanguageUpdateOption]
        """
        All existing storage data should be cleared
        """

        TRANSLATE: typing.Final[StandAloneDataTypeManager.LanguageUpdateOption]
        """
        An attempt should be made to translate from old-to-new language.
        This has limitations (i.e., similar architecture) and may result in 
        poor register mappings.
        """

        UNCHANGED: typing.Final[StandAloneDataTypeManager.LanguageUpdateOption]
        """
        Variable storage data will be retained as-is but may not de-serialize 
        properly when used.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> StandAloneDataTypeManager.LanguageUpdateOption:
            ...

        @staticmethod
        def values() -> jpype.JArray[StandAloneDataTypeManager.LanguageUpdateOption]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, rootName: typing.Union[java.lang.String, str]):
        """
        Constructor for new temporary data-type manager using the default DataOrganization.
        Note that this manager does not support the save or saveAs operation.
        
        :param java.lang.String or str rootName: Name of the root category.
        :raises RuntimeIOException: if database error occurs during creation
        """

    @typing.overload
    def __init__(self, rootName: typing.Union[java.lang.String, str], dataOrganzation: DataOrganization):
        """
        Constructor for new temporary data-type manager using a specified DataOrganization.
        Note that this manager does not support the save or saveAs operation.
        
        :param java.lang.String or str rootName: Name of the root category.
        :param DataOrganization dataOrganzation: applicable data organization
        :raises RuntimeIOException: if database error occurs during creation
        """

    def canRedo(self) -> bool:
        """
        Determine if there is a transaction previously undone (see :meth:`undo() <.undo>`) that can be 
        redone (see :meth:`redo() <.redo>`).
        
        :return: true if there is a transaction previously undone that can be redone, else false
        :rtype: bool
        """

    def canUndo(self) -> bool:
        """
        Determine if there is a previous transaction that can be reverted/undone (see :meth:`undo() <.undo>`).
        
        :return: true if there is a previous transaction that can be reverted/undone, else false.
        :rtype: bool
        """

    def clearProgramArchitecture(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Clear the program architecture setting and all architecture-specific data from this archive.
        Archive will revert to using the default :obj:`DataOrganization`.
        Archive must be open for update for this method to be used.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if task cancelled.  If thrown, this data type manager is no longer 
        stable and should be closed without saving.
        :raises IOException: if IO error occurs
        :raises LockException: failure if exclusive access is required
        :raises UnsupportedOperationException: if architecture change is not permitted by 
        implementation (e.g., :obj:`BuiltInDataTypeManager`).
        """

    def getAllRedoNames(self) -> java.util.List[java.lang.String]:
        """
        Get all transaction names that are available within the :meth:`redo() <.redo>` stack.
        
        :return: all transaction names that are available within the :meth:`redo() <.redo>` stack.
        :rtype: java.util.List[java.lang.String]
        """

    def getAllUndoNames(self) -> java.util.List[java.lang.String]:
        """
        Get all transaction names that are available within the :meth:`undo() <.undo>` stack.
        
        :return: all transaction names that are available within the :meth:`undo() <.undo>` stack.
        :rtype: java.util.List[java.lang.String]
        """

    def getPath(self) -> str:
        """
        Get the path name associated with the storage of this stand alone
        datatype manager.
        
        :return: path name or null if not applicable
        :rtype: str
        """

    def getProgramArchitectureSummary(self) -> str:
        """
        Get the program architecture information which has been associated with this 
        datatype manager.  If :meth:`getProgramArchitecture() <.getProgramArchitecture>` returns null this method
        may still return information if the program architecture was set on an archive 
        and either :meth:`isProgramArchitectureMissing() <.isProgramArchitectureMissing>` or 
        :meth:`isProgramArchitectureUpgradeRequired() <.isProgramArchitectureUpgradeRequired>` returns true.
        
        :return: program architecture summary if it has been set
        :rtype: str
        """

    def getRedoName(self) -> str:
        """
        Get the transaction name that is available for :meth:`redo() <.redo>` (see :meth:`canRedo() <.canRedo>`).
        
        :return: transaction name that is available for :meth:`redo() <.redo>` or empty String.
        :rtype: str
        """

    def getUndoName(self) -> str:
        """
        Get the transaction name that is available for :meth:`undo() <.undo>` (see :meth:`canUndo() <.canUndo>`).
        
        :return: transaction name that is available for :meth:`undo() <.undo>` or empty String.
        :rtype: str
        """

    def getWarning(self) -> StandAloneDataTypeManager.ArchiveWarning:
        """
        Get the :obj:`ArchiveWarning` which may have occured immediately following 
        instatiation of this :obj:`StandAloneDataTypeManager`.  :obj:`ArchiveWarning.NONE`
        will be returned if not warning condition.
        
        :return: warning type.
        :rtype: StandAloneDataTypeManager.ArchiveWarning
        """

    def getWarningDetail(self) -> java.lang.Exception:
        """
        Get the detail exception associated with :obj:`ArchiveWarning.LANGUAGE_NOT_FOUND` or
        :obj:`ArchiveWarning.COMPILER_SPEC_NOT_FOUND` warning (see :meth:`getWarning() <.getWarning>`)
        immediately following instatiation of this :obj:`StandAloneDataTypeManager`.
        
        :return: warning detail exception or null
        :rtype: java.lang.Exception
        """

    def getWarningMessage(self, includeDetails: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get a suitable warning message.  See :meth:`getWarning() <.getWarning>` for type and its severity level
        :meth:`ArchiveWarning.level() <ArchiveWarning.level>`.
        
        :param jpype.JBoolean or bool includeDetails: if false simple message returned, otherwise more details are included.
        :return: warning message or null if :meth:`getWarning() <.getWarning>` is :obj:`ArchiveWarning.NONE`.
        :rtype: str
        """

    def isProgramArchitectureMissing(self) -> bool:
        """
        Indicates that a failure occured establishing the program architecture 
        for the associated archive.
        
        :return: true if a failure occured establishing the program architecture
        :rtype: bool
        """

    def isProgramArchitectureUpgradeRequired(self) -> bool:
        """
        Indicates that an program architecture upgrade is required in order
        to constitute associated data.  If true, the associated archive
        must be open for update to allow the upgrade to complete, or a new
        program architecture may be set/cleared if such an operation is supported.
        
        :return: true if a program architecture upgrade is required, else false
        :rtype: bool
        """

    def redo(self):
        ...

    def setProgramArchitecture(self, language: ghidra.program.model.lang.Language, compilerSpecId: ghidra.program.model.lang.CompilerSpecID, updateOption: StandAloneDataTypeManager.LanguageUpdateOption, monitor: ghidra.util.task.TaskMonitor):
        """
        Establish the program architecture for this datatype manager.  The current setting can be 
        determined from :meth:`getProgramArchitecture() <.getProgramArchitecture>`.  Archive must be open for update for 
        this method to be used.
        
        :param ghidra.program.model.lang.Language language: language
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecId: compiler specification ID defined by the language.
        :param StandAloneDataTypeManager.LanguageUpdateOption updateOption: indicates how variable storage data should be transitioned.  If :meth:`isProgramArchitectureMissing() <.isProgramArchitectureMissing>`
        is true and :obj:`LanguageUpdateOption.TRANSLATE` specified, the translator will be based on whatever language version can 
        be found.  In this situation it may be best to force a  :obj:`LanguageUpdateOption.CLEAR`.
        :param ghidra.util.task.TaskMonitor monitor: task monitor (cancel not permitted to avoid corrupt state)
        :raises CompilerSpecNotFoundException: if invalid compilerSpecId specified for language
        :raises LanguageNotFoundException: if current language is not found (if required for data transition)
        :raises IOException: if IO error occurs
        :raises CancelledException: if task cancelled.  If thrown, this data type manager is no longer 
        stable and should be closed without saving.
        :raises LockException: failure if exclusive access is required
        :raises UnsupportedOperationException: if architecture change is not permitted
        :raises IncompatibleLanguageException: if translation requested but not possible due to incompatible language architectures
        """

    def undo(self):
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def allUndoNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def allRedoNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def undoName(self) -> java.lang.String:
        ...

    @property
    def programArchitectureMissing(self) -> jpype.JBoolean:
        ...

    @property
    def programArchitectureUpgradeRequired(self) -> jpype.JBoolean:
        ...

    @property
    def redoName(self) -> java.lang.String:
        ...

    @property
    def warningMessage(self) -> java.lang.String:
        ...

    @property
    def warning(self) -> StandAloneDataTypeManager.ArchiveWarning:
        ...

    @property
    def warningDetail(self) -> java.lang.Exception:
        ...

    @property
    def programArchitectureSummary(self) -> java.lang.String:
        ...


class SignedDWordDataType(AbstractSignedIntegerDataType):
    """
    Provides a definition of a Signed Double Word within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[SignedDWordDataType]
    """
    A statically defined SignedDWordDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class FileArchiveBasedDataTypeManager(FileBasedDataTypeManager):
    """
    Extends DataTypeManager to provide methods specific to file data type archives (.gdt).
    """

    class_: typing.ClassVar[java.lang.Class]


class FactoryStructureDataType(BuiltIn, FactoryDataType):
    """
    Abstract class used to create specialized data structures that act like
    a Structure and create a new Dynamic structure each time they are used.
    """

    class_: typing.ClassVar[java.lang.Class]


class Composite(DataType):
    """
    Interface for common methods in Structure and Union
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, dataType: DataType) -> DataTypeComponent:
        """
        Adds a new datatype to the end of this composite.  This is the preferred method
        to use for adding components to an aligned structure for fixed-length dataTypes.
        
        :param DataType dataType: the datatype to add.
        :return: the DataTypeComponent created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be added to this composite data type.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to add dt1 to dt2 since this would cause a cyclic dependency.
        """

    @typing.overload
    def add(self, dataType: DataType, length: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Adds a new datatype to the end of this composite. This is the preferred method
        to use for adding components to an aligned structure for dynamic dataTypes such as
        strings whose length must be specified.
        
        :param DataType dataType: the datatype to add.
        :param jpype.JInt or int length: the length to associate with the datatype.
        For fixed length types a length <= 0 will use the length of the resolved dataType.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be added to this composite data type or an invalid length
        is specified.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to add dt1 to dt2 since this would cause a cyclic dependency.
        """

    @typing.overload
    def add(self, dataType: DataType, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Adds a new datatype to the end of this composite.  This is the preferred method
        to use for adding components to an aligned structure for fixed-length dataTypes.
        
        :param DataType dataType: the datatype to add.
        :param java.lang.String or str name: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be added to this composite data type.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to add dt1 to dt2 since this would cause a cyclic dependency.
        """

    @typing.overload
    def add(self, dataType: DataType, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Adds a new datatype to the end of this composite.  This is the preferred method
        to use for adding components to an aligned structure for dynamic dataTypes such as
        strings whose length must be specified.
        
        :param DataType dataType: the datatype to add.
        :param jpype.JInt or int length: the length to associate with the datatype.
        For fixed length types a length <= 0 will use the length of the resolved dataType.
        :param java.lang.String or str name: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be added to this composite data type or an invalid length is specified.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to add dt1 to dt2 since this would cause a cyclic dependency.
        """

    def addBitField(self, baseDataType: DataType, bitSize: typing.Union[jpype.JInt, int], componentName: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Adds a new bitfield to the end of this composite.  This method is intended
        to be used with packed structures/unions only where the bitfield will be
        appropriately packed.  The minimum storage byte size will be applied.
        It will not provide useful results for composites with packing disabled.
        
        :param DataType baseDataType: the bitfield base datatype (certain restrictions apply).
        :param jpype.JInt or int bitSize: the bitfield size in bits
        :param java.lang.String or str componentName: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the componentDataType created whose associated data type will
        be BitFieldDataType.
        :rtype: DataTypeComponent
        :raises InvalidDataTypeException: if the specified data type is
        not a valid base type for bitfields.
        """

    def align(self, minAlignment: typing.Union[jpype.JInt, int]):
        """
        Same as :meth:`setExplicitMinimumAlignment(int) <.setExplicitMinimumAlignment>`.
        
        :param jpype.JInt or int minAlignment: the explicit minimum alignment for this Composite.
        :raises IllegalArgumentException: if a non-positive value is specified
        """

    def dataTypeAlignmentChanged(self, dt: DataType):
        """
        The alignment changed for the specified data type.  If packing is enabled for this
        composite, the placement of the component may be affected by a change in its alignment.
        A non-packed composite can ignore this notification.
        
        :param DataType dt: the data type whose alignment changed.
        """

    @typing.overload
    def delete(self, ordinal: typing.Union[jpype.JInt, int]):
        """
        Deletes the component at the given ordinal position.
         
        Note: Removal of bitfields from a structure with packing disabled will
        not shift other components causing vacated bytes to revert to undefined filler.
        
        :param jpype.JInt or int ordinal: the ordinal of the component to be deleted (numbering starts at 0).
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    @typing.overload
    def delete(self, ordinals: java.util.Set[java.lang.Integer]):
        """
        Deletes the specified set of components at the given ordinal positions.
         
        Note: Removal of bitfields from a structure with packing disabled will
        not shift other components causing vacated bytes to revert to undefined filler.
        
        :param java.util.Set[java.lang.Integer] ordinals: the ordinals of the component to be deleted.
        :raises java.lang.IndexOutOfBoundsException: if any specified component ordinal is out of bounds
        """

    def getAlignment(self) -> int:
        """
        Get the computed alignment for this composite based upon packing and minimum
        alignment settings as well as component alignment.  If packing is disabled,
        the alignment will always be 1 unless a minimum alignment has been set.
        
        :return: this composites alignment
        :rtype: int
        """

    def getAlignmentType(self) -> AlignmentType:
        """
        
        
        :return: the alignment type set for this composite
        :rtype: AlignmentType
        """

    def getComponent(self, ordinal: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Returns the component of this data type with the indicated ordinal.
        
        :param jpype.JInt or int ordinal: the component's ordinal (numbering starts at 0).
        :return: the data type component.
        :rtype: DataTypeComponent
        :raises java.lang.IndexOutOfBoundsException: if the ordinal is out of bounds
        """

    def getComponents(self) -> jpype.JArray[DataTypeComponent]:
        """
        Returns an array of Data Type Components that make up this composite including
        undefined filler components which may be present within a Structure which has packing disabled.
        The number of components corresponds to :meth:`getNumComponents() <.getNumComponents>`.
        
        :return: array all components
        :rtype: jpype.JArray[DataTypeComponent]
        """

    def getDefinedComponents(self) -> jpype.JArray[DataTypeComponent]:
        """
        Returns an array of Data Type Components that make up this composite excluding
        undefined filler components which may be present within Structures where packing is disabled.
        The number of components corresponds to :meth:`getNumDefinedComponents() <.getNumDefinedComponents>`.  For Unions and
        packed Structures this is equivalent to :meth:`getComponents() <.getComponents>`
        since they do not contain undefined filler components.
        
        :return: array all explicitly defined components
        :rtype: jpype.JArray[DataTypeComponent]
        """

    def getExplicitMinimumAlignment(self) -> int:
        """
        Get the explicit minimum alignment setting for this Composite which contributes
        to the actual computed alignment value (see :meth:`getAlignment() <.getAlignment>`.
        
        :return: the minimum alignment setting for this Composite or an undefined
        non-positive value if an explicit minimum alignment has not been set.
        :rtype: int
        """

    def getExplicitPackingValue(self) -> int:
        """
        Gets the current packing value (typically a power of 2).
        If this isn't a packed composite with an explicit packing value (see :meth:`hasExplicitPackingValue() <.hasExplicitPackingValue>`)
        then the return value is undefined.
        
        :return: the current packing value or an undefined non-positive value
        :rtype: int
        """

    def getNumComponents(self) -> int:
        """
        Gets the number of component data types in this composite.
        If this is Structure with packing disabled, the count will include all undefined filler
        components which may be present.
        
        :return: the number of components that make up this composite
        :rtype: int
        """

    def getNumDefinedComponents(self) -> int:
        """
        Returns the number of explicitly defined components in this composite.
        For Unions and packed Structures this is equivalent to :meth:`getNumComponents() <.getNumComponents>`
        since they do not contain undefined components.
        This count will always exclude all undefined filler components which may be present
        within a Structure whose packing is disabled (see :meth:`isPackingEnabled() <.isPackingEnabled>`).
        
        :return: the number of explicitly defined components in this composite
        :rtype: int
        """

    def getPackingType(self) -> PackingType:
        """
        
        
        :return: the packing type set for this composite
        :rtype: PackingType
        """

    def hasDefaultPacking(self) -> bool:
        """
        Determine if default packing is enabled.
        
        :return: true if default packing is enabled.
        :rtype: bool
        """

    def hasExplicitMinimumAlignment(self) -> bool:
        """
        Determine if an explicit minimum alignment has been set (see
        :meth:`getExplicitMinimumAlignment() <.getExplicitMinimumAlignment>`). An undefined value is returned if default alignment
        or machine alignment is enabled.
        
        :return: true if an explicit minimum alignment has been set, else false
        :rtype: bool
        """

    def hasExplicitPackingValue(self) -> bool:
        """
        Determine if packing is enabled with an explicit packing value (see :meth:`getExplicitPackingValue() <.getExplicitPackingValue>`).
        
        :return: true if packing is enabled with an explicit packing value, else false.
        :rtype: bool
        """

    @typing.overload
    def insert(self, ordinal: typing.Union[jpype.JInt, int], dataType: DataType) -> DataTypeComponent:
        """
        Inserts a new datatype at the specified ordinal position in this composite.
         
        Note: For an aligned structure the ordinal position will get adjusted
        automatically to provide the proper alignment.
        
        :param jpype.JInt or int ordinal: the ordinal where the new datatype is to be inserted (numbering starts at 0).
        :param DataType dataType: the datatype to insert.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be inserted into this composite data type.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to insert dt1 to dt2 since this would cause a cyclic dependency.
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    @typing.overload
    def insert(self, ordinal: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Inserts a new datatype at the specified ordinal position in this composite.
         
        Note: For an aligned structure the ordinal position will get adjusted
        automatically to provide the proper alignment.
        
        :param jpype.JInt or int ordinal: the ordinal where the new datatype is to be inserted (numbering starts at 0).
        :param DataType dataType: the datatype to insert.
        :param jpype.JInt or int length: the length to associate with the datatype.
        For fixed length types a length <= 0 will use the length of the resolved dataType.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be inserted into this composite data type or an invalid
        length is specified.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to insert dt1 to dt2 since this would cause a cyclic dependency.
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    @typing.overload
    def insert(self, ordinal: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Inserts a new datatype at the specified ordinal position in this composite.
         
        Note: For an aligned structure the ordinal position will get adjusted
        automatically to provide the proper alignment.
        
        :param jpype.JInt or int ordinal: the ordinal where the new datatype is to be inserted (numbering starts at 0).
        :param DataType dataType: the datatype to insert.
        :param jpype.JInt or int length: the length to associate with the datatype.
        For fixed length types a length <= 0 will use the length of the resolved dataType.
        :param java.lang.String or str name: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not
        allowed to be inserted into this composite data type or an invalid length
        is specified.
        For example, suppose dt1 contains dt2. Therefore it is not valid
        to insert dt1 to dt2 since this would cause a cyclic dependency.
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    def isDefaultAligned(self) -> bool:
        """
        Whether or not this data type is using the default alignment.  When Structure packing
        is disabled the default alignment is always 1 (see :meth:`Structure.setPackingEnabled(boolean) <Structure.setPackingEnabled>`.
        
        :return: true if this data type is using its default alignment.
        :rtype: bool
        """

    def isMachineAligned(self) -> bool:
        """
        Whether or not this data type is using the machine alignment value, specified by
        :meth:`DataOrganization.getMachineAlignment() <DataOrganization.getMachineAlignment>`, for its alignment.
        
        :return: true if this data type is using the machine alignment as its alignment.
        :rtype: bool
        """

    def isPackingEnabled(self) -> bool:
        """
        Determine if this data type has its internal components currently packed
        based upon alignment and packing settings.  If disabled, component placement
        is based upon explicit placement by offset.
        
        :return: true if this data type's components auto-packed
        :rtype: bool
        """

    def isPartOf(self, dataType: DataType) -> bool:
        """
        Check if a data type is part of this data type.  A data type could
        be part of another by:
         
        Being the same data type.
         
        containing the data type directly
         
        containing another data type that has the data type as a part of it.
        
        :param DataType dataType: the data type to look for.
        :return: true if the indicated data type is part of a sub-component of
        this data type.
        :rtype: bool
        """

    def pack(self, packingValue: typing.Union[jpype.JInt, int]):
        """
        Same as :meth:`setExplicitPackingValue(int) <.setExplicitPackingValue>`.
        
        :param jpype.JInt or int packingValue: the new positive packing value.
        :raises IllegalArgumentException: if a non-positive value is specified.
        """

    def repack(self):
        """
        Updates packed composite to any changes in the data organization. If the composite does
        not have packing enabled this method does nothing.
         
        
        NOTE: Changes to data organization is discouraged.  Attempts to use this method in such
        cases should be performed on all composites in dependency order (ignoring pointer components).
        """

    def setDescription(self, desc: typing.Union[java.lang.String, str]):
        """
        Sets the string describing this data type.
        
        :param java.lang.String or str desc: the new description.
        """

    def setExplicitMinimumAlignment(self, minAlignment: typing.Union[jpype.JInt, int]):
        """
        Sets this data type's explicit minimum alignment (positive value).
        Together with the pack setting and component alignments will
        affect the actual computed alignment of this composite.
        When packing is enabled, the alignment setting may also affect padding
        at the end of the composite and its length.  When packing is disabled,
        this setting will not affect the length of this composite.
        
        :param jpype.JInt or int minAlignment: the minimum alignment for this Composite.
        :raises IllegalArgumentException: if a non-positive value is specified
        """

    def setExplicitPackingValue(self, packingValue: typing.Union[jpype.JInt, int]):
        """
        Sets the pack value for this composite (positive value, usually a power of 2).
        If packing was previously disabled, packing will be enabled.  This value will
        establish the maximum effective alignment for this composite and each of the
        components during the alignment computation (e.g., a value of 1 will eliminate
        any padding).  The overall composite length may be influenced by the composite's
        minimum alignment setting.
        
        :param jpype.JInt or int packingValue: the new positive packing value.
        :raises IllegalArgumentException: if a non-positive value is specified.
        """

    def setPackingEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether this data type's internal components are currently packed.  The
        affect of disabled packing differs between :obj:`Structure` and :obj:`Union`.  When
        packing disabled:
         
        * Structures utilize explicit component offsets and produce undefined filler
        components where defined components do not consume space.
        * Unions always place components at offset 0 and do not pad for alignment.
        
        In addition, when packing is disabled the default alignment is always 1 unless a
        different minimum alignment has been set.  When packing is enabled the overall
        composite length influenced by the composite's minimum alignment setting.
        If a change in enablement occurs, the default alignment and packing behavior
        will be used.
        
        :param jpype.JBoolean or bool enabled: true enables packing of components respecting component
        alignment and pack setting, whereas false disables packing.
        """

    def setToDefaultAligned(self):
        """
        Sets this data type's alignment to its default alignment. For packed
        composites, this data type's alignment will be based upon the components it contains and
        its current pack settings.  This is the default state and only needs to be used
        when changing from a non-default alignment type.
        """

    def setToDefaultPacking(self):
        """
        Enables default packing behavior.
        If packing was previously disabled, packing will be enabled.
        Composite will automatically pack based upon the alignment requirements
        of its components with overall composite length possibly influenced by the composite's
        minimum alignment setting.
        """

    def setToMachineAligned(self):
        """
        Sets this data type's minimum alignment to the machine alignment which is
        specified by :meth:`DataOrganization.getMachineAlignment() <DataOrganization.getMachineAlignment>`. The machine alignment is
        defined as the maximum useful alignment for the target machine.
        """

    @property
    def partOf(self) -> jpype.JBoolean:
        ...

    @property
    def components(self) -> jpype.JArray[DataTypeComponent]:
        ...

    @property
    def explicitPackingValue(self) -> jpype.JInt:
        ...

    @explicitPackingValue.setter
    def explicitPackingValue(self, value: jpype.JInt):
        ...

    @property
    def packingEnabled(self) -> jpype.JBoolean:
        ...

    @packingEnabled.setter
    def packingEnabled(self, value: jpype.JBoolean):
        ...

    @property
    def explicitMinimumAlignment(self) -> jpype.JInt:
        ...

    @explicitMinimumAlignment.setter
    def explicitMinimumAlignment(self, value: jpype.JInt):
        ...

    @property
    def numDefinedComponents(self) -> jpype.JInt:
        ...

    @property
    def packingType(self) -> PackingType:
        ...

    @property
    def alignmentType(self) -> AlignmentType:
        ...

    @property
    def component(self) -> DataTypeComponent:
        ...

    @property
    def definedComponents(self) -> jpype.JArray[DataTypeComponent]:
        ...

    @property
    def defaultAligned(self) -> jpype.JBoolean:
        ...

    @property
    def machineAligned(self) -> jpype.JBoolean:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @property
    def numComponents(self) -> jpype.JInt:
        ...


class GenericDataType(DataTypeImpl):
    """
    Base implementation for a generic data type.
    """

    class_: typing.ClassVar[java.lang.Class]


class PointerTypedefBuilder(java.lang.Object):
    """
    ``PointerTypedefBuilder`` provides a builder for creating :obj:`Pointer` - :obj:`TypeDef`s.  
    These special typedefs allow a modified-pointer datatype to be used for special situations where
    a simple pointer will not suffice and special stored pointer interpretation/handling is required.  
     
    
    This builder simplifies the specification of various :obj:`Pointer` modifiers during the 
    construction of an associated :obj:`TypeDef`.
     
    
    A convenience method :meth:`Pointer.typedefBuilder() <Pointer.typedefBuilder>` also exists for creating a builder
    from a pointer instance.  In addition the utility class :obj:`PointerTypedefInspector`
    can be used to easily determine pointer-typedef settings.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, baseDataType: DataType, pointerSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Construct a :obj:`Pointer` - :obj:`TypeDef` builder.
        
        :param DataType baseDataType: baseDataType or null to use a default pointer
        :param jpype.JInt or int pointerSize: pointer size or -1 to use default pointer size for specified datatype manager.
        :param DataTypeManager dtm: datatype manager (highly recommended although may be null)
        """

    @typing.overload
    def __init__(self, pointerDataType: Pointer, dtm: DataTypeManager):
        """
        Construct a :obj:`Pointer` - :obj:`TypeDef` builder.
        
        :param Pointer pointerDataType: base pointer datatype (required)
        :param DataTypeManager dtm: datatype manager (highly recommended although may be null)
        """

    @typing.overload
    def addressSpace(self, space: ghidra.program.model.address.AddressSpace) -> PointerTypedefBuilder:
        """
        Update pointer referenced address space when translating to an absolute memory offset.
        
        :param ghidra.program.model.address.AddressSpace space: pointer referenced address space or null for default space
        :return: this builder
        :rtype: PointerTypedefBuilder
        """

    @typing.overload
    def addressSpace(self, spaceName: typing.Union[java.lang.String, str]) -> PointerTypedefBuilder:
        """
        Update pointer referenced address space when translating to an absolute memory offset.
        
        :param java.lang.String or str spaceName: pointer referenced address space or null for default space
        :return: this builder
        :rtype: PointerTypedefBuilder
        """

    def bitMask(self, unsignedMask: typing.Union[jpype.JLong, int]) -> PointerTypedefBuilder:
        """
        Update pointer offset bit-mask when translating to an absolute memory offset.
        If specified, bit-mask will be AND-ed with stored offset prior to any 
        specified bit-shift.
        
        :param jpype.JLong or int unsignedMask: unsigned bit-mask
        :return: this builder
        :rtype: PointerTypedefBuilder
        """

    def bitShift(self, shift: typing.Union[jpype.JInt, int]) -> PointerTypedefBuilder:
        """
        Update pointer offset bit-shift when translating to an absolute memory offset.
        If specified, bit-shift will be applied after applying any specified bit-mask.
        
        :param jpype.JInt or int shift: bit-shift (right: positive, left: negative)
        :return: this builder
        :rtype: PointerTypedefBuilder
        """

    def build(self) -> TypeDef:
        """
        Build pointer-typedef with specified settings.
        
        :return: unresolved pointer typedef
        :rtype: TypeDef
        """

    def componentOffset(self, offset: typing.Union[jpype.JLong, int]) -> PointerTypedefBuilder:
        """
        Update pointer relative component-offset.  This setting is interpretted in two
        ways: 
         
        * The specified offset is considered to be relative to the start of the base datatype
        (e.g., structure).  It may refer to a component-offset within the base datatype or outside of
        it.
        * When pointer-typedef is initially applied to memory, an :obj:`OffsetReference` will be produced
        by subtracting the component-offset from the stored pointer offset to determine the
        base-offset for the reference.  While the xref will be to the actual referenced location, the
        reference markup will be shown as<base>+<offset>
        
        
        :param jpype.JLong or int offset: component offset relative to a base-offset and associated base-datatype
        :return: this builder
        :rtype: PointerTypedefBuilder
        """

    def name(self, name: typing.Union[java.lang.String, str]) -> PointerTypedefBuilder:
        """
        Set pointer-typedef name.  If not specified a default name will be generated based 
        upon the associated pointer type and the specified settings.
        
        :param java.lang.String or str name: typedef name
        :return: this builder
        :rtype: PointerTypedefBuilder
        :raises InvalidNameException: if name contains unsupported characters
        """

    def type(self, type: PointerType) -> PointerTypedefBuilder:
        """
        Update pointer type.
        
        :param PointerType type: pointer type
        :return: this builder
        :rtype: PointerTypedefBuilder
        """


class DataTypeImpl(AbstractDataType):
    """
    Base implementation for dataTypes.
     
    NOTE: Settings are immutable when a DataTypeManager has not been specified (i.e., null).
    """

    class_: typing.ClassVar[java.lang.Class]

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Sets a String briefly describing this DataType.
         
        If a data type that extends this class wants to allow the description to be changed,
        then it must override this method.
        
        :param java.lang.String or str description: a one-liner describing this DataType.
        :raises java.lang.UnsupportedOperationException: if the description is not allowed to be set for this data type.
        """


class AbstractFloatDataType(BuiltIn):
    """
    Provides a definition of a Float within a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], encodedLength: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Abstract float datatype constructor
        
        :param java.lang.String or str name: name of the float datatype.
        :param jpype.JInt or int encodedLength: the floating encoding length as number of 8-bit bytes.
        :param DataTypeManager dtm: associated datatype manager which dictates the :obj:`DataOrganization` to
        be used.  This argument may be null to adopt the default data organization.
        """

    @staticmethod
    def getFloatDataType(rawFormatByteSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager) -> DataType:
        """
        Get a Float data-type instance with the requested raw format size in bytes. It is important that the
        "raw" format size is specified since the :meth:`aligned-length <DataType.getAlignedLength>`
        used by compilers (e.g., ``sizeof()``) may be larger and duplicated across different 
        float formats.  Example: an 80-bit (10-byte) float may have an aligned-length of 12 or 16-bytes 
        based upon alignment requirements of a given compiler.  This can result in multiple float
        types having the same aligned-length.
        
        :param jpype.JInt or int rawFormatByteSize: raw float format size, unsupported sizes will cause an undefined 
                        type to be returned.
        :param DataTypeManager dtm: optional program data-type manager, if specified a generic data-type will be
                        returned if possible (i.e., float, double, long double).
        :return: float data type of specified size
        :rtype: DataType
        """

    @staticmethod
    def getFloatDataTypes(dtm: DataTypeManager) -> jpype.JArray[AbstractFloatDataType]:
        """
        Returns all built-in floating-point data types
        
        :param DataTypeManager dtm: optional program data-type manager, if specified generic data-types will be
                    returned in place of fixed-sized data-types.
        :return: array of floating-point data types
        :rtype: jpype.JArray[AbstractFloatDataType]
        """

    def getLength(self) -> int:
        """
        Get the encoded length (number of 8-bit bytes) of this float datatype.
        
        :return: encoded length of this float datatype.
        :rtype: int
        """

    @property
    def length(self) -> jpype.JInt:
        ...


class PointerType(java.lang.Enum[PointerType]):
    """
    ``PointerType`` specified the pointer-type associated with a pointer-typedef.
    
    
    .. seealso::
    
        | :obj:`PointerTypeSettingsDefinition`
    
        | :obj:`PointerTypedefBuilder`
    
        | :obj:`PointerTypedefInspector`
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[PointerType]
    """
    Normal absolute pointer offset
    """

    IMAGE_BASE_RELATIVE: typing.Final[PointerType]
    """
    Pointer offset relative to program image base.
    """

    RELATIVE: typing.Final[PointerType]
    """
    Pointer offset relative to pointer storage address.
    NOTE: This type has limited usefulness since it can only be applied to
    a pointer stored in memory based upon its storage location.  Type-propogation
    should be avoided on the resulting pointer typedef.
    """

    FILE_OFFSET: typing.Final[PointerType]
    """
    Pointer offset corresponds to file offset within an associated file.
    """


    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> PointerType:
        ...

    @staticmethod
    @typing.overload
    def valueOf(val: typing.Union[jpype.JInt, int]) -> PointerType:
        """
        Get the type associated with the specified value.
        
        :param jpype.JInt or int val: type value
        :return: type
        :rtype: PointerType
        :raises NoSuchElementException: if invalid value specified
        """

    @staticmethod
    def values() -> jpype.JArray[PointerType]:
        ...


class UnicodeDataType(AbstractStringDataType):
    """
    A fixed-length UTF-16 string :obj:`DataType`.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnicodeDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class FunctionDefinitionDataType(GenericDataType, FunctionDefinition):
    """
    Definition of a function for things like function pointers.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dtm: DataTypeManager):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], dtm: DataTypeManager):
        ...

    @typing.overload
    def __init__(self, sig: ghidra.program.model.listing.FunctionSignature):
        ...

    @typing.overload
    def __init__(self, sig: ghidra.program.model.listing.FunctionSignature, dtm: DataTypeManager):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], sig: ghidra.program.model.listing.FunctionSignature):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], sig: ghidra.program.model.listing.FunctionSignature, dtm: DataTypeManager):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], sig: ghidra.program.model.listing.FunctionSignature, universalID: ghidra.util.UniversalID, sourceArchive: SourceArchive, lastChangeTime: typing.Union[jpype.JLong, int], lastChangeTimeInSourceArchive: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        ...

    @typing.overload
    def __init__(self, function: ghidra.program.model.listing.Function, formalSignature: typing.Union[jpype.JBoolean, bool]):
        """
        Create a Function Definition based on a Function
        
        :param ghidra.program.model.listing.Function function: the function to use to create a Function Signature.
        :param jpype.JBoolean or bool formalSignature: if true only original formal types will be retained and 
        auto-params discarded (e.g., this, __return_storage_ptr__, etc.).  If false,
        the effective signature will be used where forced indirect and auto-params
        are reflected in the signature.  This option has no affect if the specified 
        function has custom storage enabled.
        """


class IllegalRenameException(ghidra.util.exception.UsrException):
    """
    Exception thrown if a data type does not allow its name to be changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: detailed message explaining exception
        """


class DataTypeDependencyException(java.lang.Exception):
    """
    ``DataTypeDependencyException`` corresponds to a datatype dependency failure.
    This can occur under various situations, including when trying to replace a dataType 
    with a dataType that depends on the dataType being replaced.  This error may also occur
    when a datatype dependency can not be satisfied.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class ParameterDefinitionImpl(ParameterDefinition):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], dataType: DataType, comment: typing.Union[java.lang.String, str]):
        """
        Constructs a new ParameterImp with an unassigned ordinal.  The ordinal will be
        established by the function definition.
        
        :param java.lang.String or str name: the name of the parameter.
        :param DataType dataType: the fixed-length datatype of the parameter
        :param java.lang.String or str comment: the comment to store about this parameter.
        :raises IllegalArgumentException: if invalid parameter datatype specified
        """

    @staticmethod
    def validateDataType(dataType: DataType, dtMgr: DataTypeManager, voidOK: typing.Union[jpype.JBoolean, bool]) -> DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
        not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         
        * Function definition datatype
        * An unsized/zero-element array
        
        
        :param DataType dataType: datatype to be checked.  If null specified the DEFAULT datatype will be returned.
        :param DataTypeManager dtMgr: target datatype manager (null permitted which will adopt default data organization)
        :param jpype.JBoolean or bool voidOK: true if checking return datatype and void is allow, else false.
        :return: cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        :rtype: DataType
        :raises java.lang.IllegalArgumentException: if an unacceptable datatype was specified
        """


class Array(DataType):
    """
    Array interface
    """

    class_: typing.ClassVar[java.lang.Class]
    ARRAY_LABEL_PREFIX: typing.Final = "ARRAY"

    def getArrayDefaultLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions) -> str:
        """
        Get the appropriate string to use as the label prefix
        for an array, taking into account the actual data at the memory location.
         
        
        See also :meth:`getDefaultLabelPrefix() <.getDefaultLabelPrefix>`
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object
        :param jpype.JInt or int len: the length of the data.
        :param DataTypeDisplayOptions options: options for how to format the default label prefix.
        :return: the label prefix or null if not applicable
        :rtype: str
        """

    def getArrayDefaultOffcutLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions, offcutLength: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the appropriate string to use as the offcut label prefix for an array, taking into
        account the actual data at the memory location.
         
        
        See also :meth:`getDefaultLabelPrefix() <.getDefaultLabelPrefix>`
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object
        :param jpype.JInt or int len: the length of the data.
        :param DataTypeDisplayOptions options: options for how to format the default label prefix.
        :param jpype.JInt or int offcutLength: offcut offset from start of buf
        :return: the offcut label prefix or null if not applicable
        :rtype: str
        """

    def getArrayRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the representation which corresponds to an array in memory.  This will either be a
        String for the ArrayStringable case, "??" for uninitialized data,
        or the empty string if it is not.
        
        :param ghidra.program.model.mem.MemBuffer buf: data buffer
        :param ghidra.docking.settings.Settings settings: data settings
        :param jpype.JInt or int length: length of array
        :return: a String if it is an array of chars; otherwise empty string, never null.
        :rtype: str
        """

    def getArrayValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Get the value object which corresponds to an array in memory.  This will either be a
        String for the ArrayStringable case or null.
        
        :param ghidra.program.model.mem.MemBuffer buf: data buffer
        :param ghidra.docking.settings.Settings settings: data settings
        :param jpype.JInt or int length: length of array
        :return: a String if it is an array of chars; otherwise null.
        :rtype: java.lang.Object
        """

    def getArrayValueClass(self, settings: ghidra.docking.settings.Settings) -> java.lang.Class[typing.Any]:
        """
        Get the value Class of a specific arrayDt with settings
        ( see :meth:`getArrayValueClass(Settings) <.getArrayValueClass>` ).
        
        :param ghidra.docking.settings.Settings settings: the relevant settings to use or null for default.
        :return: Class of the value to be returned by the array or null if it can vary
        or is unspecified (String or Array class will be returned).
        :rtype: java.lang.Class[typing.Any]
        """

    def getDataType(self) -> DataType:
        """
        Returns the dataType of the elements in the array.
        
        :return: the dataType of the elements in the array
        :rtype: DataType
        """

    def getElementLength(self) -> int:
        """
        Returns the length of an element in the array.  In the case
        of a Dynamic base datatype, this element length will have been explicitly specified
        at the time of construction.  For a zero-length base type an element length of 1 
        will be reported with :meth:`getLength() <.getLength>` returning the number of elements.
        
        :return: the length of one element in the array.
        :rtype: int
        """

    def getNumElements(self) -> int:
        """
        Returns the number of elements in the array
        
        :return: the number of elements in the array
        :rtype: int
        """

    @property
    def arrayValueClass(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def elementLength(self) -> jpype.JInt:
        ...

    @property
    def numElements(self) -> jpype.JInt:
        ...


class Integer7DataType(AbstractSignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Integer7DataType]
    """
    A statically defined Integer7DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class GifDataType(BuiltIn, Dynamic, Resource):

    @typing.type_check_only
    class GifDataImage(DataImage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAGIC_87: typing.ClassVar[jpype.JArray[jpype.JByte]]
    MAGIC_89: typing.ClassVar[jpype.JArray[jpype.JByte]]
    GIFMASK: typing.ClassVar[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Unicode32DataType(AbstractStringDataType):
    """
    A fixed-length UTF-32 string :obj:`DataType`.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Unicode32DataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a new unicode dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class AbstractComplexDataType(BuiltIn):
    """
    Base class for a variety of Complex data types of different sizes and types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], floats: AbstractFloatDataType, dtm: DataTypeManager):
        ...

    @staticmethod
    def getComplexDataType(size: typing.Union[jpype.JInt, int], dtm: DataTypeManager) -> DataType:
        ...


class Float16DataType(AbstractFloatDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Float16DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class StringRenderParser(java.lang.Object):
    """
    A parser to invert :meth:`StringDataInstance.getStringRepresentation() <StringDataInstance.getStringRepresentation>`,
    :meth:`StringDataInstance.getCharRepresentation() <StringDataInstance.getCharRepresentation>`, and related.
    """

    class StringParseException(ghidra.util.exception.UsrException):
        """
        An exception for when a string representation cannot be parsed.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, pos: typing.Union[jpype.JInt, int], expected: java.util.Set[java.lang.Character], got: typing.Union[jpype.JChar, int, str]):
            ...

        @typing.overload
        def __init__(self, pos: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class State(java.lang.Enum[StringRenderParser.State]):

        class_: typing.ClassVar[java.lang.Class]
        INIT: typing.Final[StringRenderParser.State]
        PREFIX: typing.Final[StringRenderParser.State]
        UNIT: typing.Final[StringRenderParser.State]
        STR: typing.Final[StringRenderParser.State]
        BYTE: typing.Final[StringRenderParser.State]
        BYTE_SUFFIX: typing.Final[StringRenderParser.State]
        COMMA: typing.Final[StringRenderParser.State]
        ESCAPE: typing.Final[StringRenderParser.State]
        CODE_POINT: typing.Final[StringRenderParser.State]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> StringRenderParser.State:
            ...

        @staticmethod
        def values() -> jpype.JArray[StringRenderParser.State]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, quoteChar: typing.Union[jpype.JChar, int, str], endian: ghidra.program.model.lang.Endian, charsetName: typing.Union[java.lang.String, str], includeBOM: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a parser
        
        :param jpype.JChar or int or str quoteChar: the character expected to enclose the representation. Use double quote (")
                    for strings. Use single quote (') for characters.
        :param ghidra.program.model.lang.Endian endian: the endian for unicode strings
        :param java.lang.String or str charsetName: the character set name, as in :meth:`Charset.forName(String) <Charset.forName>`
        :param jpype.JBoolean or bool includeBOM: true to prepend a byte order marker, if applicable
        """

    def finish(self, out: java.nio.ByteBuffer):
        """
        Finish parsing and encoded a string or character representation
        
        :param java.nio.ByteBuffer out: the destination buffer for the encoded string or character
        :raises StringParseException: if the representation is not complete
        """

    @typing.overload
    def parse(self, in_: java.nio.CharBuffer) -> java.nio.ByteBuffer:
        """
        Parse and encode a complete string or character representation
        
        :param java.nio.CharBuffer in: the buffer containing the representation
        :return: a buffer containing the encoded string or character
        :rtype: java.nio.ByteBuffer
        :raises StringParseException: if the representation could not be parsed
        :raises MalformedInputException: if a character sequence in the representation is not valid
        :raises UnmappableCharacterException: if a character cannot be encoded
        """

    @typing.overload
    def parse(self, out: java.nio.ByteBuffer, in_: java.nio.CharBuffer):
        """
        Parse and encode a portion of a string or character representation
        
        :param java.nio.ByteBuffer out: the destination buffer for the encoded string or character, having matching byte
                    order to the charset.
        :param java.nio.CharBuffer in: the source buffer for the representation
        :raises StringParseException: if the representation could not be parsed
        :raises MalformedInputException: if a character sequence in the representation is not valid
        :raises UnmappableCharacterException: if a character cannot be encoded
        """

    def reset(self):
        """
        Reset the parser
        """


class IBO32DataType(AbstractPointerTypedefBuiltIn):
    """
    ``IBO32DataType`` provides a Pointer-Typedef BuiltIn for
    a 32-bit Image Base Offset Relative Pointer.  This :obj:`TypeDef` implementation 
    specifies the :obj:`PointerType.IMAGE_BASE_RELATIVE` attribute/setting
    associated with a 32-bit :obj:`Pointer`.
     
    
    This class replaces the use of the old ``ImageBaseOffset32DataType``
    which did not implement the Pointer interface.  This is an alternative 
    :obj:`BuiltIn` implementation to using the more general :obj:`PointerTypedef`
    datatype with an unspecified referenced datatype.  :obj:`PointerTypedef` should 
    be used for other cases
    (see :meth:`createIBO32PointerTypedef(DataType) <.createIBO32PointerTypedef>`).
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[IBO32DataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a 32-bit Image Base Offset relative pointer-typedef.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        """
        Constructs a 32-bit Image Base Offset relative pointer-typedef.
        
        :param DataTypeManager dtm: data-type manager whose data organization should be used
        """

    @staticmethod
    def createIBO32PointerTypedef(referencedDataType: DataType) -> PointerTypedef:
        """
        Create a IBO32 :obj:`PointerTypedef` with auto-naming.  If needed, a name and category
        may be assigned to the returned instance.  Unlike using an immutable :obj:`IBO32DataType` instance
        the returned instance is mutable.
        
        :param DataType referencedDataType: referenced datatype or null
        :return: new IBO32 pointer-typedef
        :rtype: PointerTypedef
        """


class ByteDataType(AbstractUnsignedIntegerDataType):
    """
    Provides a definition of a Byte within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[ByteDataType]
    """
    A statically defined ByteDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Pointer32DataType(PointerDataType):
    """
    Pointer32 is really a factory for generating 4-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer32DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class ParameterDefinition(java.lang.Comparable[ParameterDefinition]):
    """
    ``ParameterDefinition`` specifies a parameter which can be
    used to specify a function definition.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComment(self) -> str:
        """
        Get the Comment for this variable
        
        :return: the comment
        :rtype: str
        """

    def getDataType(self) -> DataType:
        """
        Get the Data Type of this variable
        
        :return: the data type of the variable
        :rtype: DataType
        """

    def getLength(self) -> int:
        """
        Get the length of this variable
        
        :return: the length of the variable
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get the Name of this variable.
        
        :return: the name of the variable or null if no name has been specified.
        :rtype: str
        """

    def getOrdinal(self) -> int:
        """
        Get the parameter ordinal
        
        :return: the ordinal (index) of this parameter within the function signature.
        :rtype: int
        """

    @typing.overload
    def isEquivalent(self, variable: ghidra.program.model.listing.Variable) -> bool:
        """
        Determine if a variable corresponds to a parameter which is equivalent to 
        this parameter definition by both ordinal and datatype.  Name is not considered
        relevant.
        
        :param ghidra.program.model.listing.Variable variable: variable to be compared with this parameter definition.
        :return: true if the specified variable represents the same parameter by ordinal
        and dataType.  False will always be returned if specified variable is
        not a :obj:`Parameter`.
        :rtype: bool
        """

    @typing.overload
    def isEquivalent(self, parm: ParameterDefinition) -> bool:
        """
        Determine if parm is equivalent to this parameter definition by both ordinal 
        and datatype.  Name is not considered relevant.
        
        :param ParameterDefinition parm: parameter definition to be compared with this parameter definition.
        :return: true if the specified parameter definition represents the same parameter 
        by ordinal and dataType.
        :rtype: bool
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for this variable
        
        :param java.lang.String or str comment: the comment
        """

    def setDataType(self, type: DataType):
        """
        Set the Data Type of this variable.
        
        :param DataType type: dataType the fixed-length datatype of the parameter
        :raises java.lang.IllegalArgumentException: if invalid parameter datatype specified
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Set the name of this variable.
        
        :param java.lang.String or str name: the name
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def dataType(self) -> DataType:
        ...

    @dataType.setter
    def dataType(self, value: DataType):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...


class Integer3DataType(AbstractSignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Integer3DataType]
    """
    A statically defined Integer3DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DefaultAnnotationHandler(AnnotationHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getDescription(self) -> str:
        ...

    def getFileExtensions(self) -> jpype.JArray[java.lang.String]:
        ...

    def getLanguageName(self) -> str:
        ...

    @typing.overload
    def getPrefix(self, e: Enum, member: typing.Union[java.lang.String, str]) -> str:
        ...

    @typing.overload
    def getPrefix(self, c: Composite, dtc: DataTypeComponent) -> str:
        ...

    @typing.overload
    def getSuffix(self, e: Enum, member: typing.Union[java.lang.String, str]) -> str:
        ...

    @typing.overload
    def getSuffix(self, c: Composite, dtc: DataTypeComponent) -> str:
        ...

    @property
    def fileExtensions(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def languageName(self) -> java.lang.String:
        ...


class UnionDataType(CompositeDataTypeImpl, UnionInternal):
    """
    Basic implementation of the union data type.
    NOTE: Implementation is not thread safe when being modified.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str]):
        """
        Construct a new empty union with the given name within the
        specified categry path.  An empty union will report its length as 1 and 
        :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        NOTE: A constructor form which accepts a :obj:`DataTypeManager` should be used when possible
        since there may be performance benefits during datatype resolution.
        
        :param CategoryPath path: the category path indicating where this data type is located.
        :param java.lang.String or str name: the name of the new union
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], dtm: DataTypeManager):
        """
        Construct a new empty union with the given name and datatype manager
        within the specified categry path.  An empty union will report its 
        length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` will return true.
        
        :param CategoryPath path: the category path indicating where this data type is located.
        :param java.lang.String or str name: the name of the new union
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null. 
        Also, the data type manager may not yet contain this actual data type.
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], universalID: ghidra.util.UniversalID, sourceArchive: SourceArchive, lastChangeTime: typing.Union[jpype.JLong, int], lastChangeTimeInSourceArchive: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        """
        Construct a new empty union with the given name within the specified categry path.
        An empty union will report its length as 1 and :meth:`isNotYetDefined() <.isNotYetDefined>` 
        will return true.
        
        :param CategoryPath path: the category path indicating where this data type is located.
        :param java.lang.String or str name: the name of the new structure
        :param ghidra.util.UniversalID universalID: the id for the data type
        :param SourceArchive sourceArchive: the source archive for this data type
        :param jpype.JLong or int lastChangeTime: the last time this data type was changed
        :param jpype.JLong or int lastChangeTimeInSourceArchive: the last time this data type was changed in
        its source archive.
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null. 
        Also, the data type manager may not contain this actual data type.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct a new UnionDataType.
        NOTE: A constructor form which accepts a :obj:`DataTypeManager` should be used when possible
        since there may be performance benefits during datatype resolution.
        
        :param java.lang.String or str name: the name of this dataType
        """


class PascalUnicodeDataType(AbstractStringDataType):
    """
    A length-prefixed string :obj:`DataType` (max 64k bytes) with char size of 2 bytes,
    :obj:`UTF-16 <CharsetSettingsDefinition>` charset, unbounded
    (ignores containing field size, relies on embedded length value).
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[PascalUnicodeDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Undefined4DataType(Undefined):
    """
    Provides an implementation of a 4-byte dataType that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined4DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Cronstructs a new Undefined4 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class AbstractUnsignedIntegerDataType(AbstractIntegerDataType):
    """
    Base type for unsigned integer data types.
    """

    class_: typing.ClassVar[java.lang.Class]


class StringLayoutEnum(java.lang.Enum[StringLayoutEnum]):
    """
    Controls strings termination
     
    * :obj:`StringLayoutEnum.FIXED_LEN`
    * :obj:`StringLayoutEnum.CHAR_SEQ`
    * :obj:`StringLayoutEnum.NULL_TERMINATED_UNBOUNDED`
    * :obj:`StringLayoutEnum.NULL_TERMINATED_BOUNDED`
    * :obj:`StringLayoutEnum.PASCAL_255`
    * :obj:`StringLayoutEnum.PASCAL_64k`
    """

    class_: typing.ClassVar[java.lang.Class]
    FIXED_LEN: typing.Final[StringLayoutEnum]
    """
    Fixed length string, trailing nulls trimmed, interior nulls retained.
    """

    CHAR_SEQ: typing.Final[StringLayoutEnum]
    """
    Fixed length sequence of characters, all nulls retained.
    """

    NULL_TERMINATED_UNBOUNDED: typing.Final[StringLayoutEnum]
    """
    Null terminated string that ignores it's container's length when searching for terminating null character.
    """

    NULL_TERMINATED_BOUNDED: typing.Final[StringLayoutEnum]
    """
    Null-terminated string that is limited to it's container's length.
    """

    PASCAL_255: typing.Final[StringLayoutEnum]
    """
    Pascal string, using 1 byte for length field, max 255 char elements.
    """

    PASCAL_64k: typing.Final[StringLayoutEnum]
    """
    Pascal string, using 2 bytes for length field, max 64k char elements
    """


    def isFixedLen(self) -> bool:
        """
        Returns true if this layout is one of the fixed-size types.
        
        :return: boolean true if fixed length
        :rtype: bool
        """

    def isNullTerminated(self) -> bool:
        """
        Returns true if this layout is one of the null terminated types.
        
        :return: boolean true if null terminated string
        :rtype: bool
        """

    def isPascal(self) -> bool:
        """
        Returns true if this layout is one of the pascal types.
        
        :return: boolean true if pascal
        :rtype: bool
        """

    def shouldTrimTrailingNulls(self) -> bool:
        """
        Returns true if this layout should have its trailing null characters trimmed.
        
        :return: boolean true if trailing nulls should be trimmed
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> StringLayoutEnum:
        ...

    @staticmethod
    def values() -> jpype.JArray[StringLayoutEnum]:
        ...

    @property
    def nullTerminated(self) -> jpype.JBoolean:
        ...

    @property
    def pascal(self) -> jpype.JBoolean:
        ...

    @property
    def fixedLen(self) -> jpype.JBoolean:
        ...


class Pointer(DataType):
    """
    Interface for pointers
    """

    class_: typing.ClassVar[java.lang.Class]
    NaP: typing.Final = "NaP"
    """
    Pointer representation used when unable to generate a suitable address
    """


    def getDataType(self) -> DataType:
        """
        Returns the "pointed to" dataType
        
        :return: referenced datatype (may be null)
        :rtype: DataType
        """

    def newPointer(self, dataType: DataType) -> Pointer:
        """
        Creates a pointer to the indicated data type.
        
        :param DataType dataType: the data type to point to.
        :return: the newly created pointer.
        :rtype: Pointer
        """

    def typedefBuilder(self) -> PointerTypedefBuilder:
        """
        Construct a pointer-typedef builder base on this pointer.
         
        
        Other construction options are provided when directly instantiating 
        a :obj:`PointerTypedefBuilder`.  In addition the utility class :obj:`PointerTypedefInspector`
        can be used to easily determine pointer-typedef settings.
        
        :return: pointer-typedef builder
        :rtype: PointerTypedefBuilder
        :raises IllegalArgumentException: if an invalid name is 
        specified or pointer does not have a datatype manager.
        """

    @property
    def dataType(self) -> DataType:
        ...


class BitmapResourceDataType(DynamicDataType, Resource):
    """
    Definition of a Bitmap Resource Data Structure defined within the
    resources section of a windows executable.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class UnsignedLeb128DataType(AbstractLeb128DataType):
    """
    An Unsigned Little Endian Base 128 integer data type.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedLeb128DataType]
    """
    A statically defined UnsignedLeb128DataType instance.
    """


    @typing.overload
    def __init__(self):
        """
        Creates an unsigned little endian base 128 integer data type.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        """
        Creates an unsigned little endian base 128 integer data type.
        
        :param DataTypeManager dtm: the data type manager to associate with this data type.
        """


@typing.type_check_only
class PngResource(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataUtilities(java.lang.Object):

    class ClearDataMode(java.lang.Enum[DataUtilities.ClearDataMode]):
        """
        ``ClearDataMode`` specifies how conflicting data should be cleared
        when creating/re-creating data
        """

        class_: typing.ClassVar[java.lang.Class]
        CHECK_FOR_SPACE: typing.Final[DataUtilities.ClearDataMode]
        """
        Ensure that data will fit before clearing
        a single code unit at the specified data address.
        """

        CLEAR_SINGLE_DATA: typing.Final[DataUtilities.ClearDataMode]
        """
        Always clear a single code unit at the data
        address regardless of the ability for the
        desired data-type to fit.
        """

        CLEAR_ALL_UNDEFINED_CONFLICT_DATA: typing.Final[DataUtilities.ClearDataMode]
        """
        Clear all conflicting Undefined Data provided new data will
        fit within memory and not conflict with an
        instruction or other defined data.  Undefined refers to defined
        data with the Undefined data-type (see :meth:`Undefined.isUndefined(DataType) <Undefined.isUndefined>`).
        """

        CLEAR_ALL_DEFAULT_CONFLICT_DATA: typing.Final[DataUtilities.ClearDataMode]
        """
        Clear all Default Data provided new data will fit within memory and 
        not conflict with an instruction or other defined data.  In this
        context Default Data refers to all defined data with either an
        Undefined data-type (see :meth:`Undefined.isUndefined(DataType) <Undefined.isUndefined>`) or
        is considered a default pointer which is either:
         
        1. A pointer without a referenced datatype (i.e., addr), or
        2. An auto-named pointer-typedef without a referenced datatype 
        (e.g.,pointer __((offset(0x8))).
        """

        CLEAR_ALL_CONFLICT_DATA: typing.Final[DataUtilities.ClearDataMode]
        """
        Clear all conflicting data provided new data will fit within memory and 
        not conflict with an instruction.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataUtilities.ClearDataMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataUtilities.ClearDataMode]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def createData(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, newType: DataType, length: typing.Union[jpype.JInt, int], clearMode: DataUtilities.ClearDataMode) -> ghidra.program.model.listing.Data:
        """
        Create data where existing data may already exist.  Pointer datatype stacking will not
        be performed.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address addr: data address (offcut data address only allowed if clearMode == ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        :param DataType newType: new data-type being applied
        :param jpype.JInt or int length: data length (used only for Dynamic newDataType which has canSpecifyLength()==true)
        :param DataUtilities.ClearDataMode clearMode: see CreateDataMode
        :return: new data created
        :rtype: ghidra.program.model.listing.Data
        :raises CodeUnitInsertionException: if data creation failed
        """

    @staticmethod
    @typing.overload
    def createData(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, newType: DataType, length: typing.Union[jpype.JInt, int], stackPointers: typing.Union[jpype.JBoolean, bool], clearMode: DataUtilities.ClearDataMode) -> ghidra.program.model.listing.Data:
        """
        Create data where existing data may already exist.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address addr: data address (offcut data address only allowed if clearMode == ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        :param DataType newType: new data-type being applied
        :param jpype.JInt or int length: data length (used only for Dynamic newDataType which has canSpecifyLength()==true)
        :param jpype.JBoolean or bool stackPointers: see :meth:`reconcileAppliedDataType(DataType, DataType, boolean) <.reconcileAppliedDataType>`
        :param DataUtilities.ClearDataMode clearMode: see CreateDataMode
        :return: new data created
        :rtype: ghidra.program.model.listing.Data
        :raises CodeUnitInsertionException: if data creation failed
        """

    @staticmethod
    def findFirstConflictingAddress(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], ignoreUndefinedData: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        Finds the first conflicting address in the given address range.
        
        :param ghidra.program.model.listing.Program program: The program.
        :param ghidra.program.model.address.Address addr: The starting address of the range.
        :param jpype.JInt or int length: The length of the range.
        :param jpype.JBoolean or bool ignoreUndefinedData: True if the search should ignore :obj:`Undefined` data as a
        potential conflict, or false if :obj:`Undefined` data should trigger conflicts.
        :return: The address of the first conflict in the range, or null if there were no conflicts.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getDataAtAddress(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Get the data for the given address.
         
        
        This will return a Data if and only if there is data that starts at the given address.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address address: the data address
        :return: the Data that starts at the given address or null if the address is code or offcut
        :rtype: ghidra.program.model.listing.Data
        """

    @staticmethod
    def getDataAtLocation(loc: ghidra.program.util.ProgramLocation) -> ghidra.program.model.listing.Data:
        """
        Get the data for the given address; if the code unit at the address is
        an instruction, return null.
        
        :param ghidra.program.util.ProgramLocation loc: the location. This provides the address and subcomponent
        within the data at the address.
        :return: the data or null if the code unit at the address is an instruction.
        :rtype: ghidra.program.model.listing.Data
        """

    @staticmethod
    def getMaxAddressOfUndefinedRange(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Get the maximum address of an undefined data range starting at addr.
        Both undefined code units and defined data which have an Undefined
        data type are included in the range.
        
        :param ghidra.program.model.listing.Program program: the program which will have its code units checked.
        :param ghidra.program.model.address.Address addr: the address where this will start checking for Undefined data. This address can
        be offcut into an Undefined Data.
        :return: end of undefined range or null if addr does not correspond
        to an undefined location.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getNextNonUndefinedDataAfter(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Get the next defined data that comes after the address indicated by addr and that is
        no more than the specified maxAddr and that is not a sized undefined data type.
        
        :param ghidra.program.model.listing.Program program: the program whose code units are to be checked to find the next
        non-undefined data.
        :param ghidra.program.model.address.Address addr: start looking for data after this address.
        :param ghidra.program.model.address.Address maxAddr: do not look any further than this address.
        :return: the next defined data that isn't a sized undefined data type, or return null if
        there isn't one.
        :rtype: ghidra.program.model.listing.Data
        """

    @staticmethod
    def isUndefinedData(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the specified addr corresponds to an undefined data location
        where both undefined code units and defined data which has an Undefined
        data type is considered to be undefined.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address addr: the data address
        :return: true if the data is undefined
        :rtype: bool
        """

    @staticmethod
    def isUndefinedRange(program: ghidra.program.model.listing.Program, startAddress: ghidra.program.model.address.Address, endAddress: ghidra.program.model.address.Address) -> bool:
        """
        Determine if there is only undefined data from the specified startAddress to the specified
        endAddress. The start and end addresses must both be in the same defined block of memory.
        
        :param ghidra.program.model.listing.Program program: the program whose code units are to be checked.
        :param ghidra.program.model.address.Address startAddress: start looking for undefined data at this address in a defined memory block.
        :param ghidra.program.model.address.Address endAddress: do not look any further than this address.
        This must be greater than or equal to the startAddress and must be in the same memory block
        as the start address or false is returned.
        :return: true if the range of addresses in a memory block is where only undefined data exists.
        :rtype: bool
        """

    @staticmethod
    def isValidDataTypeName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified name is a valid data-type name
        
        :param java.lang.String or str name: candidate data-type name
        :return: true if name is valid, else false
        :rtype: bool
        """

    @staticmethod
    def reconcileAppliedDataType(originalDataType: DataType, newDataType: DataType, stackPointers: typing.Union[jpype.JBoolean, bool]) -> DataType:
        """
        Determine the final data-type which should be applied based upon a
        user applied type of newDataType on an existing originalDataType.
        Pointer conversion is performed when appropriate, otherwise the
        newDataType is returned unchanged.
        If newDataType is a FunctionDefinition, or Typedef to a FunctionDefinition, it will either be stacked
        with the existing pointer if enabled/applicable, or will be converted to a pointer since
        FunctionDefinitions may only been used in the form of a pointer.
        Note that originalDataType and newDataType should be actual applied types.
        (i.e., do not strip typedefs, pointers, arrays, etc.).
        
        :param DataType originalDataType: existing data type onto which newDataTye is applied
        :param DataType newDataType: new data-type being applied
        :param jpype.JBoolean or bool stackPointers: If true the following data type transformation will be performed:
         
        * If newDataType is a default pointer and the originalDataType
        is a pointer the new pointer will wrap
        the existing pointer thus increasing is 'depth'
        (e.g., int * would become int ** when default pointer applied).
        If the originalDataType is not a pointer the newDataType will be returned unchanged.
        
        * If the originalDataType is any type of pointer the supplied newDatatype
        will replace the pointer's base type (e.g., int * would become db * when
        newDataType is:obj:`ByteDataType`).
        
         
        If false, only required transformations will be applied, Example:
        if newDataType is a FunctionDefinitionDataType it will be transformed
        to a pointer before being applied.
        :return: either a combined pointer data-type or the newDataType specified with any
        required transformation
        :rtype: DataType
        """


class FileTimeDataType(BuiltIn):
    """
    A datatype to interpret the FILETIME timestamp
    convention, which is based on the number of 100-nanosecond ticks
    since January 1, 1601.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DefaultDataType(DataTypeImpl):
    """
    Provides an implementation of a byte that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.ClassVar[DefaultDataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Get the Undefined byte as a Scalar.
        
        :param ghidra.program.model.mem.MemBuffer buf: the data buffer.
        :param ghidra.docking.settings.Settings settings: the display settings to use.
        :param jpype.JInt or int length: the number of bytes to get the value from.
        :return: the data Object.
        :rtype: java.lang.Object
        """


class BitFieldDataType(AbstractDataType):
    """
    ``BitFieldDataType`` provides a means of defining a minimally sized bit-field
    for use within data structures.  The length (i.e., storage size) of this bitfield datatype is
    the minimum number of bytes required to contain the bitfield at its specified offset.
    The effective bit-size of a bitfield will be limited by the size of the base
    datatype whose size may be controlled by its associated datatype manager and data organization
    (e.g., :obj:`IntegerDataType`). 
     
    
    NOTE: Instantiation of this datatype implementation is intended for internal use only.  
    Creating and manipulating bitfields should be accomplished directly via Structure or Union 
    bitfield methods.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def checkBaseDataType(baseDataType: DataType):
        """
        Check a bitfield base datatype
        
        :param DataType baseDataType: bitfield base data type (Enum, AbstractIntegerDataType and derived TypeDefs permitted)
        :raises InvalidDataTypeException: if baseDataType is invalid as a bitfield base type.
        """

    def clone(self, dtm: DataTypeManager) -> BitFieldDataType:
        """
        Clone this bitfield to a new datatype manager.  This may change the effective bit
        size and storage size of the resulting datatype based upon the data organization
        of the specified dtm.
        
        :param DataTypeManager dtm: target datatype manager
        :return: new instance or same instance of dtm is unchanged.
        :rtype: BitFieldDataType
        """

    def copy(self, dtm: DataTypeManager) -> DataType:
        """
        Returns a clone of this built-in DataType
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.copy(ghidra.program.model.data.DataTypeManager)`
        """

    def getBaseDataType(self) -> DataType:
        """
        Get the base datatype associated with this bit-field 
        (e.g., int, long, etc., or TypeDef to supported base type)
        
        :return: base data type
        :rtype: DataType
        """

    def getBaseTypeSize(self) -> int:
        """
        Get the size of the base data type based upon the associated data organization.
        
        :return: base type size
        :rtype: int
        """

    def getBitOffset(self) -> int:
        """
        Get the bit offset of the least-significant bit relative to bit-0 of the
        base datatype (i.e., least significant bit).  This corresponds to the
        right-shift amount within the base data type when viewed as a big-endian value.
        
        :return: bit offset
        :rtype: int
        """

    def getBitSize(self) -> int:
        """
        Get the effective bit size of this bit-field which may not exceed the size of the
        base datatype.
        
        :return: bit size
        :rtype: int
        """

    def getDeclaredBitSize(self) -> int:
        """
        Get the declared bit size of this bit-field which may be larger than the effective
        size which could be truncated.
        
        :return: bit size as defined by the field construction/declaration.
        :rtype: int
        """

    @staticmethod
    def getEffectiveBitSize(declaredBitSize: typing.Union[jpype.JInt, int], baseTypeByteSize: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the effective bit-size based upon the specified base type size.  A bit size
        larger than the base type size will truncated to the base type size.
        
        :param jpype.JInt or int declaredBitSize: 
        :param jpype.JInt or int baseTypeByteSize: 
        :return: effective bit-size
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getMinimumStorageSize(bitSize: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the minimum storage size in bytes for a given size in bits.
        This does not consider the bit offset which may increase the required 
        storage.
        
        :param jpype.JInt or int bitSize: number of bits within bitfield
        :return: minimum storage size in bytes
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getMinimumStorageSize(bitSize: typing.Union[jpype.JInt, int], bitOffset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the minimum storage size in bytes for a given size in bits with 
        the specified bitOffset (lsb position within big endian storage)
        
        :param jpype.JInt or int bitSize: number of bits within bitfield
        :param jpype.JInt or int bitOffset: normalized bitfield offset within storage (lsb)
        :return: minimum storage size in bytes
        :rtype: int
        """

    def getPrimitiveBaseDataType(self) -> AbstractIntegerDataType:
        """
        Get the base datatype associated with this bit-field 
        (e.g., int, long, etc., or TypeDef to supported base type)
        
        :return: base data type
        :rtype: AbstractIntegerDataType
        """

    def getSettingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        """
        Gets a list of all the settingsDefinitions used by this datatype.
        
        :return: a list of the settingsDefinitions used by this datatype.
        :rtype: jpype.JArray[ghidra.docking.settings.SettingsDefinition]
        """

    def getStorageSize(self) -> int:
        """
        Get the packing storage size in bytes associated with this bit-field which may be
        larger than the base type associated with the fields original definition.
        Returned value is the same as :meth:`getLength() <.getLength>`.
        
        :return: packing storage size in bytes
        :rtype: int
        """

    @staticmethod
    def isValidBaseDataType(baseDataType: DataType) -> bool:
        """
        Check if a specified baseDataType is valid for use with a bitfield
        
        :param DataType baseDataType: bitfield base data type (Enum, AbstractIntegerDataType and derived TypeDefs permitted)
        :return: true if baseDataType is valid else false
        :rtype: bool
        """

    @property
    def baseDataType(self) -> DataType:
        ...

    @property
    def declaredBitSize(self) -> jpype.JInt:
        ...

    @property
    def storageSize(self) -> jpype.JInt:
        ...

    @property
    def primitiveBaseDataType(self) -> AbstractIntegerDataType:
        ...

    @property
    def bitSize(self) -> jpype.JInt:
        ...

    @property
    def baseTypeSize(self) -> jpype.JInt:
        ...

    @property
    def settingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        ...

    @property
    def bitOffset(self) -> jpype.JInt:
        ...


class PaddingSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    The Settings definition for setting the padded/unpadded setting
    """

    class_: typing.ClassVar[java.lang.Class]
    PADDED_VALUE: typing.Final = 1
    UNPADDED_VALUE: typing.Final = 0
    DEF: typing.Final[PaddingSettingsDefinition]

    def isPadded(self, settings: ghidra.docking.settings.Settings) -> bool:
        """
        Checks if the current settings are padded or unpadded
        
        :param ghidra.docking.settings.Settings settings: the instance settings to check
        :return: true if the value is "padded".
        :rtype: bool
        """

    def setPadded(self, settings: ghidra.docking.settings.Settings, isPadded: typing.Union[jpype.JBoolean, bool]):
        """
        Set true if value should display padded out with zero's
        
        :param ghidra.docking.settings.Settings settings: settings to set padded value
        :param jpype.JBoolean or bool isPadded: true for padding
        """

    @property
    def padded(self) -> jpype.JBoolean:
        ...


class DataImage(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getImageFileType(self) -> str:
        """
        Returns the type of the underlying image data, suitable for
        :meth:`ImageIO.write(java.awt.image.RenderedImage, String, java.io.File) <ImageIO.write>`'s formatName
        parameter.
        
        :return: String image format type, ie. "png", "gif", "bmp"
        :rtype: str
        """

    def getImageIcon(self) -> javax.swing.ImageIcon:
        """
        Return image icon
        
        :return: image object
        :rtype: javax.swing.ImageIcon
        """

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Set string description (returned by toString)
        
        :param java.lang.String or str description:
        """

    @property
    def imageIcon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def imageFileType(self) -> java.lang.String:
        ...


class Pointer16DataType(PointerDataType):
    """
    Pointer16 is really a factory for generating 2-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer16DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class RenderUnicodeSettingsDefinition(ghidra.docking.settings.JavaEnumSettingsDefinition[RenderUnicodeSettingsDefinition.RENDER_ENUM]):
    """
    Settings definition for controlling the display of UNICODE characters.
    """

    class RENDER_ENUM(java.lang.Enum[RenderUnicodeSettingsDefinition.RENDER_ENUM]):

        class_: typing.ClassVar[java.lang.Class]
        ALL: typing.Final[RenderUnicodeSettingsDefinition.RENDER_ENUM]
        BYTE_SEQ: typing.Final[RenderUnicodeSettingsDefinition.RENDER_ENUM]
        ESC_SEQ: typing.Final[RenderUnicodeSettingsDefinition.RENDER_ENUM]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RenderUnicodeSettingsDefinition.RENDER_ENUM:
            ...

        @staticmethod
        def values() -> jpype.JArray[RenderUnicodeSettingsDefinition.RENDER_ENUM]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    RENDER: typing.Final[RenderUnicodeSettingsDefinition]

    def isRenderAlphanumericOnly(self, settings: ghidra.docking.settings.Settings) -> bool:
        """
        Gets the current rendering setting from the given settings objects or returns
        the default if not in either settings object
        
        :param ghidra.docking.settings.Settings settings: the instance settings
        :return: the current value for this settings definition
        :rtype: bool
        """

    @property
    def renderAlphanumericOnly(self) -> jpype.JBoolean:
        ...


class BitmapResource(java.lang.Object):

    @typing.type_check_only
    class BitmapDataImage(DataImage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BitmapDecompressResult(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buf: ghidra.program.model.mem.MemBuffer):
        """
        
        
        :raises IOException:
        """

    def getBitCount(self) -> int:
        ...

    def getClrImportant(self) -> int:
        ...

    def getClrUsed(self) -> int:
        ...

    def getColorMap(self, buf: ghidra.program.model.mem.MemBuffer) -> jpype.JArray[jpype.JInt]:
        ...

    def getColorMapLength(self) -> int:
        """
        
        
        :return: int
        :rtype: int
        """

    def getCompression(self) -> int:
        ...

    def getDataImage(self, buf: ghidra.program.model.mem.MemBuffer) -> DataImage:
        """
        
        
        :return: DataImage
        :rtype: DataImage
        """

    def getHeight(self) -> int:
        ...

    def getImageDataSize(self) -> int:
        """
        Returns the uncompressed image data size.  The default implementation will
        return the image data size specified by the header if non-zero, otherwize
        a computed data length will be returned based upon getHeight(), getWidth() and
        getBitCount().
        
        :return: image data size
        :rtype: int
        """

    def getMaskLength(self) -> int:
        """
        
        
        :return: int size of mask section in bytes
        :rtype: int
        """

    def getPixelData(self, buf: ghidra.program.model.mem.MemBuffer) -> jpype.JArray[jpype.JByte]:
        ...

    def getPlanes(self) -> int:
        ...

    def getRGBData(self, buf: ghidra.program.model.mem.MemBuffer) -> jpype.JArray[jpype.JInt]:
        ...

    def getRawSizeImage(self) -> int:
        """
        Get the raw image data size as contained within this resource.  If compressed, 
        this will be smaller than the value returned by :meth:`getImageDataSize() <.getImageDataSize>` which reflects
        the uncompressed size.
        
        :return: raw image data size
        :rtype: int
        """

    def getSize(self) -> int:
        ...

    def getWidth(self) -> int:
        ...

    def getXPelsPerMeter(self) -> int:
        ...

    def getYPelsPerMeter(self) -> int:
        ...

    @property
    def clrUsed(self) -> jpype.JInt:
        ...

    @property
    def rGBData(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def colorMapLength(self) -> jpype.JInt:
        ...

    @property
    def rawSizeImage(self) -> jpype.JInt:
        ...

    @property
    def planes(self) -> jpype.JInt:
        ...

    @property
    def xPelsPerMeter(self) -> jpype.JInt:
        ...

    @property
    def yPelsPerMeter(self) -> jpype.JInt:
        ...

    @property
    def dataImage(self) -> DataImage:
        ...

    @property
    def pixelData(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def imageDataSize(self) -> jpype.JInt:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @property
    def maskLength(self) -> jpype.JInt:
        ...

    @property
    def bitCount(self) -> jpype.JInt:
        ...

    @property
    def compression(self) -> jpype.JInt:
        ...

    @property
    def colorMap(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def clrImportant(self) -> jpype.JInt:
        ...

    @property
    def height(self) -> jpype.JInt:
        ...


class IntegerDataType(AbstractSignedIntegerDataType):
    """
    Basic implementation for an signed Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[IntegerDataType]
    """
    A statically defined IntegerDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Structure(Composite):
    """
    The structure interface.
     
    
    NOTE: A zero-length Structure will report a length of 1 which will result in
    improper code unit sizing since we are unable to support a defined data of length 0.
     
    
    NOTE: The use of zero-length bitfields within non-packed structures is discouraged since they have
    no real affect and are easily misplaced. Their use should be reserved for packed
    structures.
    """

    class BitOffsetComparator(java.util.Comparator[java.lang.Object]):
        """
        ``BitOffsetComparator`` provides ability to compare an normalized bit offset (see
        :meth:`getNormalizedBitfieldOffset(int, int, int, int, boolean) <.getNormalizedBitfieldOffset>`) with a
        :obj:`DataTypeComponent` object. The offset will be considered equal (0) if the component
        contains the offset. A normalized component bit numbering is used to establish the footprint
        of each component with an ordinal-based ordering (assumes specific LE/BE allocation rules).
        Bit offsets for this comparator number the first allocated bit of the structure as 0 and the
        last allocated bit of the structure as (8 * structLength) - 1. For big-endian bitfields the
        msb of the bitfield will be assigned the lower bit-number (assumes msb-allocated-first),
        while little-endian will perform similar numbering assuming byte-swap and bit-reversal of the
        storage unit (assumes lsb-allocated-first). Both cases result in a normalized view where
        normalized bit-0 is allocated first.
         
         
        Example:Big-Endian (normalized view):   | . . . . . . . 7 | 8 9 . . . . . . |   |<--------------------------------->| storage-size (2-bytes)                       |<--------------| bit-offset (6, lsb position within storage unit)                   |<--->|               bit-size (3)Little-Endian (normalized view, w/ storage byte-swap and bit-reversal):   | . . . . . . 6 7 | 8 . . . . . . . |   |------------>|                       bit-offset (6, lsb position within storage unit)                 |<--->|                 bit-size (3)
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE_LE: typing.Final[java.util.Comparator[java.lang.Object]]
        INSTANCE_BE: typing.Final[java.util.Comparator[java.lang.Object]]

        def __init__(self, bigEndian: typing.Union[jpype.JBoolean, bool]):
            ...

        @staticmethod
        def getNormalizedBitfieldOffset(byteOffset: typing.Union[jpype.JInt, int], storageSize: typing.Union[jpype.JInt, int], effectiveBitSize: typing.Union[jpype.JInt, int], bitOffset: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
            """
            Compute the normalized bit offset of a bitfield relative to the start of a structure.
             
            NOTE: This implementation currently relies only on endianness to dictate bit allocation
            ordering. If future support is added for alternate bitfield packing, this implementation
            will require modification.
            
            :param jpype.JInt or int byteOffset: byte offset within structure of storage unit
            :param jpype.JInt or int storageSize: storage unit size (i.e., component length)
            :param jpype.JInt or int effectiveBitSize: size of bitfield in bits
            :param jpype.JInt or int bitOffset: left shift amount for bitfield based upon a big-endian view of the
                        storage unit
            :param jpype.JBoolean or bool bigEndian: true if big-endian packing applies
            :return: normalized bit-offset
            :rtype: int
            """


    class_: typing.ClassVar[java.lang.Class]

    def clearAtOffset(self, offset: typing.Union[jpype.JInt, int]):
        """
        Clears all defined components containing the specified offset in this structure. If the offset
        corresponds to a bit-field or zero-length component (e.g., 0-element array) multiple 
        components may be cleared.  This method will preserve the structure length and placement 
        of other components since freed space will appear as undefined components.
         
        
        To avoid clearing zero-length components at a specified offset within a non-packed structure,
        the :meth:`replaceAtOffset(int, DataType, int, String, String) <.replaceAtOffset>` may be used with to clear
        only the sized component at the offset by specified :obj:`DataType.DEFAULT` as the replacement
        datatype.
        
        :param jpype.JInt or int offset: the byte offset into the structure where the component(s) are to be deleted.
        """

    def clearComponent(self, ordinal: typing.Union[jpype.JInt, int]):
        """
        Clears the defined component at the specified component ordinal. Clearing a component within
        a non-packed structure causes a defined component to be replaced with a number of undefined 
        components.  This may not the case when clearing a zero-length component or bit-field 
        which may not result in such undefined components.  In the case of a packed structure 
        clearing is always completed without backfill.
        
        :param jpype.JInt or int ordinal: the ordinal of the component to clear (numbering starts at 0).
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    def deleteAll(self):
        """
        Remove all components from this structure, effectively setting the
        length to zero.  Packing and minimum alignment settings are unaffected.
        """

    def deleteAtOffset(self, offset: typing.Union[jpype.JInt, int]):
        """
        Deletes all defined components containing the specified offset in this structure. If the offset
        corresponds to a bit-field or zero-length component (e.g., 0-element array) multiple 
        components may be deleted.  Bit-fields are only cleared and may leave residual undefined 
        components in their place.  This method will generally reduce the length of the structure.
        The :meth:`clearAtOffset(int) <.clearAtOffset>` method should be used for non-packed structures to 
        preserve the structure length and placement of other components.
        
        :param jpype.JInt or int offset: the byte offset into the structure where the component(s) are to be deleted.
        An offset equal to the structure length may be specified to delete any trailing zero-length 
        components.
        :raises java.lang.IllegalArgumentException: if a negative offset is specified
        """

    def getComponent(self, ordinal: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Returns the component of this structure with the indicated ordinal.
        
        :param jpype.JInt or int ordinal: the ordinal of the component requested (numbering starts at 0).
        :return: the data type component.
        :rtype: DataTypeComponent
        :raises java.lang.IndexOutOfBoundsException: if the ordinal is out of bounds
        """

    def getComponentAt(self, offset: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Gets the first non-zero-length component that starts at the specified offset. 
        Note that one or more components may share the same offset when a bit-field or zero-length
        component is present since these may share an offset.  A null may be returned under one of
        the following conditions:
         
        * offset only corresponds to a zero-length component within a packed structure
        * offset corresponds to a padding byte within a packed structure
        * offset is contained within a component but is not the starting offset of that component
        * offset is >= structure length
        
        If a bitfield is returned, and the caller supports bitfields, it is recommended that 
        :meth:`getComponentsContaining(int) <.getComponentsContaining>` be invoked to gather all bitfields which contain the 
        specified offset.
        
        :param jpype.JInt or int offset: the byte offset into this structure
        :return: the first component that starts at specified offset or null if not found.
        :rtype: DataTypeComponent
        """

    def getComponentContaining(self, offset: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Gets the first non-zero-length component that contains the byte at the specified offset. 
        Note that one or more components may share the same offset when a bit-field or zero-length
        component is present since these may share an offset.  A null may be returned under one of
        the following conditions:
         
        * offset only corresponds to a zero-length component within a packed structure
        * offset corresponds to a padding byte within a packed structure
        * offset is >= structure length.
        
        If a bitfield is returned, and the caller supports bitfields, it is recommended that 
        :meth:`getComponentsContaining(int) <.getComponentsContaining>` be invoked to gather all bitfields which contain the 
        specified offset.
        
        :param jpype.JInt or int offset: the byte offset into this structure
        :return: the first non-zero-length component that contains the byte at the specified offset
        or null if not found.
        :rtype: DataTypeComponent
        """

    def getComponentsContaining(self, offset: typing.Union[jpype.JInt, int]) -> java.util.List[DataTypeComponent]:
        """
        Get an ordered list of components that contain the byte at the specified offset.
        Unlike :meth:`getComponentAt(int) <.getComponentAt>` and :meth:`getComponentContaining(int) <.getComponentContaining>` this method will
        include zero-length components if they exist at the specified offset.  For this reason the
        specified offset may equal the structure length to obtain and trailing zero-length components.
        Note that this method will only return more than one component when a bit-fields and/or 
        zero-length components are present since these may share an offset. An empty list may be 
        returned under the following conditions:
         
        * offset only corresponds to a padding byte within a packed structure
        * offset is equal structure length and no trailing zero-length components exist
        * offset is > structure length
        
        
        :param jpype.JInt or int offset: the byte offset into this structure
        :return: a list of zero or more components containing the specified offset
        :rtype: java.util.List[DataTypeComponent]
        """

    def getDataTypeAt(self, offset: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Returns the lowest-level component that contains the specified offset. This is useful 
        for structures that have sub-structures. This method is best used when working with 
        known structures which do not contain bitfields or zero-length components since in 
        those situations multiple components may correspond to the specified offset.  
        A similar ambiguous condition occurs if offset corresponds to a union component.
        
        :param jpype.JInt or int offset: the byte offset into this data type.
        :return: a primitive component data type which contains the specified offset.
        :rtype: DataTypeComponent
        """

    def getDefinedComponentAtOrAfterOffset(self, offset: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Gets the first defined component located at or after the specified offset.  If a
        component contains the specified offset that component will be returned.
        Note: The returned component may be a zero-length component.
        
        :param jpype.JInt or int offset: the byte offset into this structure
        :return: the first defined component located at or after the specified offset or null if not found.
        :rtype: DataTypeComponent
        """

    def growStructure(self, amount: typing.Union[jpype.JInt, int]):
        """
        Increases the size of the structure by the specified positive amount by adding undefined filler at the
        end of the structure.  NOTE: This method only has an affect on non-packed structures.
        
        :param jpype.JInt or int amount: the amount by which to grow the structure.
        :raises IllegalArgumentException: if amount < 0
        """

    @typing.overload
    def insertAtOffset(self, offset: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Inserts a new datatype at the specified offset into this structure. Inserting a component
        will cause any conflicting components to shift down to the extent necessary to avoid a
        conflict.
        
        :param jpype.JInt or int offset: the byte offset into the structure where the new datatype is to be inserted.
        :param DataType dataType: the datatype to insert.  If :obj:`DataType.DEFAULT` is specified for a packed 
                        structure an :obj:`Undefined1DataType` will be used in its place.
        :param jpype.JInt or int length: the length to associate with the dataType. For fixed length types a length
                    <= 0 will use the length of the resolved dataType.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not allowed to be inserted
                    into this composite data type or an invalid length is specified. For example,
                    suppose dt1 contains dt2. Therefore it is not valid to insert dt1 to dt2 since
                    this would cause a cyclic dependency.
        """

    @typing.overload
    def insertAtOffset(self, offset: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Inserts a new datatype at the specified offset into this structure. Inserting a component
        will cause any conflicting components to shift down to the extent necessary to avoid a
        conflict.
         
        
        This method does not support bit-field insertions which must use the method 
        :meth:`insertBitFieldAt(int, int, int, DataType, int, String, String) <.insertBitFieldAt>`.
        
        :param jpype.JInt or int offset: the byte offset into the structure where the new datatype is to be inserted.
        :param DataType dataType: the datatype to insert.  If :obj:`DataType.DEFAULT` is specified for a packed 
                        structure an :obj:`Undefined1DataType` will be used in its place.
        :param jpype.JInt or int length: the length to associate with the dataType. For fixed length types a length
                    <= 0 will use the length of the resolved dataType.
        :param java.lang.String or str name: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the componentDataType created.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: if the specified data type is not allowed to be inserted
                    into this composite data type or an invalid length is specified. For example,
                    suppose dt1 contains dt2. Therefore it is not valid to insert dt1 to dt2 since
                    this would cause a cyclic dependency.
        """

    def insertBitField(self, ordinal: typing.Union[jpype.JInt, int], byteWidth: typing.Union[jpype.JInt, int], bitOffset: typing.Union[jpype.JInt, int], baseDataType: DataType, bitSize: typing.Union[jpype.JInt, int], componentName: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Inserts a new bitfield at the specified ordinal position in this structure. Within packed
        structures the specified byteWidth and bitOffset will be ignored since packing will occur at
        the specified ordinal position. The resulting component length and bitfield details will
        reflect the use of minimal storage sizing.
         
        
        For structures with packing disabled, a component shift will only occur if the bitfield placement
        conflicts with another component. If no conflict occurs, the bitfield will be placed at the
        specified location consuming any DEFAULT components as needed. When a conflict does occur a
        shift will be performed at the ordinal position based upon the specified byteWidth. When
        located onto existing bitfields they will be packed together provided they do not conflict,
        otherwise the conflict rule above applies.
         
        
        Supported packing starts with bit-0 (lsb) of the first byte for little-endian, and
        with bit-7 (msb) of the first byte for big-endian. This is the default behavior for most
        compilers. Insertion behavior may not work as expected if packing rules differ from this.
        
        :param jpype.JInt or int ordinal: the ordinal of the component to be inserted (numbering starts at 0).
        :param jpype.JInt or int byteWidth: the storage allocation unit width which contains the bitfield. Must be large
                    enough to contain the "effective bit size" and corresponding bitOffset. The actual
                    component size used will be recomputed during insertion.
        :param jpype.JInt or int bitOffset: corresponds to the bitfield left-shift amount with the storage unit when
                    viewed as big-endian. The final offset may be reduced based upon the minimal
                    storage size determined during insertion.
        :param DataType baseDataType: the bitfield base datatype (certain restrictions apply).
        :param jpype.JInt or int bitSize: the declared bitfield size in bits. The effective bit size may be adjusted
                    based upon the specified baseDataType.
        :param java.lang.String or str componentName: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the bitfield component created whose associated data type will be BitFieldDataType.
        :rtype: DataTypeComponent
        :raises InvalidDataTypeException: if the specified baseDataType is not a valid base type for
                    bitfields.
        :raises java.lang.IndexOutOfBoundsException: if ordinal is less than 0 or greater than the current
                    number of components.
        """

    def insertBitFieldAt(self, byteOffset: typing.Union[jpype.JInt, int], byteWidth: typing.Union[jpype.JInt, int], bitOffset: typing.Union[jpype.JInt, int], baseDataType: DataType, bitSize: typing.Union[jpype.JInt, int], componentName: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Inserts a new bitfield at the specified location in this composite. This method is intended
        to be used with structures with packing disabled where the bitfield will be precisely placed. Within an
        packed structure the specified byteOffset, byteWidth and bitOffset will be used to identify
        the appropriate ordinal but may not be preserved. The component length will be computed based
        upon the specified parameters and will be reduced from byteWidth to its minimal size for the
        new component.
         
        
        When packing disabled, a component shift will only occur if the bitfield placement conflicts
        with another component. If no conflict occurs, the bitfield will be placed at the specified
        location consuming any DEFAULT components as needed. When a conflict does occur a shift will
        be performed at the point of conflict based upon the specified byteWidth. When located onto
        existing bitfields they will be packed together provided they do not conflict, otherwise the
        conflict rule above applies.
         
        
        Supported packing for little-endian fills lsb first, whereas big-endian fills msb first.
        Insertion behavior may not work as expected if packing rules differ from this.
         
        
         
        Zero length bitfields may be inserted although they have no real affect when packing disabled. 
        Only the resulting byte offset within the structure is of significance in
        determining its ordinal placement.
        
        :param jpype.JInt or int byteOffset: the first byte offset within this structure which corresponds to the first
                    byte of the specified storage unit identified by its byteWidth.
        :param jpype.JInt or int byteWidth: the storage unit width which contains the bitfield. Must be large enough to
                    contain the specified bitSize and corresponding bitOffset. The actual component
                    size used will be recomputed during insertion.
        :param jpype.JInt or int bitOffset: corresponds to the bitfield left-shift amount with the storage unit when
                    viewed as big-endian. The final offset may be reduced based upon the minimal
                    storage size determined during insertion.
        :param DataType baseDataType: the bitfield base datatype (certain restrictions apply).
        :param java.lang.String or str componentName: the field name to associate with this component.
        :param jpype.JInt or int bitSize: the bitfield size in bits. A bitSize of 0 may be specified although its name
                    will be ignored.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the componentDataType created whose associated data type will be BitFieldDataType.
        :rtype: DataTypeComponent
        :raises InvalidDataTypeException: if the specified data type is not a valid base type for
                    bitfields.
        """

    @typing.overload
    def replace(self, ordinal: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int]) -> DataTypeComponent:
        """
        Replaces the component at the specified ordinal with a new component using the 
        specified datatype, length, name and comment.  In the case of a packed structure 
        a 1-for-1 replacement will occur.  In the case of a non-packed structure certain
        restrictions apply:
         
        * A zero-length component may only be replaced with another zero-length component.
        * If ordinal corresponds to a bit-field, all bit-fields which overlap the specified 
        bit-field will be replaced.
        
        There must be sufficient space to complete the replacement factoring in the space freed 
        by the consumed component(s).  If there are no remaining defined components beyond the 
        consumed components the structure will expand its length as needed. For a packed structure, this 
        method behaves the same as a ordinal-based delete followed by an insert.
         
        
        Datatypes not permitted include :obj:`FactoryDataType` types, non-sizable 
        :obj:`Dynamic` types, and those which result in a circular direct dependency.
         
        
        NOTE: In general, it is not recommended that this method be used with non-packed 
        structures where the replaced component is a bit-field.
        
        :param jpype.JInt or int ordinal: the ordinal of the component to be replaced (numbering starts at 0).
        :param DataType dataType: the datatype to insert. If :obj:`DataType.DEFAULT` is specified for a packed 
                    structure an :obj:`Undefined1DataType` will be used in its place.  If :obj:`DataType.DEFAULT` 
                    is specified for a non-packed structure this is equivelant to :meth:`clearComponent(int) <.clearComponent>`, ignoring
                    the length, name and comment arguments.
        :param jpype.JInt or int length: component length for containing the specified dataType. A positive length is required 
                    for sizable :obj:`Dynamic` datatypes and should be specified as -1 for fixed-length
                    datatypes to rely on their resolved size.
        :return: the new component.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: may be caused by: 1) invalid offset specified, 2) invalid datatype or 
                    associated length specified, or 3) insufficient space for replacement.
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    @typing.overload
    def replace(self, ordinal: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Replaces the component at the specified ordinal with a new component using the 
        specified datatype, length, name and comment.  In the case of a packed structure 
        a 1-for-1 replacement will occur.  In the case of a non-packed structure certain
        restrictions apply:
         
        * A zero-length component may only be replaced with another zero-length component.
        * If ordinal corresponds to a bit-field, all bit-fields which overlap the specified 
        bit-field will be replaced.
        
        There must be sufficient space to complete the replacement factoring in the space freed 
        by the consumed component(s).  If there are no remaining defined components beyond the 
        consumed components the structure will expand its length as needed. For a packed structure, this 
        method behaves the same as a ordinal-based delete followed by an insert.
         
        
        Datatypes not permitted include :obj:`FactoryDataType` types, non-sizable 
        :obj:`Dynamic` types, and those which result in a circular direct dependency.
         
        
        NOTE: In general, it is not recommended that this method be used with non-packed 
        structures where the replaced component is a bit-field.
        
        :param jpype.JInt or int ordinal: the ordinal of the component to be replaced (numbering starts at 0).
        :param DataType dataType: the datatype to insert.  If :obj:`DataType.DEFAULT` is specified for a packed 
                    structure an :obj:`Undefined1DataType` will be used in its place.  If :obj:`DataType.DEFAULT` 
                    is specified for a non-packed structure this is equivelant to :meth:`clearComponent(int) <.clearComponent>`, ignoring
                    the length, name and comment arguments.
        :param jpype.JInt or int length: component length for containing the specified dataType. A positive length is required 
                    for sizable :obj:`Dynamic` datatypes and should be specified as -1 for fixed-length
                    datatypes to rely on their resolved size.
        :param java.lang.String or str name: the field name to associate with this component or null.
        :param java.lang.String or str comment: the comment to associate with this component or null.
        :return: the new component.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: may be caused by: 1) invalid offset specified, 2) invalid datatype or 
                    associated length specified, or 3) insufficient space for replacement.
        :raises java.lang.IndexOutOfBoundsException: if component ordinal is out of bounds
        """

    def replaceAtOffset(self, offset: typing.Union[jpype.JInt, int], dataType: DataType, length: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Replaces all components containing the specified byte offset with a new component using the 
        specified datatype, length, name and comment. If the offset corresponds to a bit-field 
        more than one component may be consumed by this replacement.  
         
        
        This method may not be used to replace a zero-length component since there may be any number 
        of zero-length components at the same offset. If the only defined component(s) at the specified
        offset are zero-length the subsequent undefined will be replaced in the case of a non-packed 
        structure.  For a packed structure such a case would be treated as an insert as would an offset 
        which is not contained within a component.  
         
        
        For a non-packed structure a replacement will attempt to consume sufficient
        space within moving other defined components.  There must be sufficient space to complete 
        the replacement factoring in the space freed by the consumed component(s).  When replacing the 
        last defined component the structure size will be expanded as needed to fit the new component.
        For a packed If there are no remaining defined components beyond 
        the consumed components, or an offset equals to the structure length is specified, the
        structure will expand its length as needed. 
         
        
        For a non-packed structure the new component will use the specified offset.  In the case of 
        packed structure, the actual offset will be determined during a repack.
         
        
        Datatypes not permitted include :obj:`FactoryDataType` types, non-sizable 
        :obj:`Dynamic` types, and those which result in a circular direct dependency.
        
        :param jpype.JInt or int offset: the byte offset into the structure where the datatype is to be placed.  The specified
                    offset must be less than the length of the structure.
        :param DataType dataType: the datatype to insert.  If :obj:`DataType.DEFAULT` is specified for a packed 
                        structure an :obj:`Undefined1DataType` will be used in its place.  If :obj:`DataType.DEFAULT` 
                    is specified for a non-packed structure this is equivelant to clearing all components, 
                    which contain the specified offset, ignoring the length, name and comment arguments.
        :param jpype.JInt or int length: component length for containing the specified dataType. A positive length is required 
                    for sizable :obj:`Dynamic` datatypes and should be specified as -1 for fixed-length
                    datatypes to rely on their resolved size.
        :param java.lang.String or str name: the field name to associate with this component or null.
        :param java.lang.String or str comment: the comment to associate with this component or null.
        :return: the new component.
        :rtype: DataTypeComponent
        :raises java.lang.IllegalArgumentException: may be caused by: 1) invalid offset specified, 2) invalid datatype or 
                    associated length specified, or 3) insufficient space for replacement.
        """

    def setLength(self, length: typing.Union[jpype.JInt, int]):
        """
        Set the size of the structure to the specified byte-length.  If the length is shortened defined
        components will be cleared and removed as required.
        NOTE: This method only has an affect on non-packed structures.
        
        :param jpype.JInt or int length: new structure length
        :raises IllegalArgumentException: if length < 0
        """

    @property
    def dataTypeAt(self) -> DataTypeComponent:
        ...

    @property
    def componentContaining(self) -> DataTypeComponent:
        ...

    @property
    def component(self) -> DataTypeComponent:
        ...

    @property
    def definedComponentAtOrAfterOffset(self) -> DataTypeComponent:
        ...

    @property
    def componentsContaining(self) -> java.util.List[DataTypeComponent]:
        ...

    @property
    def componentAt(self) -> DataTypeComponent:
        ...


class DataTypeConflictHandler(java.lang.Object):
    """
    :obj:`DataTypeConflictHandler` provides the :obj:`DataTypeManager` with a handler that is 
    used to provide a disposition when a datatype conflict is detected during 
    :meth:`DataTypeManager.resolve(DataType, DataTypeConflictHandler) <DataTypeManager.resolve>` processing.
     
    
    Known Issue: resolve processing identifies a conflict on an outer datatype (e.g., Structure)
    before a resolve conflict decision has been made on its referenced datatypes.  Depending
    upon the conflict handler used, this can result in duplicate conflict types once the full
    resolution is completed (see GP-3632).
    """

    class ConflictResolutionPolicy(java.lang.Enum[DataTypeConflictHandler.ConflictResolutionPolicy]):
        """
        ``ConflictResolutionPolicy`` indicates the conflict resolution policy
        which should be applied when any conflict is encountered
        """

        class_: typing.ClassVar[java.lang.Class]
        RENAME_AND_ADD: typing.Final[DataTypeConflictHandler.ConflictResolutionPolicy]
        USE_EXISTING: typing.Final[DataTypeConflictHandler.ConflictResolutionPolicy]
        REPLACE_EXISTING: typing.Final[DataTypeConflictHandler.ConflictResolutionPolicy]
        REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD: typing.Final[DataTypeConflictHandler.ConflictResolutionPolicy]

        def getHandler(self) -> DataTypeConflictHandler:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataTypeConflictHandler.ConflictResolutionPolicy:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataTypeConflictHandler.ConflictResolutionPolicy]:
            ...

        @property
        def handler(self) -> DataTypeConflictHandler:
            ...


    class ConflictResult(java.lang.Enum[DataTypeConflictHandler.ConflictResult]):
        """
        ``ConflictResult`` indicates the resolution which should be
        applied to a specific conflict
        """

        class_: typing.ClassVar[java.lang.Class]
        RENAME_AND_ADD: typing.Final[DataTypeConflictHandler.ConflictResult]
        USE_EXISTING: typing.Final[DataTypeConflictHandler.ConflictResult]
        REPLACE_EXISTING: typing.Final[DataTypeConflictHandler.ConflictResult]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DataTypeConflictHandler.ConflictResult:
            ...

        @staticmethod
        def values() -> jpype.JArray[DataTypeConflictHandler.ConflictResult]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_HANDLER: typing.Final[DataTypeConflictHandler]
    REPLACE_HANDLER: typing.ClassVar[DataTypeConflictHandler]
    KEEP_HANDLER: typing.Final[DataTypeConflictHandler]
    REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER: typing.Final[DataTypeConflictHandler]
    """
    This :obj:`conflict handler <DataTypeConflictHandler>` behaves similar to 
    the :obj:`.DEFAULT_HANDLER` with the difference being that a 
    empty composite (see :meth:`Composite.isNotYetDefined() <Composite.isNotYetDefined>`) will be 
    replaced by a similar non-empty composite type.  Alignment (e.g., packing)
    is not considered when determining conflict resolution.
     
    
    For datatypes originating from a source archive with matching ID, the 
    replacment strategy will utilize the implementation with the 
    latest timestamp.
     
    
    Unlike the :obj:`.DEFAULT_HANDLER`, follow-on dependency datatype 
    resolutions will retain the same conflict resolution strategy.
    """


    def __init__(self):
        ...

    def getSubsequentHandler(self) -> DataTypeConflictHandler:
        """
        Returns the appropriate handler for recursive resolve calls.
        """

    def resolveConflict(self, addedDataType: DataType, existingDataType: DataType) -> DataTypeConflictHandler.ConflictResult:
        """
        Callback to handle conflicts in a datatype manager when new datatypes are added that
        have the same name as an existing datatype. The implementer of this interface should do
        one of the following:
                return the addedDataType - which means to replace the existingDataType with the addedDataType
                                    (may throw exception if the datatypes are not compatible)
                return the existingDataType the addedDataType will be ignored and the existing dataType will
                                    be used.
                return a new DataType with a new name/category
        
        :param DataType addedDataType: the datatype being added.
        :param DataType existingDataType: the datatype that exists with the same name/category as the one added
        :return: an enum specify how to handle the conflict
        :rtype: DataTypeConflictHandler.ConflictResult
        """

    def shouldUpdate(self, sourceDataType: DataType, localDataType: DataType) -> bool:
        """
        Callback invoked when an associated dataType is being resolved and its local version of the
        dataType is different from the source archive's dataType.  This method returns true if the
        local version should be updated to the archive's version of the dataType.  Otherwise, the
        local dataType will be used (without updating) in the resolve operation.
        
        :param DataType sourceDataType: 
        :param DataType localDataType: 
        :return: true if the localDataType should be updated to be equivalent to the sourceDataType.
        :rtype: bool
        """

    @property
    def subsequentHandler(self) -> DataTypeConflictHandler:
        ...


class Dynamic(BuiltInDataType):
    """
    A DataType class that must compute its length based upon actual data.
    This type may be referred to directly within a listing (including pointers).
    This type may only appear within a structure if canSpecifyLength() returns 
    true.  A pointer to this type can always appear within a structure.
    TypeDef to this data-type should not be allowed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canSpecifyLength(self) -> bool:
        """
        Determine if the length may be specified for an instanceof this 
        datatype (e.g., :obj:`Data`, :obj:`Array`, :obj:`DataTypeComponent`, etc.).
        
        :return: true if a user-specified length can be used, else false
        :rtype: bool
        """

    def getLength(self, buf: ghidra.program.model.mem.MemBuffer, maxLength: typing.Union[jpype.JInt, int]) -> int:
        """
        Compute the length for this data-type which corresponds to the 
        specified memory location.
        
        :param ghidra.program.model.mem.MemBuffer buf: memory location
        :param jpype.JInt or int maxLength: maximum number of bytes to consume in computing length, or -1
        for unspecified.
        :return: data length or -1 if it could not be determined.  Returned length may exceed
        maxLength if data-type does not supported constrained lengths.
        :rtype: int
        """

    def getReplacementBaseType(self) -> DataType:
        """
        Returns a suitable replacement base data-type for pointers and arrays 
        when exporting to C code
        
        :return: suitable base data-type for this Dynamic data-type
        :rtype: DataType
        """

    @property
    def replacementBaseType(self) -> DataType:
        ...


class AnnotationHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL AnnotationHandler CLASSES MUST END IN "AnnotationHandler".  If not,
    the ClassSearcher will not find them.
     
    AnnotationHandlers provide prefix/suffix information for various datatypes
    for specific C-like languages.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        """
        Returns the description of the specific handler
        
        :return: the description of the specific handler
        :rtype: str
        """

    def getFileExtensions(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array of known extensions for the output file type.  If no extensions are 
        preferred, the an empty array should be returned.
        
        :return: an array of known extensions for the output file type.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getLanguageName(self) -> str:
        """
        Returns the name of the C-like language that this handler supports
        
        :return: the name of the C-like language that this handler supports
        :rtype: str
        """

    @typing.overload
    def getPrefix(self, e: Enum, member: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the prefix for type Enum
        
        :param Enum e: the Enum datatype
        :param java.lang.String or str member: the name of the member of the Enum
        :return: the prefix for type Enum
        :rtype: str
        """

    @typing.overload
    def getPrefix(self, c: Composite, dtc: DataTypeComponent) -> str:
        """
        Returns the prefix for type Composite
        
        :param Composite c: the Composite datatype
        :param DataTypeComponent dtc: the name of the member of the Composite
        :return: the prefix for type Composite
        :rtype: str
        """

    @typing.overload
    def getSuffix(self, e: Enum, member: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the suffix for type Enum
        
        :param Enum e: the Enum datatype
        :param java.lang.String or str member: the name of the member of the Enum
        :return: the suffix for type Enum
        :rtype: str
        """

    @typing.overload
    def getSuffix(self, c: Composite, dtc: DataTypeComponent) -> str:
        """
        Returns the suffix for type Composite
        
        :param Composite c: the Composite datatype
        :param DataTypeComponent dtc: the name of the member of the Composite
        :return: the suffix for type Composite
        :rtype: str
        """

    def toString(self) -> str:
        """
        Returns a string description of this handler.
        
        :return: a string description of this handler
        :rtype: str
        """

    @property
    def fileExtensions(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def languageName(self) -> java.lang.String:
        ...


class PascalStringDataType(AbstractStringDataType):
    """
    A length-prefixed string :obj:`DataType` (max 64k bytes) with char size of 1 byte,
    user setable :obj:`charset <CharsetSettingsDefinition>` (default ASCII),
    unbounded (ignores containing field size, relies on embedded length value).
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[PascalStringDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class StructureFactory(java.lang.Object):
    """
    Creates and initializes :obj:`Structure` objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_STRUCTURE_NAME: typing.Final = "struct"

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def createStructureDataType(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, dataLength: typing.Union[jpype.JInt, int]) -> Structure:
        """
        Creates a :obj:`StructureDataType` instance based upon the information
        provided.  The instance will not be placed in memory.
         
        
        This method is just a pass-through method for
        :meth:`createStructureDataType(Program,Address,int,String,boolean) <.createStructureDataType>`
        equivalent to calling:
         
            Structure newStructure = StructureFactory.createStructureDataType(
                program, address, dataLength, DEFAULT_STRUCTURE_NAME, true );
         
        
        :param ghidra.program.model.listing.Program program: The program to which the structure will belong.
        :param ghidra.program.model.address.Address address: The address of the structure.
        :param jpype.JInt or int dataLength: The number of components to add to the structure.
        :return: A new structure not yet added to memory.
        :rtype: Structure
        :raises IllegalArgumentException: for the following conditions:
                 
        * if dataLength is not greater than zero
        * if the number of components to add exceeds the available
        address space
        * if there are any instructions in the provided
        address space
        * if there are no data components to add to the structure
        """

    @staticmethod
    @typing.overload
    def createStructureDataType(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, dataLength: typing.Union[jpype.JInt, int], structureName: typing.Union[java.lang.String, str], makeUniqueName: typing.Union[jpype.JBoolean, bool]) -> Structure:
        """
        Creates a :obj:`StructureDataType` instance based upon the information
        provided.  The instance will not be placed in memory.
        
        :param ghidra.program.model.listing.Program program: The program to which the structure will belong.
        :param ghidra.program.model.address.Address address: The address of the structure.
        :param jpype.JInt or int dataLength: The number of components to add to the structure.
        :param java.lang.String or str structureName: The name of the structure to create.
        :param jpype.JBoolean or bool makeUniqueName: True indicates that the provided name should be
                altered as necessary in order to make it unique in the program.
        :return: A new structure not yet added to memory.
        :rtype: Structure
        :raises IllegalArgumentException: for the following conditions:
                 
        * if structureName is null
        * if dataLength is not greater than zero
        * if the number of components to add exceeds the available
        address space
        * if there are any instructions in the provided
        address space
        * if there are no data components to add to the structure
        """

    @staticmethod
    @typing.overload
    def createStructureDataTypeInStrucuture(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, fromPath: jpype.JArray[jpype.JInt], toPath: jpype.JArray[jpype.JInt]) -> Structure:
        """
        Creates a :obj:`StructureDataType` instance, which is inside of
        another structure, based upon the information provided.  The instance
        will not be placed in memory.
         
        
        This method is just a pass-through method for
        :meth:`createStructureDataTypeInStrucuture(Program,Address,int[],int[],String,boolean) <.createStructureDataTypeInStrucuture>`
        equivalent to calling:
         
            Structure newStructure = StructureFactory.createStructureDataTypeInStrucuture(
                program, address, fromPath, toPath, DEFAULT_STRUCTURE_NAME, true );
         
        
        :param ghidra.program.model.listing.Program program: The program to which the structure will belong.
        :param ghidra.program.model.address.Address address: The address of the structure.
        :param jpype.JArray[jpype.JInt] fromPath: The path to the first element in the parent structure
                that will be in the new structure.
        :param jpype.JArray[jpype.JInt] toPath: The path to the last element in the parent structure
                that will be in the new structure.
        :return: A new structure not yet added to memory.
        :rtype: Structure
        :raises IllegalArgumentException: for the following conditions:
                 
        * if the component at fromPath or the component
        attoPath are null
        * if there is not data to add to the structure
        * if the parent data type is not a structure
        """

    @staticmethod
    @typing.overload
    def createStructureDataTypeInStrucuture(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, fromPath: jpype.JArray[jpype.JInt], toPath: jpype.JArray[jpype.JInt], structureName: typing.Union[java.lang.String, str], makeUniqueName: typing.Union[jpype.JBoolean, bool]) -> Structure:
        """
        Creates a :obj:`StructureDataType` instance, which is inside of
        another structure, based upon the information provided.  The instance
        will not be placed in memory.
        
        :param ghidra.program.model.listing.Program program: The program to which the structure will belong.
        :param ghidra.program.model.address.Address address: The address of the structure.
        :param jpype.JArray[jpype.JInt] fromPath: The path to the first element in the parent structure
                that will be in the new structure.
        :param jpype.JArray[jpype.JInt] toPath: The path to the last element in the parent structure
                that will be in the new structure.
        :param java.lang.String or str structureName: the name of the structure to create
        :param jpype.JBoolean or bool makeUniqueName: True indicates that the provided name should be
                altered as necessary in order to make it unique in the program.
        :return: A new structure not yet added to memory.
        :rtype: Structure
        :raises IllegalArgumentException: for the following conditions:
                 
        * if structureName is null
        * if the component at fromPath or the component
        attoPath are null
        * if there is not data to add to the structure
        * if the parent data type is not a structure
        """


class BuiltInDataType(DataType, ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL DATATYPE CLASSES MUST END IN "DataType".  If not,
    the ClassSearcher will not find them.
     
    Interface to mark classes as a built-in data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCTypeDeclaration(self, dataOrganization: DataOrganization) -> str:
        """
        Generate a suitable C-type declaration for this data-type as a #define or typedef.
        Since the length of a Dynamic datatype is unknown, such datatypes
        should only be referenced in C via a pointer.  FactoryDataTypes
        should never be referenced and will always return null.
        
        :param DataOrganization dataOrganization: or null for default
        :return: definition C-statement (e.g., #define or typedef) or null
        if type name is a standard C-primitive name or if type is FactoryDataType
        or Dynamic.
        :rtype: str
        """

    def setDefaultSettings(self, settings: ghidra.docking.settings.Settings):
        """
        Set the default settings for this data type.
         
        
        NOTE: This method is reserved for internal DB use.
         
        
        
        :param ghidra.docking.settings.Settings settings: the settings to be used as this dataTypes default settings.
        """

    @property
    def cTypeDeclaration(self) -> java.lang.String:
        ...


class DoubleComplexDataType(AbstractComplexDataType):
    """
    Provides a definition of a ``complex`` built-in data type consisting of two double point
    numbers in the IEEE 754 double precision format.
     
    
    The size of the double point numbers is determined by the program's data organization as defined
    by the language/compiler spec
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[DoubleComplexDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class LEB128(java.lang.Object):
    """
    Logic for reading LEB128 values.
     
    
    LEB128 is a variable length integer encoding that uses 7 bits per byte, with the high bit
    being reserved as a continuation flag, with the least significant bytes coming first 
    (**L**ittle **E**ndian **B**ase **128**).
     
    
    This implementation only supports reading values that decode to at most 64 bits (to fit into
    a java long).
     
    
    When reading a value, you must already know if it was written as a signed or unsigned value to
    be able to decode it correctly.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_SUPPORTED_LENGTH: typing.Final = 10
    """
    Max number of bytes that is supported by the deserialization code.
    """


    def __init__(self):
        ...

    @staticmethod
    def decode(bytes: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], isSigned: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Decodes a LEB128 number from a byte array and returns it as a long.
         
        
        See :meth:`read(InputStream, boolean) <.read>`
        
        :param jpype.JArray[jpype.JByte] bytes: the bytes representing the LEB128 number
        :param jpype.JInt or int offset: offset in byte array of where to start reading bytes
        :param jpype.JBoolean or bool isSigned: true if the value is signed
        :return: long integer value.  Caller must treat it as unsigned if isSigned parameter was
                set to false
        :rtype: int
        :raises IOException: if array offset is invalid, decoded value is outside the range of a java
        64 bit int (or it used more than 10 bytes to be encoded), or 
        the end of the array was reached before reaching the end of the encoded value
        """

    @staticmethod
    def getLength(is_: java.io.InputStream) -> int:
        """
        Returns the length of the variable length LEB128 value.
        
        :param java.io.InputStream is: InputStream to get bytes from
        :return: length of the LEB128 value, or -1 if the end of the value is not found
        :rtype: int
        :raises IOException: if error getting next byte from stream
        """

    @staticmethod
    def read(is_: java.io.InputStream, isSigned: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Reads a LEB128 number from the stream and returns it as a java 64 bit long int.
         
        
        Large unsigned integers that use all 64 bits are returned in a java native
        'long' type, which is signed.  It is up to the caller to treat the value as unsigned.
         
        
        Large integers that use more than 64 bits will cause an IOException to be thrown.
        
        :param java.io.InputStream is: :obj:`InputStream` to get bytes from
        :param jpype.JBoolean or bool isSigned: true if the value is signed
        :return: long integer value.  Caller must treat it as unsigned if isSigned parameter was
        set to false
        :rtype: int
        :raises IOException: if an I/O error occurs or decoded value is outside the range of a java
        64 bit int (or it used more than 10 bytes to be encoded), or 
        there is an error or EOF getting a byte from the InputStream before reaching the end of the
        encoded value
        """

    @staticmethod
    def signed(is_: java.io.InputStream) -> int:
        """
        Reads a signed LEB128 variable length integer from the stream.
        
        :param java.io.InputStream is: :obj:`InputStream` to get bytes from
        :return: leb128 value, as a long
        :rtype: int
        :raises IOException: if an I/O error occurs or decoded value is outside the range of a java
        64 bit int (or it used more than 10 bytes to be encoded), or 
        there is an error or EOF getting a byte from the InputStream before reaching the end of the
        encoded value
        """

    @staticmethod
    def unsigned(is_: java.io.InputStream) -> int:
        """
        Reads an unsigned LEB128 variable length integer from the stream.
        
        :param java.io.InputStream is: :obj:`InputStream` to get bytes from
        :return: leb128 value, as a long
        :rtype: int
        :raises IOException: if an I/O error occurs or decoded value is outside the range of a java
        64 bit int (or it used more than 10 bytes to be encoded), or 
        there is an error or EOF getting a byte from the InputStream before reaching the end of the
        encoded value
        """


class QWordDataType(AbstractUnsignedIntegerDataType):
    """
    Provides a definition of a Quad Word within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[QWordDataType]
    """
    A statically defined QWordDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class TypedefDataType(GenericDataType, TypeDef):
    """
    Basic implementation for the typedef dataType.
     
    NOTE: Settings are immutable when a DataTypeManager has not been specified (i.e., null).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dt: DataType):
        """
        Construct a new typedef within the root category
        
        :param java.lang.String or str name: name of this typedef
        :param DataType dt: data type that is being typedef'ed (may not be null)
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], dt: DataType):
        """
        Construct a new typedef.
        
        :param CategoryPath path: category path for this datatype
        :param java.lang.String or str name: name of this typedef
        :param DataType dt: data type that is being typedef'ed (may not be null)
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], dt: DataType, dtm: DataTypeManager):
        """
        Construct a new typedef.
        
        :param CategoryPath path: category path for this datatype
        :param java.lang.String or str name: name of this typedef
        :param DataType dt: data type that is being typedef'ed (may not be null)
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null.
        """

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], dt: DataType, universalID: ghidra.util.UniversalID, sourceArchive: SourceArchive, lastChangeTime: typing.Union[jpype.JLong, int], lastChangeTimeInSourceArchive: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        """
        Construct a new typedef.
        
        :param CategoryPath path: category path for this datatype
        :param java.lang.String or str name: name of this typedef
        :param DataType dt: data type that is being typedef'ed (may not be null)
        :param ghidra.util.UniversalID universalID: the id for the data type
        :param SourceArchive sourceArchive: the source archive for this data type
        :param jpype.JLong or int lastChangeTime: the last time this data type was changed
        :param jpype.JLong or int lastChangeTimeInSourceArchive: the last time this data type was changed in
        its source archive.
        :param DataTypeManager dtm: the data type manager associated with this data type. This can be null.
        """

    @staticmethod
    def clone(typedef: TypeDef, dtm: DataTypeManager) -> TypeDef:
        ...

    @staticmethod
    def copy(typedef: TypeDef, dtm: DataTypeManager) -> TypedefDataType:
        ...

    @staticmethod
    def copyTypeDefSettings(src: TypeDef, dest: TypeDef, clearBeforeCopy: typing.Union[jpype.JBoolean, bool]):
        """
        Copy all default settings , which correspond to a TypeDefSettingsDefinition,
        from the specified src TypeDef to the specified dest TypeDef.
        
        :param TypeDef src: settings source TypeDef
        :param TypeDef dest: settings destination TypeDef
        :param jpype.JBoolean or bool clearBeforeCopy: if true dest default settings will be cleared before copy performed
        """

    @staticmethod
    def generateTypedefName(modelType: TypeDef) -> str:
        """
        Generate a name for the typedef based upon its current :obj:`TypeDefSettingsDefinition` settings.
        
        :param TypeDef modelType: model typedef from which name should be derived
        :return: generated typedef auto-name with attribute specification
        :rtype: str
        """


class Complex8DataType(AbstractComplexDataType):
    """
    Provides a definition of a ``complex`` built-in data type consisting of two 32-bit floating point
    numbers in the IEEE 754 double precision format.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Complex8DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DataType(java.lang.Object):
    """
    The interface that all datatypes must implement.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[DataType]
    """
    Singleton instance of default datatype.
    """

    VOID: typing.Final[DataType]
    """
    Instance of void datatype (never use ``==``)
    
    
    .. deprecated::
    
    should use :obj:`VoidDataType.dataType` instead
    """

    CONFLICT_SUFFIX: typing.Final = ".conflict"
    """
    Datatype name conflict suffix.
     
    See :obj:`DataTypeUtilities` for various methods related to conflict name handling.
    Direct use of this string in application/user-level code is discouraged.
    """

    TYPEDEF_ATTRIBUTE_PREFIX: typing.Final = "__(("
    TYPEDEF_ATTRIBUTE_SUFFIX: typing.Final = "))"
    NO_SOURCE_SYNC_TIME: typing.Final = 0
    NO_LAST_CHANGE_TIME: typing.Final = 0

    def addParent(self, dt: DataType):
        """
        Inform this data type that it has the given parent
         
        
        TODO: This method is reserved for internal DB use.
        
        :param DataType dt: parent data type
        """

    def clone(self, dtm: DataTypeManager) -> DataType:
        """
        Returns an instance of this DataType using the specified :obj:`DataTypeManager` to allow
        its use of the corresponding :obj:`DataOrganization` while retaining its unique identity
        (see :meth:`getUniversalID() <.getUniversalID>` and archive association (see :meth:`getSourceArchive() <.getSourceArchive>`) if
        applicable.
         
        
        This instance will be returned if this datatype's DataTypeManager matches the
        specified dtm. The recursion depth of a clone will stop on any datatype whose
        :obj:`DataTypeManager` matches the specified dtm and simply use the existing datatype
        instance.
         
        
        NOTE: In general, this method should not be used to obtain an instance to be modified.
        In most cases changes may be made directly to this instance if supported or to a
        :meth:`copy(DataTypeManager) <.copy>` of this type.
        
        :param DataTypeManager dtm: the data-type manager instance whose data-organization should apply.
        :return: cloned instance which may be the same as this instance
        :rtype: DataType
        """

    def copy(self, dtm: DataTypeManager) -> DataType:
        """
        Returns a new instance (shallow copy) of this DataType with a new identity and no
        source archive association.
         
        
        Any reference to other datatypes will use :meth:`clone(DataTypeManager) <.clone>`.
        
        :param DataTypeManager dtm: the data-type manager instance whose data-organization should apply.
        :return: new instanceof of this datatype
        :rtype: DataType
        """

    def dataTypeAlignmentChanged(self, dt: DataType):
        """
        Notification that the given datatype's alignment has changed.
         
        
        DataTypes may need to make internal changes in response. 
        
        TODO: This method is reserved for internal DB use. 
        
        
        :param DataType dt: the datatype that has changed.
        """

    def dataTypeDeleted(self, dt: DataType):
        """
        Informs this datatype that the given datatype has been deleted.
         
        
        TODO: This method is reserved for internal DB use. 
        
        
        :param DataType dt: the datatype that has been deleted.
        """

    def dataTypeNameChanged(self, dt: DataType, oldName: typing.Union[java.lang.String, str]):
        """
        Informs this datatype that its name has changed from the indicated old name.
         
        
        TODO: This method is reserved for internal DB use. 
        
        
        :param DataType dt: the datatype whose name changed
        :param java.lang.String or str oldName: the datatype's old name
        """

    def dataTypeReplaced(self, oldDt: DataType, newDt: DataType):
        """
        Informs this datatype that the given oldDT has been replaced with newDT
         
        
        TODO: This method is reserved for internal DB use. 
        
        
        :param DataType oldDt: old datatype
        :param DataType newDt: new datatype
        """

    def dataTypeSizeChanged(self, dt: DataType):
        """
        Notification that the given datatype's size has changed.
         
        
        DataTypes may need to make internal changes in response. 
        
        TODO: This method is reserved for internal DB use. 
        
        
        :param DataType dt: the datatype that has changed.
        """

    def dependsOn(self, dt: DataType) -> bool:
        """
        Check if this datatype depends on the existence of the given datatype.
         
        
        For example byte[] depends on byte. If byte were deleted, then byte[] would also be deleted.
        
        :param DataType dt: the datatype to test that this datatype depends on.
        :return: true if the existence of this datatype relies on the existence of the specified
                datatype dt.
        :rtype: bool
        """

    def encodeRepresentation(self, repr: typing.Union[java.lang.String, str], buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Encode bytes according to the display format for this type.
         
        
        Converts the given representation to the byte encoding and returns it. When appropriate, this
        should seek the nearest encoding to the specified value, since the representation is likely
        coming from user input. For example, a floating-point value may be rounded. Invalid
        representations should be rejected with a :obj:`DataTypeEncodeException`.
        
        :param java.lang.String or str repr: the representation of the desired value, as in
                    :meth:`getRepresentation(MemBuffer, Settings, int) <.getRepresentation>`. The supported formats depend
                    on the specific datatype and its settings.
        :param ghidra.program.model.mem.MemBuffer buf: a buffer representing the eventual destination of the bytes.
        :param ghidra.docking.settings.Settings settings: the settings to use for the representation.
        :param jpype.JInt or int length: the expected length of the result, usually the length of the data unit, or -1
                    to let the type choose the length. It may be ignored, e.g., for fixed-length
                    types.
        :return: the encoded value.
        :rtype: jpype.JArray[jpype.JByte]
        :raises DataTypeEncodeException: if the value cannot be encoded for any reason, e.g.,
                    incorrect format, not enough space, buffer overflow, unsupported (see
                    :meth:`isEncodable() <.isEncodable>`).
        """

    def encodeValue(self, value: java.lang.Object, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Encode bytes from an Object appropriate for this DataType.
         
        
        Converts the given object to the byte encoding and returns it. When appropriate, this should
        seek the nearest encoding to the specified value, since the object may come from a user
        script. For example, a floating-point value may be rounded. Invalid values should be rejected
        with a :obj:`DataTypeEncodeException`.
        
        :param java.lang.Object value: the desired value.
        :param ghidra.program.model.mem.MemBuffer buf: a buffer representing the eventual destination of the bytes.
        :param ghidra.docking.settings.Settings settings: the settings to use.
        :param jpype.JInt or int length: the expected length of the result, usually the length of the data unit, or -1
                    to let the type choose the length. It may be ignored, e.g., for fixed-length
                    types.
        :return: the encoded value.
        :rtype: jpype.JArray[jpype.JByte]
        :raises DataTypeEncodeException: if the value cannot be encoded for any reason, e.g.,
                    incorrect type, not enough space, buffer overflow, unsupported (see
                    :meth:`isEncodable() <.isEncodable>`).
        """

    def getAlignedLength(self) -> int:
        """
        Get the aligned-length of this datatype as a number of 8-bit bytes. 
         
        
        For primitive datatypes this is equivalent to the C/C++ "sizeof" operation within source code and
        should be used when determining :obj:`Array` element length or component sizing for  a 
        :obj:`Composite`.   For :obj:`Pointer`, :obj:`Composite` and :obj:`Array` types this will 
        return the same value as :meth:`getLength() <.getLength>`. 
         
        
        Example: For x86 32-bit gcc an 80-bit ``long double`` :meth:`raw data length <.getLength>` 
        of 10-bytes will fit within a floating point register while its :meth:`aligned-length <.getAlignedLength>`  
        of 12-bytes is used by the gcc compiler for data/array/component allocations to maintain alignment 
        (i.e., ``sizeof(long double)`` ).
         
        
        NOTE: Other than the :obj:`VoidDataType`, no datatype should ever return 0, even if 
        :meth:`isZeroLength() <.isZeroLength>`, and only :obj:`Dynamic` / :obj:`FactoryDataType` /
        :obj:`FunctionDefinition` datatypes should return -1.  If :meth:`isZeroLength() <.isZeroLength>` is true 
        a length of 1 should be returned.
        
        :return: byte length of binary encoding.
        :rtype: int
        """

    def getAlignment(self) -> int:
        """
        Gets the alignment to be used when aligning this datatype within another datatype.
        
        :return: this datatype's alignment.
        :rtype: int
        """

    def getCategoryPath(self) -> CategoryPath:
        """
        Gets the categoryPath associated with this datatype
        
        :return: the datatype's category path
        :rtype: CategoryPath
        """

    def getDataOrganization(self) -> DataOrganization:
        """
        Returns the DataOrganization associated with this data-type
        
        :return: associated data organization
        :rtype: DataOrganization
        """

    def getDataTypeManager(self) -> DataTypeManager:
        """
        Get the DataTypeManager containing this datatype.
         
        
        This association should not be used to indicate whether this DataType has been resolved, but
        is intended to indicate whether the appropriate DataOrganization is being used.
        
        :return: the DataTypeManager that is associated with this datatype.
        :rtype: DataTypeManager
        """

    def getDataTypePath(self) -> DataTypePath:
        """
        Returns the dataTypePath for this datatype;
        
        :return: the dataTypePath for this datatype;
        :rtype: DataTypePath
        """

    def getDefaultAbbreviatedLabelPrefix(self) -> str:
        """
        Returns the prefix to use for this datatype when an abbreviated prefix is desired.
         
        
        For example, some datatypes will build a large default label, at which it is more desirable
        to have a shortened prefix.
        
        :return: the prefix to use for this datatype when an abbreviated prefix is desired. May return
                null.
        :rtype: str
        """

    @typing.overload
    def getDefaultLabelPrefix(self) -> str:
        """
        Returns the appropriate string to use as the default label prefix in the absence of any data.
        
        :return: the default label prefix or null if none specified.
        :rtype: str
        """

    @typing.overload
    def getDefaultLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions) -> str:
        """
        Returns the appropriate string to use as the default label prefix.
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object
        :param jpype.JInt or int len: the length of the data.
        :param DataTypeDisplayOptions options: options for how to format the default label prefix.
        :return: the default label prefix or null if none specified.
        :rtype: str
        """

    def getDefaultOffcutLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions, offcutOffset: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the appropriate string to use as the default label prefix.
         
        
        This takes into account the fact that there exists a reference to the data that references
        ``offcutLength`` bytes into this type
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object
        :param jpype.JInt or int len: the length of the data.
        :param DataTypeDisplayOptions options: options for how to format the default label prefix.
        :param jpype.JInt or int offcutOffset: offset into datatype
        :return: the default label prefix.
        :rtype: str
        """

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings:
        """
        Gets the settings for this data type.  The settings may have underlying default settings
        and may in turn become defaults for instance-specific settings (e.g., Data or DataTypeComponent).
        It is important to note that these settings are tied to a specific DataType instantiation
        so it is important to understand the scope of its use.  Example: The :obj:`BuiltInDataTypeManager`
        has its own set of DataType instances which are separate from those which have been instantiated
        or resolved to a specific Program/Archive :obj:`DataTypeManager`. Settings manipulation may
        be disabled by default in some instances.
        
        :return: the settings for this dataType.
        :rtype: ghidra.docking.settings.Settings
        """

    def getDescription(self) -> str:
        """
        Get a String briefly describing this DataType.
        
        :return: a one-liner describing this DataType.
        :rtype: str
        """

    def getDisplayName(self) -> str:
        """
        Gets the name for referring to this datatype.
        
        :return: generic name for this Data Type (i.e.: Word)
        :rtype: str
        """

    def getLastChangeTime(self) -> int:
        """
        Get the timestamp corresponding to the last time this type was changed within its datatype
        manager
        
        :return: timestamp of last change within datatype manager
        :rtype: int
        """

    def getLastChangeTimeInSourceArchive(self) -> int:
        """
        Get the timestamp corresponding to the last time this type was sync'd within its source
        archive
        
        :return: timestamp of last sync with source archive
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Get the length of this DataType as a number of 8-bit bytes. 
         
        
        For primitive datatypes this reflects the smallest varnode which can be used to
        contain its value (i.e., raw data length).  
         
        
        Example: For x86 32-bit gcc an 80-bit ``long double`` :meth:`raw data length <.getLength>` 
        of 10-bytes will fit within a floating point register while its :meth:`aligned-length <.getAlignedLength>` 
        of 12-bytes is used by the gcc compiler for data/array/component allocations to maintain alignment 
        (i.e., ``sizeof(long double)`` ).
         
        
        NOTE: Other than the :obj:`VoidDataType`, no datatype should ever return 0, even if 
        :meth:`isZeroLength() <.isZeroLength>`, and only :obj:`Dynamic`/:obj:`FactoryDataType` datatypes 
        should return -1.  If :meth:`isZeroLength() <.isZeroLength>` is true a length of 1 should be returned. 
        Where a zero-length datatype can be handled (e.g., :obj:`Composite`) the 
        :meth:`isZeroLength() <.isZeroLength>` method should be used.
        
        :return: the length of this DataType
        :rtype: int
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        Get the mnemonic for this DataType.
        
        :param ghidra.docking.settings.Settings settings: settings which may influence the result or null
        :return: the mnemonic for this DataType.
        :rtype: str
        """

    def getName(self) -> str:
        """
        Get the name of this datatype.
        
        :return: the name
        :rtype: str
        """

    def getParents(self) -> java.util.Collection[DataType]:
        """
        Get the parents of this datatype.
        
        NOTE: This method is intended to be used on a DB-managed datatype only and is not
        fully supported for use with non-DB datatype instances.
        
        :return: parents of this datatype
        :rtype: java.util.Collection[DataType]
        """

    def getPathName(self) -> str:
        """
        Get the full category path name that includes this datatype's name.
         
        
        If the category is null, then this just the datatype's name is returned.
        
        :return: the path, or just this type's name
        :rtype: str
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        Get bytes from memory in a printable format for this type.
        
        :param ghidra.program.model.mem.MemBuffer buf: the data.
        :param ghidra.docking.settings.Settings settings: the settings to use for the representation.
        :param jpype.JInt or int length: the number of bytes to represent.
        :return: the representation of the data in this format, never null.
        :rtype: str
        """

    def getSettingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        """
        Get the list of settings definitions available for use with this datatype.
         
        
        In the case of a :obj:`TypeDef`, the return list will include the
        :obj:`TypeDefSettingsDefinition` list from the associated base data type.
         
        
        Unlike :obj:`TypeDefSettingsDefinition` standard settings definitions
        generally support default, component-default and data-instance use.
        In addition, standard settings definitions are never considered during
        :meth:`isEquivalent(DataType) <.isEquivalent>` checking or during the resolve process.
        
        :return: list of the settings definitions for this datatype.
        :rtype: jpype.JArray[ghidra.docking.settings.SettingsDefinition]
        """

    def getSourceArchive(self) -> SourceArchive:
        """
        Get the source archive where this type originated
        
        :return: source archive object
        :rtype: SourceArchive
        """

    def getTypeDefSettingsDefinitions(self) -> jpype.JArray[TypeDefSettingsDefinition]:
        """
        Get the list of all settings definitions for this datatype that may be
        used for an associated :obj:`TypeDef`.  When used for an associated
        :obj:`TypeDef`, these settings will be considered during a
        :meth:`TypeDef.isEquivalent(DataType) <TypeDef.isEquivalent>` check and will be preserved
        during the resolve process.
        
        :return: a list of the settings definitions for a :obj:`TypeDef`
        associated with this datatype.
        :rtype: jpype.JArray[TypeDefSettingsDefinition]
        """

    def getUniversalID(self) -> ghidra.util.UniversalID:
        """
        Get the universal ID for this datatype.
         
        
        This value is intended to be a unique identifier across all programs and archives. The same
        ID indicates that two datatypes were originally the same one. Keep in mind names, categories,
        and component makeup may differ and have changed since there origin.
        
        :return: datatype UniversalID
        :rtype: ghidra.util.UniversalID
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Returns the interpreted data value as an instance of the 
        :meth:`advertised value class <.getValueClass>`.
         
        
        For instance, :obj:`Pointer` data types should return an Address object (or null), or
        integer data types should return a :obj:`Scalar` object.
        
        :param ghidra.program.model.mem.MemBuffer buf: the data buffer
        :param ghidra.docking.settings.Settings settings: the settings to use.
        :param jpype.JInt or int length: indicates the maximum number of bytes that may be consumed by a 
        :obj:`Dynamic` datatype, otherwise this value is ignored.  A value of -1 may be specified
        to allow a Dynamic datatype to determine the length based upon the actual data bytes
        :return: the data object, or null if data is invalid
        :rtype: java.lang.Object
        """

    def getValueClass(self, settings: ghidra.docking.settings.Settings) -> java.lang.Class[typing.Any]:
        """
        Get the Class of the value Object to be returned by this datatype
        (see :meth:`getValue(MemBuffer, Settings, int) <.getValue>`).
        
        :param ghidra.docking.settings.Settings settings: the relevant settings to use or null for default.
        :return: Class of the value to be returned by this datatype or null if it can vary or is
                unspecified. Types which correspond to a string or char array will return the String
                class.
        :rtype: java.lang.Class[typing.Any]
        """

    def hasLanguageDependantLength(self) -> bool:
        """
        Indicates if the length of this data-type is determined based upon the
        :obj:`DataOrganization` obtained from the associated :obj:`DataTypeManager`.
        
        :return: true length is language/compiler-specification dependent, else false
        :rtype: bool
        """

    def isDeleted(self) -> bool:
        """
        Returns true if this datatype has been deleted and is no longer valid
        
        :return: true if this datatype has been deleted and is no longer valid.
        :rtype: bool
        """

    def isEncodable(self) -> bool:
        """
        Check if this type supports encoding (patching)
         
        
        If unsupported, :meth:`encodeValue(Object, MemBuffer, Settings, int) <.encodeValue>` and
        :meth:`encodeRepresentation(String, MemBuffer, Settings, int) <.encodeRepresentation>` will always throw an
        exception. Actions which rely on either ``encode`` method should not be displayed if the
        applicable datatype is not encodable.
        
        :return: true if encoding is supported
        :rtype: bool
        """

    def isEquivalent(self, dt: DataType) -> bool:
        """
        Check if the given datatype is equivalent to this datatype.
         
        
        The precise meaning of "equivalent" is datatype dependent. 
        
        NOTE: if invoked by a DB object or manager it should be invoked on the DataTypeDB object
        passing the other datatype as the argument.
        
        :param DataType dt: the datatype being tested for equivalence.
        :return: true if the if the given datatype is equivalent to this datatype.
        :rtype: bool
        """

    def isNotYetDefined(self) -> bool:
        """
        Indicates if this datatype has not yet been fully defined.
         
        
        Such datatypes should always return a :meth:`getLength() <.getLength>` of 1 and true for
        :meth:`isZeroLength() <.isZeroLength>`. (example: empty structure)
        
        :return: true if this type is not yet defined.
        :rtype: bool
        """

    def isZeroLength(self) -> bool:
        """
        Indicates this datatype is defined with a zero length.
         
        
        This method should not be confused with :meth:`isNotYetDefined() <.isNotYetDefined>` which indicates that
        nothing but the name and basic type is known.
         
        
        NOTE: a zero-length datatype must return a length of 1 via :meth:`getLength() <.getLength>`. Zero-length
        datatypes used as a component within a :obj:`Composite` may, or may not, be assigned a
        component length of 0. The method :meth:`DataTypeComponent.usesZeroLengthComponent(DataType) <DataTypeComponent.usesZeroLengthComponent>`
        is used to make this determination.
        
        :return: true if type definition has a length of 0, else false
        :rtype: bool
        """

    def removeParent(self, dt: DataType):
        """
        Remove a parent datatype
         
        
        TODO: This method is reserved for internal DB use. 
        
        
        :param DataType dt: parent datatype
        """

    def replaceWith(self, dataType: DataType):
        """
        For datatypes that support change, this method replaces the internals of this datatype with
        the internals of the given datatype.
         
        
        The datatypes must be of the same "type" (i.e. structure can only be replacedWith another
        structure.
        
        :param DataType dataType: the datatype that contains the internals to upgrade to.
        :raises UnsupportedOperationException: if the datatype does not support change.
        :raises IllegalArgumentException: if the given datatype is not the same type as this datatype.
        """

    def setCategoryPath(self, path: CategoryPath):
        """
        Set the categoryPath associated with this datatype
        
        :param CategoryPath path: the new path
        :raises DuplicateNameException: if an attempt to place this datatype into the specified
                    category resulted in a name collision. This should not occur for non-DB DataType
                    instances.
        """

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Sets a String briefly describing this DataType.
        
        :param java.lang.String or str description: a one-liner describing this DataType.
        :raises java.lang.UnsupportedOperationException: if the description is not allowed to be set for this
                    datatype.
        """

    def setLastChangeTime(self, lastChangeTime: typing.Union[jpype.JLong, int]):
        """
        Sets the lastChangeTime for this datatype.
         
        
        Normally, this is updated automatically when a datatype is changed, but when committing or
        updating while synchronizing an archive, the lastChangeTime may need to be updated
        externally.
        
        :param jpype.JLong or int lastChangeTime: the time to use as the lastChangeTime for this datatype
        """

    def setLastChangeTimeInSourceArchive(self, lastChangeTimeInSourceArchive: typing.Union[jpype.JLong, int]):
        """
        Sets the lastChangeTimeInSourceArchive for this datatype.
         
        
        This is used by when a datatype change is committed back to its source archive.
        
        :param jpype.JLong or int lastChangeTimeInSourceArchive: the time to use as the lastChangeTimeInSourceArchive for
                    this datatype
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of the datatype
        
        :param java.lang.String or str name: the new name for this datatype.
        :raises InvalidNameException: if the given name does not form a valid name.
        :raises DuplicateNameException: if name change on stored :obj:`DataType` is a duplicate of
                    another datatype within the same category (only applies to DB stored
                    :obj:`DataType`).
        """

    def setNameAndCategory(self, path: CategoryPath, name: typing.Union[java.lang.String, str]):
        """
        Sets the name and category of a datatype at the same time.
        
        :param CategoryPath path: the new category path.
        :param java.lang.String or str name: the new name
        :raises InvalidNameException: if the name is invalid
        :raises DuplicateNameException: if name change on stored :obj:`DataType` is a duplicate of
                    another datatype within the same category (only applies to DB stored
                    :obj:`DataType`).
        """

    def setSourceArchive(self, archive: SourceArchive):
        """
        Set the source archive where this type originated
        
        :param SourceArchive archive: source archive object
        """

    @property
    def pathName(self) -> java.lang.String:
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def dataTypePath(self) -> DataTypePath:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @description.setter
    def description(self, value: java.lang.String):
        ...

    @property
    def defaultAbbreviatedLabelPrefix(self) -> java.lang.String:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def settingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings:
        ...

    @property
    def notYetDefined(self) -> jpype.JBoolean:
        ...

    @property
    def zeroLength(self) -> jpype.JBoolean:
        ...

    @property
    def categoryPath(self) -> CategoryPath:
        ...

    @categoryPath.setter
    def categoryPath(self, value: CategoryPath):
        ...

    @property
    def defaultLabelPrefix(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def encodable(self) -> jpype.JBoolean:
        ...

    @property
    def sourceArchive(self) -> SourceArchive:
        ...

    @sourceArchive.setter
    def sourceArchive(self, value: SourceArchive):
        ...

    @property
    def typeDefSettingsDefinitions(self) -> jpype.JArray[TypeDefSettingsDefinition]:
        ...

    @property
    def dataOrganization(self) -> DataOrganization:
        ...

    @property
    def lastChangeTimeInSourceArchive(self) -> jpype.JLong:
        ...

    @lastChangeTimeInSourceArchive.setter
    def lastChangeTimeInSourceArchive(self, value: jpype.JLong):
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def universalID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def lastChangeTime(self) -> jpype.JLong:
        ...

    @lastChangeTime.setter
    def lastChangeTime(self, value: jpype.JLong):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def valueClass(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def alignedLength(self) -> jpype.JInt:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @property
    def dataTypeManager(self) -> DataTypeManager:
        ...

    @property
    def parents(self) -> java.util.Collection[DataType]:
        ...


class DoubleDataType(AbstractFloatDataType):
    """
    Provides a definition of a Double within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[DoubleDataType]

    @typing.overload
    def __init__(self):
        """
        Creates a Double data type.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...


class MetaDataType(java.lang.Enum[MetaDataType]):

    class_: typing.ClassVar[java.lang.Class]
    VOID: typing.Final[MetaDataType]
    UNKNOWN: typing.Final[MetaDataType]
    INT: typing.Final[MetaDataType]
    UINT: typing.Final[MetaDataType]
    BOOL: typing.Final[MetaDataType]
    CODE: typing.Final[MetaDataType]
    FLOAT: typing.Final[MetaDataType]
    PTR: typing.Final[MetaDataType]
    ARRAY: typing.Final[MetaDataType]
    STRUCT: typing.Final[MetaDataType]

    @staticmethod
    def getMeta(dt: DataType) -> MetaDataType:
        ...

    @staticmethod
    def getMostSpecificDataType(a: DataType, b: DataType) -> DataType:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MetaDataType:
        ...

    @staticmethod
    def values() -> jpype.JArray[MetaDataType]:
        ...


class DataTypeDisplayOptions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MAX_LABEL_STRING_LENGTH: typing.Final = 32
    DEFAULT: typing.Final[DataTypeDisplayOptions]

    def getLabelStringLength(self) -> int:
        ...

    def useAbbreviatedForm(self) -> bool:
        ...

    @property
    def labelStringLength(self) -> jpype.JInt:
        ...


class PointerTypeSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition, TypeDefSettingsDefinition):
    """
    The settings definition for the numeric display format
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[PointerTypeSettingsDefinition]

    def getDisplayChoice(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def getType(self, settings: ghidra.docking.settings.Settings) -> PointerType:
        """
        Returns the format based on the specified settings
        
        :param ghidra.docking.settings.Settings settings: the instance settings or null for default value.
        :return: the :obj:`PointerType`.  :obj:`PointerType.DEFAULT` will be returned
        if no setting has been made.
        :rtype: PointerType
        """

    def setDisplayChoice(self, settings: ghidra.docking.settings.Settings, choice: typing.Union[java.lang.String, str]):
        """
        Sets the settings object to the enum value indicating the specified choice as a string.
        
        :param ghidra.docking.settings.Settings settings: the settings to store the value.
        :param java.lang.String or str choice: enum string representing a choice in the enum.
        """

    def setType(self, settings: ghidra.docking.settings.Settings, type: PointerType):
        ...

    @property
    def type(self) -> PointerType:
        ...

    @property
    def displayChoice(self) -> java.lang.String:
        ...


class Pointer48DataType(PointerDataType):
    """
    Pointer48 is really a factory for generating 6-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer48DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class ComponentOffsetSettingsDefinition(ghidra.docking.settings.NumberSettingsDefinition, TypeDefSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[ComponentOffsetSettingsDefinition]


class AbstractStringDataType(BuiltIn, Dynamic, DataTypeWithCharset):
    """
    Common base class for all Ghidra string :obj:`DataType`s.
     
    
    See :obj:`StringDataType` for information about string variations and configuration details.
     
    
    Sub-classes generally only need to implement a constructor that calls the mega-constructor
    :meth:`AbstractStringDataType.AbstractStringDataType(lots,of,params) <.AbstractStringDataType>` and the
    :meth:`DataType.clone(DataTypeManager) <DataType.clone>` method.
    """

    class_: typing.ClassVar[java.lang.Class]
    COMMON_STRING_SETTINGS_DEFS: typing.Final[jpype.JArray[ghidra.docking.settings.SettingsDefinition]]
    COMMON_WITH_CHARSET_STRING_SETTINGS_DEFS: typing.Final[jpype.JArray[ghidra.docking.settings.SettingsDefinition]]
    DEFAULT_UNICODE_LABEL: typing.Final = "UNICODE"
    DEFAULT_UNICODE_LABEL_PREFIX: typing.Final = "UNI"
    DEFAULT_UNICODE_ABBREV_PREFIX: typing.Final = "u"
    DEFAULT_LABEL: typing.Final = "STRING"
    DEFAULT_LABEL_PREFIX: typing.Final = "STR"
    DEFAULT_ABBREV_PREFIX: typing.Final = "s"
    USE_CHARSET_DEF_DEFAULT: typing.Final[java.lang.String]
    """
    A symbolic name to signal that the null value being passed for the charset name param
    indicates that the default charset (ie. ASCII) should be used.
    """


    def getStringDataInstance(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> StringDataInstance:
        """
        Creates a new :obj:`StringDataInstance` using the bytes in the supplied MemBuffer and
        options provided by this DataType.
        
        :param ghidra.program.model.mem.MemBuffer buf: the data.
        :param ghidra.docking.settings.Settings settings: the settings to use for the representation.
        :param jpype.JInt or int length: the number of bytes to represent.
        :return: a new :obj:`StringDataInstance`, never null.
        :rtype: StringDataInstance
        """

    def getStringLayout(self) -> StringLayoutEnum:
        """
        
        
        :return: :obj:`StringLayoutEnum` settinEnum stringLayoutype.
        :rtype: StringLayoutEnum
        """

    @property
    def stringLayout(self) -> StringLayoutEnum:
        ...


class ICategory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DELIMITER_CHAR: typing.Final = '/'
    NAME_DELIMITER: typing.Final = "/"
    DELIMITER_STRING: typing.Final = "/"

    def addDataType(self, dt: DataType, handler: DataTypeConflictHandler) -> DataType:
        ...

    def copyCategory(self, category: Category, handler: DataTypeConflictHandler, monitor: ghidra.util.task.TaskMonitor) -> Category:
        """
        Make a new subcategory from the given category.
        
        :param Category category: the category to copy into this category
        :return: category that is added to this category
        :rtype: Category
        """

    def createCategory(self, name: typing.Union[java.lang.String, str]) -> Category:
        """
        Create a category with the given name.
        
        :param java.lang.String or str name: the category name
        :raises DuplicateNameException: if this category already contains a
        category or data type with the given name
        :raises InvalidNameException: if name has invalid characters
        """

    def getCategories(self) -> jpype.JArray[Category]:
        """
        Get all categories in this category.
        
        :return: zero-length array if there are no categories
        :rtype: jpype.JArray[Category]
        """

    def getCategory(self, name: typing.Union[java.lang.String, str]) -> Category:
        """
        Get a category with the given name.
        
        :param java.lang.String or str name: the name of the category
        :return: null if there is no category by this name
        :rtype: Category
        """

    def getCategoryPath(self) -> CategoryPath:
        ...

    def getCategoryPathName(self) -> str:
        """
        Get the fully qualified name for this category.
        """

    def getDataType(self, name: typing.Union[java.lang.String, str]) -> DataType:
        """
        Get a data type with the given name.
        
        :param java.lang.String or str name: the name of the data type
        :return: null if there is no data type by this name
        :rtype: DataType
        """

    def getDataTypeManager(self) -> DataTypeManager:
        """
        Get the data type manager associated with this category.
        """

    def getDataTypes(self) -> jpype.JArray[DataType]:
        """
        Get all data types in this category.
        
        :return: zero-length array if there are no data types
        :rtype: jpype.JArray[DataType]
        """

    def getName(self) -> str:
        """
        Get the name of this category.
        """

    def getParent(self) -> Category:
        """
        Return this category's parent; return null if this is the root category.
        """

    def getRoot(self) -> Category:
        """
        Get the root category.
        """

    def isRoot(self) -> bool:
        ...

    def moveCategory(self, category: Category, monitor: ghidra.util.task.TaskMonitor):
        """
        Move the given category to this category; category is removed from
        its original parent category.
        
        :param Category category: the category to move
        :raises DuplicateNameException: if this category already contains a
        category or data type with the same name as the category param.
        """

    def moveDataType(self, type: DataType, handler: DataTypeConflictHandler):
        """
        
        
        :param DataType type:
        """

    def remove(self, type: DataType, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        
        
        :param DataType type:
        """

    def removeCategory(self, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Remove the named category from this category.
        
        :param java.lang.String or str name: the name of the category to remove
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the category was removed
        :rtype: bool
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    @property
    def parent(self) -> Category:
        ...

    @property
    def dataTypes(self) -> jpype.JArray[DataType]:
        ...

    @property
    def categoryPath(self) -> CategoryPath:
        ...

    @property
    def root(self) -> Category:
        ...

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def categoryPathName(self) -> java.lang.String:
        ...

    @property
    def categories(self) -> jpype.JArray[Category]:
        ...

    @property
    def category(self) -> Category:
        ...

    @property
    def dataTypeManager(self) -> DataTypeManager:
        ...


class DataTypeEncodeException(ghidra.util.exception.UsrException):
    """
    Exception thrown when a value cannot be encoded for a data type
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], value: java.lang.Object, dt: DataType):
        """
        Constructor
        
        :param java.lang.String or str message: the exception message
        :param java.lang.Object value: the requested value or representation
        :param DataType dt: the data type
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], value: java.lang.Object, dt: DataType, cause: java.lang.Throwable):
        """
        Constructor
        
        :param java.lang.String or str message: the exception message
        :param java.lang.Object value: the requested value or representation
        :param DataType dt: the data type
        :param java.lang.Throwable cause: the exception cause
        """

    @typing.overload
    def __init__(self, value: java.lang.Object, dt: DataType, cause: java.lang.Throwable):
        """
        Constructor
        
        :param java.lang.Object value: the requested value or representation
        :param DataType dt: the data type
        :param java.lang.Throwable cause: the exception cause
        """

    def getDataType(self) -> DataType:
        """
        Get the data type
        
        :return: the data type
        :rtype: DataType
        """

    def getValue(self) -> java.lang.Object:
        """
        Get the requested value or representation
        
        :return: the requested value representation
        :rtype: java.lang.Object
        """

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...


class AlignedStructurePacker(java.lang.Object):
    """
    ``AlignedStructurePacker`` provides support for performing aligned packing
    of Structure components.
     
    
    NOTE: We currently have no way of conveying or supporting explicit bitfield component pragmas 
    supported by some compilers (e.g., bit_field_size, bit_field_align, bit_packing).
    """

    class StructurePackResult(java.lang.Object):
        """
        ``StructurePackResult`` provides access to aligned
        packing results
        """

        class_: typing.ClassVar[java.lang.Class]
        numComponents: typing.Final[jpype.JInt]
        structureLength: typing.Final[jpype.JInt]
        alignment: typing.Final[jpype.JInt]
        componentsChanged: typing.Final[jpype.JBoolean]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def packComponents(structure: StructureInternal, components: java.util.List[InternalDataTypeComponent]) -> AlignedStructurePacker.StructurePackResult:
        """
        Perform structure component packing.  Specified components may be updated to reflect 
        packing (ordinal, offset, length and bit-field datatypes may be modified).  The caller 
        is responsible for updating structure length and component count based upon
        returned result.  Component count is should only change if component
        list includes DEFAULT members which will be ignored.
        
        :param StructureInternal structure: structure whose members are to be aligned/packed.
        :param java.util.List[InternalDataTypeComponent] components: structure components.
        :return: aligned packing result
        :rtype: AlignedStructurePacker.StructurePackResult
        """


class CountedDynamicDataType(DynamicDataType):
    """
    A dynamic data type that changes the number of elements it contains based on a count found in
    header data type.
    The data type has a header data type which will contain the number of base data types following
    the header data type.
     
    NOTE: This is a special Dynamic data-type which can only appear as a component
    created by a Dynamic data-type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], header: DataType, baseStruct: DataType, counterOffset: typing.Union[jpype.JLong, int], counterSize: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JLong, int]):
        """
        Constructor for this dynamic data type builder.
        
        :param java.lang.String or str name: name of this dynamic data type
        :param java.lang.String or str description: description of the data type
        :param DataType header: header data type that will contain the number of following elements
        :param DataType baseStruct: base data type for each of the following elements
        :param jpype.JLong or int counterOffset: offset of the number of following elements from the start of the header
        :param jpype.JInt or int counterSize: size of the count in bytes
        :param jpype.JLong or int mask: mask to apply to the count value to get the actual number of following elements.
        """


class SignedCharDataType(CharDataType):
    """
    Provides a definition of a primitive signed char data type.
    While in most environment the size is one 8-bit byte, this
    can vary based upon data organization imposed by the 
    associated data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[SignedCharDataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a new signed char datatype.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DataTypeArchiveIdDumper(ghidra.GhidraLaunchable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DataTypeObjectComparator(java.util.Comparator[java.lang.Object]):
    """
    :obj:`DataTypeObjectComparator` provides the preferred named-based comparison of data types
    using the :obj:`DataTypeNameComparator` allowing a mix of :obj:`DataType` and/or :obj:`String`
    names to be compared.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.ClassVar[DataTypeObjectComparator]

    def __init__(self):
        ...

    def compare(self, o1: java.lang.Object, o2: java.lang.Object) -> int:
        """
        Compare two data type names
        
        :param java.lang.Object o1: the first :obj:`DataType` or :obj:`String` name to be compared.
        :param java.lang.Object o2: the second :obj:`DataType` or :obj:`String` name to be compared.
        :return: a negative integer, zero, or a positive integer as the
                first argument is less than, equal to, or greater than the
                second.
        :rtype: int
        :raises IllegalArgumentException: if object types other than :obj:`DataType` or 
        :obj:`String` are compared.
        """


class Resource(java.lang.Object):
    """
    Identifies code units that are resources, such as Bitmap, jpeg, png, etc.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramArchitectureTranslator(ghidra.program.util.LanguageTranslatorAdapter):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, oldLanguage: ghidra.program.model.lang.Language, oldCompilerSpecId: ghidra.program.model.lang.CompilerSpecID, newLanguage: ghidra.program.model.lang.Language, newCompilerSpecId: ghidra.program.model.lang.CompilerSpecID):
        ...

    @typing.overload
    def __init__(self, oldLanguageId: ghidra.program.model.lang.LanguageID, oldLanguageVersion: typing.Union[jpype.JInt, int], oldCompilerSpecId: ghidra.program.model.lang.CompilerSpecID, newLanguage: ghidra.program.model.lang.Language, newCompilerSpecId: ghidra.program.model.lang.CompilerSpecID):
        ...

    def getNewCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    def getOldCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    @property
    def oldCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    @property
    def newCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...


class ArchiveType(java.lang.Enum[ArchiveType]):

    class_: typing.ClassVar[java.lang.Class]
    BUILT_IN: typing.Final[ArchiveType]
    FILE: typing.Final[ArchiveType]
    PROJECT: typing.Final[ArchiveType]
    PROGRAM: typing.Final[ArchiveType]
    TEMPORARY: typing.Final[ArchiveType]

    def isBuiltIn(self) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ArchiveType:
        ...

    @staticmethod
    def values() -> jpype.JArray[ArchiveType]:
        ...

    @property
    def builtIn(self) -> jpype.JBoolean:
        ...


class FactoryDataType(BuiltInDataType):
    """
    A DataType class that creates data types dynamically should implement this interface.
    This prevents them being directly referred to by a data instance within the listing
    or within a composite (e.g., added to a composite using the structure editor).
    FactoryDataType's should never be parented (e.g., Pointer, Structure component, Typedef, etc.).
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataType(self, buf: ghidra.program.model.mem.MemBuffer) -> DataType:
        """
        Returns the appropriate DataType which corresponds to the specified 
        memory location.
        
        :param ghidra.program.model.mem.MemBuffer buf: memory location
        :return: fabricated datatype based upon memory data
        :rtype: DataType
        """

    def getLength(self) -> int:
        """
        All implementations must return a length of -1.
        
        :return: length of -1
        :rtype: int
        """

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class PascalString255DataType(AbstractStringDataType):
    """
    A length-prefixed string :obj:`DataType` (max 255 bytes) with char size of 1 byte,
    user setable :obj:`charset <CharsetSettingsDefinition>` (default ASCII),
    unbounded (ignores containing field size, relies on embedded length value).
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[PascalString255DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def copy(self, retainIdentity: typing.Union[jpype.JBoolean, bool]) -> DataType:
        ...


class Complex16DataType(AbstractComplexDataType):
    """
    Provides a definition of a ``complex`` built-in data type consisting of two 64-bit floating point
    numbers in the IEEE 754 double precision format.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Complex16DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class AbstractIntegerDataType(BuiltIn, ArrayStringable):
    """
    Base type for integer data types such as :obj:`chars <CharDataType>`, :obj:`ints <IntegerDataType>`, and :obj:`longs <LongDataType>`.
     
    
    If :meth:`FormatSettingsDefinition.getFormat(Settings) <FormatSettingsDefinition.getFormat>` indicates that this is a
    :obj:`CHAR <FormatSettingsDefinition.CHAR>` type, the :obj:`ArrayStringable` methods will treat
    an array of this data type as a string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], dtm: DataTypeManager):
        """
        Constructor
        
        :param java.lang.String or str name: a unique signed/unsigned data-type name (also used as the mnemonic)
        :param DataTypeManager dtm: data-type manager whose data organization should be used
        """

    def getAssemblyMnemonic(self) -> str:
        """
        
        
        :return: the Assembly style data-type declaration for this data-type.
        :rtype: str
        """

    def getCDeclaration(self) -> str:
        """
        
        
        :return: the C style data-type declaration for this data-type. Null is returned if no
                appropriate declaration exists.
        :rtype: str
        """

    def getCMnemonic(self) -> str:
        """
        
        
        :return: the C style data-type mnemonic for this data-type. NOTE: currently the same as
                getCDeclaration().
        :rtype: str
        """

    def getOppositeSignednessDataType(self) -> AbstractIntegerDataType:
        """
        
        
        :return: the data-type with the opposite signedness from this data-type. For example, this
                method on IntegerDataType will return an instance of UnsignedIntegerDataType.
        :rtype: AbstractIntegerDataType
        """

    @staticmethod
    def getSignedDataType(size: typing.Union[jpype.JInt, int], dtm: DataTypeManager) -> DataType:
        """
        Get a Signed Integer data-type instance of the requested size
        
        :param jpype.JInt or int size: data type size, sizes greater than 8 (and other than 16) will cause an
                    SignedByteDataType[size] (i.e., Array) to be returned.
        :param DataTypeManager dtm: optional program data-type manager, if specified a generic data-type will be
                    returned if possible.
        :return: signed integer data type
        :rtype: DataType
        """

    @staticmethod
    def getSignedDataTypes(dtm: DataTypeManager) -> jpype.JArray[AbstractIntegerDataType]:
        """
        Returns all built-in signed integer data-types.
        
        :param DataTypeManager dtm: optional program data-type manager, if specified generic data-types will be
                    returned in place of fixed-sized data-types.
        :return: array of all signed integer types (char and bool types excluded)
        :rtype: jpype.JArray[AbstractIntegerDataType]
        """

    @staticmethod
    def getUnsignedDataType(size: typing.Union[jpype.JInt, int], dtm: DataTypeManager) -> DataType:
        """
        Get a Unsigned Integer data-type instance of the requested size
        
        :param jpype.JInt or int size: data type size, sizes greater than 8 (and other than 16) will cause an undefined
                    type to be returned.
        :param DataTypeManager dtm: optional program data-type manager, if specified a generic data-type will be
                    returned if possible.
        :return: unsigned integer data type
        :rtype: DataType
        """

    @staticmethod
    def getUnsignedDataTypes(dtm: DataTypeManager) -> jpype.JArray[AbstractIntegerDataType]:
        """
        Returns all built-in unsigned integer data-types
        
        :param DataTypeManager dtm: optional program data-type manager, if specified generic data-types will be
                    returned in place of fixed-sized data-types.
        :return: array of all unsigned integer types (char and bool types excluded)
        :rtype: jpype.JArray[AbstractIntegerDataType]
        """

    def isSigned(self) -> bool:
        """
        Determine if this type is signed.
        
        :return: true if this is a signed integer data-type
        :rtype: bool
        """

    @property
    def cDeclaration(self) -> java.lang.String:
        ...

    @property
    def signed(self) -> jpype.JBoolean:
        ...

    @property
    def cMnemonic(self) -> java.lang.String:
        ...

    @property
    def assemblyMnemonic(self) -> java.lang.String:
        ...

    @property
    def oppositeSignednessDataType(self) -> AbstractIntegerDataType:
        ...


class RepeatedStringDataType(RepeatCountDataType):
    """
    Some number of repeated strings.  Each string can be of variable length.
     
    The data structure looks like this:
     
        RepeatedStringDT
            numberOfStrings = N
            String1
            String2
            ...
            StringN
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    @property
    def description(self) -> java.lang.String:
        ...


class MacintoshTimeStampDataType(BuiltIn):
    """
    A datatype to interpret the Mac OS timestamp
    convention, which is based on the number of 
    seconds measured from January 1, 1904.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class IconResource(BitmapResource):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buf: ghidra.program.model.mem.MemBuffer):
        ...

    def getImageDataSize(self) -> int:
        ...

    @property
    def imageDataSize(self) -> jpype.JInt:
        ...


class WideChar32DataType(BuiltIn, ArrayStringable, DataTypeWithCharset):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[WideChar32DataType]
    """
    A statically defined WideCharDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Float8DataType(AbstractFloatDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Float8DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


@typing.type_check_only
class AlignedComponentPacker(java.lang.Object):
    """
    ``AlignedComponentPacker`` provides component packing support to the 
    :obj:`AlignedStructurePacker`.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeWithCharset(DataType):

    class_: typing.ClassVar[java.lang.Class]

    def encodeCharacterRepresentation(self, repr: typing.Union[java.lang.String, str], buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings) -> jpype.JArray[jpype.JByte]:
        """
        Utility for character data types to encode a representation.
        
        :param java.lang.String or str repr: the single-character string to encode.
        :param ghidra.program.model.mem.MemBuffer buf: a buffer representing the eventual destination of the bytes.
        :param ghidra.docking.settings.Settings settings: the settings to use.
        :return: the encoded value
        :rtype: jpype.JArray[jpype.JByte]
        :raises DataTypeEncodeException: if the value cannot be encoded
        """

    def encodeCharacterValue(self, value: java.lang.Object, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings) -> jpype.JArray[jpype.JByte]:
        """
        Utility for character data types to encode a value.
        
        :param java.lang.Object value: the character value to encode.
        :param ghidra.program.model.mem.MemBuffer buf: a buffer representing the eventual destination of the bytes.
        :param ghidra.docking.settings.Settings settings: the settings to use.
        :return: the encoded value
        :rtype: jpype.JArray[jpype.JByte]
        :raises DataTypeEncodeException: if the value cannot be encoded
        """

    def getCharsetName(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        Get the character set for a specific data type and settings
        
        :param ghidra.docking.settings.Settings settings: data instance settings
        :return: Charset for this datatype and settings
        :rtype: str
        """

    @property
    def charsetName(self) -> java.lang.String:
        ...


class StructuredDynamicDataType(DynamicDataType):
    """
    Structured Dynamic Data type.
     
    Dynamic Structure that is built by adding data types to it.
     
    NOTE: This is a special Dynamic data-type which can only appear as a component
    created by a Dynamic data-type
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], dtm: DataTypeManager):
        """
        Construct an empty dynamic structure
        
        :param java.lang.String or str name: name of the dynamic structure
        :param java.lang.String or str description: description of the dynamic structure
        """

    def add(self, data: DataType, componentName: typing.Union[java.lang.String, str], componentDescription: typing.Union[java.lang.String, str]):
        """
        Add a component data type onto the end of the dynamic structure
        
        :param DataType data: data type to add
        :param java.lang.String or str componentName: name of the field in the dynamic structure
        :param java.lang.String or str componentDescription: description of the field
        """

    def getDescription(self) -> str:
        ...

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        ...

    def setComponents(self, components: java.util.List[DataType], componentNames: java.util.List[java.lang.String], componentDescs: java.util.List[java.lang.String]):
        """
        Set the components of the dynamic structure all at once.
        This does not add the components in, it replaces any existing ones.
        
        :param java.util.List[DataType] components: list of components to add
        :param java.util.List[java.lang.String] componentNames: list of field names of each component
        :param java.util.List[java.lang.String] componentDescs: list of descriptions of each component
        """

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class DataTypeComparator(java.util.Comparator[DataType]):
    """
    :obj:`DataTypeComparator` provides the preferred named-based comparison of :obj:`DataType`
    which utilizes the :obj:`DataTypeNameComparator` for a primary :meth:`name <DataType.getName>` 
    comparison followed by sub-ordering on :obj:`DataTypeManager` name and :obj:`CategoryPath`.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.ClassVar[DataTypeComparator]

    def __init__(self):
        ...


class TerminatedSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    Settings definition for strings being terminated or unterminated
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[TerminatedSettingsDefinition]

    def isTerminated(self, settings: ghidra.docking.settings.Settings) -> bool:
        """
        Gets the current termination setting from the given settings objects or returns
        the default if not in either settings object
        
        :param ghidra.docking.settings.Settings settings: the instance settings
        :return: the current value for this settings definition
        :rtype: bool
        """

    def setTerminated(self, settings: ghidra.docking.settings.Settings, isTerminated: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def terminated(self) -> jpype.JBoolean:
        ...


class FileBasedDataTypeManager(DataTypeManager):
    """
    Extends DataTypeManager to provide methods specific to a data type manager that is file based.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPath(self) -> str:
        ...

    @property
    def path(self) -> java.lang.String:
        ...


class EnumValuePartitioner(java.lang.Object):
    """
    This is a static utility class used to partition a set of long values into as many
    non-intersecting BitGroups as possible.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def partition(values: jpype.JArray[jpype.JLong], size: typing.Union[jpype.JInt, int]) -> java.util.List[BitGroup]:
        """
        Partition the given values into a list of non-intersecting BitGroups.
        
        :param jpype.JArray[jpype.JLong] values: the values to be partitioned.
        :param jpype.JInt or int size: size of enum value in bytes
        :return: a list of BitGroups with non-intersecting bits.
        :rtype: java.util.List[BitGroup]
        """


class DataTypeComponent(java.lang.Object):
    """
    DataTypeComponents are holders for the dataTypes that make up composite (Structures
    and Unions) dataTypes.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_FIELD_NAME_PREFIX: typing.Final = "field"
    """
    The default prefix for the name of a component.
    """


    def getComment(self) -> str:
        """
        Get the comment for this dataTypeComponent.
        
        :return: component comment string or null if one has not been set
        :rtype: str
        """

    def getDataType(self) -> DataType:
        """
        Returns the dataType in this component.
        
        :return: the dataType in this component
        :rtype: DataType
        """

    def getDefaultFieldName(self) -> str:
        """
        Returns a default field name for this component.  Used only if a field name is not set.
        
        :return: default field name (may be null for nameless fields such as a zero-length bitfield).
        :rtype: str
        """

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings:
        """
        Gets the default settings for this data type component.
        
        :return: a Settings object that is the set of default values for this dataType component
        :rtype: ghidra.docking.settings.Settings
        """

    def getEndOffset(self) -> int:
        """
        Get the byte offset of where this component ends relative to the start of the parent
        data type.
        
        :return: offset of end of component relative to the start of the parent
        data type.
        :rtype: int
        """

    def getFieldName(self) -> str:
        """
        Get this component's field name within its parent.
        If this method returns null :meth:`getDefaultFieldName() <.getDefaultFieldName>` can be used to obtain a default
        generated field name.
        
        :return: this component's field name within its parent or null if one has not been set.
        :rtype: str
        """

    def getLength(self) -> int:
        """
        Get the length of this component in 8-bit bytes.  Zero-length components will report a length
        of 0 and may overlap other components at the same offset.  Similarly, multiple adjacent
        bit-field components may appear to overlap at the byte-level.
        
        :return: the length of this component in 8-bit bytes
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Get the byte offset of where this component begins relative to the start of the parent
        data type.
        
        :return: offset of start of component relative to the start of the parent
        data type.
        :rtype: int
        """

    def getOrdinal(self) -> int:
        """
        Get the ordinal position within the parent dataType.
        
        :return: ordinal of this component within the parent data type.
        :rtype: int
        """

    def getParent(self) -> DataType:
        """
        returns the dataType that contains this component.
        
        :return: the dataType that contains this component.
        :rtype: DataType
        """

    def isBitFieldComponent(self) -> bool:
        """
        Determine if the specified component corresponds to a bit-field.
        
        :return: true if bit-field else false
        :rtype: bool
        """

    def isEquivalent(self, dtc: DataTypeComponent) -> bool:
        """
        Returns true if the given dataTypeComponent is equivalent to this dataTypeComponent.
        A dataTypeComponent is "equivalent" if the other component has a data type
        that is equivalent to this component's data type. The dataTypeComponents must
        also have the same offset, field name, and comment.  The length is only checked
        for components which are dynamic and whose size must be specified when creating
        a component.
        
        :param DataTypeComponent dtc: the dataTypeComponent being tested for equivalence.
        :return: true if the given dataTypeComponent is equivalent to this dataTypeComponent.
        :rtype: bool
        """

    def isUndefined(self) -> bool:
        """
        Returns true if this component is not defined. It is just a placeholder.
        
        :return: true if this component is not defined. It is just a placeholder.
        :rtype: bool
        """

    def isZeroBitFieldComponent(self) -> bool:
        """
        Determine if the specified component corresponds to a zero-length bit-field.
        
        :return: true if zero-length bit-field else false
        :rtype: bool
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Sets the comment for the component.
        
        :param java.lang.String or str comment: this components comment or null to clear comment.
        """

    def setFieldName(self, fieldName: typing.Union[java.lang.String, str]):
        """
        Sets the field name. If the field name is empty it will be set to null,
        which is the default field name. An exception is thrown if one of the
        parent's other components already has the specified field name.
        
        :param java.lang.String or str fieldName: the new field name for this component.
        :raises DuplicateNameException: This is actually never thrown anymore. All the other ways
        of naming fields did not perform this check and it would cause quite a bit of churn to 
        add that exception to all the other methods that affect field names. So to be consistent,
        we no longer do the check in this method.
        """

    @staticmethod
    def usesZeroLengthComponent(dataType: DataType) -> bool:
        """
        Determine if the specified dataType will be treated as a zero-length component
        allowing it to possibly overlap the next component.  If the specified dataType
        returns true for :meth:`DataType.isZeroLength() <DataType.isZeroLength>` and true for :meth:`DataType.isNotYetDefined() <DataType.isNotYetDefined>`
        this method will return false causing the associated component to use the reported dataType length
        of 1.
        
        :param DataType dataType: datatype to be evaluated
        :return: true if zero-length component
        :rtype: bool
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def parent(self) -> DataType:
        ...

    @property
    def endOffset(self) -> jpype.JInt:
        ...

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @fieldName.setter
    def fieldName(self, value: java.lang.String):
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def undefined(self) -> jpype.JBoolean:
        ...

    @property
    def zeroBitFieldComponent(self) -> jpype.JBoolean:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def bitFieldComponent(self) -> jpype.JBoolean:
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings:
        ...

    @property
    def defaultFieldName(self) -> java.lang.String:
        ...


class DataTypeMnemonicSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    The settings definition for the numeric display format
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final = 0
    ASSEMBLY: typing.Final = 1
    CSPEC: typing.Final = 2
    DEF: typing.Final[DataTypeMnemonicSettingsDefinition]

    def getMnemonicStyle(self, settings: ghidra.docking.settings.Settings) -> int:
        """
        Returns the format based on the specified settings
        
        :param ghidra.docking.settings.Settings settings: the instance settings.
        :return: the mnemonic style (DEFAULT, ASSEMBLY, CSPEC).  
        The ASSEMBLY style is returned if no setting has been made.
        The DEFAULT style corresponds to the use of :meth:`DataType.getName() <DataType.getName>`.
        :rtype: int
        """

    @property
    def mnemonicStyle(self) -> jpype.JInt:
        ...


class IBO64DataType(AbstractPointerTypedefBuiltIn):
    """
    ``IBO64DataType`` provides a Pointer-Typedef BuiltIn for
    a 64-bit Image Base Offset Relative Pointer.  This :obj:`TypeDef` implementation 
    specifies the :obj:`PointerType.IMAGE_BASE_RELATIVE` attribute/setting
    associated with a 64-bit :obj:`Pointer`.
     
    
    This class replaces the use of the old ``ImageBaseOffset64DataType``
    which did not implement the Pointer interface.  This is an alternative 
    :obj:`BuiltIn` implementation to using the more general :obj:`PointerTypedef`
    datatype with an unspecified referenced datatype.  :obj:`PointerTypedef` should 
    be used for other cases 
    (see :meth:`createIBO64PointerTypedef(DataType) <.createIBO64PointerTypedef>`).
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[IBO64DataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a 64-bit Image Base Offset relative pointer-typedef.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        """
        Constructs a 64-bit Image Base Offset relative pointer-typedef.
        
        :param DataTypeManager dtm: data-type manager whose data organization should be used
        """

    @staticmethod
    def createIBO64PointerTypedef(referencedDataType: DataType) -> PointerTypedef:
        """
        Create a IBO64 :obj:`PointerTypedef` with auto-naming.  If needed, a name and category
        may be assigned to the returned instance.  Unlike using an immutable :obj:`IBO32DataType` instance
        the returned instance is mutable.
        
        :param DataType referencedDataType: referenced datatype or null
        :return: new IBO64 pointer-typedef
        :rtype: PointerTypedef
        """


class ScorePlayer(Playable, javax.sound.midi.MetaEventListener):
    """
    Plays a MIDI score
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        ...


class Pointer64DataType(PointerDataType):
    """
    Pointer64 is really a factory for generating 8-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer64DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class EnumDataType(GenericDataType, Enum):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        ...

    @typing.overload
    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], universalID: ghidra.util.UniversalID, sourceArchive: SourceArchive, lastChangeTime: typing.Union[jpype.JLong, int], lastChangeTimeInSourceArchive: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        ...

    def pack(self):
        """
        Sets this enum to it smallest (power of 2) size that it can be and still represent all its
        current values.
        """

    def setLength(self, newLength: typing.Union[jpype.JInt, int]):
        ...


class ArrayStringable(DataType):
    """
    ``ArrayStringable`` identifies those data types which when formed into
    an array can be interpreted as a string (e.g., character array).  The :obj:`Array`
    implementations will leverage this interface as both a marker and to generate appropriate
    representations and values for data instances.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getArrayDefaultLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions) -> str:
        """
        For cases where an array of this type exists, get the appropriate string to use as the
        default label prefix for the array.
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object
        :param jpype.JInt or int len: the length of the data.
        :param DataTypeDisplayOptions options: options for how to format the default label prefix.
        :return: the default label prefix or null if none specified.
        :rtype: str
        """

    def getArrayDefaultOffcutLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions, offcutLength: typing.Union[jpype.JInt, int]) -> str:
        """
        For cases where an array of this type exists, get the appropriate string to use as the
        default label prefix, taking into account the fact that there exists a reference to the
        data that references ``offcutLength`` bytes into this type
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer containing the bytes.
        :param ghidra.docking.settings.Settings settings: the Settings object.
        :param jpype.JInt or int len: the length of the data.
        :param DataTypeDisplayOptions options: options for how to format the default label prefix.
        :param jpype.JInt or int offcutLength: the length of the offcut label prefix.
        :return: the default label prefix or null if none specified.
        :rtype: str
        """

    def getArrayString(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        For cases where an array of this type exists, get the array value as a String.
        When data corresponds to character data it should generally be expressed as a string.
        A null value is returned if not supported or memory is uninitialized.
        
        :param ghidra.program.model.mem.MemBuffer buf: data buffer
        :param ghidra.docking.settings.Settings settings: data settings
        :param jpype.JInt or int length: length of array
        :return: array value expressed as a string or null if data is not character data
        :rtype: str
        """

    @staticmethod
    def getArrayStringable(dt: DataType) -> ArrayStringable:
        """
        Get the ArrayStringable for a specified data type. Not used on an Array DataType, but
        on Array's element's type.
        
        :param DataType dt: data type
        :return: ArrayStringable object, or null.
        :rtype: ArrayStringable
        """

    def hasStringValue(self, settings: ghidra.docking.settings.Settings) -> bool:
        """
        For cases where an array of this type exists, determines if a String value
        will be returned.
        
        :param ghidra.docking.settings.Settings settings: 
        :return: true if array of this type with the specified settings will return
        a String value.
        :rtype: bool
        """


class CategoryPath(java.lang.Comparable[CategoryPath]):
    """
    A category path is the full path to a particular data type
    """

    class_: typing.ClassVar[java.lang.Class]
    DELIMITER_CHAR: typing.Final = '/'
    DELIMITER_STRING: typing.Final = "/"
    ESCAPED_DELIMITER_STRING: typing.Final = "\\/"
    ROOT: typing.Final[CategoryPath]

    @typing.overload
    def __init__(self, parent: CategoryPath, *subPathElements: typing.Union[java.lang.String, str]):
        """
        Construct a CategoryPath from a parent and a hierarchical array of strings where each
        string is the name of a category in the category path.
        
        :param CategoryPath parent: the parent CategoryPath.  Choose ``ROOT`` if needed.
        :param jpype.JArray[java.lang.String] subPathElements: the array of names of sub-categories of the parent.
        :raises IllegalArgumentException: if the parent is null, the elements list is null or empty,
        or an individual element is null
        """

    @typing.overload
    def __init__(self, parent: CategoryPath, subPathElements: java.util.List[java.lang.String]):
        """
        Construct a CategoryPath from a parent and a hierarchical list of strings where each
        string is the name of a category in the category path.
        
        :param CategoryPath parent: the parent CategoryPath.  Choose ``ROOT`` if needed.
        :param java.util.List[java.lang.String] subPathElements: the hierarchical array of sub-categories of the parent.
        :raises IllegalArgumentException: if the parent is null, the elements list is null or empty,
        or an individual element is null
        """

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str]):
        """
        Creates a category path given a forward-slash-delimited string (e.g., ``"/aa/bb"``).
        If an individual path component has one or more '/' characters in it, then it can be
        ***escaped*** using the :meth:`escapeString(String) <.escapeString>` utility method.  The
        :meth:`unescapeString(String) <.unescapeString>` method can be used to unescape an individual component.
         
        
        **Refrain** from using this constructor in production code, and instead use one of the
        other constructors that does not require escaping.  Situations where using this constructor
        is OK is in simple cases where a literal is passed in, such as in testing methods or in
        scripts.
        
        :param java.lang.String or str path: category path string, delimited with '/' characters where individual components
        may have '/' characters escaped.  Must start with the '/' character.
        """

    def asArray(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a hierarchical array of names of the categories in the category path, starting with
        the name just below the ``ROOT`` category.
        
        :return: a hierarchical array of names of the categories in the category path.
        :rtype: jpype.JArray[java.lang.String]
        """

    def asList(self) -> java.util.List[java.lang.String]:
        """
        Returns a hierarchical list of names of the categories in the category path, starting with
        the name just below the ``ROOT`` category.
        
        :return: a hierarchical list of names of the category in the category path.
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def escapeString(nonEscapedString: typing.Union[java.lang.String, str]) -> str:
        """
        Converts a non-escaped String into an escaped string suitable for being passed in as a
        component of a single category path string to the constructor that takes a single
        escaped category path string.  The user is responsible for constructing the single
        category path string from the escaped components.
        
        :param java.lang.String or str nonEscapedString: String that might need escaping for characters used for delimiting
        :return: escaped String
        :rtype: str
        
        .. seealso::
        
            | :obj:`.unescapeString(String)`
        """

    @typing.overload
    def extend(self, *subPathElements: typing.Union[java.lang.String, str]) -> CategoryPath:
        """
        Returns a CategoryPath that extends the current path using a hierarchical array of strings
        where each string is the name of a category in the category path extension.
        
        :param jpype.JArray[java.lang.String] subPathElements: the array of names of sub-categories of the parent.
        :return: the extended CategoryPath
        :rtype: CategoryPath
        :raises IllegalArgumentException: if an element is null
        """

    @typing.overload
    def extend(self, subPathElements: java.util.List[java.lang.String]) -> CategoryPath:
        """
        Returns a CategoryPath that extends the current path using a hierarchical list of strings
        where each  string is the name of a category in the category path extension.
        
        :param java.util.List[java.lang.String] subPathElements: the hierarchical array of sub-categories of the parent.
        :return: the extended CategoryPath
        :rtype: CategoryPath
        :raises IllegalArgumentException: if an element is null
        """

    def getName(self) -> str:
        """
        Return the terminating name of this category path.
        
        :return: the name
        :rtype: str
        """

    def getParent(self) -> CategoryPath:
        """
        Return the parent category path.
        
        :return: the parent
        :rtype: CategoryPath
        """

    @typing.overload
    def getPath(self) -> str:
        """
        Return the :obj:`String` representation of this category path including the category name,
        where components are delimited with a forward slash.  Any occurrence of a forward slash
        within individual path components will be escaped (e.g., ``"\/"``).
        
        :return: the full category path
        :rtype: str
        """

    @typing.overload
    def getPath(self, childName: typing.Union[java.lang.String, str]) -> str:
        """
        Return the :obj:`String` representation of the specified ``childName`` within this
        category path where all path components are delimited with a forward slash.  Any occurrence
        of a forward slash within individual path components, including the ``childName``, will
        be escaped (e.g., ``"\/"``).
        
        :param java.lang.String or str childName: child name
        :return: full path for a child within this category
        :rtype: str
        """

    def getPathElements(self) -> jpype.JArray[java.lang.String]:
        """
        Returns array of names in category path.
        
        :return: array of names
        :rtype: jpype.JArray[java.lang.String]
        """

    def isAncestorOrSelf(self, candidateAncestorPath: CategoryPath) -> bool:
        """
        Tests if the specified categoryPath is the same as, or an ancestor of, this category path.
        
        :param CategoryPath candidateAncestorPath: the category path to be checked.
        :return: true if the given path is the same as, or an ancestor of, this category path.
        :rtype: bool
        """

    def isRoot(self) -> bool:
        """
        Determine if this category path corresponds to the root category
        
        :return: true if this is a root category path
        :rtype: bool
        """

    @staticmethod
    def unescapeString(escapedString: typing.Union[java.lang.String, str]) -> str:
        """
        Converts an escaped String suitable for being passed in as a component of a single category
        path string into an non-escaped string.
        
        :param java.lang.String or str escapedString: String that might need unescaping for characters used for delimiting
        :return: non-escaped String
        :rtype: str
        
        .. seealso::
        
            | :obj:`.escapeString(String)`
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def parent(self) -> CategoryPath:
        ...

    @property
    def pathElements(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def root(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def ancestorOrSelf(self) -> jpype.JBoolean:
        ...


class StringUTF8DataType(AbstractStringDataType):
    """
    A fixed-length UTF-8 string :obj:`DataType`.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[StringUTF8DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class StringDataType(AbstractStringDataType):
    """
    A fixed-length string :obj:`DataType` with a user setable
    :obj:`charset <CharsetSettingsDefinition>` (default ASCII).
     
    
    All string data types:
     
    * :obj:`StringDataType` - this type, fixed length, user settable charset.
    * :obj:`StringUTF8DataType` - fixed length UTF-8 string.
    * :obj:`TerminatedStringDataType` - terminated and unbounded string, user settable charset.
    * :obj:`TerminatedUnicodeDataType` - terminated and unbounded UTF-16 string.
    * :obj:`TerminatedUnicode32DataType` - terminated and unbounded UTF-32 string.
    * :obj:`PascalString255DataType` - length-prefixed string (limited to 255 chars), user settable charset.
    * :obj:`PascalStringDataType` - length-prefixed string (limited to 64k), user settable charset.
    * :obj:`PascalUnicodeDataType` - length-prefixed UTF-16 (limited to 64k).
    * :obj:`UnicodeDataType` - fixed length UTF-16 string.
    * :obj:`Unicode32DataType` - fixed length UTF-32 string.
    
     
    
    The following settings are supported by all string types on the data instance:
     
    * :obj:`TranslationSettingsDefinition` - controls display of string values that have been
    translated to English.
    * :obj:`RenderUnicodeSettingsDefinition` - controls display of non-ascii Unicode characters.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[StringDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DataTypeManagerChangeListenerAdapter(DataTypeManagerChangeListener):
    """
    Adapter for a Category change listener.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OffsetShiftSettingsDefinition(ghidra.docking.settings.NumberSettingsDefinition, TypeDefSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[OffsetShiftSettingsDefinition]


class FloatDataType(AbstractFloatDataType):
    """
    Provides a definition of a Float within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[FloatDataType]

    @typing.overload
    def __init__(self):
        """
        Creates a Float data type.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Undefined8DataType(Undefined):
    """
    Provides an implementation of an 8-byte dataType that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined8DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Construcs a new Undefined8 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class Undefined(BuiltIn):
    """
    ``Undefined`` identifies an undefined data type
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getUndefinedDataType(size: typing.Union[jpype.JInt, int]) -> DataType:
        """
        Get an Undefined data-type instance of the requested size
        
        :param jpype.JInt or int size: data type size, sizes greater than 8 will cause an Undefined1[size] (i.e., Array) to be returned.
        :return: Undefined data type
        :rtype: DataType
        """

    @staticmethod
    def getUndefinedDataTypes() -> jpype.JArray[Undefined]:
        ...

    @staticmethod
    def isUndefined(dataType: DataType) -> bool:
        """
        Determine if the specified dataType is either a DefaultDataType, 
        an Undefined data-type, or an Array of Undefined data-types.
        
        :param DataType dataType: 
        :return: true if dataType represents an undefined data-type in
        its various forms, else false.
        :rtype: bool
        """

    @staticmethod
    def isUndefinedArray(dataType: DataType) -> bool:
        """
        Determine if the specified dataType is an undefined array
        used to represent large undefined data.
        
        :param DataType dataType: 
        :return: true if the specified dataType is an undefined array
        used to represent large undefined data, otherwise false.
        :rtype: bool
        """


class BitFieldPackingImpl(BitFieldPacking):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_USE_MS_CONVENTION: typing.Final = False
    DEFAULT_TYPE_ALIGNMENT_ENABLED: typing.Final = True
    DEFAULT_ZERO_LENGTH_BOUNDARY: typing.Final = 0

    def __init__(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Output the details of this bitfield packing to a encoded document formatter.
        
        :param ghidra.program.model.pcode.Encoder encoder: the output document encoder.
        :raises IOException: if an IO error occurs while encoding/writing output
        """

    def setTypeAlignmentEnabled(self, typeAlignmentEnabled: typing.Union[jpype.JBoolean, bool]):
        """
        Control whether the alignment of bit-field types is respected when laying out structures.
        Corresponds to PCC_BITFIELD_TYPE_MATTERS in gcc.
        
        :param jpype.JBoolean or bool typeAlignmentEnabled: true if the alignment of the bit-field type should be used
        to impact the alignment of the containing structure, and ensure that individual bit-fields 
        will not straddle an alignment boundary.
        """

    def setUseMSConvention(self, useMSConvention: typing.Union[jpype.JBoolean, bool]):
        """
        Control if the alignment and packing of bit-fields follows MSVC conventions.  
        When this is enabled it takes precedence over all other bitfield packing controls.
        
        :param jpype.JBoolean or bool useMSConvention: true if MSVC packing conventions are used, else false (e.g., GNU conventions apply).
        """

    def setZeroLengthBoundary(self, zeroLengthBoundary: typing.Union[jpype.JInt, int]):
        """
        Indicate a fixed alignment size in bytes which should be used for zero-length bit-fields.
        
        :param jpype.JInt or int zeroLengthBoundary: fixed alignment size as number of bytes for a bit-field 
        which follows a zero-length bit-field.  A value of 0 causes zero-length type size to be used.
        """


class DomainFileBasedDataTypeManager(FileBasedDataTypeManager):
    """
    Extends DataTypeManager to provide methods specific to a data type manager stored as a domain file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDomainFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile:
        ...


class SourceArchive(java.lang.Object):
    """
    DataTypeSource holds information about a single data type archive which supplied a data type
    to the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getArchiveType(self) -> ArchiveType:
        """
        Gets an indicator for the type of data type archive.
        (ArchiveType.BUILT_IN, ArchiveType.PROGRAM, ArchiveType.PROJECT, ArchiveType.FILE)
        
        :return: the type
        :rtype: ArchiveType
        """

    def getDomainFileID(self) -> str:
        """
        Gets the ID used to uniquely identify the domain file for the data type archive.
        
        :return: the domain file identifier
        :rtype: str
        """

    def getLastSyncTime(self) -> int:
        """
        Returns the last time that this source archive was synchronized to the containing 
        DataTypeManager.
        
        :return: the last time that this source archive was synchronized to the containing 
        DataTypeManager.
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of the source archive
        
        :return: the name of the source archive.
        :rtype: str
        """

    def getSourceArchiveID(self) -> ghidra.util.UniversalID:
        """
        Gets the ID that the program has associated with the data type archive.
        
        :return: the data type archive ID
        :rtype: ghidra.util.UniversalID
        """

    def isDirty(self) -> bool:
        """
        Returns true if at least one data type that originally came from this source archive has been
        changed.
        
        :return: true if at least one data type that originally came from this source archive has been
        changed.
        :rtype: bool
        """

    def setDirtyFlag(self, dirty: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the dirty flag to indicate if at least one data type that originally came from the 
        associated source archive has been changed since the last time the containing DataTypeManager
        was synchronized with it.
        
        :param jpype.JBoolean or bool dirty: true means at least one data type that originally came from this source archive has been
        changed.
        """

    def setLastSyncTime(self, time: typing.Union[jpype.JLong, int]):
        """
        Sets the last time that this source archive was synchronized to the containing 
        DataTypeManager.
        
        :param jpype.JLong or int time: the last time that this source archive was synchronized to the containing 
        DataTypeManager.
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of the source archive associated with this SourceArchive object.
        
        :param java.lang.String or str name: the name of the associated source archive.
        """

    @property
    def dirty(self) -> jpype.JBoolean:
        ...

    @property
    def archiveType(self) -> ArchiveType:
        ...

    @property
    def lastSyncTime(self) -> jpype.JLong:
        ...

    @lastSyncTime.setter
    def lastSyncTime(self, value: jpype.JLong):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def sourceArchiveID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def domainFileID(self) -> java.lang.String:
        ...


class Playable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def clicked(self, e: java.awt.event.MouseEvent):
        ...

    def getImageIcon(self) -> javax.swing.Icon:
        ...

    @property
    def imageIcon(self) -> javax.swing.Icon:
        ...


class BitFieldPacking(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getZeroLengthBoundary(self) -> int:
        """
        A non-zero value indicates the fixed alignment size for bit-fields which follow
        a zero-length bitfield if greater than a bitfields base type normal alignment. 
        Corresponds to EMPTY_FIELD_BOUNDARY in GCC.
        This value is only used when :meth:`isTypeAlignmentEnabled() <.isTypeAlignmentEnabled>` returns false.
        
        :return: fixed alignment size as number of bytes for a bit-field which follows
        a zero-length bit-field
        :rtype: int
        """

    def isEquivalent(self, obj: BitFieldPacking) -> bool:
        """
        Determine if this BitFieldPacking is equivalent to another specified instance
        
        :param BitFieldPacking obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    def isTypeAlignmentEnabled(self) -> bool:
        """
        Control whether the alignment of bit-field types is respected when laying out structures.
        Corresponds to PCC_BITFIELD_TYPE_MATTERS in GCC.
        
        :return: true when the alignment of the bit-field type should be used to impact the 
        alignment of the containing structure, and ensure that individual bit-fields will not 
        straddle an alignment boundary.
        :rtype: bool
        """

    def useMSConvention(self) -> bool:
        """
        Control if the alignment and packing of bit-fields follows MSVC conventions.  
        When this is enabled it takes precedence over all other bitfield packing controls.
        
        :return: true if MSVC packing conventions are used, else false (e.g., GNU conventions apply).
        :rtype: bool
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def zeroLengthBoundary(self) -> jpype.JInt:
        ...

    @property
    def typeAlignmentEnabled(self) -> jpype.JBoolean:
        ...


class BuiltInDataTypeClassExclusionFilter(ghidra.util.classfinder.ClassExclusionFilter):
    """
    An exclusion filter to use when searching for classes that implement :obj:`BuiltInDataType`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SignedQWordDataType(AbstractSignedIntegerDataType):
    """
    Provides a definition of a Signed Quad Word within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[SignedQWordDataType]
    """
    A statically defined SignedQWordDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class SignedWordDataType(AbstractSignedIntegerDataType):
    """
    Provides a basic implementation of a signed word datatype
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[SignedWordDataType]
    """
    A statically defined SignedWordDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class CompositeDataTypeImpl(GenericDataType, CompositeInternal):
    """
    Common implementation methods for structure and union
    """

    class_: typing.ClassVar[java.lang.Class]

    def isNotYetDefined(self) -> bool:
        """
        Determine if this composite should be treated as undefined.
         
        
        A composite is considered undefined with a zero-length when it has 
        no components and packing is disabled.  A :obj:`DataTypeComponent` defined by an
        an datatype which is not-yet-defined (i.e., :meth:`DataType.isNotYetDefined() <DataType.isNotYetDefined>` is true) 
        will always have a size of 1.  If an empty composite should be treated as 
        fully specified, packing on the composite should be enabled to ensure that 
        a zero-length component is used should the occassion arise (e.g., empty structure 
        placed within union as a component).
        """

    def repack(self, notify: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Repack components within this composite based on the current packing, alignment 
        and :obj:`DataOrganization` settings.  Non-packed Structures: change detection
        is limited to component count and length is assumed to already be correct.
         
        
        NOTE: If modifications to stored length are made prior to invoking this method, 
        detection of a size change may not be possible.  
         
        
        NOTE: Currently a change in calculated alignment can not be provided since
        this value is not stored.
        
        :param jpype.JBoolean or bool notify: if true notification will be sent to parents if a size change
        or component placement change is detected.
        :return: true if a layout change was detected.
        :rtype: bool
        """

    def setValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int], value: java.lang.Object):
        ...

    @property
    def notYetDefined(self) -> jpype.JBoolean:
        ...


class DynamicDataType(BuiltIn, Dynamic):
    """
    Interface for dataTypes that don't get applied, but instead generate dataTypes
    on the fly based on the data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self, ordinal: typing.Union[jpype.JInt, int], buf: ghidra.program.model.mem.MemBuffer) -> DataTypeComponent:
        """
        Returns the immediate n'th component of this data type.
        
        :param jpype.JInt or int ordinal: the components ordinal (zero based).
        :param ghidra.program.model.mem.MemBuffer buf: a memory buffer to be used by dataTypes that change depending on
        their data context.
        :return: the component data type or null if there is no component at the 
        indicated index.
        :rtype: DataTypeComponent
        :raises ArrayIndexOutOfBoundsException: if index is out of bounds
        """

    def getComponentAt(self, offset: typing.Union[jpype.JInt, int], buf: ghidra.program.model.mem.MemBuffer) -> DataTypeComponent:
        """
        Returns the first component containing the byte at the given offset.
        It is possible with zero-length components (see :meth:`DataType.isZeroLength() <DataType.isZeroLength>`)
        and bitfields (see @DataTypeComponent#isBitFieldComponent()} for multiple components
        to share the same offset.
        
        :param jpype.JInt or int offset: the offset into the dataType
        :param ghidra.program.model.mem.MemBuffer buf: the memory buffer containing the bytes.
        :return: the first component containing the byte at the given offset or null if no
        component defined.  A zero-length component may be returned.
        :rtype: DataTypeComponent
        """

    def getComponents(self, buf: ghidra.program.model.mem.MemBuffer) -> jpype.JArray[DataTypeComponent]:
        """
        Returns an array of components that make up this data type.
        Could return null if there are no subcomponents.
        
        :param ghidra.program.model.mem.MemBuffer buf: a memory buffer to be used by dataTypes that change depending on
        their data context.
        :return: datatype component array or null.
        :rtype: jpype.JArray[DataTypeComponent]
        """

    def getNumComponents(self, buf: ghidra.program.model.mem.MemBuffer) -> int:
        """
        Gets the number of component data types in this data type.
        
        :param ghidra.program.model.mem.MemBuffer buf: a memory buffer to be used by dataTypes that change depending on
        their data context.
        :return: the number of components that make up this data prototype
        - if this is an Array, return the number of elements in the array.
        - if this datatype is a subcomponent of another datatype and it
            won't fit in it's defined space, return -1.
        :rtype: int
        """

    def invalidateCache(self):
        ...

    @property
    def components(self) -> jpype.JArray[DataTypeComponent]:
        ...

    @property
    def numComponents(self) -> jpype.JInt:
        ...


class AlignmentType(java.lang.Enum[AlignmentType]):
    """
    ``AlignmentType`` specifies the type of alignment which applies to a composite data type.
    This can be DEFAULT, MACHINE, EXPLICIT.  For packed composites, the length of the composite
    will be padded to force the length to a multiple of the computed alignment.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[AlignmentType]
    """
    **DEFAULT** - this data type's alignment is computed based upon its current pack setting
    and data organization rules.  If packing is disabled the computed alignment will be 1.
    """

    MACHINE: typing.Final[AlignmentType]
    """
    **MACHINE** - this data type's alignment will be a multiple of the machine alignment
    specified by the data organization.  In general, and for all non-packed composites, the 
    computed alignment will match the machine alignment if this setting is used.
    """

    EXPLICIT: typing.Final[AlignmentType]
    """
    **MACHINE** - this data type's alignment will be a multiple of the explicit alignment
    value specified for the datatype.  For all non-packed composites, the 
    computed alignment will match the machine alignment if this setting is used.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AlignmentType:
        ...

    @staticmethod
    def values() -> jpype.JArray[AlignmentType]:
        ...


class TypeDef(DataType):
    """
    The typedef interface
    """

    class_: typing.ClassVar[java.lang.Class]

    def enableAutoNaming(self):
        """
        Enable auto-naming for this typedef.  This will force naming to reflect the name of
        associated datatype plus an attribute list which corresponds to any 
        :obj:`TypeDefSettingsDefinition` settings which may be set.
        """

    def getBaseDataType(self) -> DataType:
        """
        Returns the non-typedef dataType that this typedef is based on, following
        chains of typedefs as necessary.
        
        :return: the datatype which this typedef is based on (will not be another :obj:`TypeDef`).
        :rtype: DataType
        """

    def getDataType(self) -> DataType:
        """
        Returns the dataType that this typedef is based on. This could be
        another typedef
        
        :return: the datatype which this typedef is based on (may be another :obj:`TypeDef`).
        :rtype: DataType
        """

    def hasSameTypeDefSettings(self, dt: TypeDef) -> bool:
        """
        Compare the settings of two datatypes which correspond to a
        :obj:`TypeDefSettingsDefinition`. 
         
        
        NOTE: It is required that both datatypes present their settings
        definitions in the same order (see :obj:`DataType.getSettingsDefinitions`)
        to be considered the same.
        
        :param TypeDef dt: other typedef to compare with
        :return: true if both datatypes have the same settings defined 
        which correspond to :obj:`TypeDefSettingsDefinition` and have the 
        same values, else false.
        :rtype: bool
        """

    def isAutoNamed(self) -> bool:
        """
        Determine if this datatype use auto-naming (e.g., see :obj:`PointerTypedef`).  
        If true, any change to associated :obj:`TypeDefSettingsDefinition` settings
        or naming of the pointer-referenced datatype will cause a automatic renaming 
        of this datatype.
        
        :return: true if auto-named, else false.
        :rtype: bool
        """

    def isPointer(self) -> bool:
        """
        Determine if this is a Pointer-TypeDef
        
        :return: true if base datatype is a pointer
        :rtype: bool
        """

    @property
    def baseDataType(self) -> DataType:
        ...

    @property
    def pointer(self) -> jpype.JBoolean:
        ...

    @property
    def autoNamed(self) -> jpype.JBoolean:
        ...

    @property
    def dataType(self) -> DataType:
        ...


class PackingType(java.lang.Enum[PackingType]):
    """
    ``PackingType`` specifies the pack setting which applies to a composite data type.
    This can be DISABLED, DEFAULT, EXPLICIT.
    """

    class_: typing.ClassVar[java.lang.Class]
    DISABLED: typing.Final[PackingType]
    """
    **DISABLED** - indicates that automatic component placement should not be performed, with 
    components placed at specified offsets and ``undefined`` components used to
    reflects padding/unused bytes.  This mode is commonly used when reverse-engineering a
    composite since a complete and accurate definition may not be known.
    """

    DEFAULT: typing.Final[PackingType]
    """
    **DEFAULT** - indicates that components should be placed automatically based upon
    their alignment.  This is intended to reflect the default behavior of a compiler
    when a complete definition of a composite is known as well as the alignment of each 
    component.
    """

    EXPLICIT: typing.Final[PackingType]
    """
    **EXPLICIT** - indicates an explicit pack value has been specified and that components 
    should be placed automatically based upon their alignment, not to exceed the pack value.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PackingType:
        ...

    @staticmethod
    def values() -> jpype.JArray[PackingType]:
        ...


class DataOrganizationImpl(DataOrganization):
    """
    DataOrganization provides a single place for determining size and alignment information
    for data types within an archive or a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_MACHINE_ALIGNMENT: typing.Final = 8
    DEFAULT_DEFAULT_ALIGNMENT: typing.Final = 1
    DEFAULT_DEFAULT_POINTER_ALIGNMENT: typing.Final = 4
    DEFAULT_POINTER_SHIFT: typing.Final = 0
    DEFAULT_POINTER_SIZE: typing.Final = 4
    DEFAULT_CHAR_SIZE: typing.Final = 1
    DEFAULT_CHAR_IS_SIGNED: typing.Final = True
    DEFAULT_WIDE_CHAR_SIZE: typing.Final = 2
    DEFAULT_SHORT_SIZE: typing.Final = 2
    DEFAULT_INT_SIZE: typing.Final = 4
    DEFAULT_LONG_SIZE: typing.Final = 4
    DEFAULT_LONG_LONG_SIZE: typing.Final = 8
    DEFAULT_FLOAT_SIZE: typing.Final = 4
    DEFAULT_DOUBLE_SIZE: typing.Final = 8
    DEFAULT_LONG_DOUBLE_SIZE: typing.Final = 8

    def clearSizeAlignmentMap(self):
        """
        Remove all entries from the size alignment map
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Output the details of this data organization to a encoded document formatter.
        
        :param ghidra.program.model.pcode.Encoder encoder: the output document encoder.
        :raises IOException: if an IO error occurs while encoding/writing output
        """

    def getAbsoluteMaxAlignment(self) -> int:
        """
        Gets the maximum alignment value that is allowed by this data organization. When getting
        an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
        is returned, the data organization isn't specifically limited.
        
        :return: the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
        :rtype: int
        """

    @staticmethod
    def getAlignedOffset(alignment: typing.Union[jpype.JInt, int], minimumOffset: typing.Union[jpype.JInt, int]) -> int:
        """
        Determines the first offset that is equal to or greater than the minimum offset which
        has the specified alignment.  If a non-positive alignment is specified the origina
        minimumOffset will be return.
        
        :param jpype.JInt or int alignment: the desired alignment (positive value)
        :param jpype.JInt or int minimumOffset: the minimum offset
        :return: the aligned offset
        :rtype: int
        """

    def getDefaultAlignment(self) -> int:
        """
        Gets the default alignment to be used for any data type that isn't a
        structure, union, array, pointer, type definition, and whose size isn't in the
        size/alignment map.
        
        :return: the default alignment to be used if no other alignment can be
        determined for a data type.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getDefaultOrganization() -> DataOrganization:
        """
        Creates a new default DataOrganization. This has a mapping which defines the alignment
        of a data type based on its size. The map defines pairs for data types that are
        1, 2, 4, and 8 bytes in length.
        
        :return: a new default DataOrganization.
        :rtype: DataOrganization
        """

    @staticmethod
    @typing.overload
    def getDefaultOrganization(language: ghidra.program.model.lang.Language) -> DataOrganizationImpl:
        """
        Creates a new default DataOrganization. This has a mapping which defines the alignment
        of a data type based on its size. The map defines pairs for data types that are
        1, 2, 4, and 8 bytes in length.
        
        :param ghidra.program.model.lang.Language language: optional language used to initialize defaults (pointer size, endianness, etc.)
        (may be null)
        :return: a new default DataOrganization.
        :rtype: DataOrganizationImpl
        """

    def getDefaultPointerAlignment(self) -> int:
        """
        Gets the default alignment to be used for a pointer that doesn't have size.
        
        :return: the default alignment for a pointer
        :rtype: int
        """

    @staticmethod
    def getGreatestCommonDenominator(value1: typing.Union[jpype.JInt, int], value2: typing.Union[jpype.JInt, int]) -> int:
        """
        Determines the greatest common denominator of two numbers.
        
        :param jpype.JInt or int value1: the first number
        :param jpype.JInt or int value2: the second number
        :return: the greatest common denominator
        :rtype: int
        """

    def getIntegerCTypeApproximation(self, size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns the best fitting integer C-type whose size is less-than-or-equal
        to the specified size.  "long long" will be returned for any size larger
        than "long long";
        
        :param jpype.JInt or int size: integer size
        :param jpype.JBoolean or bool signed: if false the unsigned modifier will be prepended.
        :return: the best fitting
        :rtype: str
        """

    @staticmethod
    def getLeastCommonMultiple(value1: typing.Union[jpype.JInt, int], value2: typing.Union[jpype.JInt, int]) -> int:
        """
        Determines the least (lowest) common multiple of two numbers.
        
        :param jpype.JInt or int value1: the first number
        :param jpype.JInt or int value2: the second number
        :return: the least common multiple
        :rtype: int
        """

    def getMachineAlignment(self) -> int:
        """
        Gets the maximum useful alignment for the target machine
        
        :return: the machine alignment
        :rtype: int
        """

    def getSizeAlignmentCount(self) -> int:
        """
        Gets the number of sizes that have an alignment specified.
        
        :return: the number of sizes with an alignment mapped to them.
        :rtype: int
        """

    def getSizes(self) -> jpype.JArray[jpype.JInt]:
        """
        Gets the sizes that have an alignment specified.
        
        :return: the sizes with alignments mapped to them.
        :rtype: jpype.JArray[jpype.JInt]
        """

    @staticmethod
    def restore(dataMap: ghidra.program.database.DBStringMapAdapter, keyPrefix: typing.Union[java.lang.String, str]) -> DataOrganizationImpl:
        """
        Restore a data organization from the specified DB data map.
        
        :param ghidra.program.database.DBStringMapAdapter dataMap: DB data map
        :param java.lang.String or str keyPrefix: key prefix for all map entries
        :return: stored data organization or null if not stored
        :rtype: DataOrganizationImpl
        :raises IOException: if an IO error occurs
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Restore settings from an XML stream. This expects to see parser positioned on the
        <data_organization> start tag.  The XML is designed to override existing language-specific
        default settings which are pre-populated with :meth:`getDefaultOrganization(Language) <.getDefaultOrganization>`.  This
        will will ensure that the endianness setting is properly established since it is not included
        in the XML.
        
        :param ghidra.xml.XmlPullParser parser: is the XML stream
        """

    @staticmethod
    def save(dataOrg: DataOrganization, dataMap: ghidra.program.database.DBStringMapAdapter, keyPrefix: typing.Union[java.lang.String, str]):
        """
        Save the specified data organization to the specified DB data map.
        All existing map entries starting with keyPrefix will be removed prior
        to ading the new map entries.
        
        :param DataOrganization dataOrg: data organization
        :param ghidra.program.database.DBStringMapAdapter dataMap: DB data map
        :param java.lang.String or str keyPrefix: key prefix for all map entries
        :raises IOException: if an IO error occurs
        """

    def setAbsoluteMaxAlignment(self, absoluteMaxAlignment: typing.Union[jpype.JInt, int]):
        """
        Sets the maximum alignment value that is allowed by this data organization. When getting
        an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
        is returned, the data organization isn't specifically limited.
        
        :param jpype.JInt or int absoluteMaxAlignment: the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
        """

    def setBigEndian(self, bigEndian: typing.Union[jpype.JBoolean, bool]):
        """
        Set data endianness
        
        :param jpype.JBoolean or bool bigEndian: true if big-endian, false if little-endian
        """

    def setBitFieldPacking(self, bitFieldPacking: BitFieldPackingImpl):
        """
        Set the bitfield packing information associated with this data organization.
        
        :param BitFieldPackingImpl bitFieldPacking: bitfield packing information
        """

    def setCharIsSigned(self, signed: typing.Union[jpype.JBoolean, bool]):
        """
        Defines the signed-ness of the "char" data type
        
        :param jpype.JBoolean or bool signed: true if "char" type is signed
        """

    def setCharSize(self, charSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of a char (char) data type.
        
        :param jpype.JInt or int charSize: the size of a char (char).
        """

    def setDefaultAlignment(self, defaultAlignment: typing.Union[jpype.JInt, int]):
        """
        Sets the default alignment to be used for any data type that isn't a
        structure, union, array, pointer, type definition, and whose size isn't in the
        size/alignment map.
        
        :param jpype.JInt or int defaultAlignment: the default alignment to be used if no other alignment can be
        determined for a data type.
        """

    def setDefaultPointerAlignment(self, defaultPointerAlignment: typing.Union[jpype.JInt, int]):
        """
        Sets the default alignment to be used for a pointer that doesn't have size.
        
        :param jpype.JInt or int defaultPointerAlignment: the default alignment for a pointer
        """

    def setDoubleSize(self, doubleSize: typing.Union[jpype.JInt, int]):
        """
        Defines the encoding size of a double primitive data type.
        
        :param jpype.JInt or int doubleSize: the size of a double.
        """

    def setFloatSize(self, floatSize: typing.Union[jpype.JInt, int]):
        """
        Defines the encoding size of a float primitive data type.
        
        :param jpype.JInt or int floatSize: the size of a float.
        """

    def setIntegerSize(self, integerSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of an int primitive data type.
        
        :param jpype.JInt or int integerSize: the size of an int.
        """

    def setLongDoubleSize(self, longDoubleSize: typing.Union[jpype.JInt, int]):
        """
        Defines the encoding size of a long double primitive data type.
        
        :param jpype.JInt or int longDoubleSize: the size of a long double.
        """

    def setLongLongSize(self, longLongSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of a long long primitive data type.
        
        :param jpype.JInt or int longLongSize: the size of a long long.
        """

    def setLongSize(self, longSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of a long primitive data type.
        
        :param jpype.JInt or int longSize: the size of a long.
        """

    def setMachineAlignment(self, machineAlignment: typing.Union[jpype.JInt, int]):
        """
        Sets the maximum useful alignment for the target machine
        
        :param jpype.JInt or int machineAlignment: the machine alignment
        """

    def setPointerShift(self, pointerShift: typing.Union[jpype.JInt, int]):
        """
        Defines the left shift amount for a shifted pointer data type.
        Shift amount affects interpretation of in-memory pointer values only
        and will also be reflected within instruction pcode.
        
        :param jpype.JInt or int pointerShift: left shift amount for in-memory pointer values
        """

    def setPointerSize(self, pointerSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of a pointer data type.
        
        :param jpype.JInt or int pointerSize: the size of a pointer.
        """

    def setShortSize(self, shortSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of a short primitive data type.
        
        :param jpype.JInt or int shortSize: the size of a short.
        """

    def setSizeAlignment(self, size: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]):
        """
        Sets the alignment that is defined for a data type of the indicated size if one is defined.
        
        :param jpype.JInt or int size: the size of the data type
        :param jpype.JInt or int alignment: the alignment of the data type.
        """

    def setWideCharSize(self, wideCharSize: typing.Union[jpype.JInt, int]):
        """
        Defines the size of a wide-char (wchar_t) data type.
        
        :param jpype.JInt or int wideCharSize: the size of a wide-char (wchar_t).
        """

    @property
    def sizeAlignmentCount(self) -> jpype.JInt:
        ...

    @property
    def defaultPointerAlignment(self) -> jpype.JInt:
        ...

    @defaultPointerAlignment.setter
    def defaultPointerAlignment(self, value: jpype.JInt):
        ...

    @property
    def absoluteMaxAlignment(self) -> jpype.JInt:
        ...

    @absoluteMaxAlignment.setter
    def absoluteMaxAlignment(self, value: jpype.JInt):
        ...

    @property
    def sizes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def defaultAlignment(self) -> jpype.JInt:
        ...

    @defaultAlignment.setter
    def defaultAlignment(self, value: jpype.JInt):
        ...

    @property
    def machineAlignment(self) -> jpype.JInt:
        ...

    @machineAlignment.setter
    def machineAlignment(self, value: jpype.JInt):
        ...


class Category(java.lang.Comparable[Category]):
    """
    Each data type resides in a given a category.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addDataType(self, dt: DataType, handler: DataTypeConflictHandler) -> DataType:
        """
        Adds the given datatype to this category.
        
        :param DataType dt: the datatype to add to this category.
        :param DataTypeConflictHandler handler: the DataTypeConflictHandler to use if conflicts are discovered.
        :return: the new datatype with its category path adjusted.
        :rtype: DataType
        """

    def copyCategory(self, category: Category, handler: DataTypeConflictHandler, monitor: ghidra.util.task.TaskMonitor) -> Category:
        """
        Make a new sub-category from the given category.
        
        :param Category category: the category to copy into this category.
        :param DataTypeConflictHandler handler: the handler to call if there is a data type conflict.
        :param ghidra.util.task.TaskMonitor monitor: the monitor.
        :return: category that is added to this category.
        :rtype: Category
        """

    def createCategory(self, name: typing.Union[java.lang.String, str]) -> Category:
        """
        Create a category with the given name; if category already exists, then return that
        category.
        
        :param java.lang.String or str name: the category name.
        :return: the category.
        :rtype: Category
        :raises InvalidNameException: if name has invalid characters.
        """

    def getCategories(self) -> jpype.JArray[Category]:
        """
        Get all categories in this category.
        
        :return: zero-length array if there are no categories.
        :rtype: jpype.JArray[Category]
        """

    def getCategory(self, name: typing.Union[java.lang.String, str]) -> Category:
        """
        Get a category with the given name.
        
        :param java.lang.String or str name: the name of the category.
        :return: null if there is no category by this name.
        :rtype: Category
        """

    def getCategoryPath(self) -> CategoryPath:
        """
        return the full CategoryPath for this category.
        
        :return: the full CategoryPath for this category.
        :rtype: CategoryPath
        """

    def getCategoryPathName(self) -> str:
        """
        Get the fully qualified name for this category.
        
        :return: the name.
        :rtype: str
        """

    def getDataType(self, name: typing.Union[java.lang.String, str]) -> DataType:
        """
        Get a data type with the given name.
        
        :param java.lang.String or str name: the name of the data type.
        :return: null if there is no data type by this name.
        :rtype: DataType
        """

    def getDataTypeManager(self) -> DataTypeManager:
        """
        Get the data type manager associated with this category.
        
        :return: the manager.
        :rtype: DataTypeManager
        """

    def getDataTypes(self) -> jpype.JArray[DataType]:
        """
        Get all data types in this category.
        
        :return: zero-length array if there are no data types.
        :rtype: jpype.JArray[DataType]
        """

    def getDataTypesByBaseName(self, name: typing.Union[java.lang.String, str]) -> java.util.List[DataType]:
        """
        Get all data types whose name matches the given name once any conflict suffixes have been 
        removed from both the given name and the data types that are being scanned.
         
        
        NOTE: The ``name`` provided must not contain array or pointer decorations.
        
        :param java.lang.String or str name: the name for which to get conflict related data types in this category. Note:
        the name that is passed in will be normalized to its base name, so you may pass in names
        with .conflict appended as a convenience.
        :return: a list of data types that have the same base name as the base name of the given
        name.
        :rtype: java.util.List[DataType]
        """

    def getID(self) -> int:
        """
        Get the ID for this category.
        
        :return: the ID.
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get the name of this category.
        
        :return: the name.
        :rtype: str
        """

    def getParent(self) -> Category:
        """
        Return this category's parent; return null if this is the root category.
        
        :return: the category.
        :rtype: Category
        """

    def getRoot(self) -> Category:
        """
        Get the root category.
        
        :return: the category.
        :rtype: Category
        """

    def isRoot(self) -> bool:
        """
        Returns true if this is the root category.
        
        :return: true if this is the root category.
        :rtype: bool
        """

    def moveCategory(self, category: Category, monitor: ghidra.util.task.TaskMonitor):
        """
        Move the given category to this category; category is removed from its original parent
        category.
        
        :param Category category: the category to move.
        :param ghidra.util.task.TaskMonitor monitor: the monitor.
        :raises DuplicateNameException: if this category already contains a
        category or data type with the same name as the category param.
        """

    def moveDataType(self, type: DataType, handler: DataTypeConflictHandler):
        """
        Move a data type into this category.
        
        :param DataType type: data type to be moved.
        :param DataTypeConflictHandler handler: the handler to call if there is a data type conflict.
        :raises DataTypeDependencyException: if a disallowed dependency is created during the move.
        """

    def remove(self, type: DataType, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Remove a datatype from this category.
        
        :param DataType type: data type to be removed.
        :param ghidra.util.task.TaskMonitor monitor: monitor of progress in case operation takes a long time.
        :return: true if the data type was found in this category and successfully removed.
        :rtype: bool
        """

    def removeCategory(self, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Remove the named category from this category.
        
        :param java.lang.String or str name: the name of the category to remove.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :return: true if the category was removed.
        :rtype: bool
        """

    def removeEmptyCategory(self, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Remove the named category from this category, IFF it is empty.
        
        :param java.lang.String or str name: the name of the category to remove.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :return: true if the category was removed.
        :rtype: bool
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of this category.
        
        :param java.lang.String or str name: the new name for this category
        :raises DuplicateNameException: if another category exists in the same parent with the same
        name
        :raises InvalidNameException: if the name is not an acceptable name.
        """

    @property
    def parent(self) -> Category:
        ...

    @property
    def dataTypes(self) -> jpype.JArray[DataType]:
        ...

    @property
    def categoryPath(self) -> CategoryPath:
        ...

    @property
    def root(self) -> Category:
        ...

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def categoryPathName(self) -> java.lang.String:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def categories(self) -> jpype.JArray[Category]:
        ...

    @property
    def dataTypesByBaseName(self) -> java.util.List[DataType]:
        ...

    @property
    def category(self) -> Category:
        ...

    @property
    def dataTypeManager(self) -> DataTypeManager:
        ...


class UnsignedIntegerDataType(AbstractUnsignedIntegerDataType):
    """
    Basic implementation for an unsigned Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedIntegerDataType]
    """
    A statically defined UnsignedIntegerDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class TranslationSettingsDefinition(ghidra.docking.settings.JavaEnumSettingsDefinition[TranslationSettingsDefinition.TRANSLATION_ENUM]):
    """
    SettingsDefinition for translation display, handles both the toggle of
    "show" vs "don't show", as well as accessing the translated value.
    """

    class TRANSLATION_ENUM(java.lang.Enum[TranslationSettingsDefinition.TRANSLATION_ENUM]):

        class_: typing.ClassVar[java.lang.Class]
        SHOW_ORIGINAL: typing.Final[TranslationSettingsDefinition.TRANSLATION_ENUM]
        SHOW_TRANSLATED: typing.Final[TranslationSettingsDefinition.TRANSLATION_ENUM]

        def invert(self) -> TranslationSettingsDefinition.TRANSLATION_ENUM:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TranslationSettingsDefinition.TRANSLATION_ENUM:
            ...

        @staticmethod
        def values() -> jpype.JArray[TranslationSettingsDefinition.TRANSLATION_ENUM]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    TRANSLATION: typing.Final[TranslationSettingsDefinition]
    TRANSLATION_PROPERTY_MAP_NAME: typing.ClassVar[java.lang.String]

    def getTranslatedValue(self, data: ghidra.program.model.listing.Data) -> str:
        """
        Get the translated string value which been set at the specified address.
        
        :param ghidra.program.model.listing.Data data: defined string data which may have a translation
        :return: translated string value or null
        :rtype: str
        """

    def hasTranslatedValue(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Determine if a translated string value has been set at the specified address.
        
        :param ghidra.program.model.listing.Data data: defined string data which may have a translation
        :return: true if translated string has been stored else false
        :rtype: bool
        """

    def isShowTranslated(self, settings: ghidra.docking.settings.Settings) -> bool:
        ...

    def setShowTranslated(self, settings: ghidra.docking.settings.Settings, shouldShowTranslatedValue: typing.Union[jpype.JBoolean, bool]):
        ...

    def setTranslatedValue(self, data: ghidra.program.model.listing.Data, translatedValue: typing.Union[java.lang.String, str]):
        """
        Set the translated string value at the specified address.
        
        :param ghidra.program.model.listing.Data data: defined string data which may have a translation
        :param java.lang.String or str translatedValue: translated string value or null to clear
        """

    @property
    def showTranslated(self) -> jpype.JBoolean:
        ...

    @property
    def translatedValue(self) -> java.lang.String:
        ...


class OffsetMaskSettingsDefinition(ghidra.docking.settings.NumberSettingsDefinition, TypeDefSettingsDefinition):
    """
    Setting definition for a pointer offset bit-mask to be applied prior to any 
    bit-shift (if specified) during the computation of an actual address offset.  
    Mask is defined as an unsigned long value where
    a value of zero (0) is ignored and has no affect on pointer computation.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final = -1
    DEF: typing.Final[OffsetMaskSettingsDefinition]


class AbstractLeb128DataType(BuiltIn, Dynamic):
    """
    An abstract base class for a LEB128 variable length integer data type.
     
    
    See :obj:`LEB128`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], signed: typing.Union[jpype.JBoolean, bool], dtm: DataTypeManager):
        """
        Base constructor for a little endian based 128 data type.
        
        :param java.lang.String or str name: name of the leb128 data type that extends this class.
        :param jpype.JBoolean or bool signed: true if it is signed. false if unsigned.
        :param DataTypeManager dtm: the data type manager to associate with this data type.
        """


class InvalidatedListener(java.lang.Object):
    """
    
    
    
    .. seealso::
    
        | :obj:`DataTypeManager`
    """

    class_: typing.ClassVar[java.lang.Class]

    def dataTypeManagerInvalidated(self, dataTypeManager: DataTypeManager):
        """
        Called when the given ``dataTypeManager``'s cache has been invalidated.
        
        :param DataTypeManager dataTypeManager: The manager whose cache has been invalidated.
        """


class UnsignedLongDataType(AbstractUnsignedIntegerDataType):
    """
    Basic implementation for a Signed Long Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedLongDataType]
    """
    A statically defined UnsignedLongDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class CustomFormat(java.lang.Object):
    """
    Container object for a DataType and a byte array that is the format for
    the data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataType: DataType, format: jpype.JArray[jpype.JByte]):
        """
        Constructor
        
        :param DataType dataType: data type associated with this format
        :param jpype.JArray[jpype.JByte] format: bytes that define the format
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the bytes that define this format.
        """

    def getDataType(self) -> DataType:
        """
        Get the data type associated with this format.
        """

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def dataType(self) -> DataType:
        ...


class AUDataType(BuiltIn, Dynamic):

    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.ClassVar[jpype.JArray[jpype.JByte]]
    MAGIC_MASK: typing.ClassVar[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DataTypeManagerDomainObject(ghidra.framework.model.DomainObject, ghidra.app.merge.DataTypeManagerOwner):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MemBufferImageInputStream(javax.imageio.stream.ImageInputStreamImpl):
    """
    ImageInputStream for reading images that wraps a MemBuffer to get the bytes.  Adds a method
    to find out how many bytes were read by the imageReader to read the image.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buf: ghidra.program.model.mem.MemBuffer, byteOrder: java.nio.ByteOrder):
        ...

    def getConsumedLength(self) -> int:
        ...

    @property
    def consumedLength(self) -> jpype.JInt:
        ...


class MenuResourceDataType(DynamicDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class CycleGroup(java.lang.Object):
    """
    Class to define a set of dataTypes that a single action can cycle through.
    """

    @typing.type_check_only
    class ByteCycleGroup(CycleGroup):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FloatCycleGroup(CycleGroup):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class StringCycleGroup(CycleGroup):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BYTE_CYCLE_GROUP: typing.Final[CycleGroup]
    FLOAT_CYCLE_GROUP: typing.Final[CycleGroup]
    STRING_CYCLE_GROUP: typing.Final[CycleGroup]
    ALL_CYCLE_GROUPS: typing.Final[java.util.List[CycleGroup]]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataTypes: jpype.JArray[DataType], keyStroke: javax.swing.KeyStroke):
        """
        Constructs a new cycle group with the given dataTypes.
        
        :param java.lang.String or str name: cycle group name which will be the suggested action name
        for those plugins which implement a cycle group action.
        :param jpype.JArray[DataType] dataTypes: data types in the group
        :param javax.swing.KeyStroke keyStroke: default key stroke for the action to cycle through the
        data types
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dt: DataType, keyStroke: javax.swing.KeyStroke):
        """
        Constructor cycle group with one data type.
        
        :param java.lang.String or str name: cycle group name which will be the suggested action name
        for those plugins which implement a cycle group action.
        :param DataType dt: single data type for the group
        :param javax.swing.KeyStroke keyStroke: default key stroke for the action to cycle through the
        data types
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct empty group no name, data types or keystroke.
        """

    def addDataType(self, dt: DataType):
        """
        Add a data type to this group.
        
        :param DataType dt: the datatype to be added.
        """

    def addFirst(self, dt: DataType):
        """
        Add the data type as the first in the list.
        
        :param DataType dt: the dataType to be added.
        """

    def contains(self, dt: DataType) -> bool:
        """
        Return true if the given data type is in this cycle group.
        """

    def getDataTypes(self) -> jpype.JArray[DataType]:
        """
        Get the data types in this group.
        """

    def getDefaultKeyStroke(self) -> javax.swing.KeyStroke:
        ...

    def getName(self) -> str:
        """
        
        
        :return: cycle group name.
        :rtype: str
        """

    def getNextDataType(self, currentDataType: DataType, stackPointers: typing.Union[jpype.JBoolean, bool]) -> DataType:
        """
        Get next data-type which should be used
        
        :param DataType currentDataType: current data type to which this cycle group is to be applied
        :param jpype.JBoolean or bool stackPointers: if true and currentDataType is a pointer, the pointer's 
        base type will be cycled
        :return: next data-type
        :rtype: DataType
        """

    def removeDataType(self, dt: DataType):
        """
        Remove the data type from this group.
        
        :param DataType dt: the dataType to remove.
        """

    def removeFirst(self):
        """
        Remove first data type in the list.
        """

    def removeLast(self):
        """
        Remove the last data type in the list.
        """

    def size(self) -> int:
        """
        Returns number of types in group
        """

    @property
    def dataTypes(self) -> jpype.JArray[DataType]:
        ...

    @property
    def defaultKeyStroke(self) -> javax.swing.KeyStroke:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class MutabilitySettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    The settings definition for the numeric display format
    """

    class_: typing.ClassVar[java.lang.Class]
    NORMAL: typing.Final = 0
    VOLATILE: typing.Final = 1
    CONSTANT: typing.Final = 2
    WRITABLE: typing.Final = 3
    MUTABILITY: typing.Final = "mutability"
    DEF: typing.Final[MutabilitySettingsDefinition]

    def getMutabilityMode(self, settings: ghidra.docking.settings.Settings) -> int:
        """
        Returns the mutability mode based on the current settings
        
        :param ghidra.docking.settings.Settings settings: the instance settings.
        :return: the current format value
        :rtype: int
        """

    @property
    def mutabilityMode(self) -> jpype.JInt:
        ...


class UnsignedCharDataType(CharDataType):
    """
    Provides a definition of a primitive unsigned char data type.
    While in most environment the size is one 8-bit byte, this
    can vary based upon data organization imposed by the 
    associated data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedCharDataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a new unsigned char datatype.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class BooleanDataType(AbstractUnsignedIntegerDataType):
    """
    Provides a definition of an Ascii byte in a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[BooleanDataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a new Boolean datatype.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class TerminatedUnicode32DataType(AbstractStringDataType):
    """
    A null-terminated UTF-32 string :obj:`DataType`.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[TerminatedUnicode32DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class SignedByteDataType(AbstractSignedIntegerDataType):
    """
    Provides a definition of a Signed Byte within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[SignedByteDataType]
    """
    A statically defined SignedByteDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Union(Composite):
    """
    The union interface.
     
    
    NOTE: The use of bitfields within all unions assumes a default packing where bit allocation 
    always starts with byte-0 of the union.  Bit allocation order is dictated by data organization
    endianness (byte-0 msb allocated first for big-endian, while byte-0 lsb allocated first for little-endian).
    """

    class_: typing.ClassVar[java.lang.Class]

    def insertBitField(self, ordinal: typing.Union[jpype.JInt, int], baseDataType: DataType, bitSize: typing.Union[jpype.JInt, int], componentName: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> DataTypeComponent:
        """
        Inserts a new bitfield at the specified ordinal position in this union.
        For all Unions, bitfield starts with bit-0 (lsb) of the first byte 
        for little-endian, and with bit-7 (msb) of the first byte for big-endian.  This is the 
        default behavior for most compilers.  Insertion behavior may not work as expected if 
        packing rules differ from this.
        
        :param jpype.JInt or int ordinal: the ordinal where the new datatype is to be inserted (numbering starts at 0).
        :param DataType baseDataType: the bitfield base datatype (certain restrictions apply).
        :param jpype.JInt or int bitSize: the declared bitfield size in bits.  The effective bit size may be
        adjusted based upon the specified baseDataType.
        :param java.lang.String or str componentName: the field name to associate with this component.
        :param java.lang.String or str comment: the comment to associate with this component.
        :return: the bitfield component created whose associated data type will
        be BitFieldDataType.
        :rtype: DataTypeComponent
        :raises InvalidDataTypeException: if the specified baseDataType is
        not a valid base type for bitfields.
        :raises java.lang.IndexOutOfBoundsException: if ordinal is less than 0 or greater than the 
        current number of components.
        """


class IconMaskResourceDataType(IconResourceDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DataTypeManagerChangeListener(java.lang.Object):
    """
    The listener interface for notification of changes to a DataTypeManager
    """

    class_: typing.ClassVar[java.lang.Class]

    def categoryAdded(self, dtm: DataTypeManager, path: CategoryPath):
        """
        Notification when category is added.
        
        :param DataTypeManager dtm: the dataType manager
        :param CategoryPath path: the categoryPath of the newly added category.
        """

    def categoryMoved(self, dtm: DataTypeManager, oldPath: CategoryPath, newPath: CategoryPath):
        """
        Notification when a category is reparented to new category.
        
        :param DataTypeManager dtm: data type manager associated with the category
        :param CategoryPath oldPath: the path of the category before it was moved.
        :param CategoryPath newPath: the path of the category after it was moved.
        """

    def categoryRemoved(self, dtm: DataTypeManager, path: CategoryPath):
        """
        Notification when a category is removed.
        
        :param DataTypeManager dtm: data type manager associated with the category
        :param CategoryPath path: the categoryPath of the category that was removed.
        """

    def categoryRenamed(self, dtm: DataTypeManager, oldPath: CategoryPath, newPath: CategoryPath):
        """
        Notification when category is renamed.
        
        :param DataTypeManager dtm: data type manager associated with the category
        :param CategoryPath oldPath: the path of the category before it was renamed.
        :param CategoryPath newPath: the path of the category after it was renamed.  This path will only differ in
        the last segment of the path.
        """

    def dataTypeAdded(self, dtm: DataTypeManager, path: DataTypePath):
        """
        Notification when a data type is added to a category
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath path: the DataTypePath of the newly added datatype.
        """

    def dataTypeChanged(self, dtm: DataTypeManager, path: DataTypePath):
        """
        Notification when data type is changed.
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath path: the path of the datatype that changed.
        """

    def dataTypeMoved(self, dtm: DataTypeManager, oldPath: DataTypePath, newPath: DataTypePath):
        """
        Notification when a data type is moved.
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath oldPath: the path of the datatype before it was moved.
        :param DataTypePath newPath: the path of the datatype after it was moved.
        """

    def dataTypeRemoved(self, dtm: DataTypeManager, path: DataTypePath):
        """
        Notification when data type is removed.
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath path: the DataTypePath of the removed datatype.
        """

    def dataTypeRenamed(self, dtm: DataTypeManager, oldPath: DataTypePath, newPath: DataTypePath):
        """
        Notification when data type is renamed.
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath oldPath: the path of the datatype before it was renamed.
        :param DataTypePath newPath: the path of the datatype after it was renamed.
        """

    def dataTypeReplaced(self, dtm: DataTypeManager, oldPath: DataTypePath, newPath: DataTypePath, newDataType: DataType):
        """
        Notification when a data type has been replaced.
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath oldPath: the path of the datatype that was replaced.
        :param DataTypePath newPath: the path of the datatype that replaced the existing datatype.
        :param DataType newDataType: the new dataType that replaced the old dataType
        """

    def favoritesChanged(self, dtm: DataTypeManager, path: DataTypePath, isFavorite: typing.Union[jpype.JBoolean, bool]):
        """
        Notification the favorite status of a datatype has changed
        
        :param DataTypeManager dtm: data type manager for the given category paths.
        :param DataTypePath path: the DataTypePath of the datatype had its favorite status changed.
        :param jpype.JBoolean or bool isFavorite: reflects the current favorite status of the datatype.
        """

    def programArchitectureChanged(self, dataTypeManager: DataTypeManager):
        """
        Notification that the program architecture associated with the specified
        dataTypeManager has changed.
        
        :param DataTypeManager dataTypeManager: data type manager referring to the given source information.
        """

    def restored(self, dataTypeManager: DataTypeManager):
        """
        Notification that the specified datatype manager has been restored to a 
        previous state.  NOTE: this notification may duplicate the :obj:`DomainObjectEvent.RESTORED`
        employed by :obj:`DataTypeManagerDomainObject` cases.
        
        :param DataTypeManager dataTypeManager: data type manager that has been restored
        """

    def sourceArchiveAdded(self, dataTypeManager: DataTypeManager, sourceArchive: SourceArchive):
        """
        Notification that the information for a source archive has been added. This happens when
        a data type from the indicated source archive is added to this data type manager.
        
        :param DataTypeManager dataTypeManager: data type manager referring to the given source information.
        :param SourceArchive sourceArchive: the new data type source information
        """

    def sourceArchiveChanged(self, dataTypeManager: DataTypeManager, sourceArchive: SourceArchive):
        """
        Notification that the information for a particular source archive has changed. Typically,
        this would be because it was renamed or moved.
        
        :param DataTypeManager dataTypeManager: data type manager referring to the given source information.
        :param SourceArchive sourceArchive: the changed data type source information
        """


class VoidDataType(BuiltIn):
    """
    Special dataType used only for function return types.  Used to indicate that
    a function has no return value.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.ClassVar[VoidDataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    @staticmethod
    def isVoidDataType(dt: DataType) -> bool:
        """
        Determine if the specified :obj:`DataType` is a :obj:`VoidDataType` after 
        stripping away any :obj:`TypeDef`.
        
        :param DataType dt: datatype to be tested
        :return: true if dt is a void type
        :rtype: bool
        """


@typing.type_check_only
class CustomOrganization(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTypeInstance(java.lang.Object):
    """
    An instance of a DataType that is applicable for a given context.  Most
    dataTypes are not context sensitive and are suitable for use anywhere.
    Others like dynamic structures need to create an instance that wraps the
    data type.
     
    It helps for situations where a data type must have a length.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataType(self) -> DataType:
        """
        
        
        :return: the data type
        :rtype: DataType
        """

    @staticmethod
    @typing.overload
    def getDataTypeInstance(dataType: DataType, buf: ghidra.program.model.mem.MemBuffer, useAlignedLength: typing.Union[jpype.JBoolean, bool]) -> DataTypeInstance:
        """
        Generate a data-type instance
        Factory and Dynamic data-types are NOT handled.
         
        
        This container does not dictate the placement of a fixed-length type within this
        container.  It is suggested that big-endian use should evaulate the datatype
        at the far end of the container.
        
        :param DataType dataType: data type
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer
        :param jpype.JBoolean or bool useAlignedLength: if true a fixed-length primitive data type will use its 
        :meth:`aligned-length <DataType.getAlignedLength>`, otherwise it will use its
        :meth:`raw length <DataType.getLength>`.  NOTE: This generally only relates to 
        float datatypes whose raw encoding length may be shorter than their aligned-length
        generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
        true for :obj:`DataTypeComponent` and false for simple :obj:`Data` instances.
        :return: data-type instance or null if one could not be determined
        :rtype: DataTypeInstance
        """

    @staticmethod
    @typing.overload
    def getDataTypeInstance(dataType: DataType, length: typing.Union[jpype.JInt, int], useAlignedLength: typing.Union[jpype.JBoolean, bool]) -> DataTypeInstance:
        """
        Attempt to create a fixed-length data-type instance.
        Factory and non-sizable Dynamic data-types are NOT handled.
         
        
        This container does not dictate the placement of a fixed-length type within this
        container.  It is suggested that big-endian use should evaulate the datatype
        at the far end of the container.
        
        :param DataType dataType: data type
        :param jpype.JInt or int length: length for sizable Dynamic data-types, otherwise ignored
        :param jpype.JBoolean or bool useAlignedLength: if true a fixed-length primitive data type will use its 
        :meth:`aligned-length <DataType.getAlignedLength>`, otherwise it will use its
        :meth:`raw length <DataType.getLength>`.  NOTE: This generally only relates to 
        float datatypes whose raw encoding length may be shorter than their aligned-length
        generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
        true for :obj:`DataTypeComponent` and false for simple :obj:`Data` instances.
        :return: data-type instance or null if unable to create instance.
        :rtype: DataTypeInstance
        """

    @staticmethod
    @typing.overload
    def getDataTypeInstance(dataType: DataType, buf: ghidra.program.model.mem.MemBuffer, length: typing.Union[jpype.JInt, int], useAlignedLength: typing.Union[jpype.JBoolean, bool]) -> DataTypeInstance:
        """
        Attempt to create a data-type instance associated with a specific memory location.
        Factory and Dynamic data-types are handled.
         
        
        This container does not dictate the placement of a fixed-length type within this
        container.  It is suggested that big-endian use should evaulate the datatype
        at the far end of the container.
        
        :param DataType dataType: the data type
        :param ghidra.program.model.mem.MemBuffer buf: memory location
        :param jpype.JInt or int length: length for sizable Dynamic data-types, otherwise ignored
        :param jpype.JBoolean or bool useAlignedLength: if true a fixed-length primitive data type will use its 
        :meth:`aligned-length <DataType.getAlignedLength>`, otherwise it will use its
        :meth:`raw length <DataType.getLength>`.  NOTE: This generally only relates to 
        float datatypes whose raw encoding length may be shorter than their aligned-length
        generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
        true for :obj:`DataTypeComponent` and false for simple :obj:`Data` instances.
        :return: data-type instance or null if unable to create instance.
        :rtype: DataTypeInstance
        """

    def getLength(self) -> int:
        """
        
        
        :return: the fixed length of the data type
        :rtype: int
        """

    def setLength(self, length: typing.Union[jpype.JInt, int]):
        """
        Set the length of this data type instance
        """

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @length.setter
    def length(self, value: jpype.JInt):
        ...


class InternalDataTypeComponent(DataTypeComponent):

    class_: typing.ClassVar[java.lang.Class]

    def cleanupFieldName(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Internal method for cleaning up field names.
        
        :param java.lang.String or str name: the new field name
        :return: the name with bad chars removed and also set back to null in the event
        the new name is the default name.
        :rtype: str
        """

    def setDataType(self, dataType: DataType):
        """
        Sets the DataType for this component.  Must be used carefully since the component
        will not be resized.
        
        :param DataType dataType: the new DataType for this component
        """

    @staticmethod
    def toString(c: DataTypeComponent) -> str:
        ...

    def update(self, ordinal: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]):
        """
        Update component ordinal, offset and length during alignment
        
        :param jpype.JInt or int ordinal: updated ordinal
        :param jpype.JInt or int offset: updated offset
        :param jpype.JInt or int length: updated byte length
        """


class SegmentedCodePointerDataType(BuiltIn):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class StringRenderBuilder(java.lang.Object):
    """
    Helper class used to build up a formatted (for human consumption) string representation returned
    by Unicode and String data types.
     
    
    Call :meth:`build() <.build>` to retrieve the formatted string.
     
    
    Example (quotes are part of result): ``"Test\tstring",01h,02h,"Second\npart"``
    """

    class_: typing.ClassVar[java.lang.Class]
    DOUBLE_QUOTE: typing.Final = '\"'
    SINGLE_QUOTE: typing.Final = '\''

    @typing.overload
    def __init__(self, cs: java.nio.charset.Charset, charSize: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, cs: java.nio.charset.Charset, charSize: typing.Union[jpype.JInt, int], quoteChar: typing.Union[jpype.JChar, int, str]):
        ...

    def addEscapedCodePoint(self, codePoint: typing.Union[jpype.JInt, int]):
        """
        Add a unicode codepoint as its escaped hex value, with a escape character
        prefix of 'x', 'u' or 'U' depending on the magnitude of the codePoint value.
         
        
        codePoint 15 -> '\' 'x' "0F"
        
        codePoint 65535 -> '\' 'u' "FFFF"
        
        codePoint 65536 -> '\' 'U' "00010000"
        
        
        :param jpype.JInt or int codePoint: int value
        """

    def build(self) -> str:
        ...

    def decodeBytesUsingCharset(self, bb: java.nio.ByteBuffer, renderSetting: RenderUnicodeSettingsDefinition.RENDER_ENUM, trimTrailingNulls: typing.Union[jpype.JBoolean, bool]):
        """
        Adds the characters found in the supplied :obj:`ByteBuffer` to the result.
         
        
        Any portions of the byte buffer that cause problems for the charset codec will be added
        as a :meth:`byte sequence <.addByteSeq>`.
         
        
        Characters that are outside the traditional ASCII range will be rendered as-is or as
        escape sequences, depending on the RENDER_ENUM setting.
        
        :param java.nio.ByteBuffer bb: :obj:`ByteBuffer` containing bytes of a string
        :param RenderUnicodeSettingsDefinition.RENDER_ENUM renderSetting: :obj:`RENDER_ENUM`
        :param jpype.JBoolean or bool trimTrailingNulls: boolean flag, if true trailing null bytes will not be included
        in the rendered output
        """

    def toString(self) -> str:
        """
        Example (quotes are part of result): ``"Test\tstring",01,02,"Second\npart",00``
        
        :return: Formatted string
        :rtype: str
        """


@deprecated("Calling convention name strings should be used instead of this class.\n CompilerSpec provides constants for those included in this enumeration and other\n setter/getter methods exist for using the string form.")
class GenericCallingConvention(java.lang.Enum[GenericCallingConvention]):
    """
    ``GenericCallingConvention`` identifies the generic calling convention
    associated with a specific function definition.  This can be used to help identify
    the appropriate compiler-specific function prototype (i.e., calling convention).
    
    
    .. deprecated::
    
    Calling convention name strings should be used instead of this class.
    :obj:`CompilerSpec` provides constants for those included in this enumeration and other
    setter/getter methods exist for using the string form.
    """

    class_: typing.ClassVar[java.lang.Class]
    unknown: typing.Final[GenericCallingConvention]
    """
    The calling convention has not been identified
    """

    stdcall: typing.Final[GenericCallingConvention]
    """
    A MS Windows specific calling convention applies in which
    the called-function is responsible for purging the stack.
    """

    cdecl: typing.Final[GenericCallingConvention]
    """
    The standard/default calling convention applies
    in which the stack is used to pass parameters
    """

    fastcall: typing.Final[GenericCallingConvention]
    """
    A standard/default calling convention applies
    in which only registers are used to pass parameters
    """

    thiscall: typing.Final[GenericCallingConvention]
    """
    A C++ instance method calling convention applies
    """

    vectorcall: typing.Final[GenericCallingConvention]
    """
    Similar to fastcall but extended vector registers are used
    """


    @staticmethod
    def get(ordinal: typing.Union[jpype.JInt, int]) -> GenericCallingConvention:
        """
        Returns the GenericCallingConvention corresponding to the specified
        ordinal.
        
        :param jpype.JInt or int ordinal: generic calling convention ordinal
        :return: GenericCallingConvention
        :rtype: GenericCallingConvention
        """

    def getDeclarationName(self) -> str:
        ...

    @staticmethod
    def getGenericCallingConvention(callingConvention: typing.Union[java.lang.String, str]) -> GenericCallingConvention:
        """
        Returns the GenericCallingConvention corresponding to the specified
        type string or unknown if name is not defined.
        
        :param java.lang.String or str callingConvention: calling convention declaration name (e.g., "__stdcall").
        Enum name is also allowed for backward compatibility.
        :return: GenericCallingConvention or :obj:`.unknown` if not found.
        :rtype: GenericCallingConvention
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GenericCallingConvention:
        ...

    @staticmethod
    def values() -> jpype.JArray[GenericCallingConvention]:
        ...

    @property
    def declarationName(self) -> java.lang.String:
        ...


class CharsetInfo(java.lang.Object):
    """
    Additional information about :obj:`java.nio.charset.Charset's <Charset>` that
    Ghidra needs to be able to create Ghidra string datatype instances.
     
    
    See charset_info.xml to specify a custom charset.
    """

    @typing.type_check_only
    class Singleton(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CharsetInfoRec(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    UTF8: typing.Final = "UTF-8"
    UTF16: typing.Final = "UTF-16"
    UTF32: typing.Final = "UTF-32"
    USASCII: typing.Final = "US-ASCII"

    def getCharsetCharSize(self, charsetName: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the number of bytes that the specified charset needs to specify a
        character.
        
        :param java.lang.String or str charsetName: charset name
        :return: number of bytes in a character, ie. 1, 2, 4, etc, defaults to 1
                if charset is unknown or not specified in config file.
        :rtype: int
        """

    def getCharsetNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array list of the currently configured charsets.
        
        :return: String[] of current configured charsets.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getCharsetNamesWithCharSize(self, size: typing.Union[jpype.JInt, int]) -> java.util.List[java.lang.String]:
        """
        Returns list of :obj:`Charset`s that encode with the number of bytes specified.
        
        :param jpype.JInt or int size: the number of bytes for the :obj:`Charset` encoding.
        :return: Charsets that encode one byte characters.
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getInstance() -> CharsetInfo:
        """
        Get the global singleton instance of this :obj:`CharsetInfo`.
        
        :return: global singleton instance
        :rtype: CharsetInfo
        """

    @staticmethod
    def isBOMCharset(charsetName: typing.Union[java.lang.String, str]) -> bool:
        """
        
        
        :param java.lang.String or str charsetName: name of charset
        :return: true if the supported multi-byte charset does not specify LE or
                BE
        :rtype: bool
        """

    @staticmethod
    def reinitializeWithUserDefinedCharsets():
        """
        Reinitialize registered Charsets and include user defined Charsets
        specified in charset_info.xml.
        """

    @property
    def charsetNamesWithCharSize(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def charsetCharSize(self) -> jpype.JInt:
        ...

    @property
    def charsetNames(self) -> jpype.JArray[java.lang.String]:
        ...


class IndexedDynamicDataType(DynamicDataType):
    """
    Indexed Dynamic Data Type template.  Used to create instances of the data type at
    a given location in memory based on the data found there.
     
    This data struture is used when there is a structure with key field in a header.
    The key field, which is a number, sets which of a number of structures follows the header.
     
        Header
            field a
            field b
            keyfield (value 1 means struct1 follows
                    value 2 means struct2 follows
                    .....
                    value n means structN follows
        Struct1 | Struct2 | ..... | StructN
    """

    class_: typing.ClassVar[java.lang.Class]
    NULL_BODY_DESCRIPTION: typing.Final = "NullBody"
    """
    Structures which do not have a body
    """


    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], header: DataType, keys: jpype.JArray[jpype.JLong], structs: jpype.JArray[DataType], indexOffset: typing.Union[jpype.JLong, int], indexSize: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        """
        Construct and the Index dynamic data type template.
        
        :param java.lang.String or str name: name of the data type
        :param java.lang.String or str description: description of the data type
        :param DataType header: the header data type that holds the keys to the location of other data types
        :param jpype.JArray[jpype.JLong] keys: key value array, one to one mapping to structs array
        :param jpype.JArray[DataType] structs: structure[n] to use if the key value equals keys[n]
        :param jpype.JLong or int indexOffset: index into the header structure that holds the key value
        :param jpype.JInt or int indexSize: size of the key value in bytes
        :param jpype.JLong or int mask: mask used on the key value to get the final key
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], header: DataType, singleKey: typing.Union[jpype.JLong, int], structs: jpype.JArray[DataType], indexOffset: typing.Union[jpype.JLong, int], indexSize: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JLong, int], dtm: DataTypeManager):
        """
        Construct the Indexed dynamic data type template.
        Used when there is one of two structures following and a single value tells which one.
        If the key value in the header structure matches the singleKey, then the first structure is used.
        If the key value does not match the singleKey, then the second structure is used.
        
        :param java.lang.String or str name: name of the data type
        :param java.lang.String or str description: description of the data type
        :param DataType header: the header data type that holds the keys to the location of other data types
        :param jpype.JLong or int singleKey: A single key value selects whether the structure appears
                            If the key value equals the singleKey then the first structure is used
                            If the key value doesn't, the second structure is used
        :param jpype.JArray[DataType] structs: structure[n] to use if the key value equals keys[n]
        :param jpype.JLong or int indexOffset: index into the header structure that holds the key value
        :param jpype.JInt or int indexSize: size of the key value in bytes
        :param jpype.JLong or int mask: mask used on the key value to get the final key
        """


class MissingBuiltInDataType(DataTypeImpl, Dynamic):
    """
    Provides an implementation of a data type that stands-in for a missing Built-In data type.
      
     
    This field is not meant to be loaded by the :obj:`ClassSearcher`, hence the X in the name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: CategoryPath, missingBuiltInName: typing.Union[java.lang.String, str], missingBuiltInClassPath: typing.Union[java.lang.String, str], dtm: DataTypeManager):
        """
        Construct a Missing Data Type
        
        :param CategoryPath path: category path
        :param java.lang.String or str missingBuiltInName: name of missing built-in datatype for which this will standin for.
        :param java.lang.String or str missingBuiltInClassPath: classpath of missing built-in datatype for which this will standin for.
        """

    def getMissingBuiltInClassPath(self) -> str:
        """
        Returns classpath of missing built-in datatype for which this type is standing-in for
        """

    def getMissingBuiltInName(self) -> str:
        """
        Returns name of missing built-in datatype for which this type is standing-in for
        """

    @property
    def missingBuiltInName(self) -> java.lang.String:
        ...

    @property
    def missingBuiltInClassPath(self) -> java.lang.String:
        ...


class Integer16DataType(AbstractSignedIntegerDataType):
    """
    A fixed size 16 byte signed integer (commonly referred to in C as int128_t)
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Integer16DataType]
    """
    A statically defined Integer16DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class PointerTypedef(GenericDataType, TypeDef):
    """
    ``PointerTypedef`` provides a Pointer-Typedef template datatype
    which may be used as an alternative to :obj:`PointerTypedefBuilder` for
    select use cases.  Once resolved this datatype is transformed into a 
    standard :obj:`TypeDef` with appropropriate settings (see 
    :obj:`TypeDefSettingsDefinition`).
     
    
    NOTE: The name of this class intentionally does not end with ``DataType``
    since it does not implement a default constructor so it may not be treated
    like other :obj:`BuiltIn` datatypes which are managed by the 
    :obj:`BuiltInDataTypeManager`.
     
    
    NOTE: As a :obj:`BuiltIn` datatype the use of :meth:`setName(String) <.setName>` and
    :meth:`setNameAndCategory(CategoryPath, String) <.setNameAndCategory>` is disabled.  The datatype
    instance must be instantiated with the correct typedef name.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, typeDefName: typing.Union[java.lang.String, str], referencedDataType: DataType, pointerSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager, space: ghidra.program.model.address.AddressSpace):
        """
        Constructs a pointer-typedef which dereferences into a specific address space.
        
        :param java.lang.String or str typeDefName: name of this pointer-typedef or null to use auto-named typedef.
        :param DataType referencedDataType: data type this pointer-typedef points to or null
        :param jpype.JInt or int pointerSize: pointer size in bytes or -1 for default pointer size based upon specified 
        address space and datatype manager
        :param DataTypeManager dtm: data-type manager whose data organization should be used (highly recommended, may be null)
        :param ghidra.program.model.address.AddressSpace space: address space to be used when dereferencing pointer offset
        """

    @typing.overload
    def __init__(self, typeDefName: typing.Union[java.lang.String, str], referencedDataType: DataType, pointerSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager, type: PointerType):
        """
        Constructs a pointer-typedef of a specific type
        
        :param java.lang.String or str typeDefName: name of this pointer-typedef or null to use auto-named typedef.
        :param DataType referencedDataType: data type this pointer-typedef points to or null
        :param jpype.JInt or int pointerSize: pointer size in bytes or -1 for default pointer size based upon datatype manager
        :param DataTypeManager dtm: data-type manager whose data organization should be used (highly recommended, may be null)
        :param PointerType type: pointer type (IBO, RELATIVE, FILE_OFFSET)
        """

    @typing.overload
    def __init__(self, typeDefName: typing.Union[java.lang.String, str], referencedDataType: DataType, pointerSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager, componentOffset: typing.Union[jpype.JLong, int]):
        """
        Constructs a offset-pointer-typedef
        
        :param java.lang.String or str typeDefName: name of this pointer-typedef or null to use auto-named typedef.
        :param DataType referencedDataType: data type this pointer-typedef points to or null
        :param jpype.JInt or int pointerSize: pointer size in bytes or -1 for default pointer size based upon datatype manager
        :param DataTypeManager dtm: data-type manager whose data organization should be used (highly recommended, may be null)
        :param jpype.JLong or int componentOffset: signed component offset setting value (see :obj:`ComponentOffsetSettingsDefinition`
        """

    @typing.overload
    def __init__(self, typeDefName: typing.Union[java.lang.String, str], referencedDataType: DataType, pointerSize: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Constructs a pointer-typedef without any settings
        
        :param java.lang.String or str typeDefName: name of this pointer-typedef or null to use auto-named typedef.
        :param DataType referencedDataType: data type this pointer-typedef points to or null
        :param jpype.JInt or int pointerSize: pointer size in bytes or -1 for default pointer size based upon datatype manager
        :param DataTypeManager dtm: data-type manager whose data organization should be used (highly recommended, may be null)
        """

    @typing.overload
    def __init__(self, typeDefName: typing.Union[java.lang.String, str], pointerDataType: Pointer, dtm: DataTypeManager):
        """
        Constructs a pointer-typedef without any settings
        
        :param java.lang.String or str typeDefName: name of this pointer-typedef or null to use auto-named typedef.
        :param Pointer pointerDataType: associated pointer datatype
        :param DataTypeManager dtm: data-type manager whose data organization should be used (highly recommended, may be null)
        """

    def getUniversalID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def universalID(self) -> ghidra.util.UniversalID:
        ...


class DataTypePath(java.lang.Comparable[DataTypePath]):
    """
    Object to hold a category path and a datatype name.  They are held separately so that
    the datatype name can contain a categoryPath delimiter ("/") character.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, categoryPath: typing.Union[java.lang.String, str], dataTypeName: typing.Union[java.lang.String, str]):
        """
        Create DatatypePath
        
        :param java.lang.String or str categoryPath: the category path for the datatype
        :param java.lang.String or str dataTypeName: the name of the datatype.
        :raises IllegalArgumentException: if an invalid category path or dataTypeName is given.
        """

    @typing.overload
    def __init__(self, categoryPath: CategoryPath, dataTypeName: typing.Union[java.lang.String, str]):
        """
        Create DatatypePath
        
        :param CategoryPath categoryPath: the category path for the datatype
        :param java.lang.String or str dataTypeName: the name of the datatype.
        :raises IllegalArgumentException: if a null category path or dataTypeName is given.
        """

    def getCategoryPath(self) -> CategoryPath:
        """
        Returns the categoryPath for the datatype represented by this datatype path.
        (ie. the CategoryPath that contains the DataType that this DataTypePath points to).
        
        :return: the parent :obj:`CategoryPath` of the :obj:`DataType` that this DataTypePath
        points to.
        :rtype: CategoryPath
        """

    def getDataTypeName(self) -> str:
        """
        Returns the name of the datatype.
        
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Returns the full path of this datatype.  NOTE: if the datatype name contains any
        "/" characters, then the resulting path string may be ambiguous as to where the
        category path ends and the datatype name begins.
        
        :return: the full path
        :rtype: str
        """

    def isAncestor(self, otherCategoryPath: CategoryPath) -> bool:
        """
        Determine if the specified otherCategoryPath is an ancestor of this data type
        path (i.e., does this data types category or any of its parent hierarchy correspond
        to the specified categoryPath).
        
        :param CategoryPath otherCategoryPath: category path
        :return: true if otherCategoryPath is an ancestor of this data type path, else false
        :rtype: bool
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def dataTypeName(self) -> java.lang.String:
        ...

    @property
    def categoryPath(self) -> CategoryPath:
        ...

    @property
    def ancestor(self) -> jpype.JBoolean:
        ...


class UnsignedInteger5DataType(AbstractUnsignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedInteger5DataType]
    """
    A statically defined UnsignedInteger5DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class FunctionDefinition(DataType, ghidra.program.model.listing.FunctionSignature):
    """
    Defines a function signature for things like function pointers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def replaceArgument(self, ordinal: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], dt: DataType, comment: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Replace the given argument with another data type
        
        :param jpype.JInt or int ordinal: the index of the argument to be replaced, starting from '0'
        :param java.lang.String or str name: name of the new argument
        :param DataType dt: data type of the new argument
        :param java.lang.String or str comment: comment for the argument
        :param ghidra.program.model.symbol.SourceType source: the source of this function definition argument: 
        Symbol.DEFAULT, Symbol.ANALYSIS, Symbol.IMPORTED, or Symbol.USER_DEFINED
        """

    def setArguments(self, *args: ParameterDefinition):
        """
        Set the arguments to this function.
        
        :param jpype.JArray[ParameterDefinition] args: array of parameter definitions to be used as arguments to this function
        """

    def setCallingConvention(self, conventionName: typing.Union[java.lang.String, str]):
        """
        Set the calling convention associated with this function definition.
         
        
        The total number of unique calling convention names used within a given :obj:`Program`
        or :obj:`DataTypeManager` may be limited (e.g., 127).  When this limit is exceeded an error
        will be logged and this setting ignored.
        
        :param java.lang.String or str conventionName: calling convention name or null.  This name is restricted to those
        defined by :obj:`GenericCallingConvention`, the associated compiler specification.  
        The prototype model declaration name form (e.g., "__stdcall") should be specified as it 
        appears in a compiler specification (*.cspec).  The special "unknown" and "default" names 
        are also allowed.
        :raises InvalidInputException: if specified conventionName is not defined by 
        :obj:`GenericCallingConvention` or the associated compiler specification if 
        datatype manager has an associated program architecture.
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the function comment
        
        :param java.lang.String or str comment: the comment to set.
        """

    @deprecated("Use of GenericCallingConvention is deprecated since arbitrary calling\n convention names are now supported.  setCallingConvention(String) should be used.")
    def setGenericCallingConvention(self, genericCallingConvention: GenericCallingConvention):
        """
        Set the generic calling convention associated with this function definition.
         
        
        The total number of unique calling convention names used within a given :obj:`Program`
        or :obj:`DataTypeManager` may be limited (e.g., 127).  When this limit is exceeded an error
        will be logged and this setting ignored.
        
        :param GenericCallingConvention genericCallingConvention: generic calling convention
        
        .. deprecated::
        
        Use of :obj:`GenericCallingConvention` is deprecated since arbitrary calling
        convention names are now supported.  :meth:`setCallingConvention(String) <.setCallingConvention>` should be used.
        """

    def setNoReturn(self, hasNoReturn: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether or not this function has a return.
        
        :param jpype.JBoolean or bool hasNoReturn: true if this function does not return.
        """

    def setReturnType(self, type: DataType):
        """
        Set the return data type for this function
        
        :param DataType type: the return datatype to be set.
        :raises java.lang.IllegalArgumentException: if data type is not a fixed length type
        """

    def setVarArgs(self, hasVarArgs: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether parameters can be passed as a VarArg (variable argument list).
        
        :param jpype.JBoolean or bool hasVarArgs: true if this function has a variable argument list (ie printf(fmt, ...)).
        """


class FloatComplexDataType(AbstractComplexDataType):
    """
    Provides a definition of a ``complex`` built-in data type consisting of two floating point
    numbers in the IEEE 754 double precision format.
     
    
    The size of the floating point numbers is determined by the program's data organization as defined
    by the language/compiler spec
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[FloatComplexDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DialogResourceDataType(DynamicDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def getItemType(self, value: typing.Union[java.lang.Integer, int]) -> str:
        ...

    @property
    def itemType(self) -> java.lang.String:
        ...


class RepeatCountDataType(DynamicDataType):
    """
    Base abstract data type for a Dynamic structure data type that contains
    some number of repeated data types.  The first entry contains the number of
    repeated data types to follow.  Immediately following the first element are
    the repeated data types.
     
    The dynamic structure looks like this:
     
        RepeatDataType
        number = N   - two bytes, little endian
        RepDT1
        repDT2
        ...
        repDTN
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...


class DataTypeManager(java.lang.Object):
    """
    Interface for Managing data types.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_DATATYPE_ID: typing.Final = 0
    """
    ID for the default (undefined) data type.
    """

    NULL_DATATYPE_ID: typing.Final = -1
    """
    ID if data type type is not known in this data type manager.
    """

    BAD_DATATYPE_ID: typing.Final = -2
    """
    ID if data type type is BAD.
    """

    BUILT_IN_DATA_TYPES_NAME: typing.Final = "BuiltInTypes"
    """
    Name of the category for the build in data types.
    """

    LOCAL_ARCHIVE_KEY: typing.Final = 0
    BUILT_IN_ARCHIVE_KEY: typing.Final = 1
    LOCAL_ARCHIVE_UNIVERSAL_ID: typing.Final[ghidra.util.UniversalID]
    BUILT_IN_ARCHIVE_UNIVERSAL_ID: typing.Final[ghidra.util.UniversalID]

    def addDataType(self, dataType: DataType, handler: DataTypeConflictHandler) -> DataType:
        """
        Returns a data type after adding it to this data manager.
        The returned dataType will be in a category in this dataTypeManager
        that is equivalent to the category of the passed in dataType.
        
        :param DataType dataType: the dataType to be resolved.
        :param DataTypeConflictHandler handler: used to resolve conflicts with existing dataTypes.
        :return: an equivalent dataType that "belongs" to this dataTypeManager.
        :rtype: DataType
        """

    def addDataTypeManagerListener(self, l: DataTypeManagerChangeListener):
        """
        Add a listener that is notified when the dataTypeManger changes.
        
        :param DataTypeManagerChangeListener l: the listener
        """

    def addDataTypes(self, dataTypes: collections.abc.Sequence, handler: DataTypeConflictHandler, monitor: ghidra.util.task.TaskMonitor):
        """
        Sequentially adds a collection of datatypes to this data manager.
        This method provides the added benefit of equivalence caching
        for improved performance.
         
        
        WARNING: This is an experimental method whose use may cause the GUI and
        task monitor to become unresponsive due to extended hold times on the manager lock.
        
        :param collections.abc.Sequence dataTypes: collection of datatypes
        :param DataTypeConflictHandler handler: conflict handler
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if monitor is cancelled
        """

    def addInvalidatedListener(self, listener: InvalidatedListener):
        """
        Adds a listener that will be notified when this manager's cache is invalidated.  This will
        happen when the system has changed and the manager cannot determine the exact change, like
        during an undo or a redo.
        
        :param InvalidatedListener listener: The listener to add
        """

    def allowsDefaultBuiltInSettings(self) -> bool:
        """
        Determine if settings are supported for BuiltIn datatypes within this
        datatype manager.
        
        :return: true if BuiltIn Settings are permitted
        :rtype: bool
        """

    def allowsDefaultComponentSettings(self) -> bool:
        """
        Determine if settings are supported for datatype components within this
        datatype manager (i.e., for structure and union components).
        
        :return: true if BuiltIn Settings are permitted
        :rtype: bool
        """

    def associateDataTypeWithArchive(self, datatype: DataType, archive: SourceArchive):
        """
        Change the given data type and its dependencies so thier source archive is set to
        given archive.  Only those data types not already associated with a source archive
        will be changed.
        
        :param DataType datatype: the type
        :param SourceArchive archive: the archive
        """

    def close(self):
        """
        Closes this dataType manager
        """

    def contains(self, dataType: DataType) -> bool:
        """
        Return true if the given dataType exists in this data type manager
        
        :param DataType dataType: the type
        :return: true if the type is in this manager
        :rtype: bool
        """

    def containsCategory(self, path: CategoryPath) -> bool:
        """
        Returns true if the given category path exists in this datatype manager
        
        :param CategoryPath path: the path
        :return: true if the given category path exists in this datatype manager
        :rtype: bool
        """

    def createCategory(self, path: CategoryPath) -> Category:
        """
        Create a category for the given path; returns the current category if it already exits
        
        :param CategoryPath path: the path
        :return: the category
        :rtype: Category
        """

    def disassociate(self, datatype: DataType):
        """
        If the indicated data type is associated with a source archive, this will remove the
        association and the data type will become local to this data type manager.
        
        :param DataType datatype: the data type to be disassociated from a source archive.
        """

    def endTransaction(self, transactionID: typing.Union[jpype.JInt, int], commit: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Ends the current transaction.
         
        
        NOTE: If multiple transactions are outstanding the full transaction will not be ended
        until all transactions have been ended.  If any of the transactions indicate a 
        false for ``commit`` the transaction will ultimately be rolled-back when the final
        transaction is ended.
         
        
        NOTE: Use of rollback (``commit=false`` should be avoided unless absolutely
        neccessary since it will incur overhead to revert changes and may rollback multiple
        concurrent transactions if they exist.
         
        
        NOTE: If this manager is part of a larger :obj:`DomainObject` its transactions may become
        entangled with other transactions at a higher level.  In such cases, use of  the 
        :obj:`DomainObject` transaction interface is preferred.  The return value from this
        method cannot be relied on in such cases.
        
        :param jpype.JInt or int transactionID: id of the transaction to end
        :param jpype.JBoolean or bool commit: true if changes are committed, false if changes in transaction should be
        rolled back.
        :return: true if this invocation was the final transaction and all changes were comitted.
        :rtype: bool
        """

    @deprecated("use getDataType(String) or better yet getDataType(DataTypePath)")
    def findDataType(self, dataTypePath: typing.Union[java.lang.String, str]) -> DataType:
        """
        Gets the dataType for the given path. See :meth:`getDataType(String) <.getDataType>` for details.
        
        :param java.lang.String or str dataTypePath: dataType path
        :return: dataType at the given path
        :rtype: DataType
        
        .. deprecated::
        
        use :meth:`getDataType(String) <.getDataType>` or better yet :meth:`getDataType(DataTypePath) <.getDataType>`
        """

    def findDataTypeForID(self, datatypeID: ghidra.util.UniversalID) -> DataType:
        """
        Get's the data type with the matching universal data type id.
        
        :param ghidra.util.UniversalID datatypeID: The universal id of the data type to search for
        :return: The data type with the matching UUID, or null if no such data type can be found.
        :rtype: DataType
        """

    @typing.overload
    def findDataTypes(self, name: typing.Union[java.lang.String, str], list: java.util.List[DataType]):
        """
        Begin searching at the root category for all data types with the
        given name. Places all the data types in this data type manager
        with the given name into the list.  Presence of ``.conflict``
        extension will be ignored for both specified name and returned
        results.
        
        :param java.lang.String or str name: name of the data type (wildcards are not supported and will be treated
        as explicit search characters)
        :param java.util.List[DataType] list: list that will be populated with matching DataType objects
        """

    @typing.overload
    def findDataTypes(self, name: typing.Union[java.lang.String, str], list: java.util.List[DataType], caseSensitive: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Begin searching at the root category for all data types with names
        that match the given name that may contain wildcards using familiar globbing 
        characters '*' and '?'.
        
        :param java.lang.String or str name: name to match; may contain wildcards
        :param java.util.List[DataType] list: list that will be populated with matching DataType objects
        :param jpype.JBoolean or bool caseSensitive: true if the match is case sensitive
        :param ghidra.util.task.TaskMonitor monitor: task monitor to cancel the search
        """

    def findEnumValueNames(self, value: typing.Union[jpype.JLong, int], enumValueNames: java.util.Set[java.lang.String]):
        """
        Adds all enum value names that match the given value, to the given set.
        
        :param jpype.JLong or int value: the value to look for enum name matches
        :param java.util.Set[java.lang.String] enumValueNames: the set to add matches to.
        """

    def flushEvents(self):
        """
        Force all pending notification events to be flushed
        
        :raises IllegalStateException: if the client is holding this object's lock
        """

    def getAddressMap(self) -> ghidra.program.database.map.AddressMap:
        """
        Returns the associated AddressMap used by this datatype manager.
        
        :return: the AddressMap used by this datatype manager or null if 
        one has not be established.
        :rtype: ghidra.program.database.map.AddressMap
        """

    def getAllComposites(self) -> java.util.Iterator[Composite]:
        """
        Returns an iterator over all composite data types (structures and unions) in this manager
        
        :return: the iterator
        :rtype: java.util.Iterator[Composite]
        """

    @typing.overload
    def getAllDataTypes(self) -> java.util.Iterator[DataType]:
        """
        Returns an iterator over all the dataTypes in this manager
        
        :return: an iterator over all the dataTypes in this manager
        :rtype: java.util.Iterator[DataType]
        """

    @typing.overload
    def getAllDataTypes(self, list: java.util.List[DataType]):
        """
        Adds all data types to the specified list.]
        
        :param java.util.List[DataType] list: the result list into which the types will be placed
        """

    def getAllFunctionDefinitions(self) -> java.util.Iterator[FunctionDefinition]:
        """
        Returns an iterator over all function definition data types in this manager
        
        :return: the iterator
        :rtype: java.util.Iterator[FunctionDefinition]
        """

    def getAllStructures(self) -> java.util.Iterator[Structure]:
        """
        Returns an iterator over all structures in this manager
        
        :return: the iterator
        :rtype: java.util.Iterator[Structure]
        """

    def getCallingConvention(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.PrototypeModel:
        """
        Get the prototype model of the calling convention with the specified name from the 
        associated compiler specification.  If an architecture has not been established this method 
        will return null.  If :obj:`Function.DEFAULT_CALLING_CONVENTION_STRING`
        is specified :meth:`getDefaultCallingConvention() <.getDefaultCallingConvention>` will be returned.
        
        :param java.lang.String or str name: the calling convention name
        :return: the named function calling convention prototype model or null.
        :rtype: ghidra.program.model.lang.PrototypeModel
        """

    @typing.overload
    def getCategory(self, categoryID: typing.Union[jpype.JLong, int]) -> Category:
        """
        Returns the Category with the given id
        
        :param jpype.JLong or int categoryID: id of the desired category
        :return: the category
        :rtype: Category
        """

    @typing.overload
    def getCategory(self, path: CategoryPath) -> Category:
        """
        Get the category that has the given path
        
        :param CategoryPath path: the path
        :return: the category if defined, otherwise null
        :rtype: Category
        """

    def getCategoryCount(self) -> int:
        """
        Returns the total number of data type categories
        
        :return: the count
        :rtype: int
        """

    def getDataOrganization(self) -> DataOrganization:
        """
        Get the data organization associated with this data type manager.  Note that the
        DataOrganization settings may not be changed dynamically.
        
        :return: data organization (will never be null)
        :rtype: DataOrganization
        """

    @typing.overload
    def getDataType(self, dataTypePath: typing.Union[java.lang.String, str]) -> DataType:
        """
        Retrieve the data type with the fully qualified path. So you can get the data named
        "bar" in the category "foo" by calling getDataType("/foo/bar").  This method can
        be problematic now that datatype names can contain slashes.  It will work provided
        that the part of the datatype name that precedes its internal slash is not also the
        name of a category in the same category as the datatype.  For example, if you call
        getDataType("/a/b/c"), and "b/c" is the name of your datatype, it will find it unless
        there is also a category "b" under category "a".  A better solution is to use
        the :meth:`getDataType(DataTypePath) <.getDataType>` method because the DataTypePath keeps the
        category and datatype name separate.
        
        :param java.lang.String or str dataTypePath: path
        :return: the dataType or null if it isn't found
        :rtype: DataType
        """

    @typing.overload
    def getDataType(self, dataTypePath: DataTypePath) -> DataType:
        """
        Find the dataType for the given dataTypePath.
        
        :param DataTypePath dataTypePath: the DataTypePath for the datatype
        :return: the datatype for the given path.
        :rtype: DataType
        """

    @typing.overload
    def getDataType(self, dataTypeID: typing.Union[jpype.JLong, int]) -> DataType:
        """
        Returns the dataType associated with the given dataTypeId or null if the dataTypeId is
        not valid
        
        :param jpype.JLong or int dataTypeID: the ID
        :return: the type
        :rtype: DataType
        """

    @typing.overload
    def getDataType(self, path: CategoryPath, name: typing.Union[java.lang.String, str]) -> DataType:
        """
        Gets the data type with the indicated name in the indicated category.
        
        :param CategoryPath path: the path for the category
        :param java.lang.String or str name: the data type's name
        :return: the data type.
        :rtype: DataType
        """

    @typing.overload
    def getDataType(self, sourceArchive: SourceArchive, datatypeID: ghidra.util.UniversalID) -> DataType:
        """
        Finds the data type using the given source archive and id.
        
        :param SourceArchive sourceArchive: the optional source archive; required when the type is associated with
        that source archive
        :param ghidra.util.UniversalID datatypeID: the type's id
        :return: the type or null
        :rtype: DataType
        """

    def getDataTypeCount(self, includePointersAndArrays: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Returns the total number of defined data types.
        
        :param jpype.JBoolean or bool includePointersAndArrays: if true all pointers and array data types will be included
        :return: the count
        :rtype: int
        """

    def getDataTypes(self, sourceArchive: SourceArchive) -> java.util.List[DataType]:
        """
        Returns all data types within this manager that have as their source the given archive
        
        :param SourceArchive sourceArchive: the archive
        :return: the types
        :rtype: java.util.List[DataType]
        """

    @deprecated("the method DataType.getParents() should be used instead.\n Use of Set implementations for containing DataTypes is also inefficient.")
    def getDataTypesContaining(self, dataType: DataType) -> java.util.Set[DataType]:
        """
        Returns the data types within this data type manager that contain the specified data type.
        The specified dataType must belong to this datatype manager.  An empty set will be
        returned for unsupported datatype instances.
        
        :param DataType dataType: the data type
        :return: a set of data types that contain the specified data type.
        :rtype: java.util.Set[DataType]
        
        .. deprecated::
        
        the method :meth:`DataType.getParents() <DataType.getParents>` should be used instead.
        Use of :obj:`Set` implementations for containing DataTypes is also inefficient.
        """

    def getDefaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Get the default calling convention's prototype model in this datatype manager if known.
        
        :return: the default calling convention prototype model or null.
        :rtype: ghidra.program.model.lang.PrototypeModel
        """

    def getDefinedCallingConventionNames(self) -> java.util.Collection[java.lang.String]:
        """
        Get the ordered list of defined calling convention names.  The reserved names 
        "unknown" and "default" are not included.  The returned collection may not include all names 
        referenced by various functions and function-definitions.  This set is generally limited to 
        those defined by the associated compiler specification.  If this instance does not have an 
        assigned architecture the :obj:`GenericCallingConvention` names will be returned.
         
        
        For a set of all known names (including those that are not defined by compiler spec)
        see :meth:`getKnownCallingConventionNames() <.getKnownCallingConventionNames>`.
        
        :return: the set of defined calling convention names.
        :rtype: java.util.Collection[java.lang.String]
        """

    def getFavorites(self) -> java.util.List[DataType]:
        """
        Returns a list of datatypes that have been designated as favorites.
        
        :return: the list of favorite datatypes in this manager.
        :rtype: java.util.List[DataType]
        """

    def getID(self, dt: DataType) -> int:
        """
        Returns the dataTypeId for the given dataType.  If the dataType does not exist,
        a -1 will be returned
        
        :param DataType dt: the datatype to get an id for
        :return: the ID of the type
        :rtype: int
        """

    def getKnownCallingConventionNames(self) -> java.util.Collection[java.lang.String]:
        """
        Get the ordered list of known calling convention names.  The reserved names 
        "unknown" and "default" are not included.  The returned collection will include all names 
        ever used or resolved by associated :obj:`Function` and :obj:`FunctionDefinition` objects, 
        even if not currently defined by the associated :obj:`CompilerSpec` or :obj:`Program` 
        :obj:`SpecExtension`.  To get only those calling conventions formally defined, the method 
        :meth:`CompilerSpec.getCallingConventions() <CompilerSpec.getCallingConventions>` should be used.
        
        :return: all known calling convention names.
        :rtype: java.util.Collection[java.lang.String]
        """

    def getLastChangeTimeForMyManager(self) -> int:
        """
        Returns the timestamp of the last time this manager was changed
        
        :return: the timestamp
        :rtype: int
        """

    def getLocalSourceArchive(self) -> SourceArchive:
        """
        Returns the source archive for this manager
        
        :return: the archive; null if the ID is null; null if the archive does not exist
        :rtype: SourceArchive
        """

    def getName(self) -> str:
        """
        Returns this data type manager's name
        
        :return: the name
        :rtype: str
        """

    @typing.overload
    def getPointer(self, datatype: DataType) -> Pointer:
        """
        Returns a default sized pointer to the given datatype.  The pointer size is established
        dynamically based upon the data organization established by the compiler specification.
        
        :param DataType datatype: the pointed to data type
        :return: the pointer
        :rtype: Pointer
        """

    @typing.overload
    def getPointer(self, datatype: DataType, size: typing.Union[jpype.JInt, int]) -> Pointer:
        """
        Returns a pointer of the given size to the given datatype.
        Note: It is preferred to use default sized pointers when possible (i.e., size=-1,
        see :meth:`getPointer(DataType) <.getPointer>`) instead of explicitly specifying the size value.
        
        :param DataType datatype: the pointed to data type
        :param jpype.JInt or int size: the size of the pointer to be created or -1 for a default sized pointer
        :return: the pointer
        :rtype: Pointer
        """

    def getProgramArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture:
        """
        Get the optional program architecture details associated with this archive
        
        :return: program architecture details or null if none
        :rtype: ghidra.program.model.lang.ProgramArchitecture
        """

    def getProgramArchitectureSummary(self) -> str:
        """
        Get the program architecture information which has been associated with this 
        datatype manager.  If :meth:`getProgramArchitecture() <.getProgramArchitecture>` returns null this method
        may still return information if the program architecture was set on an archive but unable
        to properly instantiate.
        
        :return: program architecture summary if it has been set
        :rtype: str
        """

    def getResolvedID(self, dt: DataType) -> int:
        """
        Returns the dataTypeId for the given dataType.  If the dataType is not
        currently in the dataTypeManger, it will be added
        
        :param DataType dt: the data type
        :return: the ID of the resolved type
        :rtype: int
        """

    def getRootCategory(self) -> Category:
        """
        Returns the root category Manager
        
        :return: the category
        :rtype: Category
        """

    def getSourceArchive(self, sourceID: ghidra.util.UniversalID) -> SourceArchive:
        """
        Returns the source archive for the given ID
        
        :param ghidra.util.UniversalID sourceID: the ID
        :return: the archive; null if the ID is null; null if the archive does not exist
        :rtype: SourceArchive
        """

    def getSourceArchives(self) -> java.util.List[SourceArchive]:
        """
        Returns a list of source archives not including the builtin or the program's archive.
        
        :return: a list of source archives not including the builtin or the program's archive.
        :rtype: java.util.List[SourceArchive]
        """

    def getType(self) -> ArchiveType:
        """
        Returns this manager's archive type
        
        :return: the type
        :rtype: ArchiveType
        """

    def getUniqueName(self, path: CategoryPath, baseName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a unique name not currently used by any other dataType or category
        with the same baseName.  This does not produce a conflict name and is intended 
        to be used when generating an artifical datatype name only (e.g., ``temp_1``,
        ``temp_2``; for ``baseName="temp"``.
        
        :param CategoryPath path: the path of the name
        :param java.lang.String or str baseName: the base name to be made unique
        :return: a unique name starting with baseName
        :rtype: str
        """

    def getUniversalID(self) -> ghidra.util.UniversalID:
        """
        Returns the universal ID for this dataType manager
        
        :return: the universal ID for this dataType manager
        :rtype: ghidra.util.UniversalID
        """

    def isFavorite(self, datatype: DataType) -> bool:
        """
        Returns true if the given datatype has been designated as a favorite. If the datatype
        does not belong to this datatype manager, then false will be returned.
        
        :param DataType datatype: the datatype to check.
        :return: true if the given datatype is a favorite in this manager.
        :rtype: bool
        """

    def isUpdatable(self) -> bool:
        """
        Returns true if this DataTypeManager can be modified.
        
        :return: true if this DataTypeMangaer can be modified.
        :rtype: bool
        """

    def openTransaction(self, description: typing.Union[java.lang.String, str]) -> db.Transaction:
        """
        Open new transaction.  This should generally be done with a try-with-resources block:
         
        try (Transaction tx = dtm.openTransaction(description)) {
            // ... Do something
        }
         
        
        :param java.lang.String or str description: a short description of the changes to be made.
        :return: transaction object
        :rtype: db.Transaction
        :raises java.lang.IllegalStateException: if this :obj:`DataTypeManager` has already been closed.
        """

    def remove(self, dataType: DataType, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Remove the given datatype from this manager.
         
        
        NOTE: Any use of the specified datatype within a :obj:`FunctionDefinition` will be 
        converted to the :obj:`default 'undefined' datatype <DataType.DEFAULT>`.  Any use within
        a :obj:`Structure` or :obj:`Union` will be converted to the :obj:`BadDataType` as
        a placeholder to retain the component's field name and length (the comment will be prefixed
        with a message indicating the remval of the old datatype.
        
        :param DataType dataType: the dataType to be removed
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the data type existed and was removed
        :rtype: bool
        """

    def removeDataTypeManagerListener(self, l: DataTypeManagerChangeListener):
        """
        Remove the DataTypeManger change listener.
        
        :param DataTypeManagerChangeListener l: the listener
        """

    def removeInvalidatedListener(self, listener: InvalidatedListener):
        """
        Removes a previously added InvalidatedListener
        
        :param InvalidatedListener listener: the listener to remove.
        """

    def removeSourceArchive(self, sourceArchive: SourceArchive):
        """
        Removes the source archive from this manager.  This will disassociate all data types in
        this manager from the given archive.
        
        :param SourceArchive sourceArchive: the archive
        """

    def replaceDataType(self, existingDt: DataType, replacementDt: DataType, updateCategoryPath: typing.Union[jpype.JBoolean, bool]) -> DataType:
        """
        Replace an existing dataType with another.  All instances and references will be updated to
        use the replacement dataType.
        
        :param DataType existingDt: the dataType to be replaced.
        :param DataType replacementDt: the dataType to use as the replacement.
        :param jpype.JBoolean or bool updateCategoryPath: if true, the replacementDt will have its categoryPath changed
        to the exitingDt's path.
        :return: the resolved replacement dataType.
        :rtype: DataType
        :raises DataTypeDependencyException: if the replacement datatype depends on
        the existing dataType;
        """

    def resolve(self, dataType: DataType, handler: DataTypeConflictHandler) -> DataType:
        """
        Returns a dataType that is "in" (ie suitable implementation) this
        Manager, creating a new one if necessary.  Also the returned dataType
        will be in a category in this dataTypeManager that is equivalent to the
        category of the passed in dataType.
        
        :param DataType dataType: the dataType to be resolved.
        :param DataTypeConflictHandler handler: used to resolve conflicts with existing dataTypes.
        :return: an equivalent dataType that "belongs" to this dataTypeManager.
        :rtype: DataType
        """

    def resolveSourceArchive(self, sourceArchive: SourceArchive) -> SourceArchive:
        """
        Returns or creates a persisted version of the given source archive
        
        :param SourceArchive sourceArchive: the archive
        :return: the archive
        :rtype: SourceArchive
        """

    def setFavorite(self, datatype: DataType, isFavorite: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the given dataType to be either a favorite or not a favorite.
        
        :param DataType datatype: the datatype for which to change its status as a favorite.
        :param jpype.JBoolean or bool isFavorite: true if the datatype is to be a favorite or false otherwise.
        :raises IllegalArgumentException: if the given datatype does not belong to this manager.
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets this data type manager's name
        
        :param java.lang.String or str name: the new name
        :raises InvalidNameException: if the given name is invalid (such as when null or empty)
        """

    def startTransaction(self, description: typing.Union[java.lang.String, str]) -> int:
        """
        Starts a transaction for making changes in this data type manager.
        
        :param java.lang.String or str description: a short description of the changes to be made.
        :return: the transaction ID
        :rtype: int
        """

    @typing.overload
    def updateSourceArchiveName(self, archiveFileID: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> bool:
        """
        Updates the name associated with a source archive in this data type manager.
        
        :param java.lang.String or str archiveFileID: Universal domain file ID of the source data type archive that has a new name.
        :param java.lang.String or str name: the new name of the program or archive.
        :return: true if the name associated with the source data type archive was changed.
        false if it wasn't changed.
        :rtype: bool
        """

    @typing.overload
    def updateSourceArchiveName(self, sourceID: ghidra.util.UniversalID, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Updates the name associated with a source archive in this data type manager.
        
        :param ghidra.util.UniversalID sourceID: Universal archive ID of the source data type archive that has a new name.
        :param java.lang.String or str name: the new name of the program or archive.
        :return: true if the name associated with the source data type archive was changed.
        false if it wasn't changed.
        :rtype: bool
        """

    @typing.overload
    def withTransaction(self, description: typing.Union[java.lang.String, str], callback: utility.function.ExceptionalCallback[E]):
        """
        Performs the given callback inside of a transaction.  Use this method in place of the more
        verbose try/catch/finally semantics.
         
        program.withTransaction("My Description", () -> {
            // ... Do something
        });
         
         
         
        
        Note: the transaction created by this method will always be committed when the call is 
        finished.  If you need the ability to abort transactions, then you need to use the other 
        methods on this interface.
        
        :param java.lang.String or str description: brief description of transaction
        :param utility.function.ExceptionalCallback[E] callback: the callback that will be called inside of a transaction
        :raises E: any exception that may be thrown in the given callback
        """

    @typing.overload
    def withTransaction(self, description: typing.Union[java.lang.String, str], supplier: utility.function.ExceptionalSupplier[T, E]) -> T:
        """
        Calls the given supplier inside of a transaction.  Use this method in place of the more
        verbose try/catch/finally semantics.
         
        program.withTransaction("My Description", () -> {
            // ... Do something
            return result;
        });
         
         
        
        If you do not need to supply a result, then use 
        :meth:`withTransaction(String, ExceptionalCallback) <.withTransaction>` instead.
        
        :param E: the exception that may be thrown from this method:param T: the type of result returned by the supplier:param java.lang.String or str description: brief description of transaction
        :param utility.function.ExceptionalSupplier[T, E] supplier: the supplier that will be called inside of a transaction
        :return: the result returned by the supplier
        :rtype: T
        :raises E: any exception that may be thrown in the given callback
        """

    @property
    def favorites(self) -> java.util.List[DataType]:
        ...

    @property
    def sourceArchives(self) -> java.util.List[SourceArchive]:
        ...

    @property
    def callingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        ...

    @property
    def localSourceArchive(self) -> SourceArchive:
        ...

    @property
    def type(self) -> ArchiveType:
        ...

    @property
    def allStructures(self) -> java.util.Iterator[Structure]:
        ...

    @property
    def allComposites(self) -> java.util.Iterator[Composite]:
        ...

    @property
    def programArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture:
        ...

    @property
    def dataTypes(self) -> java.util.List[DataType]:
        ...

    @property
    def allFunctionDefinitions(self) -> java.util.Iterator[FunctionDefinition]:
        ...

    @property
    def categoryCount(self) -> jpype.JInt:
        ...

    @property
    def dataTypesContaining(self) -> java.util.Set[DataType]:
        ...

    @property
    def knownCallingConventionNames(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def programArchitectureSummary(self) -> java.lang.String:
        ...

    @property
    def pointer(self) -> Pointer:
        ...

    @property
    def dataTypeCount(self) -> jpype.JInt:
        ...

    @property
    def addressMap(self) -> ghidra.program.database.map.AddressMap:
        ...

    @property
    def defaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        ...

    @property
    def dataType(self) -> DataType:
        ...

    @property
    def sourceArchive(self) -> SourceArchive:
        ...

    @property
    def dataOrganization(self) -> DataOrganization:
        ...

    @property
    def definedCallingConventionNames(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def universalID(self) -> ghidra.util.UniversalID:
        ...

    @property
    def lastChangeTimeForMyManager(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def updatable(self) -> jpype.JBoolean:
        ...

    @property
    def allDataTypes(self) -> java.util.Iterator[DataType]:
        ...

    @property
    def resolvedID(self) -> jpype.JLong:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def rootCategory(self) -> Category:
        ...

    @property
    def category(self) -> Category:
        ...

    @property
    def favorite(self) -> jpype.JBoolean:
        ...


class LongLongDataType(AbstractSignedIntegerDataType):
    """
    Basic implementation for an Signed LongLong Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[LongLongDataType]
    """
    A statically defined LongLongDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class UnsignedInteger16DataType(AbstractUnsignedIntegerDataType):
    """
    A fixed size 16 byte unsigned integer (commonly referred to in C as uint128_t)
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedInteger16DataType]
    """
    A statically defined UnsignedInteger16DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class UnionInternal(Union, CompositeInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BitGroup(java.lang.Object):
    """
    Class used to organize long values into sets of values with overlapping bits.
    For example, if you had values 1,2,3, 8, 12, you could partition them into two bit groups.
    The values 1,2,3, would be in one bit group because they all use the "1" or "2" bit.
    (If there was no "3" enum value, then the "1" bit and the "2" bit would be in separate groups
    since there are no enum values that share any bits.) Also, the values "8" and "12" are in the same
    group since they share the "8" bit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMask(self) -> int:
        """
        Returns the mask that represents all the bits that are used by the values in this
        BitGroup.
        
        :return: the mask that represents all the bits that are used by the values in this
        BitGroup.
        :rtype: int
        """

    def getValues(self) -> java.util.Set[java.lang.Long]:
        """
        Gets the set of values that make up this BitGroup.
        
        :return: the set of values that make up this BitGroup.
        :rtype: java.util.Set[java.lang.Long]
        """

    def intersects(self, bitGroup: BitGroup) -> bool:
        """
        Tests if this bit group has any overlapping bits with the given bit group.
        
        :param BitGroup bitGroup: the BitGroup to test for overlap.
        :return: true if the groups have any bits in common.
        :rtype: bool
        """

    def merge(self, bitGroup: BitGroup):
        """
        Merges the given BitGroup into the group.  All of its values will be added to this
        group's values and the masks will be or'ed together.
        
        :param BitGroup bitGroup: the BitGroup to merge into this one.
        """

    @property
    def values(self) -> java.util.Set[java.lang.Long]:
        ...

    @property
    def mask(self) -> jpype.JLong:
        ...


class LongDoubleComplexDataType(AbstractComplexDataType):
    """
    Provides a definition of a ``complex`` built-in data type consisting of two LongDouble
    numbers in the IEEE 754 double precision format.
     
    
    The size of the LongDouble floating point numbers is determined by the program's data organization as defined
    by the language/compiler spec
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[LongDoubleComplexDataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Undefined5DataType(Undefined):
    """
    Provides an implementation of a byte that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined5DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Constructs a new Undefined1 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class Float4DataType(AbstractFloatDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Float4DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class AbstractDataType(DataType):
    """
    Base class for DataType classes. Many of the DataType methods are stubbed out so simple datatype
    classes can be created without implementing too many methods.
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeWriter(java.lang.Object):
    """
    A class used to convert data types into ANSI-C.
    
    The ANSI-C code should compile on most platforms.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dtm: DataTypeManager, writer: java.io.Writer):
        """
        Constructs a new instance of this class using the given writer. The default annotation
        handler is used.
        
        :param DataTypeManager dtm: data-type manager corresponding to target program or null for default
        :param java.io.Writer writer: the writer to use when writing data types
        :raises IOException: if there is an exception writing the output
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager, writer: java.io.Writer, cppStyleComments: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new instance of this class using the given writer. The default annotation
        handler is used.
        
        :param DataTypeManager dtm: data-type manager corresponding to target program or null for default
        :param java.io.Writer writer: the writer to use when writing data types
        :param jpype.JBoolean or bool cppStyleComments: whether to use C++ style comments
        :raises IOException: if there is an exception writing the output
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager, writer: java.io.Writer, annotator: AnnotationHandler):
        """
        Constructs a new instance of this class using the given writer and annotation handler
        
        :param DataTypeManager dtm: data-type manager corresponding to target program or null for default
        :param java.io.Writer writer: the writer to use when writing data types
        :param AnnotationHandler annotator: the annotation handler to use to annotate the data types
        :raises IOException: if there is an exception writing the output
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager, writer: java.io.Writer, annotator: AnnotationHandler, cppStyleComments: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new instance of this class using the given writer and annotation handler
        
        :param DataTypeManager dtm: data-type manager corresponding to target program or null for default
        :param java.io.Writer writer: the writer to use when writing data types
        :param AnnotationHandler annotator: the annotation handler to use to annotate the data types
        :param jpype.JBoolean or bool cppStyleComments: whether to use C++ style comments
        :raises IOException: if there is an exception writing the output
        """

    @typing.overload
    def write(self, dataTypeManager: DataTypeManager, monitor: ghidra.util.task.TaskMonitor):
        """
        Converts all data types in the data type manager into ANSI-C code.
        
        :param DataTypeManager dataTypeManager: the manager containing the data types to write
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if there is an exception writing the output
        :raises CancelledException: if the action is cancelled by the user
        """

    @typing.overload
    def write(self, category: Category, monitor: ghidra.util.task.TaskMonitor):
        """
        Converts all data types in the category into ANSI-C code.
        
        :param Category category: the category containing the datatypes to write
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if there is an exception writing the output
        :raises CancelledException: if the action is cancelled by the user
        """

    @typing.overload
    def write(self, dataTypes: jpype.JArray[DataType], monitor: ghidra.util.task.TaskMonitor):
        """
        Converts all data types in the array into ANSI-C code.
        
        :param jpype.JArray[DataType] dataTypes: the data types to write
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if there is an exception writing the output
        :raises CancelledException: if the action is cancelled by the user
        """

    @typing.overload
    def write(self, dataTypes: java.util.List[DataType], monitor: ghidra.util.task.TaskMonitor):
        """
        Converts all data types in the list into ANSI-C code.
        
        :param java.util.List[DataType] dataTypes: the data types to write
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if there is an exception writing the output
        :raises CancelledException: if the action is cancelled by the user
        """

    @typing.overload
    def write(self, dataTypes: java.util.List[DataType], monitor: ghidra.util.task.TaskMonitor, throwExceptionOnInvalidType: typing.Union[jpype.JBoolean, bool]):
        ...


class WAVEDataType(BuiltIn, Dynamic):

    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.ClassVar[jpype.JArray[jpype.JByte]]
    MAGIC_MASK: typing.ClassVar[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class TypeDefSettingsDefinition(ghidra.docking.settings.SettingsDefinition):
    """
    ``TypeDefSettingsDefinition`` specifies a :obj:`SettingsDefinition` whose
    use as a :obj:`TypeDef` setting will be available for use within a non-Program 
    DataType archive.  Such settings will be considered for DataType equivalence checks and
    preserved during DataType cloning and resolve processing.  As such, these settings
    are only currently supported as a default-setting on a :obj:`TypeDef`
    (see :meth:`DataType.getDefaultSettings() <DataType.getDefaultSettings>`) and do not support component-specific 
    or data-instance use.
     
    NOTE: Full support for this type of setting has only been fully implemented for TypeDef
    in support. There may be quite a few obstacles to overcome when introducing such 
    settings to a different datatype.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAttributeSpecification(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        Get the :obj:`TypeDef` attribute specification for this setting and its
        current value.
        
        :param ghidra.docking.settings.Settings settings: typedef settings
        :return: attribute specification or null if not currently set.
        :rtype: str
        """

    @property
    def attributeSpecification(self) -> java.lang.String:
        ...


class Pointer24DataType(PointerDataType):
    """
    Pointer24 is really a factory for generating 3-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer24DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class NoisyStructureBuilder(java.lang.Object):
    """
    Build a structure from a "noisy" source of field information.
    Feed it field records, either via addDataType(), when we
    have more definitive info about the size of the field, or via addReference()
    when we have a pointer reference to the field with possibly less info about the field size.
     
    As records come in, overlaps and conflicts in specific field data-types are resolved.
    In a conflict, less specific data-types are replaced.
    After all information is collected a final Structure can be built by iterating over
    the final field entries.
     
    NOTE: No attempt has been made to utilize :meth:`DataType.getAlignedLength() <DataType.getAlignedLength>` when considering
    component type lengths.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addDataType(self, offset: typing.Union[jpype.JLong, int], dt: DataType):
        """
        Add data-type information about a specific field
        
        :param jpype.JLong or int offset: of the field within the structure
        :param DataType dt: is the data-type of field if known (null otherwise)
        """

    def addReference(self, offset: typing.Union[jpype.JLong, int], dt: DataType):
        """
        Adds information for a field given a pointer reference.
        The data-type information is not used unless it is a pointer.
        
        :param jpype.JLong or int offset: is the offset of the field within the structure
        :param DataType dt: is the data-type of the pointer to the field (or null)
        """

    def getSize(self) -> int:
        """
        
        
        :return: the size of the structure in bytes (given current information)
        :rtype: int
        """

    def iterator(self) -> java.util.Iterator[java.util.Map.Entry[java.lang.Long, DataType]]:
        """
        
        
        :return: an iterator to the current field entries
        :rtype: java.util.Iterator[java.util.Map.Entry[java.lang.Long, DataType]]
        """

    def populateOriginalStructure(self, dt: Structure):
        """
        Populate this builder with fields from a preexisting Structure.
        The builder presumes it is rebuilding this Structure so it can check for
        pathological containment issues.
        
        :param Structure dt: is the preexisting Structure
        """

    def setMinimumSize(self, size: typing.Union[jpype.JLong, int]):
        """
        We may have partial information about the size of the structure.  This method feeds it to the
        builder as a minimum size for the structure.
        
        :param jpype.JLong or int size: is the minimum size in bytes
        """

    @property
    def size(self) -> jpype.JLong:
        ...


class DataTypeManagerChangeListenerHandler(DataTypeManagerChangeListener):
    """
    Default implementation for a :obj:`DataTypeManagerChangeListener` that sends out the
    events to its own list of listeners.
     
    NOTE: all listener notifications must be asynchronous within a different thread.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addDataTypeManagerListener(self, l: DataTypeManagerChangeListener):
        """
        Add the given category change listener.
        
        :param DataTypeManagerChangeListener l: the listener to be added.
        """

    def removeDataTypeManagerListener(self, l: DataTypeManagerChangeListener):
        """
        Remove the category change listener.
        
        :param DataTypeManagerChangeListener l: the listener to be removed.
        """


class Integer6DataType(AbstractSignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Integer6DataType]
    """
    A statically defined Integer6DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class ShiftedAddressDataType(BuiltIn):
    """
    Provides a definition of a Double Word within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[ShiftedAddressDataType]

    @typing.overload
    def __init__(self):
        """
        Creates a Double Word data type.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    @staticmethod
    def getAddressValue(buf: ghidra.program.model.mem.MemBuffer, size: typing.Union[jpype.JInt, int], shift: typing.Union[jpype.JInt, int], targetSpace: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.Address:
        """
        Generate an address value based upon bytes stored at the specified buf location
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer and stored pointer location
        :param jpype.JInt or int size: pointer size in bytes
        :param jpype.JInt or int shift: left shift amount
        :param ghidra.program.model.address.AddressSpace targetSpace: address space for returned pointer
        :return: pointer value or null if unusable buf or data
        :rtype: ghidra.program.model.address.Address
        """


class Undefined1DataType(Undefined):
    """
    Provides an implementation of a byte that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined1DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Constructs a new Undefined1 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class PointerDataType(BuiltIn, Pointer):
    """
    Basic implementation for a pointer dataType
    """

    @typing.type_check_only
    class PointerReferenceClassification(java.lang.Enum[PointerDataType.PointerReferenceClassification]):

        class_: typing.ClassVar[java.lang.Class]
        NORMAL: typing.Final[PointerDataType.PointerReferenceClassification]
        LOOP: typing.Final[PointerDataType.PointerReferenceClassification]
        DEEP: typing.Final[PointerDataType.PointerReferenceClassification]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PointerDataType.PointerReferenceClassification:
            ...

        @staticmethod
        def values() -> jpype.JArray[PointerDataType.PointerReferenceClassification]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[PointerDataType]
    MAX_POINTER_SIZE_BYTES: typing.Final = 8
    POINTER_NAME: typing.Final = "pointer"
    POINTER_LABEL_PREFIX: typing.Final = "PTR"
    POINTER_LABEL_PREFIX_U: typing.Final = "PTR_"
    POINTER_LOOP_LABEL: typing.Final = "PTR_LOOP"
    NOT_A_POINTER: typing.Final = "NaP"

    @typing.overload
    def __init__(self):
        """
        Creates a dynamically-sized default pointer data type. A dynamic pointer size
        of 4-bytes will be in used, but will adapt to a data type manager's data
        organization when resolved.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        """
        Creates a dynamically-sized default pointer data type. The pointer size is
        established dynamically based upon the data organization associated with the
        specified dtm but can adapt to another data type manager's data organization
        when resolved.
        
        :param DataTypeManager dtm: data-type manager whose data organization should be used
        """

    @typing.overload
    def __init__(self, referencedDataType: DataType):
        """
        Construct a dynamically-sized pointer to a referencedDataType A dynamic
        pointer size of 4-bytes will be in used, but will adapt to a data type
        manager's data organization when resolved.
        
        :param DataType referencedDataType: data type this pointer points to
        """

    @typing.overload
    def __init__(self, referencedDataType: DataType, length: typing.Union[jpype.JInt, int]):
        """
        Construct a pointer of a specified length to a referencedDataType. Note: It
        is preferred to use default sized pointers when possible (i.e., length=-1,
        see :meth:`PointerDataType(DataType) <.PointerDataType>`) instead of explicitly specifying the
        pointer length value.
        
        :param DataType referencedDataType: data type this pointer points to
        :param jpype.JInt or int length: pointer length (values <= 0 will result in
                                dynamically-sized pointer)
        """

    @typing.overload
    def __init__(self, referencedDataType: DataType, dtm: DataTypeManager):
        """
        Construct a dynamically-sized pointer to the given data type. The pointer
        size is established dynamically based upon the data organization associated
        with the specified dtm but can adapt to another data type manager's data
        organization when resolved.
        
        :param DataType referencedDataType: data type this pointer points to
        :param DataTypeManager dtm: data-type manager whose data organization should be
                                used
        """

    @typing.overload
    def __init__(self, referencedDataType: DataType, length: typing.Union[jpype.JInt, int], dtm: DataTypeManager):
        """
        Construct a pointer of a specified length to a referencedDataType. Note: It
        is preferred to use default sized pointers when possible (i.e., length=-1,
        see :meth:`PointerDataType(DataType, DataTypeManager) <.PointerDataType>`) instead of
        explicitly specifying the pointer length value.
        
        :param DataType referencedDataType: data type this pointer points to
        :param jpype.JInt or int length: pointer length (-1 will result in dynamically-sized
                                pointer)
        :param DataTypeManager dtm: associated data type manager whose data
                                organization will be used
        """

    @staticmethod
    @typing.overload
    def getAddressValue(buf: ghidra.program.model.mem.MemBuffer, size: typing.Union[jpype.JInt, int], settings: ghidra.docking.settings.Settings) -> ghidra.program.model.address.Address:
        """
        Generate an address value based upon bytes stored at the specified buf
        location.  Interpretation of settings may depend on access to a :obj:`Memory` 
        object associated with the specified :obj:`MemBuffer` buf.
         
        
        The following pointer-typedef settings are supported:
         
        * :obj:`AddressSpaceSettingsDefinition`
        * :obj:`OffsetMaskSettingsDefinition`
        * :obj:`OffsetShiftSettingsDefinition`
        * :obj:`PointerTypeSettingsDefinition`
        
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer positioned to stored pointer
        :param jpype.JInt or int size: pointer size in bytes
        :param ghidra.docking.settings.Settings settings: settings which may influence address generation
        :return: address value or null if unusable buf or data
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    @typing.overload
    def getAddressValue(buf: ghidra.program.model.mem.MemBuffer, size: typing.Union[jpype.JInt, int], settings: ghidra.docking.settings.Settings, errorHandler: java.util.function.Consumer[java.lang.String]) -> ghidra.program.model.address.Address:
        """
        Generate an address value based upon bytes stored at the specified buf
        location.  Interpretation of settings may depend on access to a :obj:`Memory` 
        object associated with the specified :obj:`MemBuffer` buf.
         
        
        The following pointer-typedef settings are supported:
         
        * :obj:`AddressSpaceSettingsDefinition`
        * :obj:`OffsetMaskSettingsDefinition`
        * :obj:`OffsetShiftSettingsDefinition`
        * :obj:`PointerTypeSettingsDefinition`
        
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer positioned to stored pointer
        :param jpype.JInt or int size: pointer size in bytes
        :param ghidra.docking.settings.Settings settings: settings which may influence address generation
        :param java.util.function.Consumer[java.lang.String] errorHandler: if null returned an error may be conveyed to this errorHandler
        :return: address value or null if unusable buf or data
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    @typing.overload
    def getAddressValue(buf: ghidra.program.model.mem.MemBuffer, size: typing.Union[jpype.JInt, int], targetSpace: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.Address:
        """
        Generate an address value based upon bytes stored at the specified buf
        location.  The stored bytes will be interpreted as an unsigned byte 
        offset into the specified targetSpace.
        
        :param ghidra.program.model.mem.MemBuffer buf: memory buffer and stored pointer location
        :param jpype.JInt or int size: pointer size in bytes
        :param ghidra.program.model.address.AddressSpace targetSpace: address space for returned address
        :return: address value or null if unusable buf or data
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getLabelString(buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: typing.Union[jpype.JInt, int], options: DataTypeDisplayOptions) -> str:
        ...

    @staticmethod
    @typing.overload
    def getPointer(dt: DataType, dtm: DataTypeManager) -> Pointer:
        """
        Get a pointer data-type instance with a default size
        
        :param DataType dt: data-type referenced by pointer
        :param DataTypeManager dtm: program data-type manager (required) a generic data-type will be
                    returned if possible.
        :return: signed integer data type
        :rtype: Pointer
        """

    @staticmethod
    @typing.overload
    def getPointer(dt: DataType, pointerSize: typing.Union[jpype.JInt, int]) -> Pointer:
        """
        Get a pointer data-type instance of the requested size. NOTE: The returned
        data-type will not be associated with any particular data-type-manager and
        may therefore not utilize dynamically-sized-pointers when a valid pointerSize
        is specified. If an invalid pointerSize is specified, a dynamically-size
        pointer will be returned whose length is based upon the
        default-data-organization.
        
        :param DataType dt: data-type referenced by pointer
        :param jpype.JInt or int pointerSize: pointer size
        :return: signed integer data type
        :rtype: Pointer
        """


class DWordDataType(AbstractUnsignedIntegerDataType):
    """
    Provides a definition of a Double Word within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[DWordDataType]
    """
    A statically defined DWordDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Float10DataType(AbstractFloatDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Float10DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class DataTypeTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is a DataType object.
    """

    class_: typing.ClassVar[java.lang.Class]
    localDataTypeFlavor: typing.Final[java.awt.datatransfer.DataFlavor]
    localBuiltinDataTypeFlavor: typing.Final[java.awt.datatransfer.DataFlavor]

    def __init__(self, dt: DataType):
        """
        Constructor
        
        :param DataType dt: the dataType being transfered
        """

    def getTransferData(self, f: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Return the transfer data with the given data flavor.
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return all data flavors that this class supports.
        """

    def isDataFlavorSupported(self, f: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return whether the specifed data flavor is supported.
        """

    def lostOwnership(self, clipboard: java.awt.datatransfer.Clipboard, contents: java.awt.datatransfer.Transferable):
        """
        ClipboardOwner interface method.
        """

    def toString(self) -> str:
        """
        Get the string representation for this transferable.
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


class MIDIDataType(BuiltIn, Dynamic):

    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.ClassVar[jpype.JArray[jpype.JByte]]
    MAGIC_MASK: typing.ClassVar[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Undefined6DataType(Undefined):
    """
    Provides an implementation of a byte that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined6DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Constructs a new Undefined1 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class UnsignedLongLongDataType(AbstractUnsignedIntegerDataType):
    """
    Basic implementation for an Signed LongLong Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedLongLongDataType]
    """
    A statically defined UnsignedLongLongDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class CharDataType(AbstractIntegerDataType, DataTypeWithCharset):
    """
    Provides a definition of an primitive char in a program. The size and signed-ness of this type is
    determined by the data organization of the associated data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[CharDataType]

    @typing.overload
    def __init__(self):
        """
        Constructs a new char datatype.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def getCDeclaration(self) -> str:
        """
        Returns the C style data-type declaration for this data-type. Null is returned if no
        appropriate declaration exists.
        """

    @property
    def cDeclaration(self) -> java.lang.String:
        ...


class DataOrganization(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    NO_MAXIMUM_ALIGNMENT: typing.Final = 0

    def getAbsoluteMaxAlignment(self) -> int:
        """
        Gets the maximum alignment value that is allowed by this data organization. When getting
        an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
        is returned, the data organization isn't specifically limited.
        
        :return: the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
        :rtype: int
        """

    def getAlignment(self, dataType: DataType) -> int:
        """
        Determines the alignment value for the indicated data type. (i.e. how the data type gets
        aligned within other data types.)  NOTE: this method should not be used for bitfields
        which are highly dependent upon packing for a composite.  This method will always return 1
        for Dynamic and FactoryDataTypes.
        
        :param DataType dataType: the data type
        :return: the datatype alignment
        :rtype: int
        """

    def getBitFieldPacking(self) -> BitFieldPacking:
        """
        Get the composite bitfield packing information associated with this data organization.
        
        :return: composite bitfield packing information
        :rtype: BitFieldPacking
        """

    def getCharSize(self) -> int:
        """
        
        
        :return: the size of a char (char) primitive data type in bytes.
        :rtype: int
        """

    def getDefaultAlignment(self) -> int:
        """
        Gets the default alignment to be used for any data type that isn't a 
        structure, union, array, pointer, type definition, and whose size isn't in the 
        size/alignment map.
        
        :return: the default alignment to be used if no other alignment can be 
        determined for a data type.
        :rtype: int
        """

    def getDefaultPointerAlignment(self) -> int:
        """
        Gets the default alignment to be used for a pointer that doesn't have size.
        
        :return: the default alignment for a pointer
        :rtype: int
        """

    def getDoubleSize(self) -> int:
        """
        
        
        :return: the encoding size of a double primitive data type in bytes.
        :rtype: int
        """

    def getFloatSize(self) -> int:
        """
        
        
        :return: the encoding size of a float primitive data type in bytes.
        :rtype: int
        """

    def getIntegerCTypeApproximation(self, size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns the best fitting integer C-type whose size is less-than-or-equal
        to the specified size.  "long long" will be returned for any size larger
        than "long long";
        
        :param jpype.JInt or int size: integer size
        :param jpype.JBoolean or bool signed: if false the unsigned modifier will be prepended.
        :return: the best fitting
        :rtype: str
        """

    def getIntegerSize(self) -> int:
        """
        
        
        :return: the size of a int primitive data type in bytes.
        :rtype: int
        """

    def getLongDoubleSize(self) -> int:
        """
        
        
        :return: the encoding size of a long double primitive data type in bytes.
        :rtype: int
        """

    def getLongLongSize(self) -> int:
        """
        
        
        :return: the size of a long long primitive data type in bytes.
        :rtype: int
        """

    def getLongSize(self) -> int:
        """
        
        
        :return: the size of a long primitive data type in bytes.
        :rtype: int
        """

    def getMachineAlignment(self) -> int:
        """
        Gets the maximum useful alignment for the target machine
        
        :return: the machine alignment
        :rtype: int
        """

    def getPointerShift(self) -> int:
        """
        Shift amount affects interpretation of in-memory pointer values only
        and will also be reflected within instruction pcode.  A value of zero indicates
        that shifted-pointers are not supported.
        
        :return: the left shift amount for shifted-pointers.
        :rtype: int
        """

    def getPointerSize(self) -> int:
        """
        
        
        :return: the size of a pointer data type in bytes.
        :rtype: int
        """

    def getShortSize(self) -> int:
        """
        
        
        :return: the size of a short primitive data type in bytes.
        :rtype: int
        """

    def getSizeAlignment(self, size: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the primitive data alignment that is defined for the specified size.  If no entry has 
        been defined for the specified size alignment of the next smaller map entry will be returned.
        If the map is empty the :meth:`default alignment <.getDefaultAlignment>`.  The returned
        value will not exceed the :meth:`defined maximum alignment <.getAbsoluteMaxAlignment>`.
        
        :param jpype.JInt or int size: the primitive data size
        :return: the alignment of the data type.
        :rtype: int
        """

    def getSizeAlignmentCount(self) -> int:
        """
        Gets the number of sizes that have an alignment specified.
        
        :return: the number of sizes with an alignment mapped to them.
        :rtype: int
        """

    def getSizes(self) -> jpype.JArray[jpype.JInt]:
        """
        Gets the ordered list of sizes that have an alignment specified.
        
        :return: the ordered list of sizes with alignments mapped to them.
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getWideCharSize(self) -> int:
        """
        
        
        :return: the size of a wide-char (wchar_t) primitive data type in bytes.
        :rtype: int
        """

    def isBigEndian(self) -> bool:
        """
        
        
        :return: true if data stored big-endian byte order
        :rtype: bool
        """

    def isEquivalent(self, obj: DataOrganization) -> bool:
        """
        Determine if this DataOrganization is equivalent to another specific instance
        
        :param DataOrganization obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    def isSignedChar(self) -> bool:
        """
        
        
        :return: true if the "char" type is signed
        :rtype: bool
        """

    @property
    def sizeAlignmentCount(self) -> jpype.JInt:
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def integerSize(self) -> jpype.JInt:
        ...

    @property
    def signedChar(self) -> jpype.JBoolean:
        ...

    @property
    def defaultPointerAlignment(self) -> jpype.JInt:
        ...

    @property
    def sizeAlignment(self) -> jpype.JInt:
        ...

    @property
    def shortSize(self) -> jpype.JInt:
        ...

    @property
    def absoluteMaxAlignment(self) -> jpype.JInt:
        ...

    @property
    def longSize(self) -> jpype.JInt:
        ...

    @property
    def charSize(self) -> jpype.JInt:
        ...

    @property
    def pointerSize(self) -> jpype.JInt:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def wideCharSize(self) -> jpype.JInt:
        ...

    @property
    def sizes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def pointerShift(self) -> jpype.JInt:
        ...

    @property
    def defaultAlignment(self) -> jpype.JInt:
        ...

    @property
    def machineAlignment(self) -> jpype.JInt:
        ...

    @property
    def longDoubleSize(self) -> jpype.JInt:
        ...

    @property
    def doubleSize(self) -> jpype.JInt:
        ...

    @property
    def floatSize(self) -> jpype.JInt:
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @property
    def bitFieldPacking(self) -> BitFieldPacking:
        ...

    @property
    def longLongSize(self) -> jpype.JInt:
        ...


class Undefined2DataType(Undefined):
    """
    Provides an implementation of a 2 byte dataType that has not been defined yet as a
    particular type of data in the program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Undefined2DataType]
    """
    A statically defined DefaultDataType used when an Undefined byte is needed.
    """


    @typing.overload
    def __init__(self):
        """
        Constructs a new Undefined2 dataType
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...

    def getDescription(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getDescription()`
        """

    def getLength(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getLength()`
        """

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getMnemonic(Settings)`
        """

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getRepresentation(MemBuffer, Settings, int)`
        """

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)`
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class ReadOnlyDataTypeComponent(DataTypeComponent, java.io.Serializable):
    """
    DataTypeComponents from dataTypes that can not be modified.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataType: DataType, parent: DynamicDataType, length: typing.Union[jpype.JInt, int], ordinal: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], fieldName: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Create a new DataTypeComponent
        
        :param DataType dataType: the dataType for this component
        :param DynamicDataType parent: the dataType that this component belongs to
        :param jpype.JInt or int length: the length of the dataType in this component.
        :param jpype.JInt or int offset: the byte offset within the parent
        :param jpype.JInt or int ordinal: the index of this component in the parent.
        :param java.lang.String or str fieldName: the name associated with this component
        :param java.lang.String or str comment: the comment associated with ths component
        """

    @typing.overload
    def __init__(self, dataType: DataType, parent: DynamicDataType, length: typing.Union[jpype.JInt, int], ordinal: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int]):
        """
        Create a new DataTypeComponent
        
        :param DataType dataType: the dataType for this component
        :param DynamicDataType parent: the dataType that this component belongs to
        :param jpype.JInt or int length: the length of the dataType in this component.
        :param jpype.JInt or int ordinal: the index of this component in the parent.
        :param jpype.JInt or int offset: the byte offset within the parent
        """


class LongDoubleDataType(AbstractFloatDataType):
    """
    Provides a definition of a Long Double within a program.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[LongDoubleDataType]

    @typing.overload
    def __init__(self):
        """
        Creates a Double data type.
        """

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...

    def clone(self, dtm: DataTypeManager) -> DataType:
        ...


class Integer5DataType(AbstractSignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Integer5DataType]
    """
    A statically defined Integer5DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class ArrayDataType(DataTypeImpl, Array):
    """
    Basic implementation of the Array interface.
     
    NOTE: The use of :obj:`FactoryDataType` and :obj:`Dynamic`, where 
    :meth:`Dynamic.canSpecifyLength() <Dynamic.canSpecifyLength>` is false, are not supported for array use.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataType: DataType, numElements: typing.Union[jpype.JInt, int]):
        """
        Constructs a new Array dataType for fixed-length datatypes.  The specified datatype's
        :obj:`DataTypeManager` will be used for its data organization.
        
        :param DataType dataType: the dataType of the elements in the array (:obj:`FactoryDataType` and
        :obj:`Dynamic` data types are not permitted).
        :param jpype.JInt or int numElements: the number of elements in the array (0 is permitted).
        :raises IllegalArgumentException: if invalid datatype is specified or required valid
        ``elementLength`` required.
        """

    @typing.overload
    def __init__(self, dataType: DataType, numElements: typing.Union[jpype.JInt, int], elementLength: typing.Union[jpype.JInt, int]):
        """
        Constructs a new Array dataType.  The specified datatype's :obj:`DataTypeManager` will 
        be used for its data organization.
        
        :param DataType dataType: the dataType of the elements in the array. :obj:`FactoryDataType` and
        :obj:`Dynamic`, where :meth:`Dynamic.canSpecifyLength() <Dynamic.canSpecifyLength>` is false, are not permitted.
        :param jpype.JInt or int numElements: the number of elements in the array (0 is permitted).
        :param jpype.JInt or int elementLength: the length of an individual element in the array.  This value
        is only used for :obj:`Dynamic` dataType where :meth:`Dynamic.canSpecifyLength() <Dynamic.canSpecifyLength>` 
        returns true.  A -1 value can be specified for fixed-length datatypes.
        :raises IllegalArgumentException: if invalid datatype is specified or required valid
        ``elementLength`` required.
        """

    @typing.overload
    def __init__(self, dataType: DataType, numElements: typing.Union[jpype.JInt, int], elementLength: typing.Union[jpype.JInt, int], dataMgr: DataTypeManager):
        """
        Constructs a new Array dataType.
        
        :param DataType dataType: the dataType of the elements in the array. :obj:`FactoryDataType` and
        :obj:`Dynamic`, where :meth:`Dynamic.canSpecifyLength() <Dynamic.canSpecifyLength>` is false, are not permitted.
        :param jpype.JInt or int numElements: the number of elements in the array (0 is permitted).
        :param jpype.JInt or int elementLength: the length of an individual element in the array.  This value
        is only used for :obj:`Dynamic` dataType where :meth:`Dynamic.canSpecifyLength() <Dynamic.canSpecifyLength>` 
        returns true.  A -1 value can be specified for fixed-length datatypes.
        :param DataTypeManager dataMgr: datatype manager or null.  If null, the datatype manager associated with the
        specified datatype will be used.
        :raises IllegalArgumentException: if invalid datatype is specified or required valid
        ``elementLength`` required.
        """


class BuiltIn(DataTypeImpl, BuiltInDataType):
    """
    NOTE:  ALL DATATYPE CLASSES MUST END IN "DataType".  If not,
    the ClassSearcher will not find them.
     
    Base class for built-in Datatypes.  A built-in data type is
    searched for in the classpath and added automatically to the available
    data types in the data type manager.
     
    NOTE: Settings are immutable when a DataTypeManager has not been specified (i.e., null).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: CategoryPath, name: typing.Union[java.lang.String, str], dataMgr: DataTypeManager):
        ...

    def copy(self, dtm: DataTypeManager) -> DataType:
        """
        Returns a clone of this built-in DataType
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.DataType.copy(ghidra.program.model.data.DataTypeManager)`
        """

    def getCTypeDeclaration(self, dataOrganization: DataOrganization) -> str:
        """
        Returns null for FactoryDataType (which should never be used) and Dynamic types which should
        generally be replaced by a primitive array (e.g., char[5]) or, a primitive pointer (e.g., char *).
        For other types an appropriately sized unsigned integer typedef is returned.
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.data.BuiltInDataType.getCTypeDeclaration(ghidra.program.model.data.DataOrganization)`
        """

    def getDecompilerDisplayName(self, language: ghidra.program.model.lang.DecompilerLanguage) -> str:
        """
        Return token used to represent this type in decompiler/source-code output
        
        :param ghidra.program.model.lang.DecompilerLanguage language: is the language being displayed
        :return: the name string
        :rtype: str
        """

    def getSettingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        """
        Gets a list of all the settingsDefinitions used by this datatype.
        
        :return: a list of the settingsDefinitions used by this datatype.
        :rtype: jpype.JArray[ghidra.docking.settings.SettingsDefinition]
        """

    @property
    def decompilerDisplayName(self) -> java.lang.String:
        ...

    @property
    def cTypeDeclaration(self) -> java.lang.String:
        ...

    @property
    def settingsDefinitions(self) -> jpype.JArray[ghidra.docking.settings.SettingsDefinition]:
        ...


class ShortDataType(AbstractSignedIntegerDataType):
    """
    Basic implementation for a Short Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[ShortDataType]
    """
    A statically defined ShortDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class AIFFDataType(BuiltIn, Dynamic):
    """
    AIFF / AIFC header format:
     
    struct {
        int32 ckID;                'FORM'
        int32 ckDataSize;
        int32 formType;            'AIFF', 'AIFC'
    -variable length chunk data-
    }
    """

    class_: typing.ClassVar[java.lang.Class]
    MAGIC_AIFF: typing.ClassVar[jpype.JArray[jpype.JByte]]
    """
    Magic bytes for 'AIFF' audio file header
    """

    MAGIC_AIFC: typing.ClassVar[jpype.JArray[jpype.JByte]]
    """
    Magic bytes for 'AIFC' audio file header (almost same as AIFF)
    """

    MAGIC_MASK: typing.ClassVar[jpype.JArray[jpype.JByte]]
    """
    Byte search mask for magic bytes
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class JPEGDataType(BuiltIn, Dynamic, Resource):

    @typing.type_check_only
    class JPEGDataImage(DataImage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAGIC: typing.ClassVar[jpype.JArray[jpype.JByte]]
    MAGIC_MASK: typing.ClassVar[jpype.JArray[jpype.JByte]]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class UnsignedInteger6DataType(AbstractUnsignedIntegerDataType):

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[UnsignedInteger6DataType]
    """
    A statically defined UnsignedInteger6DataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...


class Pointer40DataType(PointerDataType):
    """
    Pointer40 is really a factory for generating 5-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer40DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class DataTypeNameComparator(java.util.Comparator[java.lang.String]):
    """
    :obj:`DataTypeNameComparator` provides the preferred named-based comparison of :obj:`DataType`
    which handles both some degree of case-insensity as well as proper grouping and ordering of
    conflict datatypes.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[DataTypeNameComparator]

    def __init__(self):
        ...


class StructureInternal(Structure, CompositeInternal):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Enum(DataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Add a enum entry.
        
        :param java.lang.String or str name: name of the new entry
        :param jpype.JLong or int value: value of the new entry
        """

    @typing.overload
    def add(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str]):
        """
        Add a enum entry.
        
        :param java.lang.String or str name: name of the new entry
        :param jpype.JLong or int value: value of the new entry
        :param java.lang.String or str comment: comment of the new entry
        """

    @typing.overload
    def contains(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if this enum has an entry with the given name.
        
        :param java.lang.String or str name: the name to check for an entry
        :return: true if this enum has an entry with the given name
        :rtype: bool
        """

    @typing.overload
    def contains(self, value: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if this enum has an entry with the given value.
        
        :param jpype.JLong or int value: the value to check for an entry
        :return: true if this enum has an entry with the given value
        :rtype: bool
        """

    def getComment(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Get the comment for the given name.
        
        :param java.lang.String or str name: name of the entry.
        :return: the comment or the empty string if the name does not exist in this enum or if no
        comment is set.
        :rtype: str
        """

    def getCount(self) -> int:
        """
        Get the number of entries in this Enum.
        
        :return: the number of entries in this Enum.
        :rtype: int
        """

    def getMaxPossibleValue(self) -> int:
        """
        Returns the maximum value that this enum can represent based on its size and signedness.
        
        :return: the maximum value that this enum can represent based on its size and signedness.
        :rtype: int
        """

    def getMinPossibleValue(self) -> int:
        """
        Returns the maximum value that this enum can represent based on its size and signedness.
        
        :return: the maximum value that this enum can represent based on its size and signedness.
        :rtype: int
        """

    def getMinimumPossibleLength(self) -> int:
        """
        Returns the smallest length (size in bytes) this enum can be and still represent all of
        it's current values. Note that this will only return powers of 2 (1,2,4, or 8)
        
        :return: the smallest length (size in bytes) this enum can be and still represent all of
        it's current values
        :rtype: int
        """

    def getName(self, value: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the name for the given value.
        
        :param jpype.JLong or int value: value of the enum entry.
        :return: null if the name with the given value was not found.
        :rtype: str
        """

    @typing.overload
    def getNames(self, value: typing.Union[jpype.JLong, int]) -> jpype.JArray[java.lang.String]:
        """
        Returns all names that map to the given value.
        
        :param jpype.JLong or int value: value for the enum entries.
        :return: all names; null if there is not name for the given value.
        :rtype: jpype.JArray[java.lang.String]
        """

    @typing.overload
    def getNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of the enum entries.  The returned names are first sorted by the enum int
        value, then sub-sorted by name value where there are multiple name values per int value.
        
        :return: the names of the enum entries.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getRepresentation(self, bigInt: java.math.BigInteger, settings: ghidra.docking.settings.Settings, bitLength: typing.Union[jpype.JInt, int]) -> str:
        """
        Get enum representation of the big-endian value.
        
        :param java.math.BigInteger bigInt: BigInteger value with the appropriate sign
        :param ghidra.docking.settings.Settings settings: integer format settings (PADDING, FORMAT, etc.)
        :param jpype.JInt or int bitLength: the bit length
        :return: formatted integer string
        :rtype: str
        """

    def getSignedState(self) -> ghidra.program.database.data.EnumSignedState:
        """
        Returns the signed state.
        
        :return: the signed state.
        :rtype: ghidra.program.database.data.EnumSignedState
        """

    def getValue(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Get the value for the given name.
        
        :param java.lang.String or str name: name of the entry.
        :return: the value.
        :rtype: int
        :raises NoSuchElementException: if the name does not exist in this Enum.
        """

    def getValues(self) -> jpype.JArray[jpype.JLong]:
        """
        Get the values of the enum entries.
        
        :return: values sorted in ascending order
        :rtype: jpype.JArray[jpype.JLong]
        """

    def isSigned(self) -> bool:
        """
        Returns true if the enum contains at least one negative value. Internally, enums have
        three states, signed, unsigned, and none (can't tell from the values). If any of
        the values are negative, the enum is considered signed. If any of the values are large
        unsigned values (upper bit set), then it is considered unsigned. This method will return
        true if the enum is signed, and false if it is either unsigned or none (meaning that it
        doesn't matter for the values that are contained in the enum.
        
        :return: true if the enum contains at least one negative value
        :rtype: bool
        """

    def remove(self, name: typing.Union[java.lang.String, str]):
        """
        Remove the enum entry with the given name.
        
        :param java.lang.String or str name: name of entry to remove.
        """

    def setDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Set the description for this Enum.
        
        :param java.lang.String or str description: the description
        """

    @property
    def signedState(self) -> ghidra.program.database.data.EnumSignedState:
        ...

    @property
    def names(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def values(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def signed(self) -> jpype.JBoolean:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def minimumPossibleLength(self) -> jpype.JInt:
        ...

    @property
    def minPossibleValue(self) -> jpype.JLong:
        ...

    @property
    def maxPossibleValue(self) -> jpype.JLong:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class Pointer8DataType(PointerDataType):
    """
    Pointer8 is really a factory for generating 1-byte pointers.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[Pointer8DataType]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dt: DataType):
        ...


class CompositeAlignmentHelper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getAlignment(dataOrganization: DataOrganization, composite: CompositeInternal) -> int:
        ...

    @staticmethod
    def getPackedAlignment(dataOrganization: DataOrganization, packingValue: typing.Union[jpype.JInt, int], component: DataTypeComponent) -> int:
        ...


class LongDataType(AbstractSignedIntegerDataType):
    """
    Basic implementation for a Signed Long Integer dataType
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[LongDataType]
    """
    A statically defined LongDataType instance.
    """


    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: DataTypeManager):
        ...



__all__ = ["Float2DataType", "Undefined3DataType", "WideChar16DataType", "GIFResource", "AlignmentDataType", "StringDataInstance", "CharsetSettingsDefinition", "Undefined7DataType", "Complex32DataType", "IconResourceDataType", "PngDataType", "AbstractPointerTypedefBuiltIn", "WideCharDataType", "AlignedStructureInspector", "AudioPlayer", "InvalidDataTypeException", "Pointer56DataType", "UnsignedInteger7DataType", "BadDataType", "StructureDataType", "AddressSpaceSettingsDefinition", "TerminatedStringDataType", "WordDataType", "ProgramBasedDataTypeManager", "UnsignedShortDataType", "EndianSettingsDefinition", "CompositeInternal", "UnsignedInteger3DataType", "BuiltInDataTypeManager", "ProjectArchiveBasedDataTypeManager", "DataTypeComponentImpl", "SignedLeb128DataType", "AbstractSignedIntegerDataType", "FileDataTypeManager", "TerminatedUnicodeDataType", "RepeatedDynamicDataType", "StandAloneDataTypeManager", "SignedDWordDataType", "FileArchiveBasedDataTypeManager", "FactoryStructureDataType", "Composite", "GenericDataType", "PointerTypedefBuilder", "DataTypeImpl", "AbstractFloatDataType", "PointerType", "UnicodeDataType", "FunctionDefinitionDataType", "IllegalRenameException", "DataTypeDependencyException", "ParameterDefinitionImpl", "Array", "Integer7DataType", "GifDataType", "Unicode32DataType", "AbstractComplexDataType", "Float16DataType", "StringRenderParser", "IBO32DataType", "ByteDataType", "Pointer32DataType", "ParameterDefinition", "Integer3DataType", "DefaultAnnotationHandler", "UnionDataType", "PascalUnicodeDataType", "Undefined4DataType", "AbstractUnsignedIntegerDataType", "StringLayoutEnum", "Pointer", "BitmapResourceDataType", "UnsignedLeb128DataType", "PngResource", "DataUtilities", "FileTimeDataType", "DefaultDataType", "BitFieldDataType", "PaddingSettingsDefinition", "DataImage", "Pointer16DataType", "RenderUnicodeSettingsDefinition", "BitmapResource", "IntegerDataType", "Structure", "DataTypeConflictHandler", "Dynamic", "AnnotationHandler", "PascalStringDataType", "StructureFactory", "BuiltInDataType", "DoubleComplexDataType", "LEB128", "QWordDataType", "TypedefDataType", "Complex8DataType", "DataType", "DoubleDataType", "MetaDataType", "DataTypeDisplayOptions", "PointerTypeSettingsDefinition", "Pointer48DataType", "ComponentOffsetSettingsDefinition", "AbstractStringDataType", "ICategory", "DataTypeEncodeException", "AlignedStructurePacker", "CountedDynamicDataType", "SignedCharDataType", "DataTypeArchiveIdDumper", "DataTypeObjectComparator", "Resource", "ProgramArchitectureTranslator", "ArchiveType", "FactoryDataType", "PascalString255DataType", "Complex16DataType", "AbstractIntegerDataType", "RepeatedStringDataType", "MacintoshTimeStampDataType", "IconResource", "WideChar32DataType", "Float8DataType", "AlignedComponentPacker", "DataTypeWithCharset", "StructuredDynamicDataType", "DataTypeComparator", "TerminatedSettingsDefinition", "FileBasedDataTypeManager", "EnumValuePartitioner", "DataTypeComponent", "DataTypeMnemonicSettingsDefinition", "IBO64DataType", "ScorePlayer", "Pointer64DataType", "EnumDataType", "ArrayStringable", "CategoryPath", "StringUTF8DataType", "StringDataType", "DataTypeManagerChangeListenerAdapter", "OffsetShiftSettingsDefinition", "FloatDataType", "Undefined8DataType", "Undefined", "BitFieldPackingImpl", "DomainFileBasedDataTypeManager", "SourceArchive", "Playable", "BitFieldPacking", "BuiltInDataTypeClassExclusionFilter", "SignedQWordDataType", "SignedWordDataType", "CompositeDataTypeImpl", "DynamicDataType", "AlignmentType", "TypeDef", "PackingType", "DataOrganizationImpl", "Category", "UnsignedIntegerDataType", "TranslationSettingsDefinition", "OffsetMaskSettingsDefinition", "AbstractLeb128DataType", "InvalidatedListener", "UnsignedLongDataType", "CustomFormat", "AUDataType", "DataTypeManagerDomainObject", "MemBufferImageInputStream", "MenuResourceDataType", "CycleGroup", "MutabilitySettingsDefinition", "UnsignedCharDataType", "BooleanDataType", "TerminatedUnicode32DataType", "SignedByteDataType", "Union", "IconMaskResourceDataType", "DataTypeManagerChangeListener", "VoidDataType", "CustomOrganization", "DataTypeInstance", "InternalDataTypeComponent", "SegmentedCodePointerDataType", "StringRenderBuilder", "GenericCallingConvention", "CharsetInfo", "IndexedDynamicDataType", "MissingBuiltInDataType", "Integer16DataType", "PointerTypedef", "DataTypePath", "UnsignedInteger5DataType", "FunctionDefinition", "FloatComplexDataType", "DialogResourceDataType", "RepeatCountDataType", "DataTypeManager", "LongLongDataType", "UnsignedInteger16DataType", "UnionInternal", "BitGroup", "LongDoubleComplexDataType", "Undefined5DataType", "Float4DataType", "AbstractDataType", "DataTypeWriter", "WAVEDataType", "TypeDefSettingsDefinition", "Pointer24DataType", "NoisyStructureBuilder", "DataTypeManagerChangeListenerHandler", "Integer6DataType", "ShiftedAddressDataType", "Undefined1DataType", "PointerDataType", "DWordDataType", "Float10DataType", "DataTypeTransferable", "MIDIDataType", "Undefined6DataType", "UnsignedLongLongDataType", "CharDataType", "DataOrganization", "Undefined2DataType", "ReadOnlyDataTypeComponent", "LongDoubleDataType", "Integer5DataType", "ArrayDataType", "BuiltIn", "ShortDataType", "AIFFDataType", "JPEGDataType", "UnsignedInteger6DataType", "Pointer40DataType", "DataTypeNameComparator", "StructureInternal", "Enum", "Pointer8DataType", "CompositeAlignmentHelper", "LongDataType"]
