from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.base.project
import ghidra.program.model.listing
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.xml.parsers # type: ignore
import org.jdom # type: ignore
import org.jdom.input # type: ignore
import org.jdom.output # type: ignore
import org.xml.sax # type: ignore


@typing.type_check_only
class XmlSummary(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class XmlTestHelper(java.lang.Object):

    @typing.type_check_only
    class MyErrorHandler(org.xml.sax.ErrorHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tmpDirPath: typing.Union[java.lang.String, str], gp: ghidra.base.project.GhidraProject):
        ...

    @typing.overload
    def __init__(self, tmpDirPath: typing.Union[java.lang.String, str]):
        ...

    def add(self, xml: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    @typing.overload
    def assertXMLFilesEquals(expectedXMLFile: jpype.protocol.SupportsPath, testXMLFile: jpype.protocol.SupportsPath):
        ...

    @staticmethod
    @typing.overload
    def assertXMLFilesEquals(expectedXMLParser: ghidra.xml.XmlPullParser, testXMLParser: ghidra.xml.XmlPullParser):
        ...

    def clearXml(self):
        ...

    def compareXml(self, file: jpype.protocol.SupportsPath):
        ...

    def containsXml(self, line: typing.Union[java.lang.String, str]) -> bool:
        ...

    def dispose(self):
        ...

    def getProject(self) -> ghidra.base.project.GhidraProject:
        ...

    def getTempFile(self, name: typing.Union[java.lang.String, str]) -> java.io.File:
        ...

    def getXmlParser(self, name: typing.Union[java.lang.String, str]) -> ghidra.xml.XmlPullParser:
        ...

    def loadResourceProgram(self, programName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Program:
        ...

    def loadXmlResource(self, pkg: java.lang.Package, name: typing.Union[java.lang.String, str]):
        """
        Read an XML file as a resource.
        
        :param java.lang.Package pkg: where resource resides
        :param java.lang.String or str name: name of the resource that is in the given package
        :raises IOException: thrown if there was a problem accessing the xml resource.
        """

    def printExpectedLines(self):
        ...

    @property
    def xmlParser(self) -> ghidra.xml.XmlPullParser:
        ...

    @property
    def tempFile(self) -> java.io.File:
        ...

    @property
    def project(self) -> ghidra.base.project.GhidraProject:
        ...


class SpecXmlUtils(java.lang.Object):
    """
    Utilities for encoding and decoding XML datatypes for use in specification files that
    are validated by RelaxNG.  This currently includes the SLEIGH/Decompiler configuration files.
    I.e.
            .ldef files
            .pspec files
            .cspec files
            .sla files
      
    Philosophy here is to use and enforce datatype encodings from XML schemas
    to try to be as standard as possible and facilitate use of relax grammars etc.  But in decoding
    possibly be a little more open to deal with resources generated outside of our control.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def decodeBoolean(val: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    @typing.overload
    def decodeBoolean(val: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    @staticmethod
    def decodeInt(intString: typing.Union[java.lang.String, str]) -> int:
        ...

    @staticmethod
    def decodeLong(longString: typing.Union[java.lang.String, str]) -> int:
        ...

    @staticmethod
    def decodeNullableBoolean(val: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def encodeBoolean(val: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    def encodeBooleanAttribute(buf: java.lang.StringBuilder, nm: typing.Union[java.lang.String, str], val: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    def encodeDoubleAttribute(buf: java.lang.StringBuilder, nm: typing.Union[java.lang.String, str], val: typing.Union[jpype.JDouble, float]):
        ...

    @staticmethod
    def encodeSignedInteger(val: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def encodeSignedIntegerAttribute(buf: java.lang.StringBuilder, nm: typing.Union[java.lang.String, str], val: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def encodeStringAttribute(buf: java.lang.StringBuilder, nm: typing.Union[java.lang.String, str], val: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def encodeUnsignedInteger(val: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def encodeUnsignedIntegerAttribute(buf: java.lang.StringBuilder, nm: typing.Union[java.lang.String, str], val: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def getXmlHandler() -> org.xml.sax.ErrorHandler:
        ...

    @staticmethod
    def xmlEscape(buf: java.lang.StringBuilder, val: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def xmlEscapeAttribute(buf: java.lang.StringBuilder, nm: typing.Union[java.lang.String, str], val: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def xmlEscapeWriter(writer: java.io.Writer, val: typing.Union[java.lang.String, str]):
        ...


class XmlAttributes(java.lang.Object):
    """
    A container class for creating XML attribute strings.
    For example, given the following code:
     
    XmlAttributes attrs = new XmlAttributes();
    attrs.add("FIVE", 32, true);
    attrs.add("BAR", "foo");
    attrs.add("PI", 3.14159);
     
    
    The output would be: ``FIVE="0x20" BAR="foo" PI="3.14159".``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new empty XML attributes.
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Add a new string attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param java.lang.String or str value: the string value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new boolean attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JBoolean or bool value: the boolean value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JFloat, float]):
        """
        Add a new float attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JFloat or float value: the float value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JDouble, float]):
        """
        Add a new double attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JDouble or float value: the double value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JByte, int]):
        """
        Add a new byte attribute as decimal.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JByte or int value: the byte value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JByte, int], hex: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new byte attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JByte or int value: the byte value
        :param jpype.JBoolean or bool hex: true if value should be written in hex
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JShort, int]):
        """
        Add a new short attribute as decimal.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JShort or int value: the short value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JShort, int], hex: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new short attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JShort or int value: the short value
        :param jpype.JBoolean or bool hex: true if value should be written in hex
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Add a new int attribute as decimal.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JInt or int value: the int value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int], hex: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new int attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JInt or int value: the int value
        :param jpype.JBoolean or bool hex: true if value should be written in hex
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Add a new long attribute as decimal.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JLong or int value: the long value
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int], hex: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new long attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param jpype.JLong or int value: the long value
        :param jpype.JBoolean or bool hex: true if value should be written in hex
        """

    @typing.overload
    def addAttribute(self, name: typing.Union[java.lang.String, str], value: java.math.BigInteger, hex: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new big integer attribute.
        
        :param java.lang.String or str name: the name of the new attribute
        :param java.math.BigInteger value: the big integer value
        """

    def isEmpty(self) -> bool:
        """
        
        
        :return: the number of attributes in this
        :rtype: bool
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class GenericXMLOutputter(org.jdom.output.XMLOutputter):
    """
    A simple extension of ``XMLOutputter`` that sets default settings to fix common bugs.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_INDENT: typing.Final = "    "

    def __init__(self):
        """
        This constructor performs basic setup that can be changed later by the user.  For example,
         
            setTextNormalize( true );
            setIndent( DEFAULT_INDENT );
            setNewlines( true );
        """


class XmlWriter(java.lang.Object):
    """
    A class for creating XML files.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, dtdName: typing.Union[java.lang.String, str]):
        """
        Constructs a new XML writer.
        
        :param jpype.protocol.SupportsPath file: the name of the output XML file
        :param java.lang.String or str dtdName: the name of the DTD
        :raises IOException: if an i/o error occurs
        """

    @typing.overload
    def __init__(self, out: java.io.OutputStream, dtdName: typing.Union[java.lang.String, str]):
        """
        Constructs a new XML writer.
        
        :param java.io.OutputStream out: the output stream
        :param java.lang.String or str dtdName: the name of the DTD
        :raises IOException: if an i/o error occurs
        """

    def close(self):
        """
        Closes this XML writer.
        """

    def endElement(self, name: typing.Union[java.lang.String, str]):
        """
        Writes the specified end element.
        
        :param java.lang.String or str name: the name of the end element
        """

    def getCounter(self) -> Counter:
        """
        Returns the XML summary string.
        
        :return: the XML summary string
        :rtype: Counter
        """

    @typing.overload
    def startElement(self, name: typing.Union[java.lang.String, str]):
        """
        Writes the specified start element.
        
        :param java.lang.String or str name: the name of the start element
        """

    @typing.overload
    def startElement(self, name: typing.Union[java.lang.String, str], attrs: XmlAttributes):
        """
        Writes the specified start element with the attributes.
        
        :param java.lang.String or str name: the name of the start element
        :param XmlAttributes attrs: the attributes of the start element
        """

    def writeDTD(self, dtdName: typing.Union[java.lang.String, str]):
        """
        Writes the specified DTD into the file.
        
        :param java.lang.String or str dtdName: the name of the DTD
        :raises IOException: if an i/o error occurs
        """

    @typing.overload
    def writeElement(self, name: typing.Union[java.lang.String, str], attrs: XmlAttributes):
        """
        Writes the specified element with the attributes.
        
        :param java.lang.String or str name: the name of the start element
        :param XmlAttributes attrs: the attributes of the start element
        """

    @typing.overload
    def writeElement(self, name: typing.Union[java.lang.String, str], attrs: XmlAttributes, text: typing.Union[java.lang.String, str]):
        """
        Writes the specified element with the attributes and text.
        
        :param java.lang.String or str name: the name of the element
        :param XmlAttributes attrs: the attributes of the element
        :param java.lang.String or str text: the text of the element
        """

    @property
    def counter(self) -> Counter:
        ...


class XmlUtilities(java.lang.Object):
    """
    A set of utility methods for working with XML.
    """

    class ThrowingErrorHandler(org.xml.sax.ErrorHandler):
        """
        Simple :obj:`SAX error handler <ErrorHandler>` that re-throws any
        :obj:`SAXParseException`s as a :obj:`SAXException`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    FEATURE_DISALLOW_DTD: typing.Final = "http://apache.org/xml/features/disallow-doctype-decl"
    FEATURE_EXTERNAL_GENERAL_ENTITIES: typing.Final = "http://xml.org/sax/features/external-general-entities"
    FEATURE_EXTERNAL_PARAMETER_ENTITIES: typing.Final = "http://xml.org/sax/features/external-parameter-entities"

    def __init__(self):
        ...

    @staticmethod
    def byteArrayToXml(bytes: jpype.JArray[jpype.JByte]) -> org.jdom.Element:
        """
        Converts the specified byte array into an XML element.
        
        :param jpype.JArray[jpype.JByte] bytes: the XML bytes
        :return: an XML element
        :rtype: org.jdom.Element
        """

    @staticmethod
    def createSecureSAXBuilder(validate: typing.Union[jpype.JBoolean, bool], needsDTD: typing.Union[jpype.JBoolean, bool]) -> org.jdom.input.SAXBuilder:
        """
        Create a :obj:`SAXBuilder` that is not susceptible to XXE.
         
        This configures the builder to ignore external entities.
        
        :param jpype.JBoolean or bool validate: indicates whether validation should occur
        :param jpype.JBoolean or bool needsDTD: false to disable doctype declarations altogether
        :return: the configured builder
        :rtype: org.jdom.input.SAXBuilder
        """

    @staticmethod
    def createSecureSAXParserFactory(needsDTD: typing.Union[jpype.JBoolean, bool]) -> javax.xml.parsers.SAXParserFactory:
        """
        Create a :obj:`SAXParserFactory` that is not susceptible to XXE.
         
        This configures the factory to ignore external entities.
        
        :param jpype.JBoolean or bool needsDTD: false to disable doctype declarations altogether
        :return: the configured factory
        :rtype: javax.xml.parsers.SAXParserFactory
        """

    @staticmethod
    def escapeElementEntities(xml: typing.Union[java.lang.String, str]) -> str:
        """
        Converts any special or reserved characters in the specified XML string
        into the equivalent Unicode encoding.
        
        :param java.lang.String or str xml: the XML string
        :return: the encoded XML string
        :rtype: str
        """

    @staticmethod
    def fromString(s: typing.Union[java.lang.String, str]) -> org.jdom.Element:
        """
        Convert a String into a JDOM :obj:`Element`.
        
        :param java.lang.String or str s: 
        :return: 
        :rtype: org.jdom.Element
        :raises JDOMException: 
        :raises IOException:
        """

    @staticmethod
    def getChildren(ele: org.jdom.Element, childName: typing.Union[java.lang.String, str]) -> java.util.List[org.jdom.Element]:
        """
        Type-safe way of getting a list of :obj:`Element`s from JDom.
        
        :param org.jdom.Element ele: the parent element
        :param java.lang.String or str childName: the name of the children elements to return
        :return: List<Element> of elements
        :rtype: java.util.List[org.jdom.Element]
        """

    @staticmethod
    def hasInvalidXMLCharacters(s: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests a string for characters that would cause a problem if added to an
        xml attribute or element.
        
        :param java.lang.String or str s: a string
        :return: boolean true if the string will cause a problem if added to an
                xml attribute or element.
        :rtype: bool
        """

    @staticmethod
    def parseBoolean(boolStr: typing.Union[java.lang.String, str]) -> bool:
        """
        Parses the given string into a boolean value. Acceptable inputs are
        y,n,true,fase. A null input string will return false (useful if optional
        boolean attribute is false by default)
        
        :param java.lang.String or str boolStr: the string to parse into a boolean value
        :return: the boolean result.
        :rtype: bool
        :raises XmlAttributeException: if the string in not one of y,n,true,false
                    or null.
        """

    @staticmethod
    def parseBoundedInt(intStr: typing.Union[java.lang.String, str], minValue: typing.Union[jpype.JInt, int], maxValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Parses the specified string as a decimal number, returning its integer
        value.
        
        :param java.lang.String or str intStr: String with integer digits
        :param jpype.JInt or int minValue: minimum value allowed (inclusive)
        :param jpype.JInt or int maxValue: maximum value allowed (inclusive)
        :return: integer value of the intStr
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr is null or empty or could not be
                    parsed or is out of range.
        """

    @staticmethod
    def parseBoundedIntAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], minValue: typing.Union[jpype.JInt, int], maxValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Parses the required attribute as a decimal number, returning its integer
        value.
        
        :param org.jdom.Element ele: JDom element that contains the attribute
        :param java.lang.String or str attrName: the name of the xml attribute to parse
        :param jpype.JInt or int minValue: minimum value allowed (inclusive)
        :param jpype.JInt or int maxValue: maximum value allowed (inclusive)
        :return: integer value of the attribute
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr could not be parsed or is out of
                    range.
        """

    @staticmethod
    def parseBoundedLong(longStr: typing.Union[java.lang.String, str], minValue: typing.Union[jpype.JLong, int], maxValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Parses the specified string as a decimal number, returning its long
        integer value.
         
        
        Note, using :obj:`Long.MIN_VALUE` and/or :obj:`Long.MAX_VALUE` as lower
        and upper bounds is problematic and should be avoided as the range check
        will become a NO-OP and always succeed.
        
        :param java.lang.String or str longStr: String with integer digits
        :param jpype.JLong or int minValue: minimum value allowed (inclusive)
        :param jpype.JLong or int maxValue: maximum value allowed (inclusive)
        :return: long integer value of the longStr
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr is null or empty or could not be
                    parsed or is out of range.
        """

    @staticmethod
    def parseBoundedLongAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], minValue: typing.Union[jpype.JLong, int], maxValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Parses the required attribute as a decimal number, returning its long
        integer value.
         
        
        Note, using :obj:`Long.MIN_VALUE` and/or :obj:`Long.MAX_VALUE` as lower
        and upper bounds is problematic and should be avoided as the range check
        will become a NO-OP and always succeed.
        
        :param org.jdom.Element ele: JDom element that contains the attribute
        :param java.lang.String or str attrName: the name of the xml attribute to parse
        :param jpype.JLong or int minValue: minimum value allowed (inclusive)
        :param jpype.JLong or int maxValue: maximum value allowed (inclusive)
        :return: long integer value of the attribute
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr could not be parsed or is out of
                    range.
        """

    @staticmethod
    @typing.overload
    def parseInt(intStr: typing.Union[java.lang.String, str]) -> int:
        """
        Parse the given string as either a hex number (if it starts with 0x) or a
        decimal number.
        
        :param java.lang.String or str intStr: the string to parse into an integer
        :return: the parsed integer.
        :rtype: int
        :raises NumberFormatException: if the given string does not represent a
                    valid integer.
        """

    @staticmethod
    @typing.overload
    def parseInt(intStr: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Parses the optional specified string as a decimal number, returning its
        integer value.
        
        :param java.lang.String or str intStr: string with integer digits, or empty or null
        :param jpype.JInt or int defaultValue: value to return if intStr is missing
        :return: integer value of the intStr
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr could not be parsed or the string
                    specifies a value outside the range of a signed 32 bit
                    integer.
        """

    @staticmethod
    def parseLong(longStr: typing.Union[java.lang.String, str]) -> int:
        """
        Parse the given string as either a hex number (if it starts with 0x) or a
        decimal number.
        
        :param java.lang.String or str longStr: the string to parse into an long
        :return: the parsed long.
        :rtype: int
        :raises NumberFormatException: if the given string does not represent a
                    valid long.
        """

    @staticmethod
    def parseOptionalBooleanAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Parses the optional attribute as a boolean value, returning its value or
        the specified defaultValue if missing.
        
        :param org.jdom.Element ele: JDom element that contains the attribute
        :param java.lang.String or str attrName: the name of the xml attribute to parse
        :param jpype.JBoolean or bool defaultValue: boolean value to return if the attribute is not
                    defined
        :return: boolean equiv of the attribute string value ("y", "true"/"n",
                "false")
        :rtype: bool
        :raises IOException: if attribute value is not valid boolean string
        """

    @staticmethod
    def parseOptionalBoundedInt(intStr: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int], minValue: typing.Union[jpype.JInt, int], maxValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Parses the optional specified string as a decimal number, returning its
        integer value, or defaultValue if the string is null.
        
        :param java.lang.String or str intStr: string with integer digits, or null.
        :param jpype.JInt or int defaultValue: value to return if intStr is null.
        :param jpype.JInt or int minValue: minimum value allowed (inclusive).
        :param jpype.JInt or int maxValue: maximum value allowed (inclusive).
        :return: integer value of the intStr.
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr could not be parsed or is out of
                    range.
        """

    @staticmethod
    def parseOptionalBoundedIntAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int], minValue: typing.Union[jpype.JInt, int], maxValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Parses an optional attribute as a decimal number, returning its integer
        value, or the defaultValue if the attribute is null.
        
        :param org.jdom.Element ele: JDOM element that contains the attribute.
        :param java.lang.String or str attrName: the name of the xml attribute to parse.
        :param jpype.JInt or int defaultValue: the default value to return if attribute is missing.
        :param jpype.JInt or int minValue: minimum value allowed (inclusive).
        :param jpype.JInt or int maxValue: maximum value allowed (inclusive).
        :return: integer value of the attribute.
        :rtype: int
        :raises java.lang.NumberFormatException: if the attribute value could not be parsed
                    or is out of range.
        """

    @staticmethod
    def parseOptionalBoundedLongAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int], minValue: typing.Union[jpype.JLong, int], maxValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Parses the required attribute as a decimal number, returning its long
        integer value.
         
        
        Note, using :obj:`Long.MIN_VALUE` and/or :obj:`Long.MAX_VALUE` as lower
        and upper bounds is problematic and should be avoided as the range check
        will become a NO-OP and always succeed.
        
        :param org.jdom.Element ele: JDom element that contains the attribute.
        :param java.lang.String or str attrName: the name of the xml attribute to parse.
        :param jpype.JLong or int defaultValue: the default value to return if attribute is missing.
        :param jpype.JLong or int minValue: minimum value allowed (inclusive).
        :param jpype.JLong or int maxValue: maximum value allowed (inclusive).
        :return: long integer value of the attribute.
        :rtype: int
        :raises java.lang.NumberFormatException: if intStr could not be parsed or is out of
                    range.
        """

    @staticmethod
    def parseOverlayName(addrStr: typing.Union[java.lang.String, str]) -> str:
        """
        Parses the overlay name from the specified address string. Returns null
        if the address string does appear to represent an overlay.
        
        :param java.lang.String or str addrStr: the address string
        :return: the overlay name or null
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def readDocFromFile(f: jpype.protocol.SupportsPath) -> org.jdom.Document:
        """
        Read a File and convert to jdom xml doc.
        
        :param jpype.protocol.SupportsPath f: :obj:`File` to read
        :return: JDOM :obj:`Document`
        :rtype: org.jdom.Document
        :raises JDOMException: if text in file isn't valid XML
        :raises IOException: if IO error when reading file.
        """

    @staticmethod
    @typing.overload
    def readDocFromFile(f: generic.jar.ResourceFile) -> org.jdom.Document:
        """
        Read a File and convert to jdom xml doc.
        
        :param generic.jar.ResourceFile f: :obj:`ResourceFile` to read
        :return: JDOM :obj:`Document`
        :rtype: org.jdom.Document
        :raises JDOMException: if text in file isn't valid XML
        :raises IOException: if IO error when reading file.
        """

    @staticmethod
    def requireStringAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str]) -> str:
        """
        Throws an :obj:`IOException` with a verbose explanation if the requested
        attribute is not present or is empty.
        
        :param org.jdom.Element ele: JDOM :obj:`Element` that contains the attribute
        :param java.lang.String or str attrName: the attribute name
        :return: String value of the attribute (never null or empty)
        :rtype: str
        :raises IOException: if attribute is missing or empty
        """

    @staticmethod
    def setIntAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], attrValue: typing.Union[jpype.JInt, int]):
        """
        Sets an integer attribute on the specified element.
        
        :param org.jdom.Element ele: JDom element
        :param java.lang.String or str attrName: name of attribute
        :param jpype.JInt or int attrValue: value of attribute
        """

    @staticmethod
    def setStringAttr(ele: org.jdom.Element, attrName: typing.Union[java.lang.String, str], attrValue: typing.Union[java.lang.String, str]):
        """
        Sets a string attribute on the specified element.
        
        :param org.jdom.Element ele: JDom element
        :param java.lang.String or str attrName: name of attribute
        :param java.lang.String or str attrValue: value of attribute, null ok
        """

    @staticmethod
    def toString(root: org.jdom.Element) -> str:
        """
        Converts the specified XML element into a String.
        
        :param org.jdom.Element root: the root element
        :return: String translation of the given element
        :rtype: str
        """

    @staticmethod
    def unEscapeElementEntities(escapedXMLString: typing.Union[java.lang.String, str]) -> str:
        """
        Converts any escaped character entities into their unescaped character
        equivalents. This method is designed to be compatible with the output of
        :meth:`escapeElementEntities(String) <.escapeElementEntities>`.
        
        :param java.lang.String or str escapedXMLString: The string with escaped data
        :return: the unescaped string
        :rtype: str
        """

    @staticmethod
    def writeDocToFile(doc: org.jdom.Document, dest: jpype.protocol.SupportsPath):
        """
        Writes a JDOM XML :obj:`Document` to a :obj:`File`.
        
        :param org.jdom.Document doc: JDOM XML :obj:`Document` to write.
        :param jpype.protocol.SupportsPath dest: :obj:`File` to write to.
        :raises IOException: if error when writing file.
        """

    @staticmethod
    def writePrettyDocToFile(doc: org.jdom.Document, dest: jpype.protocol.SupportsPath):
        """
        Writes a JDOM XML :obj:`Document` to a :obj:`File`, with a prettier
        format than :meth:`writeDocToFile(Document, File) <.writeDocToFile>`.
        
        :param org.jdom.Document doc: JDOM XML :obj:`Document` to write.
        :param jpype.protocol.SupportsPath dest: :obj:`File` to write to.
        :raises IOException: if error when writing file.
        """

    @staticmethod
    def xmlToByteArray(root: org.jdom.Element) -> jpype.JArray[jpype.JByte]:
        """
        Converts the specified XML element into a byte array.
        
        :param org.jdom.Element root: the root element
        :return: the byte array translation of the given element
        :rtype: jpype.JArray[jpype.JByte]
        """


@typing.type_check_only
class Counter(java.lang.Object):

    @typing.type_check_only
    class Count(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class XmlParserElement(java.lang.Object):
    """
    A class to represent the start or end tag from an XML file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAttrNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array containing the names of all attributes defined in this element.
        
        :return: an array containing the names of all attributes defined in this element
        :rtype: jpype.JArray[java.lang.String]
        """

    def getAttrValue(self, attrName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the value of the specified attribute.
        Or, null if no attribute exists with the specified name.
        
        :param java.lang.String or str attrName: the name of the attribute
        :return: the value of the specified attribute
        :rtype: str
        """

    def getAttrValueAsBool(self, attrName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns the boolean value of the specified attribute.
        
        :param java.lang.String or str attrName: the name of the attribute
        :return: the boolean value of the specified attribute
        :rtype: bool
        :raises XmlAttributeException: if no attribute exists with the specified name
        """

    def getAttrValueAsDouble(self, attrName: typing.Union[java.lang.String, str]) -> float:
        """
        Returns the double value of the specified attribute.
        
        :param java.lang.String or str attrName: the name of the attribute
        :return: the double value of the specified attribute
        :rtype: float
        :raises XmlAttributeException: if no attribute exists with the specified name
        """

    def getAttrValueAsInt(self, attrName: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the integer value of the specified attribute.
        
        :param java.lang.String or str attrName: the name of the attribute
        :return: the integer value of the specified attribute
        :rtype: int
        :raises XmlAttributeException: if no attribute exists with the specified name
        """

    def getAttrValueAsLong(self, attrName: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the long value of the specified attribute.
        
        :param java.lang.String or str attrName: the name of the attribute
        :return: the long value of the specified attribute
        :rtype: int
        :raises XmlAttributeException: if no attribute exists with the specified name
        """

    def getLineNum(self) -> int:
        """
        Returns the line number where this element was defined.
        
        :return: the line number where this element was defined
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of this element/tag.
        
        :return: the name of this element/tag
        :rtype: str
        """

    def getText(self) -> str:
        """
        Returns the text of this element. Or, null if no text existed
        in the XML.
        
        :return: the text of this element
        :rtype: str
        """

    def hasAttr(self, attrName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if this element contains an attribute with the specified name.
        
        :param java.lang.String or str attrName: the name of the attribute
        :return: true if this element contains an attribute with the specified name
        :rtype: bool
        """

    def isEnd(self) -> bool:
        """
        Returns true if this element represents an end tag.
        
        :return: true if this element represents an end tag
        :rtype: bool
        """

    def isStart(self) -> bool:
        """
        Returns true if this element represents a start tag.
        
        :return: true if this element represents a start tag
        :rtype: bool
        """

    def setAttribute(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Sets the value of the specified attribute.
        
        :param java.lang.String or str name: the name of the attribute
        :param java.lang.String or str value: the value of the attribute
        """

    @property
    def start(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def attrValueAsLong(self) -> jpype.JLong:
        ...

    @property
    def lineNum(self) -> jpype.JInt:
        ...

    @property
    def attrValueAsDouble(self) -> jpype.JDouble:
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def attrValue(self) -> java.lang.String:
        ...

    @property
    def attrNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def attrValueAsInt(self) -> jpype.JInt:
        ...

    @property
    def attrValueAsBool(self) -> jpype.JBoolean:
        ...


class XmlAttributeException(java.lang.RuntimeException):
    """
    A runtime exception that is throw when invalid
    or missing attributes are encountered.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a new runtime exception with the specified detail message.
        
        :param java.lang.String or str message: the detail message
        """



__all__ = ["XmlSummary", "XmlTestHelper", "SpecXmlUtils", "XmlAttributes", "GenericXMLOutputter", "XmlWriter", "XmlUtilities", "Counter", "XmlParserElement", "XmlAttributeException"]
