from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.app.util.importer
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.xml.sax # type: ignore
import org.xml.sax.helpers # type: ignore


class XmlPullParserFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def create(input: java.io.InputStream, inputName: typing.Union[java.lang.String, str], errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]) -> XmlPullParser:
        """
        Constructs a new parser using the specified stream and name.
        
        :param java.io.InputStream input: the input XML stream
        :param java.lang.String or str inputName: the name of the stream
        :param org.xml.sax.ErrorHandler errHandler: the XML error handler
        :param jpype.JBoolean or bool validate: true if the parse should validate against the DTD
        :raises SAXException: if an XML parse error occurs
        :raises IOException:
        """

    @staticmethod
    @typing.overload
    def create(file: jpype.protocol.SupportsPath, errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]) -> XmlPullParser:
        """
        Constructs a new parser using the specified XML file.
        
        :param jpype.protocol.SupportsPath file: the input XML file
        :param org.xml.sax.ErrorHandler errHandler: the XML error handler
        :param jpype.JBoolean or bool validate: true if the parse should validate against the DTD
        :raises SAXException: if an XML parse error occurs
        :raises IOException: if an i/o error occurs
        """

    @staticmethod
    @typing.overload
    def create(file: generic.jar.ResourceFile, errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]) -> XmlPullParser:
        """
        Constructs a new parser using the specified XML file.
        
        :param generic.jar.ResourceFile file: the input XML file
        :param org.xml.sax.ErrorHandler errHandler: the XML error handler
        :param jpype.JBoolean or bool validate: true if the parse should validate against the DTD
        :raises SAXException: if an XML parse error occurs
        :raises IOException: if an i/o error occurs
        """

    @staticmethod
    @typing.overload
    def create(input: typing.Union[java.lang.String, str], inputName: typing.Union[java.lang.String, str], errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]) -> XmlPullParser:
        """
        Constructs a new parser using the specified XML file.
        
        :param java.lang.String or str input: A string that contains the XML input data
        :param java.lang.String or str inputName: A descriptive name for the XML process (this will appear as the thread name)
        :param org.xml.sax.ErrorHandler errHandler: the XML error handler
        :param jpype.JBoolean or bool validate: true if the parse should validate against the DTD
        :raises SAXException: if an XML parse error occurs
        """

    @staticmethod
    def setCreateTracingParsers(xmlTracer: XmlTracer):
        ...


class XmlTreeNode(java.lang.Object):
    """
    A class to represent a corresponding start and end tag. This value is one
    node on the XML parse tree.
    """

    @typing.type_check_only
    class TagIterator(java.util.Iterator[XmlTreeNode]):

        class_: typing.ClassVar[java.lang.Class]

        def hasNext(self) -> bool:
            ...

        def next(self) -> XmlTreeNode:
            ...

        def remove(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parser: XmlPullParser):
        """
        Constructs a new XML tree node given the specified parser.
        
        :param XmlPullParser parser: the XML parser
        :raises SAXParseException: if an XML parser error occurs
        """

    def deleteChildNode(self, node: XmlTreeNode):
        """
        Deletes the specified child node.
        
        :param XmlTreeNode node: the node to delete
        """

    def getChild(self, name: typing.Union[java.lang.String, str]) -> XmlTreeNode:
        """
        Returns the first child element with the specified name.
        
        :param java.lang.String or str name: the name of the desired child element
        :return: the first child element with the specified name
        :rtype: XmlTreeNode
        """

    def getChildAt(self, index: typing.Union[jpype.JInt, int]) -> XmlTreeNode:
        ...

    def getChildCount(self) -> int:
        """
        Returns the number of children below this node.
        
        :return: the number of children below this node
        :rtype: int
        """

    @typing.overload
    def getChildren(self) -> java.util.Iterator[XmlTreeNode]:
        """
        Returns an iterator over all of the children of this node.
        
        :return: an iterator over all of the children of this node
        :rtype: java.util.Iterator[XmlTreeNode]
        """

    @typing.overload
    def getChildren(self, name: typing.Union[java.lang.String, str]) -> java.util.Iterator[XmlTreeNode]:
        """
        Returns an iterator over all of the children of this node with the
        specfied name.
        
        :param java.lang.String or str name: the name of the desired children
        :return: an iterator over all of the children of this node with the
                specfied name
        :rtype: java.util.Iterator[XmlTreeNode]
        """

    def getEndElement(self) -> XmlElement:
        """
        Returns the end element of this node.
        
        :return: the end element of this node
        :rtype: XmlElement
        """

    def getStartElement(self) -> XmlElement:
        """
        Returns the start element of this node.
        
        :return: the start element of this node
        :rtype: XmlElement
        """

    @property
    def endElement(self) -> XmlElement:
        ...

    @property
    def childAt(self) -> XmlTreeNode:
        ...

    @property
    def startElement(self) -> XmlElement:
        ...

    @property
    def children(self) -> java.util.Iterator[XmlTreeNode]:
        ...

    @property
    def childCount(self) -> jpype.JInt:
        ...

    @property
    def child(self) -> XmlTreeNode:
        ...


class XmlParseException(java.lang.Exception):
    """
    Exception that gets thrown if there is a problem parsing XML.
     
    
    NOTE: We used to use :obj:`javax.management.modelmbean.XMLParseException`
    but dealing with that class was annoying in Java 9.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], t: java.lang.Throwable):
        ...


class XmlTracer(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def trace(self, locator: org.xml.sax.Locator, traceMessage: typing.Union[java.lang.String, str], throwableIfAvailable: java.lang.Throwable):
        """
        The trace callback.  Please be quick.
        
        :param org.xml.sax.Locator locator: locator, or null if not available (note: locator information may be inaccurate!)
        :param java.lang.String or str traceMessage: the trace message
        :param java.lang.Throwable throwableIfAvailable: an exception if we're encountering one (or null)
        """


class XmlMessageLog(ghidra.app.util.importer.MessageLog):
    """
    A sub-class of MessageLog to handle appending messages from the XML parser.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new XML message log.
        """

    def setParser(self, parser: XmlPullParser):
        """
        Sets the XML parser.
        
        :param XmlPullParser parser: the XML parser
        """


class NonThreadedXmlPullParserImpl(AbstractXmlPullParser):

    @typing.type_check_only
    class DefaultContentHandlerWrapper(org.xml.sax.helpers.DefaultHandler):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, errorHandler: org.xml.sax.ErrorHandler, reallyCreateNoncompliantDeprecated: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, input: typing.Union[java.lang.String, str], inputName: typing.Union[java.lang.String, str], errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, input: java.io.InputStream, inputName: typing.Union[java.lang.String, str], errHandler: org.xml.sax.ErrorHandler, validate: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class ThreadedXmlPullParserImpl(AbstractXmlPullParser):
    """
    Constructs a new XML parser. This is class is designed for reading XML files.
    It is built on top of a ContentHandler. However, instead of being a "push"
    pattern, it has been translated into a "pull" pattern. That is, the user of
    this class can process the elements as needed. As well as skipping elements
    as needed.
    """

    @typing.type_check_only
    class ContentHandlerRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultContentHandlerWrapper(org.xml.sax.helpers.DefaultHandler):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, errorHandler: org.xml.sax.ErrorHandler):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Disposes this XML parser. No more elements may be read after dispose is
        called.
        """

    def getProcessingInstruction(self, piName: typing.Union[java.lang.String, str], attribute: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the value of the attribute of the processing instruction. For
        example, ``<?program_dtd version="1"?>``
        
        :param java.lang.String or str piName: the name of the processing instruction
        :param java.lang.String or str attribute: the name of the attribute
        :return: the value of the attribute of the processing instruction
        :rtype: str
        """

    def hasNext(self) -> bool:
        """
        Returns true if the parser has more elements to read.
        
        :return: true if the parser has more elements to read
        :rtype: bool
        """

    def next(self) -> XmlElement:
        """
        Returns the next element to be read and increments the iterator.
        
        :return: the next element to be read and increments the iterator
        :rtype: XmlElement
        """

    def peek(self) -> XmlElement:
        """
        Returns the next element to be read, but does not increment the iterator.
        
        :return: the next element to be read, but does not increment the iterator
        :rtype: XmlElement
        """


class AbstractXmlPullParser(XmlPullParser):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def discardSubTree(self) -> int:
        ...

    @typing.overload
    def discardSubTree(self, element: XmlElement) -> int:
        ...

    @typing.overload
    def discardSubTree(self, elementName: typing.Union[java.lang.String, str]) -> int:
        ...

    @typing.overload
    def end(self) -> XmlElement:
        ...

    @typing.overload
    def end(self, element: XmlElement) -> XmlElement:
        ...

    def getColumnNumber(self) -> int:
        ...

    def getCurrentLevel(self) -> int:
        ...

    def getLineNumber(self) -> int:
        ...

    def softStart(self, *names: typing.Union[java.lang.String, str]) -> XmlElement:
        ...

    def start(self, *names: typing.Union[java.lang.String, str]) -> XmlElement:
        ...

    @property
    def currentLevel(self) -> jpype.JInt:
        ...

    @property
    def columnNumber(self) -> jpype.JInt:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...


class XmlElementImpl(XmlElement):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, isStart: typing.Union[jpype.JBoolean, bool], isEnd: typing.Union[jpype.JBoolean, bool], name: typing.Union[java.lang.String, str], level: typing.Union[jpype.JInt, int], attributes: java.util.LinkedHashMap[java.lang.String, java.lang.String], text: typing.Union[java.lang.String, str], columnNumber: typing.Union[jpype.JInt, int], lineNumber: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def splitEmptyElement(element: XmlElementImpl) -> jpype.JArray[XmlElement]:
        ...


class XmlException(java.lang.RuntimeException):

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


class XmlElement(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAttribute(self, key: typing.Union[java.lang.String, str]) -> str:
        ...

    def getAttributeIterator(self) -> java.util.Iterator[java.util.Map.Entry[java.lang.String, java.lang.String]]:
        ...

    def getAttributes(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    def getColumnNumber(self) -> int:
        ...

    def getLevel(self) -> int:
        ...

    def getLineNumber(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getText(self) -> str:
        ...

    def hasAttribute(self, key: typing.Union[java.lang.String, str]) -> bool:
        ...

    def isContent(self) -> bool:
        ...

    def isEnd(self) -> bool:
        ...

    def isStart(self) -> bool:
        ...

    def setAttribute(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    @property
    def level(self) -> jpype.JInt:
        ...

    @property
    def columnNumber(self) -> jpype.JInt:
        ...

    @property
    def start(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def end(self) -> jpype.JBoolean:
        ...

    @property
    def attributes(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def attribute(self) -> java.lang.String:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def attributeIterator(self) -> java.util.Iterator[java.util.Map.Entry[java.lang.String, java.lang.String]]:
        ...

    @property
    def content(self) -> jpype.JBoolean:
        ...


class XmlPullParser(java.lang.Object):
    """
    An interface describing the API for the XML pull parsing system. This is
    similar to XmlParser, except that it has slightly different methods and IS
    case sensitive, conforming to the XML spec.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def discardSubTree(self) -> int:
        """
        Discards the current subtree. If the current element (peek()) is a
        content or end element, then just that element is discarded. If it's a
        start element, then the entire subtree starting with the start element is
        discarded (i.e. next() is called until the current element is now the
        element after the subtree's end element).
        
        :return: the number of elements discarded
        :rtype: int
        """

    @typing.overload
    def discardSubTree(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Discards the current subtree. The current element must be a start
        element, and must be named name, otherwise an XmlException is thrown.
        
        :param java.lang.String or str name: what the current start element must be named
        :return: the number of elements discarded
        :rtype: int
        """

    @typing.overload
    def discardSubTree(self, element: XmlElement) -> int:
        """
        Discards a subtree. The element provided is used as the "start" of the
        subtree (although it doesn't actually have to be a start element; only
        its name and level are used). The queue of elements is discarded such
        that the last element discarded is an end element, has the same name as
        the provided element, and is the same level as the provided element. If
        the provided element's level is higher than the current level, then
        nothing is discarded.
        
        :param XmlElement element: the element provided as the "start" element
        :return: the number of elements discarded
        :rtype: int
        """

    def dispose(self):
        """
        Disposes all resources of the parser. It's important that this is called
        when a client is finished with the parser, because this allows files to
        be closed, threads to be stopped, etc.
        """

    @typing.overload
    def end(self) -> XmlElement:
        """
        Returns the next element, which must be an end element. The name doesn't
        matter. This method throws an XmlException if the next element is not an
        end element. Use this method when you really know you're matching the
        right end and want to avoid extra constraint checks.
        
        :return: the next element (which is an end element)
        :rtype: XmlElement
        """

    @typing.overload
    def end(self, element: XmlElement) -> XmlElement:
        """
        Returns the next element, which must be an end element, and must match
        the supplied XmlElement's name (presumably the start element of the
        subtree). This method throws an XmlException if the next element is not
        an end element, or if the name doesn't match.
        
        :param XmlElement element: the presumed start element to match names
        :return: the next element (which is an end element)
        :rtype: XmlElement
        """

    def getColumnNumber(self) -> int:
        """
        Returns the current column number where the parser is (note that this may
        actually be ahead of where you think it is because of look-ahead and
        caching).
        
        :return: the current column number
        :rtype: int
        """

    def getCurrentLevel(self) -> int:
        """
        The current element level, as if the XML document was a tree. The root
        element is at level 0. Each child is at a level one higher than its
        parent.
         
        Note that this is the same as peek().getLevel().
        
        :return: the current element level
        :rtype: int
        """

    def getLineNumber(self) -> int:
        """
        Returns the current line number where the parser is (note that this may
        actually be ahead of where you think it is because of look-ahead and
        caching).
        
        :return: the current line number
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the name of this parser.
        
        :return: the name of this parser
        :rtype: str
        """

    def getProcessingInstruction(self, name: typing.Union[java.lang.String, str], attribute: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the value of the attribute of the processing instruction.
        For example, ``<?program_dtd version="1"?>``
        
        :param java.lang.String or str name: the name of the processing instruction
        :param java.lang.String or str attribute: the name of the attribute
        :return: the value of the attribute of the processing instruction
        :rtype: str
        """

    def hasNext(self) -> bool:
        """
        Returns whether there is a next element.
        
        :return: whether there is a next element
        :rtype: bool
        """

    def isPullingContent(self) -> bool:
        """
        Returns whether the parser will return content elements as well as start
        and end elements (they're always accumulated and provided in the
        appropriate end element).
        
        :return: whether the parser will return content elements
        :rtype: bool
        """

    def next(self) -> XmlElement:
        """
        Returns the next element, removing it from the queue (assuming there is
        such a next element). This method should be used RARELY. Typically, when
        you're reading XML, you almost always at least know that you're either
        starting or ending a subtree, so start() or end() should be used instead.
        The only time you really might need to use this is if you don't really
        know where you are and you need to pop elements off until you synchronize
        back into a sane state.
        
        :return: the next element, removing it
        :rtype: XmlElement
        """

    def peek(self) -> XmlElement:
        """
        Returns the next element, without removing it from the queue (assuming
        there is such a next element). This is very useful for examining the next
        item to decide who should handle the subtree, and then delegating to a
        subordinate with the parser state intact.
        
        :return: the next element, without removing it
        :rtype: XmlElement
        """

    def setPullingContent(self, pullingContent: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether the parser will return content elements. Note that this
        method may throw an exception if the parser cannot comply with the
        setting (usually when setting to true).
        
        :param jpype.JBoolean or bool pullingContent: whether the parser will return content elements
        """

    def softStart(self, *names: typing.Union[java.lang.String, str]) -> XmlElement:
        """
        Returns the next element, which must be a start element, and must be one
        of the supplied names (if provided). This method is very useful for
        starting a subtree, but differs from start(...) in that failures are
        soft. This means that if the next element isn't a start element, or
        doesn't match one of the optional provided names, null is returned
        (instead of raising an XmlException).
        
        :param jpype.JArray[java.lang.String] names: optional vararg Strings which start element name must be one
                    of
        :return: the next element (which is a start element) or null
        :rtype: XmlElement
        """

    def start(self, *names: typing.Union[java.lang.String, str]) -> XmlElement:
        """
        Returns the next element, which must be a start element, and must be one
        of the supplied names (if provided). This method is very useful for
        starting a subtree, and throws an XmlException if the next element does
        not conform to your specification.
        
        :param jpype.JArray[java.lang.String] names: optional vararg Strings which start element name must be one
                    of
        :return: the next element (which is a start element)
        :rtype: XmlElement
        """

    @property
    def currentLevel(self) -> jpype.JInt:
        ...

    @property
    def columnNumber(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def pullingContent(self) -> jpype.JBoolean:
        ...

    @pullingContent.setter
    def pullingContent(self, value: jpype.JBoolean):
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...



__all__ = ["XmlPullParserFactory", "XmlTreeNode", "XmlParseException", "XmlTracer", "XmlMessageLog", "NonThreadedXmlPullParserImpl", "ThreadedXmlPullParserImpl", "AbstractXmlPullParser", "XmlElementImpl", "XmlException", "XmlElement", "XmlPullParser"]
