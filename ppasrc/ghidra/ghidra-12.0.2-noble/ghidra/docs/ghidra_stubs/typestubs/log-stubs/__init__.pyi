from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import org.apache.logging.log4j.core # type: ignore
import org.apache.logging.log4j.core.appender # type: ignore
import org.apache.logging.log4j.core.pattern # type: ignore


class LogPanelAppender(org.apache.logging.log4j.core.appender.AbstractAppender):
    """
    Log4j appender that writes messages to the log panel in the main Ghidra window. 
    This is configured in the various log4j configuration files 
    (generic.log4j.xml, generic.logjdev.xml, etc...).
     
    
    Note: This appender is created when the log4j configuration is processed and will 
    start receiving log messages immediately. These messages will be dropped on the 
    floor however, until an implementation of :obj:`LogListener` is instantiated and 
    the :meth:`setLogListener(LogListener) <.setLogListener>` method is invoked.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createAppender(name: typing.Union[java.lang.String, str], layout: org.apache.logging.log4j.core.Layout[java.io.Serializable], filter: org.apache.logging.log4j.core.Filter, otherAttribute: typing.Union[java.lang.String, str]) -> LogPanelAppender:
        ...

    def setLogListener(self, listener: LogListener):
        ...


class Log4jDevelopmentPatternConverter(org.apache.logging.log4j.core.pattern.LogEventPatternConverter):
    """
    Pattern converter for Log4j 2.x that adds a hyperlink for the calling class
    of the current log message. This is to be used in log4j configurations as part
    of a pattern layout. eg:
     
            <PatternLayout pattern="%-5p %m %hl %n"/> 
     
    See generic.log4jdev.xml for a working example.
    """

    @typing.type_check_only
    class MethodPattern(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def format(self, event: org.apache.logging.log4j.core.LogEvent, toAppendTo: java.lang.StringBuilder):
        """
        Appends the desired hyperlink to the existing event message.
        
        :param org.apache.logging.log4j.core.LogEvent event: the current log event
        :param java.lang.StringBuilder toAppendTo: the string to append to
        """

    @staticmethod
    def newInstance(options: jpype.JArray[java.lang.String]) -> Log4jDevelopmentPatternConverter:
        """
        Required instance method for all log4j 2.x converters.
        
        :param jpype.JArray[java.lang.String] options: unused
        :return: new converter instance
        :rtype: Log4jDevelopmentPatternConverter
        """


class LogListener(java.lang.Object):
    """
    An interface that allows clients to receive log messages.
    """

    class_: typing.ClassVar[java.lang.Class]

    def messageLogged(self, message: typing.Union[java.lang.String, str], isError: typing.Union[jpype.JBoolean, bool]):
        """
        Called when a log message is received.
        
        :param java.lang.String or str message: the message of the log event
        :param jpype.JBoolean or bool isError: true if the message is considered an error, as opposed to an informational
                message.
        """



__all__ = ["LogPanelAppender", "Log4jDevelopmentPatternConverter", "LogListener"]
