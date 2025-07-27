from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


class HttpUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getContent(httpUrlString: typing.Union[java.lang.String, str], httpRequestProperties: java.util.Properties, allowRedirect: typing.Union[jpype.JBoolean, bool]) -> java.net.HttpURLConnection:
        """
        Execute an HTTP/HTTPS GET request and return the resulting HttpURLConnection.
        
        :param java.lang.String or str httpUrlString: HTTP/HTTPS URL
        :param java.util.Properties httpRequestProperties: optional HTTP request header values to be included (may be null)
        :param jpype.JBoolean or bool allowRedirect: allow site redirects to be handled if true
        :return: HttpURLConnection which contains information about the URL
        :rtype: java.net.HttpURLConnection
        :raises MalformedURLException: bad httpUrlString specified
        :raises IOException: if an error occurs while executing request
        """

    @staticmethod
    def getFile(httpUrlString: typing.Union[java.lang.String, str], httpRequestProperties: java.util.Properties, allowRedirect: typing.Union[jpype.JBoolean, bool], destFile: jpype.protocol.SupportsPath) -> str:
        """
        Download a file by executing an HTTP/HTTPS GET request.
        
        :param java.lang.String or str httpUrlString: HTTP/HTTPS URL
        :param java.util.Properties httpRequestProperties: optional HTTP request header values to be included (may be null)
        :param jpype.JBoolean or bool allowRedirect: allow site redirects to be handled if true
        :param jpype.protocol.SupportsPath destFile: destination file
        :raises MalformedURLException: bad httpUrlString specified
        :raises IOException: if an error occurs while executing request
        :return: String representing the content-type of the file, or null if the information is not available
        :rtype: str
        """



__all__ = ["HttpUtil"]
