from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util.task
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


class LibreTranslatePlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.options.OptionsChangeListener):

    class SOURCE_LANGUAGE_OPTION(java.lang.Enum[LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION]):

        class_: typing.ClassVar[java.lang.Class]
        AUTO: typing.Final[LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION]
        PROMPT: typing.Final[LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION:
            ...

        @staticmethod
        def values() -> jpype.JArray[LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    LIBRE_TRANSLATE_SERVICE_NAME: typing.Final = "LibreTranslate"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class LibreTranslateStringTranslationService(ghidra.app.services.StringTranslationService):
    """
    Connects to an external LibreTranslate server via HTTP.
    """

    class SupportedLanguage(java.lang.Record):
        """
        Information about a language supported by LibreTranslate
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], langCode: typing.Union[java.lang.String, str], targets: java.util.List[java.lang.String]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def getDescription(self) -> str:
            ...

        def hashCode(self) -> int:
            ...

        def langCode(self) -> str:
            ...

        def name(self) -> str:
            ...

        def targets(self) -> java.util.List[java.lang.String]:
            ...

        def toString(self) -> str:
            ...

        @property
        def description(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serverURI: java.net.URI, apiKey: typing.Union[java.lang.String, str], sourceLanguageOption: LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION, targetLanguageCode: typing.Union[java.lang.String, str], batchSize: typing.Union[jpype.JInt, int], httpTimeout: typing.Union[jpype.JInt, int], httpTimeoutPerString: typing.Union[jpype.JInt, int]):
        """
        Creates an instance of :obj:`LibreTranslateStringTranslationService`
        
        :param java.net.URI serverURI: URL of the LibreTranslate server
        :param java.lang.String or str apiKey: optional string, api key required to submit requests to the server
        :param LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION sourceLanguageOption: :obj:`SOURCE_LANGUAGE_OPTION` enum
        :param java.lang.String or str targetLanguageCode: language code that the server should translate each string into
        :param jpype.JInt or int batchSize: max number of strings to submit to the server per request
        :param jpype.JInt or int httpTimeout: time to wait for a http request to finish
        :param jpype.JInt or int httpTimeoutPerString: additional time per string element to wait for http request to finish
        """

    def getSupportedLanguages(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[LibreTranslateStringTranslationService.SupportedLanguage]:
        """
        Returns a list of languages that the LibreTranslate server supports.
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: list of :obj:`SupportedLanguage` records
        :rtype: java.util.List[LibreTranslateStringTranslationService.SupportedLanguage]
        :raises IOException: if error connecting or excessive time to respond
        :raises CancelledException: if cancelled
        """

    @property
    def supportedLanguages(self) -> java.util.List[LibreTranslateStringTranslationService.SupportedLanguage]:
        ...



__all__ = ["LibreTranslatePlugin", "LibreTranslateStringTranslationService"]
