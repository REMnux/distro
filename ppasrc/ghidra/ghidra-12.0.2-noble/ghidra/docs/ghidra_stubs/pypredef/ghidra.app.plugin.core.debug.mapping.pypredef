from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.debug.api.platform
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.target
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore


class AbstractDebuggerPlatformOpinion(DebuggerPlatformOpinion):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractDebuggerPlatformOffer(DebuggerPlatformOffer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, description: typing.Union[java.lang.String, str], cSpec: ghidra.program.model.lang.CompilerSpec):
        ...


class DebuggerPlatformOpinion(ghidra.util.classfinder.ExtensionPoint):
    """
    An opinion governing analysis and display of a trace according to a platform (processor, ISA, OS,
    ABI, etc.)
     
     
    
    This is meant for "object-based" traces, which may soon supplant "table-based" traces. The latter
    requires mapping between the target model and the trace, and so the UI need not worry about
    normalizing; however, without a mapping, nothing works. The former allows for direct recording of
    the model into the trace without prior mapping. Instead, the choice of platform and
    interpretation is performed by the front-end analysis and display. These are essentially the
    counterpart to :obj:`DebuggerMappingOpinion`.
     
     
    
    The opinions are queried, each of which may produce zero or more scored offers. Depending on
    context and automation, the top offer may be chosen automatically, or the user may be prompted to
    select from a sorted list. The chosen offer is then applied. Application here means writing
    metadata to the trace database, usually as "guest platforms." The analysis and display use that
    metadata to interpret the trace data, e.g., to select a language when disassembling at the
    program counter.
    """

    class_: typing.ClassVar[java.lang.Class]
    HIGHEST_CONFIDENCE_FIRST: typing.Final[java.util.Comparator[DebuggerPlatformOffer]]

    @staticmethod
    def getArchitectureFromEnv(env: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def getDebugggerFromEnv(env: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def getEndianFromEnv(env: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.lang.Endian:
        """
        Get the endianness from the given environment
        
        :param ghidra.trace.model.target.TraceObject env: the environment object
        :param jpype.JLong or int snap: the current snap
        :return: the endianness, or null
        :rtype: ghidra.program.model.lang.Endian
        """

    @staticmethod
    def getEnvironment(object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.target.TraceObject:
        """
        Find the environment for the given object
        
        :param ghidra.trace.model.target.TraceObject object: the object, usually the user's focus
        :param jpype.JLong or int snap: the current snap
        :return: the environment object, or null
        :rtype: ghidra.trace.model.target.TraceObject
        """

    def getOffers(self, trace: ghidra.trace.model.Trace, object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int], includeOverrides: typing.Union[jpype.JBoolean, bool]) -> java.util.Set[DebuggerPlatformOffer]:
        """
        Render offers for the given object
        
        :param ghidra.trace.model.target.TraceObject object: the object, usually the one in focus
        :param jpype.JBoolean or bool includeOverrides: true to include offers with negative confidence
        :return: zero or more offers to interpret the target according to a platform
        :rtype: java.util.Set[DebuggerPlatformOffer]
        """

    @staticmethod
    def getOperatingSystemFromEnv(env: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def getStringAttribute(obj: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int], key: typing.Union[java.lang.String, str]) -> str:
        ...

    @staticmethod
    def queryOpinions(trace: ghidra.trace.model.Trace, object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int], includeOverrides: typing.Union[jpype.JBoolean, bool]) -> java.util.List[DebuggerPlatformOffer]:
        """
        Query all known opinions for offers of platform interpretation
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.trace.model.target.TraceObject object: the object, usually the one in focus
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool includeOverrides: true to include offers with negative confidence
        :return: the list of offers ordered highest confidence first
        :rtype: java.util.List[DebuggerPlatformOffer]
        """


class AbstractDebuggerPlatformMapper(ghidra.debug.api.platform.DebuggerPlatformMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace):
        ...


class DebuggerPlatformOffer(java.lang.Object):
    """
    An offer to map from a trace to a Ghidra langauge / compiler
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        """
        Get the compiler to which this offer can map
        
        :return: the compiler spec
        :rtype: ghidra.program.model.lang.CompilerSpec
        """

    @typing.overload
    def getCompilerSpec(self, langID: ghidra.program.model.lang.LanguageID, cSpecID: ghidra.program.model.lang.CompilerSpecID) -> ghidra.program.model.lang.CompilerSpec:
        """
        Load a compiler spec from the language service given the language and cspec IDs
        
        :param ghidra.program.model.lang.LanguageID langID: the langauge ID
        :param ghidra.program.model.lang.CompilerSpecID cSpecID: the compiler spec ID
        :return: the compiler spec
        :rtype: ghidra.program.model.lang.CompilerSpec
        :raises AssertionError: if either the language or the compiler spec is not found
        """

    def getCompilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID:
        """
        Get the compiler spec ID to which this offer can map
        
        :return: the language ID
        :rtype: ghidra.program.model.lang.CompilerSpecID
        """

    def getConfidence(self) -> int:
        """
        Get the confidence of this offer.
         
         
        
        Offers with numerically higher confidence are preferred. Negative confidence values are
        considered "manual overrides," and so are never selected automatically and are hidden from
        prompts by default.
         
         
        
        TODO: Spec out some standard numbers. Maybe an enum?
        
        :return: the confidence
        :rtype: int
        """

    def getDescription(self) -> str:
        """
        Get a human-readable description of the offer.
         
         
        
        Generally, more detailed descriptions imply a higher confidence.
        
        :return: the description
        :rtype: str
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language to which this offer can map
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        """
        Get the language ID to which this offer can map
        
        :return: the language ID
        :rtype: ghidra.program.model.lang.LanguageID
        """

    def isCreatorOf(self, mapper: ghidra.debug.api.platform.DebuggerPlatformMapper) -> bool:
        """
        Check if this or an equivalent offer was the creator of the given mapper
        
        :param ghidra.debug.api.platform.DebuggerPlatformMapper mapper: the mapper
        :return: true if this offer could be the mapper's creator
        :rtype: bool
        """

    def isOverride(self) -> bool:
        """
        Check if the confidence indicates this offer is a manual override.
        
        :return: true if the confidence is negative
        :rtype: bool
        """

    def take(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        """
        Get the mapper, which implements this offer
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        :param ghidra.trace.model.Trace trace: the trace the trace to be mapped
        :return: the mapper
        :rtype: ghidra.debug.api.platform.DebuggerPlatformMapper
        """

    @property
    def confidence(self) -> jpype.JInt:
        ...

    @property
    def languageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def compilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def override(self) -> jpype.JBoolean:
        ...

    @property
    def creatorOf(self) -> jpype.JBoolean:
        ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...


class DefaultDebuggerPlatformMapper(AbstractDebuggerPlatformMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
        ...


class HostDebuggerPlatformOpinion(DebuggerPlatformOpinion):
    """
    An opinion which just uses the trace's "host" platform, i.e., because the target created the
    trace with the correct host language. Other mappers assume the trace language is DATA, and that
    the real language must be mapped as a guest platform.
    """

    @typing.type_check_only
    class HostDebuggerPlatformMapper(AbstractDebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace):
            ...


    @typing.type_check_only
    class Offers(java.lang.Enum[HostDebuggerPlatformOpinion.Offers], DebuggerPlatformOffer):

        class_: typing.ClassVar[java.lang.Class]
        HOST_UNKNOWN: typing.Final[HostDebuggerPlatformOpinion.Offers]
        """
        The host platform when the back-end defaulted to DATA
        """

        HOST_KNOWN: typing.Final[HostDebuggerPlatformOpinion.Offers]
        """
        The host platform when the back-end chose the language and compiler
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> HostDebuggerPlatformOpinion.Offers:
            ...

        @staticmethod
        def values() -> jpype.JArray[HostDebuggerPlatformOpinion.Offers]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CONFIDENCE_HOST_KNOWN: typing.Final = 10000

    def __init__(self):
        ...



__all__ = ["AbstractDebuggerPlatformOpinion", "AbstractDebuggerPlatformOffer", "DebuggerPlatformOpinion", "AbstractDebuggerPlatformMapper", "DebuggerPlatformOffer", "DefaultDebuggerPlatformMapper", "HostDebuggerPlatformOpinion"]
