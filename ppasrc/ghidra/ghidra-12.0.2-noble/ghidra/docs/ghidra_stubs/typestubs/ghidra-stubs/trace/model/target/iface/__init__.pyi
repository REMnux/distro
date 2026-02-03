from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.trace.model.target
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.stream # type: ignore


T = typing.TypeVar("T")


class TraceActivatable(TraceObjectInterface):
    """
    An object which can be activated
     
     
    
    Activation generally means to become the active, selected or focused object. Subsequent commands
    to the debugger implicitly apply to this object. For example, if a user activates a thread, then
    subsequent register read/write commands ought to affect the active thread's context.
     
     
    
    This interface is only used by RMI targets. The back end must register a suitable method so that
    the front end can notify it when the user has activated this object. Generally, a user activates
    the object by double-clicking it in the appropriate table or tree. If it is *not* marked
    with this interface, the UI will ignore the action. If it is, the UI will mark it the active
    object and invoke the appropriate target method. If this interface is present, but a suitable
    method is not, an error is logged upon attempted activation.
     
     
    
    We cannot just use the presence or absence of a suitable activation method as a proxy for this
    interface, because the registry is only available when the back end is alive.
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceTogglable(TraceObjectInterface):
    """
    An object which can be toggled
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_ENABLED: typing.Final = "_enabled"


class TraceEventScope(TraceObjectInterface):
    """
    An object that can emit events affecting itself and its successors
     
     
    
    If this is present, it must be on the root object.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_EVENT_THREAD: typing.Final = "_event_thread"
    KEY_TIME_SUPPORT: typing.Final = "_time_support"
    """
    See :obj:`ScheduleForm`
    """



class TraceExecutionStateful(TraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]
    KEY_STATE: typing.Final = "_state"


class TraceFocusScope(TraceObjectInterface):
    """
    An object having a designated "focus"
     
     
    
    Focus is usually communicated via various UI hints, but also semantically implies that actions
    taken within this scope apply to the focused object. The least confusing option is to implement
    this at the root, but that need not always be the case.
     
     
    
    If this is present, it must be on the root object.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_FOCUS: typing.Final = "_focus"


class TraceMethod(TraceObjectInterface):
    """
    An object which can be invoked as a method
     
     
    
    TODO: Should parameters and return type be something incorporated into Schemas?
     
     
    
    NOTE: We might keep this around a bit longer, since some connectors may like to reflect an object
    model that presents methods in the tree. The connector will need to provide the means of
    invocation, and that may become better integrated into the UI, but at least for now, being able
    to show and hide them is important, so we at least need a named interface for them.
    """

    class Value(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> T:
            ...


    class BoolValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.lang.Boolean]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.BoolValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.BoolValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> bool:
            ...


    class IntValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.lang.Integer]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.IntValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.IntValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> int:
            ...


    class LongValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.lang.Long]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.LongValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.LongValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> int:
            ...


    class FloatValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.lang.Float]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.FloatValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.FloatValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> float:
            ...


    class DoubleValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.lang.Double]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.DoubleValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.DoubleValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> float:
            ...


    class BytesValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[jpype.JArray[jpype.JByte]]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.BytesValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.BytesValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> jpype.JArray[jpype.JByte]:
            ...


    class StringValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.lang.String]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.StringValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.StringValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> str:
            ...


    class StringsValue(java.lang.annotation.Annotation):

        class Val(java.lang.Record, TraceMethod.Value[java.util.List[java.lang.String]]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, v: TraceMethod.StringsValue):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def toString(self) -> str:
                ...

            def v(self) -> TraceMethod.StringsValue:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def specified(self) -> bool:
            ...

        def value(self) -> jpype.JArray[java.lang.String]:
            ...


    class Param(java.lang.annotation.Annotation):

        class_: typing.ClassVar[java.lang.Class]
        DEFAULTS: typing.Final[java.util.List[java.util.function.Function[TraceMethod.Param, TraceMethod.Value[typing.Any]]]]

        def choicesString(self) -> TraceMethod.StringsValue:
            ...

        def defaultBool(self) -> TraceMethod.BoolValue:
            ...

        def defaultBytes(self) -> TraceMethod.BytesValue:
            ...

        def defaultDouble(self) -> TraceMethod.DoubleValue:
            ...

        def defaultFloat(self) -> TraceMethod.FloatValue:
            ...

        def defaultInt(self) -> TraceMethod.IntValue:
            ...

        def defaultLong(self) -> TraceMethod.LongValue:
            ...

        def defaultString(self) -> TraceMethod.StringValue:
            ...

        def description(self) -> str:
            ...

        def display(self) -> str:
            ...

        def name(self) -> str:
            ...

        def required(self) -> bool:
            ...

        def schema(self) -> str:
            ...


    class ParameterDescription(java.lang.Object, typing.Generic[T]):
        """
        A description of a method parameter
         
         
        
        TODO: Should this be incorporated into schemas?
        """

        class_: typing.ClassVar[java.lang.Class]
        type: typing.Final[java.lang.Class[T]]
        name: typing.Final[java.lang.String]
        defaultValue: typing.Final[T]
        required: typing.Final[jpype.JBoolean]
        display: typing.Final[java.lang.String]
        description: typing.Final[java.lang.String]
        schema: typing.Final[java.lang.String]
        choices: typing.Final[java.util.Set[T]]

        def adjust(self, arguments: collections.abc.Mapping, adjuster: java.util.function.Function[T, T]):
            """
            Adjust the argument for this parameter
            
            :param collections.abc.Mapping arguments: the arguments to modify
            :param java.util.function.Function[T, T] adjuster: a function of the old argument to the new argument. If the argument is
                        not currently set, the function will receive null.
            """

        @staticmethod
        def annotated(parameter: java.lang.reflect.Parameter) -> TraceMethod.ParameterDescription[typing.Any]:
            ...

        @staticmethod
        @typing.overload
        def choices(type: java.lang.Class[T], name: typing.Union[java.lang.String, str], choices: collections.abc.Sequence, display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]) -> TraceMethod.ParameterDescription[T]:
            """
            Create a parameter having enumerated choices
            
            :param T: the type of the parameter:param java.lang.Class[T] type: the class representing the type of the parameter
            :param java.lang.String or str name: the name of the parameter
            :param collections.abc.Sequence choices: the non-empty set of choices. The first is the default.
            :param java.lang.String or str display: the human-readable name of this parameter
            :param java.lang.String or str description: the human-readable description of this parameter
            :return: the new parameter description
            :rtype: TraceMethod.ParameterDescription[T]
            """

        @staticmethod
        @typing.overload
        def choices(type: java.lang.Class[T], name: typing.Union[java.lang.String, str], choices: collections.abc.Sequence, defaultValue: T, display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]) -> TraceMethod.ParameterDescription[T]:
            """
            Create a parameter having enumerated choices
            
            :param T: the type of the parameter:param java.lang.Class[T] type: the class representing the type of the parameter
            :param java.lang.String or str name: the name of the parameter
            :param collections.abc.Sequence choices: the non-empty set of choices
            :param T defaultValue: the default value of this parameter
            :param java.lang.String or str display: the human-readable name of this parameter
            :param java.lang.String or str description: the human-readable description of this parameter
            :return: the new parameter description
            :rtype: TraceMethod.ParameterDescription[T]
            """

        @staticmethod
        @typing.overload
        def create(type: java.lang.Class[T], name: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool], defaultValue: T, display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], schema: typing.Union[java.lang.String, str]) -> TraceMethod.ParameterDescription[T]:
            """
            Create a parameter
            
            :param T: the type of the parameter:param java.lang.Class[T] type: the class representing the type of the parameter
            :param java.lang.String or str name: the name of the parameter
            :param jpype.JBoolean or bool required: true if this parameter must be provided
            :param T defaultValue: the default value of this parameter
            :param java.lang.String or str display: the human-readable name of this parameter
            :param java.lang.String or str description: the human-readable description of this parameter
            :param java.lang.String or str schema: the parameter's schema
            :return: the new parameter description
            :rtype: TraceMethod.ParameterDescription[T]
            """

        @staticmethod
        @typing.overload
        def create(type: java.lang.Class[T], name: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool], defaultValue: T, display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]) -> TraceMethod.ParameterDescription[T]:
            """
            Create a parameter
            
            :param T: the type of the parameter:param java.lang.Class[T] type: the class representing the type of the parameter
            :param java.lang.String or str name: the name of the parameter
            :param jpype.JBoolean or bool required: true if this parameter must be provided
            :param T defaultValue: the default value of this parameter
            :param java.lang.String or str display: the human-readable name of this parameter
            :param java.lang.String or str description: the human-readable description of this parameter
            :return: the new parameter description
            :rtype: TraceMethod.ParameterDescription[T]
            """

        def get(self, arguments: collections.abc.Mapping) -> T:
            """
            Extract the argument for this parameter
             
             
            
            You must validate the arguments, using
            :meth:`TraceMethod.validateArguments(Map, Map, boolean) <TraceMethod.validateArguments>`, first.
            
            :param collections.abc.Mapping arguments: the validated arguments
            :return: the parameter
            :rtype: T
            """

        def set(self, arguments: collections.abc.Mapping, value: T):
            """
            Set the argument for this parameter
            
            :param collections.abc.Mapping arguments: the arguments to modify
            :param T value: the value to assign the parameter
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def makeParameters(params: java.util.stream.Stream[TraceMethod.ParameterDescription[typing.Any]]) -> java.util.Map[java.lang.String, TraceMethod.ParameterDescription[typing.Any]]:
        """
        Construct a map of parameter descriptions from a stream
        
        :param java.util.stream.Stream[TraceMethod.ParameterDescription[typing.Any]] params: the descriptions
        :return: a map of descriptions by name
        :rtype: java.util.Map[java.lang.String, TraceMethod.ParameterDescription[typing.Any]]
        """

    @staticmethod
    @typing.overload
    def makeParameters(params: collections.abc.Sequence) -> java.util.Map[java.lang.String, TraceMethod.ParameterDescription[typing.Any]]:
        """
        Construct a map of parameter descriptions from a collection
        
        :param collections.abc.Sequence params: the descriptions
        :return: a map of descriptions by name
        :rtype: java.util.Map[java.lang.String, TraceMethod.ParameterDescription[typing.Any]]
        """

    @staticmethod
    @typing.overload
    def makeParameters(*params: TraceMethod.ParameterDescription[typing.Any]) -> java.util.Map[java.lang.String, TraceMethod.ParameterDescription[typing.Any]]:
        """
        Construct a map of parameter descriptions from an array
        
        :param jpype.JArray[TraceMethod.ParameterDescription[typing.Any]] params: the descriptions
        :return: a map of descriptions by name
        :rtype: java.util.Map[java.lang.String, TraceMethod.ParameterDescription[typing.Any]]
        """

    @staticmethod
    def validateArguments(parameters: collections.abc.Mapping, arguments: collections.abc.Mapping, permitExtras: typing.Union[jpype.JBoolean, bool]) -> java.util.Map[java.lang.String, java.lang.Object]:
        """
        Validate the given arguments against the given parameters
        
        :param collections.abc.Mapping parameters: the parameter descriptions
        :param collections.abc.Mapping arguments: the arguments
        :param jpype.JBoolean or bool permitExtras: false to require every named argument has a named parameter
        :return: the map of validated arguments
        :rtype: java.util.Map[java.lang.String, java.lang.Object]
        """


class TraceObjectInterface(java.lang.Object):
    """
    A common interface for object-based implementations of other trace manager entries, e.g.,
    :obj:`TraceThread`.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_DISPLAY: typing.Final = "_display"
    KEY_SHORT_DISPLAY: typing.Final = "_short_display"
    KEY_KIND: typing.Final = "_kind"
    KEY_ORDER: typing.Final = "_order"
    KEY_MODIFIED: typing.Final = "_modified"
    KEY_TYPE: typing.Final = "_type"
    KEY_VALUE: typing.Final = "_value"
    KEY_COMMENT: typing.Final = "_comment"

    def getObject(self) -> ghidra.trace.model.target.TraceObject:
        """
        Get the object backing this implementation
        
        :return: the object
        :rtype: ghidra.trace.model.target.TraceObject
        """

    @property
    def object(self) -> ghidra.trace.model.target.TraceObject:
        ...


class TraceEnvironment(TraceObjectInterface):
    """
    Provides information about a given target object
     
     
    
    This is mostly a marker interface so that the client knows where to look for information about a
    target. This may be attached to the entire session, or it may be attached to individual targets
    in a session. The information is generally encoded as string-valued attributes. The form of the
    strings is not strictly specified. They should generally just take verbatim whatever string the
    connected debugger would use to describe the platform. It is up to the client to interpret the
    information.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_ARCH: typing.Final = "_arch"
    KEY_DEBUGGER: typing.Final = "_debugger"
    KEY_ENDIAN: typing.Final = "_endian"
    KEY_OS: typing.Final = "_os"


class TraceAggregate(TraceObjectInterface):
    """
    A marker interface which indicates its attributes represent the object as a whole
     
     
    
    Often applied to processes and sessions, this causes ancestry traversals to include this object's
    children when visited.
     
     
    
    LATER (GP-5754): This should be an attribute of the schema, not an interface.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["TraceActivatable", "TraceTogglable", "TraceEventScope", "TraceExecutionStateful", "TraceFocusScope", "TraceMethod", "TraceObjectInterface", "TraceEnvironment", "TraceAggregate"]
