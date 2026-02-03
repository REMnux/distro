from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.script
import ghidra.app.util.headless
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.framework.project
import ghidra.pyghidra.interpreter
import ghidra.util.task
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.apache.commons.lang3.function # type: ignore


class PyGhidraTaskMonitor(ghidra.util.task.TaskMonitor):
    """
    A :obj:`TaskMonitor` for use by PyGhidra, which features a cancellation timer and a change 
    callback mechanism
    """

    @typing.type_check_only
    class PyGhidraTimeOutTask(java.util.TimerTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, timeoutSecs: typing.Union[java.lang.Integer, int], changeCallback: org.apache.commons.lang3.function.TriConsumer[java.lang.String, java.lang.Long, java.lang.Long]):
        """
        Creates a new :obj:`PyGhidraTaskMonitor`
        
        :param java.lang.Integer or int timeoutSecs: The number of seconds before a cancellation timeout is triggered, or
        ``null`` for no timeout
        :param org.apache.commons.lang3.function.TriConsumer[java.lang.String, java.lang.Long, java.lang.Long] changeCallback: A function that gets called any time a change to the monitor occurred,
        or ``null`` for no callback
        """


class PyGhidraProject(ghidra.framework.project.DefaultProject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, projectManager: PyGhidraProjectManager, projectData: ghidra.framework.model.ProjectData):
        ...


class PyGhidraScriptProvider(ghidra.app.script.AbstractPythonScriptProvider):
    """
    :obj:`GhidraScript` provider for native python3 scripts
    """

    @typing.type_check_only
    class PyGhidraGhidraScript(ghidra.app.script.GhidraScript, PythonFieldExposer):

        @typing.type_check_only
        class ExposedField(PythonFieldExposer.ExposedField):
            """
            Helper inner class that can create a :obj:`java.lang.invoke.MethodHandles.Lookup`
            that can access the protected fields of the :obj:`GhidraScript`
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, name: typing.Union[java.lang.String, str], type: java.lang.Class[typing.Any]):
                ...


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PyGhidraHeadlessScript(ghidra.app.util.headless.HeadlessScript, PythonFieldExposer):

        @typing.type_check_only
        class ExposedField(PythonFieldExposer.ExposedField):
            """
            Helper inner class that can create a :obj:`java.lang.invoke.MethodHandles.Lookup`
            that can access the protected fields of the :obj:`GhidraScript`
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, name: typing.Union[java.lang.String, str], type: java.lang.Class[typing.Any]):
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def setScriptRunner(scriptRunner: java.util.function.Consumer[ghidra.app.script.GhidraScript]):
        """
        Sets the Python side script runner.
         
        This method is for **internal use only** and is only public so it can be
        called from Python.
        
        :param java.util.function.Consumer[ghidra.app.script.GhidraScript] scriptRunner: the Python side script runner
        :raises AssertException: if the script runner has already been set
        """


class PyGhidraPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    This plugin provides the interactive Python interpreter.
    """

    class_: typing.ClassVar[java.lang.Class]
    TITLE: typing.Final = "PyGhidra"
    script: typing.Final[ghidra.pyghidra.interpreter.InterpreterGhidraScript]
    interpreter: ghidra.pyghidra.interpreter.PyGhidraInterpreter

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def setInitializer(initializer: java.util.function.Consumer[PyGhidraPlugin]):
        """
        Sets the plugin's Python side initializer.
        
         
        This method is for **internal use only** and is only public so it can be
        called from Python.
        
        :param java.util.function.Consumer[PyGhidraPlugin] initializer: the Python side initializer
        :raises AssertException: if the code completer has already been set
        """


class PythonFieldExposer(java.lang.Object):
    """
    A marker interface to apply Jpype class customizations to a class.
     
    The Jpype class customizations will create Python properties which can access protected fields.
     
    This interface is for **internal use only** and is only public so it can be
    visible to Python to apply the Jpype class customizations.
    """

    class ExposedFields(java.lang.annotation.Annotation):
        """
        An annotation for exposing protected fields of a class to Python
        """

        class_: typing.ClassVar[java.lang.Class]

        def exposer(self) -> java.lang.Class[PythonFieldExposer.ExposedField]:
            """
            
            
            :return: the :obj:`ExposedField` subclass with access to the protected fields
            :rtype: java.lang.Class[PythonFieldExposer.ExposedField]
            """

        def names(self) -> jpype.JArray[java.lang.String]:
            """
            
            
            :return: the names of the protected fields to be exposed
            :rtype: jpype.JArray[java.lang.String]
            """

        def types(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
            """
            
            
            :return: the types of the protected fields to be exposed
            :rtype: jpype.JArray[java.lang.Class[typing.Any]]
            """


    class ExposedField(java.lang.Object):
        """
        Base class for making a protected field accessible from Python.
         
        Child classes are to be defined inside the class containing the fields to be exposed.
        The only requirement of the child class is to provide a :obj:`Lookup` with access
        to the protected fields, to the :obj:`ExposedField` constructor as shown below.
         
        .. code-block:: java
            :dedent: 4
        
            public class ExampleClass implements PythonFieldExposer {
                protected int counter = 0;
             
                private static class ExposedField extends PythonFieldExposer.ExposedField {
                    public ExposedField(String name, Class<?> type) {
                        super(MethodHandles.lookup().in(ExampleClass.class), name, type);
                    }
                }
            }
        """

        class_: typing.ClassVar[java.lang.Class]

        def fget(self, self_: java.lang.Object) -> java.lang.Object:
            """
            Gets the field value
            
            :param java.lang.Object self: the instance containing the field
            :return: the field value
            :rtype: java.lang.Object
            """

        def fset(self, self_: java.lang.Object, value: java.lang.Object):
            """
            Sets the field value
            
            :param java.lang.Object self: the instance containing the field
            :param java.lang.Object value: the field value
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getProperties(cls: java.lang.Class[PythonFieldExposer]) -> java.util.Map[java.lang.String, PythonFieldExposer.ExposedField]:
        """
        Gets a mapping of all the explicitly exposed fields of a class.
         
        This method is for **internal use only** and is only public so it can be
        called from Python.
        
        :param java.lang.Class[PythonFieldExposer] cls: the PythonFieldExposer class
        :return: a map of the exposed fields
        :rtype: java.util.Map[java.lang.String, PythonFieldExposer.ExposedField]
        """


class PyGhidraProjectManager(ghidra.framework.project.DefaultProjectManager):
    """
    A :obj:`DefaultProjectManager` for use by PyGhidra
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["PyGhidraTaskMonitor", "PyGhidraProject", "PyGhidraScriptProvider", "PyGhidraPlugin", "PythonFieldExposer", "PyGhidraProjectManager"]
