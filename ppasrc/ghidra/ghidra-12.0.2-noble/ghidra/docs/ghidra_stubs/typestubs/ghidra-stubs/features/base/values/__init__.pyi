from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.values
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class GhidraValuesMap(docking.widgets.values.GValuesMap):
    """
    Extends GValuesMap to add Ghidra specific types such as Address and Program
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def defineAddress(self, name: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> AddressValue:
        """
        Defines a value of type :obj:`Address` with no default value.
        
        :param java.lang.String or str name: the name for this value
        :param ghidra.program.model.listing.Program program: the program used to get an :obj:`AddressFactory` for parsing addresses
        :return: the new AddressValue that was defined.
        :rtype: AddressValue
        """

    @typing.overload
    def defineAddress(self, name: typing.Union[java.lang.String, str], defaultValue: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> AddressValue:
        """
        Defines a value of type :obj:`Address`
        
        :param java.lang.String or str name: the name for this value
        :param ghidra.program.model.address.Address defaultValue: an option default value
        :param ghidra.program.model.listing.Program program: the program used to get an :obj:`AddressFactory` for parsing addresses
        :return: the new AddressValue that was defined.
        :rtype: AddressValue
        """

    @typing.overload
    def defineAddress(self, name: typing.Union[java.lang.String, str], defaultValue: ghidra.program.model.address.Address, factory: ghidra.program.model.address.AddressFactory) -> AddressValue:
        """
        Defines a value of type :obj:`Address`
        
        :param java.lang.String or str name: the name for this value
        :param ghidra.program.model.address.Address defaultValue: an option default value
        :param ghidra.program.model.address.AddressFactory factory: the :obj:`AddressFactory` used to parse addresses
        :return: the new AddressValue that was defined.
        :rtype: AddressValue
        """

    def defineLanguage(self, name: typing.Union[java.lang.String, str], defaultValue: ghidra.program.model.lang.LanguageCompilerSpecPair) -> LanguageValue:
        """
        Defines a value of type LanguageCompilerSpecPair (folders in a Ghidra project).
        
        :param java.lang.String or str name: the name for this value
        :param ghidra.program.model.lang.LanguageCompilerSpecPair defaultValue: the initial value (can be null)
        :return: the new ProjectFolderValue that was defined
        :rtype: LanguageValue
        """

    @typing.overload
    def defineProgram(self, name: typing.Union[java.lang.String, str]) -> ProgramFileValue:
        """
        Defines a value of type Program file.
        
        :param java.lang.String or str name: the name for this value
        :return: the new ProgramFileValue defined
        :rtype: ProgramFileValue
        """

    @typing.overload
    def defineProgram(self, name: typing.Union[java.lang.String, str], startPath: typing.Union[java.lang.String, str]) -> ProgramFileValue:
        """
        Defines a value of type Program file.
        
        :param java.lang.String or str name: the name for this value
        :param java.lang.String or str startPath: the starting folder to display when picking programs from the chooser
        :return: the new ProgramFileValue that was defined
        :rtype: ProgramFileValue
        """

    @typing.overload
    def defineProjectFile(self, name: typing.Union[java.lang.String, str]) -> ProjectFileValue:
        """
        Defines a value of type DomainFile (files in a Ghidra project).
        
        :param java.lang.String or str name: the name for this value
        :return: the new ProjectFileValue that was defined
        :rtype: ProjectFileValue
        """

    @typing.overload
    def defineProjectFile(self, name: typing.Union[java.lang.String, str], startingPath: typing.Union[java.lang.String, str]) -> ProjectFileValue:
        """
        Defines a value of type DomainFile (files in a Ghidra project).
        
        :param java.lang.String or str name: the name for this value
        :param java.lang.String or str startingPath: the initial folder path for the chooser widget
        :return: the new ProjectFileValue that was defined
        :rtype: ProjectFileValue
        """

    @typing.overload
    def defineProjectFolder(self, name: typing.Union[java.lang.String, str]) -> ProjectFolderValue:
        """
        Defines a value of type DomainFolder (folders in a Ghidra project).
        
        :param java.lang.String or str name: the name for this value
        :return: the new ProjectFolderValue that was defined
        :rtype: ProjectFolderValue
        """

    @typing.overload
    def defineProjectFolder(self, name: typing.Union[java.lang.String, str], defaultValuePath: typing.Union[java.lang.String, str]) -> ProjectFolderValue:
        """
        Defines a value of type DomainFolder (files in a Ghidra project).
        
        :param java.lang.String or str name: the name for this value
        :param java.lang.String or str defaultValuePath: the path for the initial value (can be null)
        :return: the new ProjectFolderValue that was defined
        :rtype: ProjectFolderValue
        """

    def getAddress(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Gets the :obj:`Address` value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined Address value
        :return: the Address
        :rtype: ghidra.program.model.address.Address
        :raises IllegalArgumentException: if the name hasn't been defined as an Address type
        """

    def getLanguage(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Gets the Language (:obj:`LanguageCompilerSpecPair`) value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined language value
        :return: the language value
        :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
        :raises IllegalArgumentException: if the name hasn't been defined as a language type
        """

    def getProgram(self, name: typing.Union[java.lang.String, str], consumer: java.lang.Object, tool: docking.Tool, upgradeIfNeeded: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Program:
        """
        Gets (opens) the :obj:`Program` value for the given name. If the program is already open,
        then the consumer will be added to the program. The caller of this method is responsible
        for calling :meth:`Program.release(Object) <Program.release>` with the same consumer when it is done using this
        program. Program are only closed after all consumers are released. If multiple calls
        are made to this method, then the consumer will be added multiple times and must be released
        multiple times.
         
        
        The consumer can be any object, but since the consumer's purpose is to keep the program open 
        while some object is using it, the object itself is typically passed in as
        the consumer. For example, when used in a script, passing in the java keyword "this" as the
        consumer will make the script itself the consumer.
        
        :param java.lang.String or str name: the name of a previously defined program value
        :param java.lang.Object consumer: the consumer to be used to open the program
        :param docking.Tool tool: if non-null, the program will also be opened in the given tool. Note: the
        program will only be added to the tool once even if this method is called multiple times.
        :param jpype.JBoolean or bool upgradeIfNeeded: if true, program will be upgraded if needed and possible. If false,
        the program will only be upgraded after first prompting the user. In headless mode, it will
        attempt to upgrade only if the parameter is true.
        :return: an opened program with the given consumer for the selected domain file or null if
        no program was selected.
        :rtype: ghidra.program.model.listing.Program
        :raises VersionException: if the Program is out-of-date from the version of GHIDRA and an 
        upgrade was not been performed. In non-headless mode, the user will have already been
        notified via a popup dialog.
        current Ghidra Program version.
        :raises IOException: if there is an error accessing the Program's DomainObject
        :raises CancelledException: if the operation is cancelled
        :raises IllegalArgumentException: if the name hasn't been defined as a project folder type
        """

    def getProjectFile(self, name: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Gets the project file (:obj:`DomainFile`) value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined project file value
        :return: the project file value
        :rtype: ghidra.framework.model.DomainFile
        :raises IllegalArgumentException: if the name hasn't been defined as a project file type
        """

    def getProjectFolder(self, name: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFolder:
        """
        Gets the project folder (:obj:`DomainFolder`) value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined project folder value
        :return: the project folder value
        :rtype: ghidra.framework.model.DomainFolder
        :raises IllegalArgumentException: if the name hasn't been defined as a project folder type
        """

    def setAddress(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address):
        """
        Sets the address value for the given name.
        
        :param java.lang.String or str name: the name of the Address value that was previously defined
        :param ghidra.program.model.address.Address address: the address to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as an Address type
        """

    def setLanguage(self, name: typing.Union[java.lang.String, str], value: ghidra.program.model.lang.LanguageCompilerSpecPair):
        """
        Sets the Language (:obj:`LanguageCompilerSpecPair`) value for the given name.
        
        :param java.lang.String or str name: the name of the Language value that was previously defined
        :param ghidra.program.model.lang.LanguageCompilerSpecPair value: the Language to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a Language type
        """

    def setProgram(self, name: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program):
        """
        Sets the :obj:`Program` value for the given name.
        
        :param java.lang.String or str name: the name of the Program value that was previously defined
        :param ghidra.program.model.listing.Program program: the Program to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a Program type
        """

    def setProjectFile(self, name: typing.Union[java.lang.String, str], file: ghidra.framework.model.DomainFile):
        """
        Sets the project file :obj:`DomainFile` value for the given name.
        
        :param java.lang.String or str name: the name of the project file value that was previously defined
        :param ghidra.framework.model.DomainFile file: the project file to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a project file type
        """

    def setProjectFolder(self, name: typing.Union[java.lang.String, str], folder: ghidra.framework.model.DomainFolder):
        """
        Sets the project folder :obj:`DomainFolder` value for the given name.
        
        :param java.lang.String or str name: the name of the project folder value that was previously defined
        :param ghidra.framework.model.DomainFolder folder: the project folder to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a project folder type
        """

    def setTaskMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Sets a task monitor to be used when opening programs. Otherwise, :obj:`TaskMonitor.DUMMY` is
        used.
        
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor to use for opening programs
        """

    @property
    def projectFile(self) -> ghidra.framework.model.DomainFile:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    @property
    def projectFolder(self) -> ghidra.framework.model.DomainFolder:
        ...


class AddressValue(docking.widgets.values.AbstractValue[ghidra.program.model.address.Address]):
    """
    Value class for :obj:`Address` types. In order to parse and create Address types, an 
    :obj:`AddressFactory` is required when defining this type. As a convenience, it can
    be constructed with a :obj:`Program`, in which case it will use the AddressFactory from 
    that program.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program):
        """
        Creates an AddressValue with an optional default value and uses the :obj:`AddressFactory` 
        from the given program.
        
        :param java.lang.String or str name: the name of this value
        :param ghidra.program.model.address.Address defaultValue: an optional default value
        :param ghidra.program.model.listing.Program program: the program whose AddressFactory will be used to create Addresses.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: ghidra.program.model.address.Address, factory: ghidra.program.model.address.AddressFactory):
        """
        Creates an AddressValue with an optional default value.
        
        :param java.lang.String or str name: the name of this value
        :param ghidra.program.model.address.Address defaultValue: an optional default value
        :param ghidra.program.model.address.AddressFactory factory: the AddressFactory that will be used to create Addresses.
        """


class ProgramFileValue(ProjectFileValue):
    """
    Value class for :obj:`Program` files. The editor component consists of the :obj:`JTextField` 
    and a browse button for bringing up a :obj:`DataTreeDialog` for picking programs from the 
    current project. This class also provides a convenience method for opening a program.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor for creating a new ProgramFileValue with the given name.
        
        :param java.lang.String or str name: the name of the value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], startingPath: typing.Union[java.lang.String, str]):
        """
        Constructor for creating a new ProgramFileValue with the given name and a starting
        folder when using the project file chooser.
        
        :param java.lang.String or str name: the name of the value
        :param java.lang.String or str startingPath: the path to a starting folder
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], project: ghidra.framework.model.Project, startingPath: typing.Union[java.lang.String, str]):
        """
        Constructor for ProgramValue when wanting to pick from a different project than the
        active project, such as a read-only project.
        
        :param java.lang.String or str name: the name of the value
        :param ghidra.framework.model.Project project: The project from which to pick a project.
        :param java.lang.String or str startingPath: the path to a starting folder (Can also be a path to program)
        """

    def openProgram(self, consumer: java.lang.Object, tool: docking.Tool, upgradeIfNeeded: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Program:
        """
        Convenience method for opening the program for the current program file value. If the program
        is already open, then the consumer will be added to the program. The caller of this method is
        responsible for calling :meth:`Program.release(Object) <Program.release>` with the same consumer when it is
        done using this program. Program are only closed after all consumers are released. If
        multiple calls are made to this method, then the consumer will be added multiple times
        and must be released multiple times.
         
        
        The consumer can be any object, but since the consumer's purpose is to keep the program open 
        while some object is using it, the object itself is typically passed in as
        the consumer. For example, when used in a script, passing in the java keyword "this" as the
        consumer will make the script itself the consumer.
        
        :param java.lang.Object consumer: the consumer to be used to open the program
        :param docking.Tool tool: optional tool that if non-null, the program will also be opened in the tool
        :param jpype.JBoolean or bool upgradeIfNeeded: if true, program will be upgraded if needed and possible. If false,
        the program will only be upgraded after first prompting the user. In headless mode, it will
        attempt to upgrade only if the parameter is true.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for cancelling the open program.
        :return: a program for the currently selected program file. If no file chosen, returns null
        :rtype: ghidra.program.model.listing.Program
        :raises VersionException: if the Program is out-of-date from the version of GHIDRA and an 
        upgrade was not been performed. In non-headless mode, the user will have already been
        notified via a popup dialog.
        current Ghidra Program version.
        :raises IOException: if there is an error accessing the Program's DomainObject
        :raises CancelledException: if the operation is cancelled
        """


class ProjectFolderValue(docking.widgets.values.AbstractValue[ghidra.framework.model.DomainFolder]):
    """
    Value class for project folders (:obj:`DomainFile`). The editor component consists of the
    :obj:`JTextField` and a browse button for bringing up a :obj:`DataTreeDialog` for picking
    project folders from the current project.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    @typing.type_check_only
    class ProjectFolderBrowserPanel(AbstractProjectBrowserPanel):
        """
        Component used by ProjectFolderValues for picking project folders
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor for ProjectFolderValues with the given name.
        
        :param java.lang.String or str name: the name of the value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValuePath: typing.Union[java.lang.String, str]):
        """
        Constructor for creating a new ProjectFolderValue with the given name and a path
        for a default folder value.
        
        :param java.lang.String or str name: the name of the value
        :param java.lang.String or str defaultValuePath: the path for a default folder value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], project: ghidra.framework.model.Project, defaultValuePath: typing.Union[java.lang.String, str]):
        """
        Constructor for creating ProjectFolderValues for projects other than the active project.
        
        :param java.lang.String or str name: the name of the value
        :param ghidra.framework.model.Project project: the project to find a folder from
        :param java.lang.String or str defaultValuePath: the path of a default folder value
        """


class LanguageValue(docking.widgets.values.AbstractValue[ghidra.program.model.lang.LanguageCompilerSpecPair]):
    """
    Value class for LanguageCompilerSpecPair types. The component for this class is a 
    TextField with a browse button for bringing up a language/compiler chooser. It supports
    the concept of no value when the text field is empty. If it is not empty, the contents
    must be one of the known valid language/compiler spec pairs.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    @typing.type_check_only
    class LangaugeValuePanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...

        def getFile(self) -> java.io.File:
            ...

        def getLanguage(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
            ...

        def setLanguage(self, value: ghidra.program.model.lang.LanguageCompilerSpecPair):
            ...

        def setText(self, val: typing.Union[java.lang.String, str]):
            ...

        @property
        def file(self) -> java.io.File:
            ...

        @property
        def language(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
            ...

        @language.setter
        def language(self, value: ghidra.program.model.lang.LanguageCompilerSpecPair):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Construct a new LanguageVlue with no value
        
        :param java.lang.String or str name: the name of the value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: ghidra.program.model.lang.LanguageCompilerSpecPair):
        """
        Construct a new LanguageVlue with a given optional default value.
        
        :param java.lang.String or str name: the name of the value
        :param ghidra.program.model.lang.LanguageCompilerSpecPair defaultValue: the optional default value
        """

    def parseLanguageCompileSpecPair(self, languageString: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Parses a LanguageCompilerSpecPair from a string.
        
        :param java.lang.String or str languageString: The string to parse.
        :return: The LanguageCompilerSpecPair parsed from a string or null if the string does
        not parse to a known language-compiler pair.
        :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
        :raises ValuesMapParseException: if the value can't be parsed into a LanguageComilerSpecPair
        """


@typing.type_check_only
class AbstractProjectBrowserPanel(javax.swing.JPanel):
    """
    Base class for either project file chooser or project folder chooser
    """

    class_: typing.ClassVar[java.lang.Class]


class ProjectFileValue(docking.widgets.values.AbstractValue[ghidra.framework.model.DomainFile]):
    """
    Value class for project files (:obj:`DomainFile`). The editor component consists of a
    :obj:`JTextField` and a browse button for bringing up a :obj:`DataTreeDialog` for picking
    project files from the current project.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    @typing.type_check_only
    class ProjectFileBrowserPanel(AbstractProjectBrowserPanel):
        """
        Component used by ProjectFileValues for picking project files
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor for creating a new ProjectFileValue with the given name.
        
        :param java.lang.String or str name: the name of the value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], projectFileClass: java.lang.Class[ghidra.framework.model.DomainObject]):
        """
        Constructor for creating a new ProgramFileValue with the given name and :obj:`DomainObject`
        class to filter on (All other types will be filtered out in the chooser).
        
        :param java.lang.String or str name: the name of the value
        :param java.lang.Class[ghidra.framework.model.DomainObject] projectFileClass: the DomainObject class to filter
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], startingPath: typing.Union[java.lang.String, str]):
        """
        Constructor for creating a new ProjectFileValue with the given name and a starting
        folder when using the project file chooser.
        
        :param java.lang.String or str name: the name of the value
        :param java.lang.String or str startingPath: the path to a starting folder
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], project: ghidra.framework.model.Project, startingPath: typing.Union[java.lang.String, str], projectFileClass: java.lang.Class[ghidra.framework.model.DomainObject]):
        """
        Constructor for ProgramValue when wanting to pick from a different project than the
        active project, such as a read-only project.
        
        :param java.lang.String or str name: the name of the value
        :param ghidra.framework.model.Project project: The project from which to pick a project.
        :param java.lang.String or str startingPath: the path to a starting folder (Can also be a path to program)
        :param java.lang.Class[ghidra.framework.model.DomainObject] projectFileClass: a :obj:`DomainFile` class to filter on. (Only those types
        will appear in the chooser)
        """



__all__ = ["GhidraValuesMap", "AddressValue", "ProgramFileValue", "ProjectFolderValue", "LanguageValue", "AbstractProjectBrowserPanel", "ProjectFileValue"]
