"""

**************************
Ghidra Script Development.
**************************

In order to write a script:
 
1. Ghidra script must be written in Java.
2. Your script class must extend ghidra.app.script.GhidraScript.
3. You must implement the run() method. This is where you insert your
script-specific code.
4. You should create a description comment at the top of the file. Each description
line should start with"//".

 


When you create a new script using the script manager,
you will automatically receive a source code stub (as shown below).
 
// TODO write a description for this script

    public class NewScript extends GhidraScript {

        public void run() throws Exception {
            // TODO Add User Code Here
        }
    }
 
 
===================
Ghidra Script State
===================

     
    All scripts, when run, will be handed the current state in the form of class instance
    variable. These variables are:
     
    1. currentProgram: the active program
    2. currentAddress: the address of the current cursor location in the tool
    3. currentLocation: the program location of the current cursor location
    in the tool, or null if no program location exists
    4. currentSelection: the current selection in the tool, or null
    if no selection exists
    5. currentHighlight: the current highlight in the tool, or null
    if no highlight exists


 
===================
Hello World Example
===================

This example, when run, will simply print "Hello World" into the Ghidra console.
 
    public class HelloWorldScript extends GhidraScript {
        public void run() throws Exception {
            println("Hello World!");
        }
    }
 
All scripts, when run, will be handed the current state and are automatically
run in a separate thread.
 



.. seealso::

    | :obj:`ghidra.app.script.GhidraState`

    | :obj:`ghidra.program.model.listing.Program`
"""

from __future__ import annotations
import collections.abc
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.app.script
import ghidra.app.tablechooser
import ghidra.features.base.values
import ghidra.framework.cmd
import ghidra.framework.generic.auth
import ghidra.framework.model
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.program.util.string
import ghidra.util
import ghidra.util.task
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


from ghidra.app.script import *


R = typing.TypeVar("R")
T = typing.TypeVar("T")


MAX_REFERENCES_TO: typing.Final = 4096
currentProgram: ghidra.program.model.listing.Program
monitor: ghidra.util.task.TaskMonitor
sourceFile: generic.jar.ResourceFile
state: GhidraState
writer: java.io.PrintWriter
currentAddress: ghidra.program.model.address.Address
currentLocation: ghidra.program.util.ProgramLocation
currentSelection: ghidra.program.util.ProgramSelection
currentHighlight: ghidra.program.util.ProgramSelection
propertiesFileParams: GhidraScriptProperties
potentialPropertiesFileLocs: java.util.List[generic.jar.ResourceFile]


def addEntryPoint(address: ghidra.program.model.address.Address):
    """
    Adds an entry point at the specified address.
    
    :param ghidra.program.model.address.Address address: address to create entry point
    """


def addInstructionXref(from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], type: ghidra.program.model.symbol.FlowType) -> ghidra.program.model.symbol.Reference:
    """
    Adds a cross reference (XREF).
    
    :param ghidra.program.model.address.Address from: the source address of the reference
    :param ghidra.program.model.address.Address to: the destination address of the reference
    :param jpype.JInt or int opIndex: the operand index (-1 indicates the mnemonic)
    :param ghidra.program.model.symbol.FlowType type: the flow type
    :return: the newly created reference
    :rtype: ghidra.program.model.symbol.Reference
    
    .. seealso::
    
        | :obj:`ghidra.program.model.symbol.FlowType`
    
        | :obj:`ghidra.program.model.symbol.Reference`
    """


@deprecated("the method analyzeAll or analyzeChanges should be invoked.\n These separate methods were created to clarify their true behavior since many times it is\n only necessary to analyze changes and not the entire program which can take much\n longer and affect more of the program than is necessary.")
def analyze(program: ghidra.program.model.listing.Program):
    """
    Starts auto-analysis on the specified program and performs complete analysis
    of the entire program.  This is usually only necessary if full analysis was never
    performed. This method will block until analysis completes.
    
    :param ghidra.program.model.listing.Program program: the program to analyze
    
    .. deprecated::
    
    the method :obj:`.analyzeAll` or :obj:`.analyzeChanges` should be invoked.
    These separate methods were created to clarify their true behavior since many times it is
    only necessary to analyze changes and not the entire program which can take much
    longer and affect more of the program than is necessary.
    """


def analyzeAll(program: ghidra.program.model.listing.Program):
    """
    Starts auto-analysis on the specified program and performs complete analysis
    of the entire program.  This is usually only necessary if full analysis was never
    performed. This method will block until analysis completes.
    
    :param ghidra.program.model.listing.Program program: the program to analyze
    """


def analyzeChanges(program: ghidra.program.model.listing.Program):
    """
    Starts auto-analysis if not started and waits for pending analysis to complete.
    Only pending analysis on program changes is performed, including changes resulting
    from any analysis activity.  This method will block until analysis completes.
    NOTE: The auto-analysis manager will only detect program changes once it has been
    instantiated for a program (i.e, AutoAnalysisManager.getAnalysisManager(program) ).
    This is automatically done for the initial currentProgram, however, if a script is
    opening/instantiating its own programs it may be necessary to do this prior to
    making changes to the program.
    
    :param ghidra.program.model.listing.Program program: the program to analyze
    """


@typing.overload
def askAddress(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
    """
    Returns an Address, using the String parameters for guidance.  The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid Address value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    for an address value. If the same popup has been run before in the same session,
    the address input field will be pre-populated with the last-used address. If not,
    the    address input field will be pre-populated with the .properties value (if it
    exists).
    2. In the headless environment, this method returns an Address representing the
    .properties value (if it exists), or throws an Exception if there is an invalid or
    missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the
                second part of the variable name (in headless mode or when using .properties file)
    :return: the user-specified Address value
    :rtype: ghidra.program.model.address.Address
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid Address
                specified in the .properties file
    """


@typing.overload
def askAddress(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
    """
    Returns an Address, using the String parameters for guidance.  The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid Address value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    for an address value. If the same popup has been run before in the same session,
    the address input field will be pre-populated with the last-used address. If not,
    the    address input field will be pre-populated with the .properties value (if it
    exists).
    2. In the headless environment, this method returns an Address representing the
    .properties value (if it exists), or throws an Exception if there is an invalid or
    missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the
                second part of the variable name (in headless mode or when using .properties file)
    :param java.lang.String or str defaultValue: the optional default address as a String - if null is passed or an invalid
                address is given no default will be shown in dialog
    :return: the user-specified Address value
    :rtype: ghidra.program.model.address.Address
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid Address
                specified in the .properties file
    """


def askBytes(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
    """
    Returns a byte array, using the String parameters for guidance. The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents valid bytes, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the
    user for a byte pattern. If the same popup has been run before in the same session,
    the byte pattern input field will be pre-populated with    the last-used bytes string.
    If not, the byte pattern input field will be pre-populated with the .properties
    value (if it exists).
    2. In the headless environment, this method returns a byte array representing the
    .properties byte pattern value (if it exists), or throws an Exception if there is
    an invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable
                name (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the
                second part of the variable name (in headless mode or when using .properties file)
    :return: the user-specified byte array
    :rtype: jpype.JArray[jpype.JByte]
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid bytes
                string specified in the .properties file
    """


def askChoice(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], choices: java.util.List[T], defaultValue: T) -> T:
    """
    Returns an object that represents one of the choices in the given list. The actual behavior
    of the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid choice, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    to choose from the given list of objects. The pre-chosen choice will be the last
    user-chosen value (if the dialog has been run before). If that does not exist, the
    pre-chosen value is the .properties value. If that does not exist or is invalid,
    then the 'defaultValue' parameter is used (as long as it is not null).
    2. In the headless environment, this method returns an object representing the
    .properties value (if it exists and is a valid choice), or throws an Exception if
    there is an invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :param java.util.List[T] choices: set of choices (toString() value of each object will be displayed in the dialog)
    :param T defaultValue: the default value to display in the input field; may be
                        null, but must be a valid choice if non-null.
    :return: the user-selected value
    :rtype: T
    :raises CancelledException: if the user hit the 'cancel' button
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    choice
                specified in the .properties file
    """


@typing.overload
def askChoices(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], choices: java.util.List[T]) -> java.util.List[T]:
    """
    Returns an array of Objects representing one or more choices from the given list. The actual
    behavior of the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents valid choices, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a pop-up dialog that presents the user
    with checkbox choices (to allow a more flexible option where the user can pick
    some, all, or none).
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the choices to return. The method will look in the .properties file
    by searching for a property name equal to a space-separated concatenation of the
    String parameters (title + " " + message). If that property name exists and
    represents a list (one or more) of valid choice(s) in the form
    "choice1;choice2;choice3;..." (<-- note the quotes surrounding the choices), then
    an Object array of those choices is returned. Otherwise, an Exception is thrown if
    there is an invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display with the choices (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :param java.util.List[T] choices: set of choices (toString() value of each object will be displayed in the dialog)
    :return: the user-selected value(s); an empty list if no selection was made
    :rtype: java.util.List[T]
    :raises CancelledException: if the user hits the 'cancel' button
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    set of
                choices specified in the .properties file
    """


@typing.overload
def askChoices(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], choices: java.util.List[T], choiceLabels: java.util.List[java.lang.String]) -> java.util.List[T]:
    """
    Returns an array of Objects representing one or more choices from the given list. The user
    specifies the choices as Objects, also passing along a corresponding array of String
    representations for each choice (used as the checkbox label). The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents valid choices, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a pop-up dialog that presents the user
    with checkbox choices (to allow a more flexible option where the user can pick
    some, all, or none).
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the choices to return. The method will look in the .properties file
    by searching for a property name equal to a space-separated concatenation of the
    String parameters (title + " " + message). If that property name exists and
    represents a list (one or more) of valid choice(s) in the form
    "choice1;choice2;choice3;..." (<-- note the quotes surrounding the choices), then
    an Object array of those choices is returned. Otherwise, an Exception is thrown if
    there is an invalid or missing .properties value. NOTE: the choice names for
    this method must match those in the stringRepresentationOfChoices array.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display with the choices (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :param java.util.List[T] choices: set of choices
    :param java.util.List[java.lang.String] choiceLabels: the String representation for each choice, used for
                checkbox labels
    :return: the user-selected value(s); null if no selection was made
    :rtype: java.util.List[T]
    :raises CancelledException: if the user hits the 'cancel' button
    :raises IllegalArgumentException: if choices is empty; if in headless mode,
            there was a missing or invalid set of choices    specified in the .properties file
    """


def askDirectory(title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]) -> java.io.File:
    """
    Returns a directory File object, using the String parameters for guidance. The actual
    behavior of the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + approveButtonText).
    If that property name exists and its value represents a valid **absolute path** of a valid
    directory File, then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a file chooser dialog that allows the
    user to select a directory. If the file chooser dialog has been run before in the
    same session, the directory selection will be pre-populated with the last-selected
    directory. If not, the directory selection will be pre-populated with the
    .properties    value (if it exists).
    2. In the headless environment, this method returns a directory File representing
    the .properties value (if it exists), or throws an Exception if there is an invalid
    or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str approveButtonText: the approve button text (in GUI mode - typically, this would be
                "Open" or "Save") or the second part of the variable name (in headless mode or
                when using .properties file)
    :return: the selected directory or null if no tool was available
    :rtype: java.io.File
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid
                    directory name specified in the .properties file
    """


def askDomainFile(title: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
    """
    Returns a DomainFile, using the title parameter for guidance.  The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is the
    title String parameter.  If that property name exists and its value represents a valid
    domain file, then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog listing all domain files
    in the current project, allowing the user to select one.
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the name of the DomainFile to return. The method will look in the
    .properties file by searching for a property name equal to the 'title' parameter. If
    that property name exists and its value represents a valid DomainFile in the project,
    then that value is returned. Otherwise, an Exception is thrown if there is an invalid
    or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the pop-up dialog (in GUI mode) or the variable name (in headless
            mode or when using .properties file)
    :return: the user-selected domain file
    :rtype: ghidra.framework.model.DomainFile
    :raises CancelledException: if the operation is cancelled
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    domain
                file specified in the .properties file
    """


def askDouble(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> float:
    """
    Returns a double, using the String parameters for guidance. The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid double value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
        for a double value. If the same popup has been run before in the same session, the
        double input field will be pre-populated with the last-used double. If not, the
        double input field will be pre-populated with the .properties value (if it exists).
    
    2. In the headless environment, this method returns a double value representing the
    .properties value (if it exists), or throws an Exception if there is an    invalid or
    missing .properties value.
    
     
    
    Note that in both headless and GUI modes, you may specify "PI" or "E" and get the
    corresponding floating point value to 15 decimal places.
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :return: the user-specified double value
    :rtype: float
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or    invalid double
                specified in the .properties file
    """


def askFile(title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]) -> java.io.File:
    """
    Returns a File object, using the String parameters for guidance.  The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + approveButtonText).
    If that property name exists and its value represents a valid **absolute path** of a valid
    File, then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a file chooser dialog that allows the
        user to select a file. If the file chooser dialog has been run before in the same
        session, the File selection will be pre-populated with the last-selected file. If
        not, the File selection will be pre-populated with the .properties value (if it
        exists).
    
    2. In the headless environment, this method returns a File object representing    the
        .properties    String value, or throws an Exception if there is an invalid or missing
        .properties value.
    
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using using .properties file)
    :param java.lang.String or str approveButtonText: the approve button text (in GUI mode - typically, this would
                be "Open" or "Save") or the second part of the variable name (in headless mode
                or when using .properties file)
    :return: the selected file or null if no tool was available
    :rtype: java.io.File
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid file
                name specified in the .properties file
    """


def askInt(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
    """
    Returns an int, using the String parameters for guidance.  The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid int value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
        for an int value. If the same popup has been run before in the same session, the int
        input field will be pre-populated with the last-used int. If not, the int input
        field will be pre-populated with the .properties value (if it exists).
    
    2. In the headless environment, this method returns an int value representing the
        .properties value (if it exists), or throws an Exception if there is an invalid
        or missing .properties value.
    
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :return: the user-specified int value
    :rtype: int
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid int
                specified in the .properties file
    """


def askLanguage(title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
    """
    Returns a LanguageCompilerSpecPair, using the String parameters for guidance. The actual
    behavior of the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid LanguageCompilerSpecPair value,
    then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a language table dialog and returns
    the selected language. If the same popup has been run before in the same session,
    the last-used language will be pre-selected. If not, the language specified in the
    .properties file will be pre-selected (if it exists).
    2. In the headless environment, this method returns a LanguageCompilerSpecPair
    representing the .properties value (if it exists), or throws an Exception if there
    is an invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str approveButtonText: the approve button text (in GUI mode - typically, this would be
                "Open" or "Save") or the second part of the variable name (in headless mode or
                when using .properties file)
    :return: the selected LanguageCompilerSpecPair
    :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
    :raises CancelledException: if the user hit the 'cancel' button
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    language
                specified in the .properties file
    """


def askLong(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
    """
    Returns a long, using the String parameters for guidance.  The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid long value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
        for a long value. If the same popup has been run before in the same session, the
        long input field will be pre-populated with the last-used long. If not, the long
        input field will be pre-populated with the .properties value (if it exists).
    
    2. In the headless environment, this method returns a long value representing the
    .properties value (if it exists), or throws an Exception if there is an invalid or
    missing .properties    value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                part of the    variable name (in headless mode or when using .properties file)
    :return: the user-specified long value
    :rtype: int
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    long
                specified in the .properties file
    """


def askPassword(title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str]) -> ghidra.framework.generic.auth.Password:
    """
    Returns a :obj:`Password`, using the String input parameters for guidance. This method can
    only be used in headed mode.
     
    
    In the GUI environment, this method displays a password popup dialog that prompts the user
    for a password. There is no pre-population of the input. If the user cancels the dialog, it
    is immediately disposed, and any input to that dialog is cleared from memory. If the user
    completes the dialog, then the password is returned in a wrapped buffer. The buffer can be
    cleared by calling :meth:`Password.close() <Password.close>`; however, it is meant to be used in a
    ``try-with-resources`` block. The pattern does not guarantee protection of the password,
    but it will help you avoid some typical pitfalls:
    
     
    String user = askString("Login", "Username:");
    Project project;
    try (Password password = askPassword("Login", "Password:")) {
        project = doLoginAndOpenProject(user, password.getPasswordChars());
    }
     
    
    The buffer will be zero-filled upon leaving the ``try-with-resources`` block. If, in the
    sample, the ``doLoginAndOpenProject`` method or any part of its implementation needs to
    retain the password, it must make a copy. It is then the implementation's responsibility to
    protect its copy.
    
    :param java.lang.String or str title: the title of the dialog
    :param java.lang.String or str prompt: the prompt to the left of the input field, or null to display "Password:"
    :return: the password
    :rtype: ghidra.framework.generic.auth.Password
    :raises CancelledException: if the user cancels
    :raises ImproperUseException: if in headless mode
    """


@typing.overload
def askProgram(title: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Program:
    """
    Returns a Program, using the title parameter for guidance. The actual behavior of the
    method depends on your environment, which can be GUI or headless. If in headless mode,
    the program will not be upgraded (see :meth:`askProgram(String, boolean) <.askProgram>` if you want
    more control). In GUI mode, the user will be prompted to upgrade.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is the
    title String parameter.  If that property name exists and its value represents a valid
    program, then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    to select a program.
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the name of the program to return. The method will look in the
    .properties file by searching for a property name equal to the 'title' parameter. If
    that property name exists and its value represents a valid Program in the project,
    then that value    is returned. Otherwise, an Exception is thrown if there is an
    invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the pop-up dialog (in GUI mode) or the variable name (in
                headless mode)
    :return: the user-selected Program with this script as the consumer if a program was
    selected. Null is returned if a program is not selected. NOTE: It is very important that
    the program instance returned by this method ALWAYS be properly released when no longer
    needed.  The script which invoked this method must be
    specified as the consumer upon release (i.e., ``program.release(this)`` - failure to
    properly release the program may result in improper project disposal.  If the program was
    opened by the tool, the tool will be a second consumer responsible for its own release.
    :rtype: ghidra.program.model.listing.Program
    :raises VersionException: if the Program is out-of-date from the version of Ghidra and an
    upgrade was not been performed. In non-headless mode, the user will have already been
    notified via a popup dialog.
    :raises IOException: if there is an error accessing the Program's DomainObject
    :raises CancelledException: if the program open operation is cancelled
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    program
                specified in the .properties file
    """


@typing.overload
def askProgram(title: typing.Union[java.lang.String, str], upgradeIfNeeded: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Program:
    """
    Returns a Program, using the title parameter for guidance with the option to upgrade
    if needed. The actual behavior of the method depends on your environment, which can be
    GUI or headless. You can control whether or not the program is allowed to upgrade via
    the ``upgradeIfNeeded`` parameter.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is the
    title String parameter.  If that property name exists and its value represents a valid
    program, then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    to select a program.
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the name of the program to return. The method will look in the
    .properties file by searching for a property name equal to the 'title' parameter. If
    that property name exists and its value represents a valid Program in the project,
    then that value    is returned. Otherwise, an Exception is thrown if there is an
    invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the pop-up dialog (in GUI mode) or the variable name (in
                headless mode)
    :param jpype.JBoolean or bool upgradeIfNeeded: if true, program will be upgraded if needed and possible. If false,
    the program will only be upgraded after first prompting the user. In headless mode, it will
    attempt to upgrade only if the parameter is true.
    :return: the user-selected Program with this script as the consumer if a program was
    selected. Null is returned if a program is not selected. NOTE: It is very important that
    the program instance returned by this method ALWAYS be properly released when no longer
    needed.  The script which invoked this method must be
    specified as the consumer upon release (i.e., ``program.release(this)`` - failure to
    properly release the program may result in improper project disposal.  If the program was
    opened by the tool, the tool will be a second consumer responsible for its own release.
    :rtype: ghidra.program.model.listing.Program
    :raises VersionException: if the Program is out-of-date from the version of GHIDRA and an
    upgrade was not been performed. In non-headless mode, the user will have already been
    notified via a popup dialog.
    :raises IOException: if there is an error accessing the Program's DomainObject
    :raises CancelledException: if the program open operation is cancelled
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    program
                specified in the .properties file
    """


def askProjectFolder(title: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFolder:
    """
    Returns a DomainFolder object, using the supplied title string for guidance.  The actual
    behavior of the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is the
    title String parameter.  If that property name exists and its value represents a valid
    project folder, then the .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a file chooser dialog that allows the
    user to select a project folder. The selected folder will be returned.
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the name of the project folder to return. The method will look in
    the .properties    file by searching for a property name equal to the 'title' parameter.
    If that property name exists and its value represents a valid DomainFolder in the
    project, then that value is returned. Otherwise, an Exception is thrown if there is
    an invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (GUI) or the variable name    (headless or when
                using .properties file)
    :return: the selected project folder or null if there was an invalid .properties value
    :rtype: ghidra.framework.model.DomainFolder
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    project
                folder specified in the .properties file
    """


@typing.overload
def askString(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> str:
    """
    Returns a String, using the String input parameters for guidance. The actual behavior of
    the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid String value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
        for a String value. If the same popup has been run before in the same session, the
        String input field will be pre-populated with the last-used String. If not, the
        String input field will be pre-populated with the .properties value (if it exists).
    
    2. In the headless environment, this method returns a String value    representing the
    .properties value (if it exists), or throws an Exception if there is an invalid or
    missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable    name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :return: the user-specified String value
    :rtype: str
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IndexOutOfBoundsException: if in headless mode and arguments are being used, but not
            enough arguments were passed in to accommodate the request.
    :raises IllegalArgumentException: if in headless mode, there was an invalid String
                specified in the arguments, or an invalid or missing String specified in the
            .properties file
    """


@typing.overload
def askString(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
    """
    Returns a String, using the String input parameters for guidance. The actual behavior of the
    method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + message).
    If that property name exists and its value represents a valid String value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    for a String value. The pre-populated value for the String input field will be the
    last-used String (if the dialog has been run before). If that does not exist, the
    pre-populated value is the .properties value. If that does    not exist or is invalid,
    then the 'defaultValue' parameter is used (as long as it is not    null or the empty
    String).
    2. In the headless environment, this method returns a String value representing the
    .properties value (if it exists). Otherwise, if the 'defaultValue' parameter is
    not null or an empty String, it is returned. In all other cases, an exception
    is thrown.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode or when using .properties file)
    :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                part of the variable name (in headless mode or when using .properties file)
    :param java.lang.String or str defaultValue: the optional default value
    :return: the user-specified String value
    :rtype: str
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid String
                specified in the .properties file
    """


def askValues(title: typing.Union[java.lang.String, str], optionalMessage: typing.Union[java.lang.String, str], values: ghidra.features.base.values.GhidraValuesMap) -> ghidra.features.base.values.GhidraValuesMap:
    """
    Prompts for multiple values at the same time. To use this method, you must first
    create a :obj:`GhidraValuesMap` and define the values that will be supplied by this method.
    In the GUI environment, this will result in a single dialog with an entry for each value
    defined in the values map. This method returns a GhidraValuesMap with the values supplied by
    the user in GUI mode or command line arguments in headless mode. If the user cancels the
    dialog, a cancelled exception will be thrown, and unless it is explicity caught by the
    script, will terminate the script. Also, if the values map has a :obj:`ValuesMapValidator`,
    the values will be validated when the user presses the "OK" button and will only exit the
    dialog if the validate check passes. Otherwise, the validator should have reported an error
    message in the dialog and the dialog will remain visible.
    
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next arguments in the array and advance the array index until all values in the values map
    have been satisfied and so the next call to an ask method will get the next argument after
    those consumed by this call.
    
    :param java.lang.String or str title: the title of the dialog if in GUI mode
    :param java.lang.String or str optionalMessage: an optional message that is displayed in the dialog, just above the
    list of name/value pairs
    :param ghidra.features.base.values.GhidraValuesMap values: the GhidraValuesMap containing the values to include in the dialog.
    :return: the GhidraValuesMap with values set from user input in the dialog (This is the same
    instance that was passed in, so you don't need to use this)
    :rtype: ghidra.features.base.values.GhidraValuesMap
    :raises CancelledException: if the user hit the 'cancel' button in GUI mode
    """


def askYesNo(title: typing.Union[java.lang.String, str], question: typing.Union[java.lang.String, str]) -> bool:
    """
    Returns a boolean value, using the String parameters for guidance. The actual behavior of
    the method depends on your environment, which can be GUI or headless.
     
    
    Regardless of environment -- if script arguments have been set, this method will use the
    next argument in the array and advance the array index so the next call to an ask method
    will get the next argument.  If there are no script arguments and a .properties file
    sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
    Script1.java), then this method will then look there for the String value to return.
    The method will look in the .properties file by searching for a property name that is a
    space-separated concatenation of the input String parameters (title + " " + question).
    If that property name exists and its value represents a valid boolean value, then the
    .properties value will be used in the following way:
     
    1. In the GUI environment, this method displays a popup dialog that prompts the user
    with a yes/no dialog with the specified title and question. Returns true if the user
    selects "yes" to the question or false if the user selects "no".
    2. In the headless environment, if a .properties file sharing the same base name as the
    Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
    looks there for the boolean value to return. The method will look in the .properties
    file by searching for a property name that is a space-separated concatenation of the
    String parameters (title + " " + question). If that property name exists and its
    value represents a valid boolean value (either 'true' or 'false', case insensitive),
    then that value    is returned. Otherwise, an Exception is thrown if there is an
    invalid or missing .properties value.
    
    
    :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                (in headless mode)
    :param java.lang.String or str question: the question to display to the user (in GUI mode) or the second part of the
                variable name (in headless mode)
    :return: true if the user selects "yes" to the question (in GUI mode) or "true" (in headless
                mode)
    :rtype: bool
    :raises IllegalArgumentException: if in headless mode, there was a missing or invalid boolean
                specified in the .properties file
    """


def cleanup(success: typing.Union[jpype.JBoolean, bool]):
    """
    A callback for scripts to perform any needed cleanup after the script is finished
    
    :param jpype.JBoolean or bool success: true if the script was successful
    """


@typing.overload
def clearBackgroundColor(address: ghidra.program.model.address.Address):
    """
    Clears the background of the Listing at the given address to the given color.  See the
    Listing help page in Ghidra help for more information.
     
    
    This method is unavailable in headless mode.
     
    
    Note: you can use the :obj:`ColorizingService` directly to access more color changing
    functionality.  See the source code of this method to learn how to access services from
    a script.
    
    :param ghidra.program.model.address.Address address: The address at which to clear the color
    :raises ImproperUseException: if this method is run in headless mode
    
    .. seealso::
    
        | :obj:`.setBackgroundColor(AddressSetView, Color)`
    
        | :obj:`.clearBackgroundColor(AddressSetView)`
    
        | :obj:`ColorizingService`
    """


@typing.overload
def clearBackgroundColor(addresses: ghidra.program.model.address.AddressSetView):
    """
    Clears the background of the Listing at the given addresses to the given color.  See the
    Listing help page in Ghidra help for more information.
     
    
    This method is unavailable in headless mode.
     
    
    Note: you can use the :obj:`ColorizingService` directly to access more color changing
    functionality.  See the source code of this method to learn how to access services from
    a script.
    
    :param ghidra.program.model.address.AddressSetView addresses: The address at which to clear the color
    :raises ImproperUseException: if this method is run in headless mode
    
    .. seealso::
    
        | :obj:`.setBackgroundColor(AddressSetView, Color)`
    
        | :obj:`.clearBackgroundColor(AddressSetView)`
    
        | :obj:`ColorizingService`
    """


@typing.overload
def clearListing(address: ghidra.program.model.address.Address):
    """
    Clears the code unit (instruction or data) defined at the address.
    
    :param ghidra.program.model.address.Address address: the address to clear the code unit
    :raises CancelledException: if cancelled
    """


@typing.overload
def clearListing(start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
    """
    Clears the code units (instructions or data) in the specified range.
    
    :param ghidra.program.model.address.Address start: the start address
    :param ghidra.program.model.address.Address end: the end address (INCLUSIVE)
    :raises CancelledException: if cancelled
    """


@typing.overload
def clearListing(set: ghidra.program.model.address.AddressSetView):
    """
    Clears the code units (instructions or data) in the specified set
    
    :param ghidra.program.model.address.AddressSetView set: the set to clear
    :raises CancelledException: if cancelled
    """


@typing.overload
def clearListing(set: ghidra.program.model.address.AddressSetView, code: typing.Union[jpype.JBoolean, bool], symbols: typing.Union[jpype.JBoolean, bool], comments: typing.Union[jpype.JBoolean, bool], properties: typing.Union[jpype.JBoolean, bool], functions: typing.Union[jpype.JBoolean, bool], registers: typing.Union[jpype.JBoolean, bool], equates: typing.Union[jpype.JBoolean, bool], userReferences: typing.Union[jpype.JBoolean, bool], analysisReferences: typing.Union[jpype.JBoolean, bool], importReferences: typing.Union[jpype.JBoolean, bool], defaultReferences: typing.Union[jpype.JBoolean, bool], bookmarks: typing.Union[jpype.JBoolean, bool]) -> bool:
    """
    Clears the listing in the specified address set.
    
    :param ghidra.program.model.address.AddressSetView set: the address set where to clear
    :param jpype.JBoolean or bool code: true if code units should be cleared (instructions and defined data)
    :param jpype.JBoolean or bool symbols: true if symbols should be cleared
    :param jpype.JBoolean or bool comments: true if comments should be cleared
    :param jpype.JBoolean or bool properties: true if properties should be cleared
    :param jpype.JBoolean or bool functions: true if functions should be cleared
    :param jpype.JBoolean or bool registers: true if registers should be cleared
    :param jpype.JBoolean or bool equates: true if equates should be cleared
    :param jpype.JBoolean or bool userReferences: true if user references should be cleared
    :param jpype.JBoolean or bool analysisReferences: true if analysis references should be cleared
    :param jpype.JBoolean or bool importReferences: true if import references should be cleared
    :param jpype.JBoolean or bool defaultReferences: true if default references should be cleared
    :param jpype.JBoolean or bool bookmarks: true if bookmarks should be cleared
    :return: true if the address set was successfully cleared
    :rtype: bool
    """


@typing.overload
def clearListing(set: ghidra.program.model.address.AddressSetView, instructions: typing.Union[jpype.JBoolean, bool], data: typing.Union[jpype.JBoolean, bool], symbols: typing.Union[jpype.JBoolean, bool], comments: typing.Union[jpype.JBoolean, bool], properties: typing.Union[jpype.JBoolean, bool], functions: typing.Union[jpype.JBoolean, bool], registers: typing.Union[jpype.JBoolean, bool], equates: typing.Union[jpype.JBoolean, bool], userReferences: typing.Union[jpype.JBoolean, bool], analysisReferences: typing.Union[jpype.JBoolean, bool], importReferences: typing.Union[jpype.JBoolean, bool], defaultReferences: typing.Union[jpype.JBoolean, bool], bookmarks: typing.Union[jpype.JBoolean, bool]) -> bool:
    """
    Clears the listing in the specified address set.
    
    :param ghidra.program.model.address.AddressSetView set: the address set where to clear
    :param jpype.JBoolean or bool instructions: true if instructions should be cleared
    :param jpype.JBoolean or bool data: true if defined data should be cleared
    :param jpype.JBoolean or bool symbols: true if symbols should be cleared
    :param jpype.JBoolean or bool comments: true if comments should be cleared
    :param jpype.JBoolean or bool properties: true if properties should be cleared
    :param jpype.JBoolean or bool functions: true if functions should be cleared
    :param jpype.JBoolean or bool registers: true if registers should be cleared
    :param jpype.JBoolean or bool equates: true if equates should be cleared
    :param jpype.JBoolean or bool userReferences: true if user references should be cleared
    :param jpype.JBoolean or bool analysisReferences: true if analysis references should be cleared
    :param jpype.JBoolean or bool importReferences: true if import references should be cleared
    :param jpype.JBoolean or bool defaultReferences: true if default references should be cleared
    :param jpype.JBoolean or bool bookmarks: true if bookmarks should be cleared
    :return: true if the address set was successfully cleared
    :rtype: bool
    """


def closeProgram(program: ghidra.program.model.listing.Program):
    """
    Closes the specified program in the current tool.
    
    :param ghidra.program.model.listing.Program program: the program to close
    """


def createAddressSet() -> ghidra.program.model.address.AddressSet:
    """
    Creates a new mutable address set.
    
    :return: a new mutable address set
    :rtype: ghidra.program.model.address.AddressSet
    """


@typing.overload
def createAsciiString(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a null terminated ascii string starting
    at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to create the string
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createAsciiString(address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Data:
    """
    Create an ASCII string at the specified address.
    
    :param ghidra.program.model.address.Address address: the address
    :param jpype.JInt or int length: length of string (a value of 0 or negative will force use
    of dynamic null terminated string)
    :return: string data created
    :rtype: ghidra.program.model.listing.Data
    :raises CodeUnitInsertionException: if there is a data conflict
    """


def createBookmark(address: ghidra.program.model.address.Address, category: typing.Union[java.lang.String, str], note: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Bookmark:
    """
    Creates a ``NOTE`` bookmark at the specified address
     
    
    NOTE: if a ``NOTE`` bookmark already exists at the address, it will be replaced.
    This is intentional and is done to match the behavior of setting bookmarks from the UI.
    
    :param ghidra.program.model.address.Address address: the address to create the bookmark
    :param java.lang.String or str category: the bookmark category (it may be null)
    :param java.lang.String or str note: the bookmark text
    :return: the newly created bookmark
    :rtype: ghidra.program.model.listing.Bookmark
    """


def createByte(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a byte datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the byte
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def createChar(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a char datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the char
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def createClass(parent: ghidra.program.model.symbol.Namespace, className: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.GhidraClass:
    """
    Creates a new :obj:`GhidraClass` with the given name contained inside the
    specified parent namespace.
    Pass ``null`` for parent to indicate the global namespace.
    If a GhidraClass with the given name already exists, the existing one will be returned.
    
    :param ghidra.program.model.symbol.Namespace parent: the parent namespace, or null for global namespace
    :param java.lang.String or str className: the requested classes name
    :return: the GhidraClass with the given name
    :rtype: ghidra.program.model.listing.GhidraClass
    :raises InvalidInputException: if the name is invalid
    :raises DuplicateNameException: thrown if a :obj:`Library` or :obj:`Namespace`
    symbol already exists with the given name.
    Use :meth:`SymbolTable.convertNamespaceToClass(Namespace) <SymbolTable.convertNamespaceToClass>` for converting an
    existing Namespace to a GhidraClass.
    :raises IllegalArgumentException: if the given parent namespace is not from
    the :obj:`.currentProgram`.
    :raises ConcurrentModificationException: if the given parent has been deleted
    :raises IllegalArgumentException: if parent Namespace does not correspond to
    ``currerntProgram``
    
    .. seealso::
    
        | :obj:`SymbolTable.convertNamespaceToClass(Namespace)`
    """


def createDWord(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a dword datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the dword
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def createData(address: ghidra.program.model.address.Address, datatype: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data:
    """
    Creates a new defined Data object at the given address.
    
    :param ghidra.program.model.address.Address address: the address at which to create a new Data object.
    :param ghidra.program.model.data.DataType datatype: the Data Type that describes the type of Data object to create.
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises CodeUnitInsertionException: if a conflicting code unit already exists
    """


def createDouble(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a double datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the double
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def createDwords(start: ghidra.program.model.address.Address, count: typing.Union[jpype.JInt, int]):
    """
    Creates a list of dword datatypes starting at the given address.
    
    :param ghidra.program.model.address.Address start: the start address to create the dwords
    :param jpype.JInt or int count: the number of dwords to create
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createEquate(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], equateName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Equate:
    """
    Creates a new equate on the scalar value
    at the operand index of the instruction.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index on the instruction
    :param java.lang.String or str equateName: the name of the equate
    :return: the newly created equate
    :rtype: ghidra.program.model.symbol.Equate
    :raises java.lang.Exception: if a scalar does not exist of the specified
    operand index of the instruction
    """


@typing.overload
def createEquate(data: ghidra.program.model.listing.Data, equateName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Equate:
    """
    Creates a new equate on the scalar value
    at the value of the data.
    
    :param ghidra.program.model.listing.Data data: the data
    :param java.lang.String or str equateName: the name of the equate
    :return: the newly created equate
    :rtype: ghidra.program.model.symbol.Equate
    :raises InvalidInputException: if a scalar does not exist on the data
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createExternalReference(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], externalAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
    """
    Creates an external reference from the given instruction.
    For instructions with flow, the FlowType will be assumed, otherwise
    :obj:`RefType.DATA` will be assumed.  To specify the appropriate
    RefType use the alternate form of this method.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index on the instruction
    :param java.lang.String or str libraryName: the name of the library being referred
    :param java.lang.String or str externalLabel: the name of function in the library being referred
    :param ghidra.program.model.address.Address externalAddr: the address of the function in the library being referred
    :return: the newly created external reference
    :rtype: ghidra.program.model.symbol.Reference
    :raises java.lang.Exception: if an exception occurs
    """


@typing.overload
def createExternalReference(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], externalAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
    """
    Creates an external reference from the given instruction.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index on the instruction
    :param java.lang.String or str libraryName: the name of the library being referred
    :param java.lang.String or str externalLabel: the name of function in the library being referred
    :param ghidra.program.model.address.Address externalAddr: the address of the function in the library being referred
    :param ghidra.program.model.symbol.RefType refType: the appropriate external reference type (e.g., DATA, COMPUTED_CALL, etc.)
    :return: the newly created external reference
    :rtype: ghidra.program.model.symbol.Reference
    :raises java.lang.Exception: if an exception occurs
    """


@typing.overload
def createExternalReference(data: ghidra.program.model.listing.Data, libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], externalAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
    """
    Creates an external reference from the given data.  The reference type :obj:`RefType.DATA`
    will be used.
    
    :param ghidra.program.model.listing.Data data: the data
    :param java.lang.String or str libraryName: the name of the library being referred
    :param java.lang.String or str externalLabel: the name of function in the library being referred
    :param ghidra.program.model.address.Address externalAddr: the address of the function in the library being referred
    :return: the newly created external reference
    :rtype: ghidra.program.model.symbol.Reference
    :raises java.lang.Exception: if an exception occurs
    """


def createFloat(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a float datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the float
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
@deprecated("This method is deprecated because it did not allow you to include the\n largest possible address.  Instead use the one that takes a start address and a length.")
def createFragment(fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.listing.ProgramFragment:
    """
    Creates a fragment in the root folder of the default program tree.
    
    :param java.lang.String or str fragmentName: the name of the fragment
    :param ghidra.program.model.address.Address start: the start address
    :param ghidra.program.model.address.Address end: the end address (NOT INCLUSIVE)
    :return: the newly created fragment
    :rtype: ghidra.program.model.listing.ProgramFragment
    :raises DuplicateNameException: if the given fragment name already exists
    :raises NotFoundException: if any address in the fragment would be outside of the program
    
    .. deprecated::
    
    This method is deprecated because it did not allow you to include the
    largest possible address.  Instead use the one that takes a start address and a length.
    """


@typing.overload
def createFragment(fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> ghidra.program.model.listing.ProgramFragment:
    """
    Creates a fragment in the root folder of the default program tree.
    
    :param java.lang.String or str fragmentName: the name of the fragment
    :param ghidra.program.model.address.Address start: the start address
    :param jpype.JLong or int length: the length of the fragment
    :return: the newly created fragment
    :rtype: ghidra.program.model.listing.ProgramFragment
    :raises DuplicateNameException: if the given fragment name already exists
    :raises NotFoundException: if any address in the fragment would be outside of the program
    """


@typing.overload
@deprecated("This method is deprecated because it did not allow you to include the\n largest possible address.  Instead use the one that takes a start address and a length.")
def createFragment(module: ghidra.program.model.listing.ProgramModule, fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.listing.ProgramFragment:
    """
    Creates a fragment in the given folder of the default program tree.
    
    :param ghidra.program.model.listing.ProgramModule module: the parent module (or folder)
    :param java.lang.String or str fragmentName: the name of the fragment
    :param ghidra.program.model.address.Address start: the start address
    :param ghidra.program.model.address.Address end: the end address (NOT INCLUSIVE)
    :return: the newly created fragment
    :rtype: ghidra.program.model.listing.ProgramFragment
    :raises DuplicateNameException: if the given fragment name already exists
    :raises NotFoundException: if any address in the fragment would be outside of the program
    
    .. deprecated::
    
    This method is deprecated because it did not allow you to include the
    largest possible address.  Instead use the one that takes a start address and a length.
    """


@typing.overload
def createFragment(module: ghidra.program.model.listing.ProgramModule, fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> ghidra.program.model.listing.ProgramFragment:
    """
    Creates a fragment in the given folder of the default program tree.
    
    :param ghidra.program.model.listing.ProgramModule module: the parent module (or folder)
    :param java.lang.String or str fragmentName: the name of the fragment
    :param ghidra.program.model.address.Address start: the start address
    :param jpype.JLong or int length: the length of the fragment
    :return: the newly created fragment
    :rtype: ghidra.program.model.listing.ProgramFragment
    :raises DuplicateNameException: if the given fragment name already exists
    :raises NotFoundException: if any address in the fragment would be outside of the program
    """


def createFunction(entryPoint: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Function:
    """
    Creates a function at entry point with the specified name
    
    :param ghidra.program.model.address.Address entryPoint: the entry point of the function
    :param java.lang.String or str name: the name of the function or null for a default function
    :return: the new function or null if the function was not created
    :rtype: ghidra.program.model.listing.Function
    """


def createHighlight(set: ghidra.program.model.address.AddressSetView):
    """
    Sets this script's highlight state (both the local variable
    ``currentHighlight`` and the
    ``GhidraState``'s currentHighlight) to the given address set.  Also sets the tool's highlight
    if the tool exists. (Same as calling setCurrentHightlight(set);
    
    :param ghidra.program.model.address.AddressSetView set: the set of addresses to include in the highlight.  May be null.
    """


@typing.overload
def createLabel(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Symbol:
    """
    Creates a label at the specified address in the global namespace.
    If makePrimary==true, then the new label is made primary.
    
    :param ghidra.program.model.address.Address address: the address to create the symbol
    :param java.lang.String or str name: the name of the symbol
    :param jpype.JBoolean or bool makePrimary: true if the symbol should be made primary
    :return: the newly created code or function symbol
    :rtype: ghidra.program.model.symbol.Symbol
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createLabel(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
    """
    Creates a label at the specified address in the global namespace.
    If makePrimary==true, then the new label is made primary.
    If makeUnique==true, then if the name is a duplicate, the address
    will be concatenated to name to make it unique.
    
    :param ghidra.program.model.address.Address address: the address to create the symbol
    :param java.lang.String or str name: the name of the symbol
    :param jpype.JBoolean or bool makePrimary: true if the symbol should be made primary
    :param ghidra.program.model.symbol.SourceType sourceType: the source type.
    :return: the newly created code or function symbol
    :rtype: ghidra.program.model.symbol.Symbol
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createLabel(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, makePrimary: typing.Union[jpype.JBoolean, bool], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
    """
    Creates a label at the specified address in the specified namespace.
    If makePrimary==true, then the new label is made primary if permitted.
    If makeUnique==true, then if the name is a duplicate, the address
    will be concatenated to name to make it unique.
    
    :param ghidra.program.model.address.Address address: the address to create the symbol
    :param java.lang.String or str name: the name of the symbol
    :param ghidra.program.model.symbol.Namespace namespace: label's parent namespace
    :param jpype.JBoolean or bool makePrimary: true if the symbol should be made primary
    :param ghidra.program.model.symbol.SourceType sourceType: the source type.
    :return: the newly created code or function symbol
    :rtype: ghidra.program.model.symbol.Symbol
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createMemoryBlock(name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, input: java.io.InputStream, length: typing.Union[jpype.JLong, int], overlay: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.mem.MemoryBlock:
    """
    Create a new memory block.
    If the input stream is null, then an uninitialized block will be created.
    
    :param java.lang.String or str name: the name of the block
    :param ghidra.program.model.address.Address start: start address of the block
    :param java.io.InputStream input: source of the data used to fill the block.
    :param jpype.JLong or int length: the size of the block
    :param jpype.JBoolean or bool overlay: true will create an overlay, false will not
    :return: the newly created memory block
    :rtype: ghidra.program.model.mem.MemoryBlock
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createMemoryBlock(name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], overlay: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.mem.MemoryBlock:
    """
    Create a new memory block.
    
    :param java.lang.String or str name: the name of the block
    :param ghidra.program.model.address.Address start: start address of the block
    :param jpype.JArray[jpype.JByte] bytes: the bytes of the memory block
    :param jpype.JBoolean or bool overlay: true will create an overlay, false will not
    :return: the newly created memory block
    :rtype: ghidra.program.model.mem.MemoryBlock
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def createMemoryReference(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, flowType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
    """
    Creates a memory reference from the given instruction.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index on the instruction
    :param ghidra.program.model.address.Address toAddress: the TO address
    :param ghidra.program.model.symbol.RefType flowType: the flow type of the reference
    :return: the newly created memory reference
    :rtype: ghidra.program.model.symbol.Reference
    """


@typing.overload
def createMemoryReference(data: ghidra.program.model.listing.Data, toAddress: ghidra.program.model.address.Address, dataRefType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
    """
    Creates a memory reference from the given data.
    
    :param ghidra.program.model.listing.Data data: the data
    :param ghidra.program.model.address.Address toAddress: the TO address
    :param ghidra.program.model.symbol.RefType dataRefType: the type of the reference
    :return: the newly created memory reference
    :rtype: ghidra.program.model.symbol.Reference
    """


def createNamespace(parent: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
    """
    Creates a new :obj:`Namespace` with the given name contained inside the
    specified parent namespace.
    Pass ``null`` for parent to indicate the global namespace.
    If a :obj:`Namespace` or :obj:`GhidraClass` with the given name already exists, the
    existing one will be returned.
    
    :param ghidra.program.model.symbol.Namespace parent: the parent namespace, or null for global namespace
    :param java.lang.String or str namespaceName: the requested namespace's name
    :return: the namespace with the given name
    :rtype: ghidra.program.model.symbol.Namespace
    :raises DuplicateNameException: if a :obj:`Library` symbol exists with the given name
    :raises InvalidInputException: if the name is invalid
    :raises IllegalArgumentException: if parent Namespace does not correspond to
    ``currerntProgram``
    """


@typing.overload
def createProgram(programName: typing.Union[java.lang.String, str], languageID: ghidra.program.model.lang.LanguageID, compilerSpecID: ghidra.program.model.lang.CompilerSpecID) -> ghidra.program.model.listing.Program:
    """
    Creates a new program with specified name and language name. The actual language object
    is located using the language name provided.
     
    
    Please note: the program is not automatically saved into the program.
    
    :param java.lang.String or str programName: the program name
    :param ghidra.program.model.lang.LanguageID languageID: the language ID
    :param ghidra.program.model.lang.CompilerSpecID compilerSpecID: the compiler Spec ID
    :return: the new unsaved program
    :rtype: ghidra.program.model.listing.Program
    :raises java.lang.Exception: the language name is invalid or an I/O error occurs
    """


@typing.overload
def createProgram(programName: typing.Union[java.lang.String, str], languageID: ghidra.program.model.lang.LanguageID) -> ghidra.program.model.listing.Program:
    """
    Creates a new program with specified name and language name. The actual language object
    is located using the language name provided.
     
    
    Please note: the program is not automatically saved into the program.
    
    :param java.lang.String or str programName: the program name
    :param ghidra.program.model.lang.LanguageID languageID: the language name
    :return: the new unsaved program
    :rtype: ghidra.program.model.listing.Program
    :raises java.lang.Exception: the language name is invalid or an I/O error occurs
    """


@typing.overload
def createProgram(programName: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
    """
    Creates a new program with specified name and language. It uses the default compilerSpec
    for the given language.
     
    
    Please note: the program is not automatically saved into the project.
    
    :param java.lang.String or str programName: the program name
    :param ghidra.program.model.lang.Language language: the language
    :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compilerSpec to use.
    :return: the new unsaved program
    :rtype: ghidra.program.model.listing.Program
    :raises java.lang.Exception: the language name is invalid or an I/O error occurs
    """


def createQWord(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a qword datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the qword
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def createSelection(set: ghidra.program.model.address.AddressSetView):
    """
    Calling this method is equivalent to calling :meth:`setCurrentSelection(AddressSetView) <.setCurrentSelection>`.
    
    :param ghidra.program.model.address.AddressSetView set: the addresses
    """


def createStackReference(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], isWrite: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Reference:
    """
    Create a stack reference from the given instruction
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index on the instruction
    :param jpype.JInt or int stackOffset: the stack offset of the reference
    :param jpype.JBoolean or bool isWrite: true if the reference is WRITE access or false if the
    reference is READ access
    :return: the newly created stack reference
    :rtype: ghidra.program.model.symbol.Reference
    """


@typing.overload
@deprecated("use createLabel(Address, String, boolean) instead.\n Deprecated in Ghidra 7.4")
def createSymbol(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Symbol:
    """
    
    
    
    .. deprecated::
    
    use :meth:`createLabel(Address, String, boolean) <.createLabel>` instead.
    Deprecated in Ghidra 7.4
    """


@typing.overload
@deprecated("use createLabel(Address, String, boolean, SourceType) instead. Deprecated in Ghidra 7.4")
def createSymbol(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool], makeUnique: typing.Union[jpype.JBoolean, bool], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
    """
    
    
    
    .. deprecated::
    
    use :meth:`createLabel(Address, String, boolean, SourceType) <.createLabel>` instead. Deprecated in Ghidra 7.4
    """


@typing.overload
def createTableChooserDialog(title: typing.Union[java.lang.String, str], executor: ghidra.app.tablechooser.TableChooserExecutor) -> ghidra.app.tablechooser.TableChooserDialog:
    """
    Creates a TableChooserDialog that allows the script to display a list of addresses (and
    associated column data) in a table and also provides the capability to execute an
    action from a selection in the table.
     
    
    This method is unavailable in headless mode.
    
    :param java.lang.String or str title: the title of the dialog
    :param ghidra.app.tablechooser.TableChooserExecutor executor: the TableChooserExecuter to be used to apply operations on table entries.
    :return: a new TableChooserDialog.
    :rtype: ghidra.app.tablechooser.TableChooserDialog
    :raises ImproperUseException: if this method is run in headless mode
    """


@typing.overload
def createTableChooserDialog(title: typing.Union[java.lang.String, str], executor: ghidra.app.tablechooser.TableChooserExecutor, isModal: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.tablechooser.TableChooserDialog:
    """
    Creates a TableChooserDialog that allows the script to display a list of addresses (and
    associated column data) in a table and also provides the capability to execute an
    action from a selection in the table.
     
    
    This method is unavailable in headless mode.
    
    :param java.lang.String or str title: of the dialog
    :param ghidra.app.tablechooser.TableChooserExecutor executor: the TableChooserExecuter to be used to apply operations on table entries.
    :param jpype.JBoolean or bool isModal: indicates whether the dialog should be modal or not
    :return: a new TableChooserDialog.
    :rtype: ghidra.app.tablechooser.TableChooserDialog
    :raises ImproperUseException: if this method is run in headless mode; if this script is
                                run directly via Java or another script where the state does
                                not include a tool.
    """


def createUnicodeString(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a null terminated unicode string starting at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to create the string
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def createWord(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Creates a word datatype at the given address.
    
    :param ghidra.program.model.address.Address address: the address to create the word
    :return: the newly created Data object
    :rtype: ghidra.program.model.listing.Data
    :raises java.lang.Exception: if there is any exception
    """


def disassemble(address: ghidra.program.model.address.Address) -> bool:
    """
    Start disassembling at the specified address.
    The disassembler will follow code flows.
    
    :param ghidra.program.model.address.Address address: the address to begin disassembling
    :return: true if the program was successfully disassembled
    :rtype: bool
    """


def end(commit: typing.Union[jpype.JBoolean, bool]):
    """
    Ends the transactions on the current program.
    
    :param jpype.JBoolean or bool commit: true if changes should be committed
    """


def execute(runState: GhidraState, runMonitor: ghidra.util.task.TaskMonitor, runWriter: java.io.PrintWriter):
    """
    Execute/run script and :obj:`.doCleanup` afterwards.
    
    :param GhidraState runState: state object
    :param ghidra.util.task.TaskMonitor runMonitor: the monitor to use during run
    :param java.io.PrintWriter runWriter: the target of script "print" statements
    :raises java.lang.Exception: if the script excepts
    """


@typing.overload
def find(start: ghidra.program.model.address.Address, value: typing.Union[jpype.JByte, int]) -> ghidra.program.model.address.Address:
    """
    Finds the first occurrence of the byte
    starting from the address. If the start address
    is null, then the find will start from the minimum address
    of the program.
    
    :param ghidra.program.model.address.Address start: the address to start searching
    :param jpype.JByte or int value: the byte to search for
    :return: the first address where the byte was found
    :rtype: ghidra.program.model.address.Address
    """


@typing.overload
def find(start: ghidra.program.model.address.Address, values: jpype.JArray[jpype.JByte]) -> ghidra.program.model.address.Address:
    """
    Finds the first occurrence of the byte array sequence
    starting from the address. If the start address
    is null, then the find will start from the minimum address
    of the program.
    
    :param ghidra.program.model.address.Address start: the address to start searching
    :param jpype.JArray[jpype.JByte] values: the byte array sequence to search for
    :return: the first address where the byte was found, or
    null if the bytes were not found
    :rtype: ghidra.program.model.address.Address
    """


@typing.overload
def find(text: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
    """
    Finds the first occurrence of 'text' in the program listing.
    The search order is defined as:
     
    1. PLATE comments
    2. PRE comments
    3. labels
    4. code unit mnemonics and operands
    5. EOL comments
    6. repeatable comments
    7. POST comments
    
    
    :param java.lang.String or str text: the text to search for
    :return: the first address where the 'text' was found, or null
    if the text was not found
    :rtype: ghidra.program.model.address.Address
    """


@typing.overload
def findBytes(start: ghidra.program.model.address.Address, byteString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
    """
    Finds the first occurrence of the byte array sequence that matches the given byte string,
    starting from the address. If the start address is null, then the find will start
    from the minimum address of the program.
     
    
    The ``byteString`` may contain regular expressions.  The following
    highlights some example search strings (note the use of double backslashes ("\\")):
     
                "\\x80" - A basic search pattern for a byte value of 0x80
    "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                        followed by 0-10 occurrences of any byte value, followed
                        by the byte 0x55
     
    
    :param ghidra.program.model.address.Address start: the address to start searching.  If null, then the start of the program
            will be used.
    :param java.lang.String or str byteString: the byte pattern for which to search
    :return: the first address where the byte was found, or null if the bytes were not found
    :rtype: ghidra.program.model.address.Address
    :raises IllegalArgumentException: if the byteString is not a valid regular expression
    
    .. seealso::
    
        | :obj:`.findBytes(Address, String, int)`
    """


@typing.overload
def findBytes(start: ghidra.program.model.address.Address, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
    """
    Finds the first ``<matchLimit>`` occurrences of the byte array sequence that matches
    the given byte string, starting from the address. If the start address is null, then the
    find will start from the minimum address of the program.
     
    
    The ``byteString`` may contain regular expressions.  The following
    highlights some example search strings (note the use of double backslashes ("\\")):
     
                "\\x80" - A basic search pattern for a byte value of 0x80
    "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                        followed by 0-10 occurrences of any byte value, followed
                        by the byte 0x55
     
    
    :param ghidra.program.model.address.Address start: the address to start searching.  If null, then the start of the program
            will be used.
    :param java.lang.String or str byteString: the byte pattern for which to search
    :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
    :return: the start addresses that contain byte patterns that match the given byteString
    :rtype: jpype.JArray[ghidra.program.model.address.Address]
    :raises IllegalArgumentException: if the byteString is not a valid regular expression
    
    .. seealso::
    
        | :obj:`.findBytes(Address, String)`
    """


@typing.overload
def findBytes(start: ghidra.program.model.address.Address, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
    """
    Finds the first ``<matchLimit>`` occurrences of the byte array sequence that matches
    the given byte string, starting from the address. If the start address is null, then the
    find will start from the minimum address of the program.
     
    
    The ``byteString`` may contain regular expressions.  The following
    highlights some example search strings (note the use of double backslashes ("\\")):
     
                "\\x80" - A basic search pattern for a byte value of 0x80
    "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                        followed by 0-10 occurrences of any byte value, followed
                        by the byte 0x55
     
    
    :param ghidra.program.model.address.Address start: the address to start searching.  If null, then the start of the program
            will be used.
    :param java.lang.String or str byteString: the byte pattern for which to search
    :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
    :param jpype.JInt or int alignment: byte alignment to use for search starts. For example, a value of
        1 searches from every byte.  A value of 2 only matches runs that begin on a even
        address boundary.
    :return: the start addresses that contain byte patterns that match the given byteString
    :rtype: jpype.JArray[ghidra.program.model.address.Address]
    :raises IllegalArgumentException: if the byteString is not a valid regular expression
    
    .. seealso::
    
        | :obj:`.findBytes(Address, String)`
    """


@typing.overload
def findBytes(set: ghidra.program.model.address.AddressSetView, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
    """
    Finds a byte pattern within an addressSet.
    
    Note: The ranges within the addressSet are NOT treated as a contiguous set when searching
     
    
    The ``byteString`` may contain regular expressions.  The following
    highlights some example search strings (note the use of double backslashes ("\\")):
     
                "\\x80" - A basic search pattern for a byte value of 0x80
    "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                        followed by 0-10 occurrences of any byte value, followed
                        by the byte 0x55
     
    
    :param ghidra.program.model.address.AddressSetView set: the addressSet specifying which addresses to search.
    :param java.lang.String or str byteString: the byte pattern for which to search
    :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
    :param jpype.JInt or int alignment: byte alignment to use for search starts. For example, a value of
        1 searches from every byte.  A value of 2 only matches runs that begin on a even
        address boundary.
    :return: the start addresses that contain byte patterns that match the given byteString
    :rtype: jpype.JArray[ghidra.program.model.address.Address]
    :raises IllegalArgumentException: if the byteString is not a valid regular expression
    
    .. seealso::
    
        | :obj:`.findBytes(Address, String)`
    """


@typing.overload
@deprecated("see description for details.")
def findBytes(set: ghidra.program.model.address.AddressSetView, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], searchAcrossAddressGaps: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.address.Address]:
    """
    This method has been deprecated, use :meth:`findBytes(Address, String, int, int) <.findBytes>` instead.
    The concept of searching and finding matches that span gaps (address ranges where no memory
    blocks have been defined), is no longer supported. If this capability has value to anyone, 
    please contact the Ghidra team and let us know.
     
    
    Finds a byte pattern within an addressSet.
    
    Note: The ranges within the addressSet are NOT treated as a contiguous set when searching
     
    
    The ``byteString`` may contain regular expressions.  The following
    highlights some example search strings (note the use of double backslashes ("\\")):
     
                "\\x80" - A basic search pattern for a byte value of 0x80
    "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                        followed by 0-10 occurrences of any byte value, followed
                        by the byte 0x55
     
    
    :param ghidra.program.model.address.AddressSetView set: the addressSet specifying which addresses to search.
    :param java.lang.String or str byteString: the byte pattern for which to search
    :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
    :param jpype.JInt or int alignment: byte alignment to use for search starts. For example, a value of
        1 searches from every byte.  A value of 2 only matches runs that begin on a even
        address boundary.
    :param jpype.JBoolean or bool searchAcrossAddressGaps: This parameter is no longer supported and its value is
    ignored. Previously, if true, match results were allowed to span non-continguous memory
    ranges.
    :return: the start addresses that contain byte patterns that match the given byteString
    :rtype: jpype.JArray[ghidra.program.model.address.Address]
    :raises IllegalArgumentException: if the byteString is not a valid regular expression
    
    .. deprecated::
    
    see description for details.
    
    .. seealso::
    
        | :obj:`.findBytes(Address, String)`
    """


def findPascalStrings(addressSet: ghidra.program.model.address.AddressSetView, minimumStringLength: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], includePascalUnicode: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.util.string.FoundString]:
    """
    Search for sequences of Pascal Ascii strings in program memory.  See
    :obj:`AsciiCharSetRecognizer` to see exactly what chars are considered ASCII for purposes
    of this search.
    
    :param ghidra.program.model.address.AddressSetView addressSet: The address set to search. Use null to search all memory;
    :param jpype.JInt or int minimumStringLength: The smallest number of chars in a sequence to be considered a
    "string".
    :param jpype.JInt or int alignment: specifies any alignment requirements for the start of the string.  An
    alignment of 1, means the string can start at any address.  An alignment of 2 means the
    string must start on an even address and so on.  Only allowed values are 1,2, and 4.
    :param jpype.JBoolean or bool includePascalUnicode: if true, UTF16 size strings will be included in addition to UTF8.
    :return: a list of "FoundString" objects which contain the addresses, length, and type of
    possible strings.
    :rtype: java.util.List[ghidra.program.util.string.FoundString]
    """


def findStrings(addressSet: ghidra.program.model.address.AddressSetView, minimumStringLength: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], requireNullTermination: typing.Union[jpype.JBoolean, bool], includeAllCharWidths: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.util.string.FoundString]:
    """
    Search for sequences of Ascii strings in program memory.  See :obj:`AsciiCharSetRecognizer`
    to see exactly what chars are considered ASCII for purposes of this search.
    
    :param ghidra.program.model.address.AddressSetView addressSet: The address set to search. Use null to search all memory;
    :param jpype.JInt or int minimumStringLength: The smallest number of chars in a sequence to be considered a
    "string".
    :param jpype.JInt or int alignment: specifies any alignment requirements for the start of the string.  An
    alignment of 1, means the string can start at any address.  An alignment of 2 means the
    string must start on an even address and so on.  Only allowed values are 1,2, and 4.
    :param jpype.JBoolean or bool requireNullTermination: If true, only strings that end in a null will be returned.
    :param jpype.JBoolean or bool includeAllCharWidths: if true, UTF16 and UTF32 size strings will be included in
    addition to UTF8.
    :return: a list of "FoundString" objects which contain the addresses, length, and type of
    possible strings.
    :rtype: java.util.List[ghidra.program.util.string.FoundString]
    """


def getAddressFactory() -> ghidra.program.model.address.AddressFactory:
    ...


def getAnalysisOptionDefaultValue(program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str]) -> str:
    """
    Returns the default value for the given analysis option.  Returns empty string if
    invalid option.
    
    :param ghidra.program.model.listing.Program program: the program for which we want to retrieve the default value for the
                given analysis option
    :param java.lang.String or str analysisOption: the analysis option for which we want to retrieve the default value
    :return: String representation of default value (returns empty string if analysis option
                is invalid).
    :rtype: str
    """


def getAnalysisOptionDefaultValues(program: ghidra.program.model.listing.Program, analysisOptions: java.util.List[java.lang.String]) -> java.util.Map[java.lang.String, java.lang.String]:
    """
    Returns a mapping of the given analysis options to their default values in String form.
    An individual option is mapped to the empty String if the option is invalid.
    
    :param ghidra.program.model.listing.Program program: the program for which to retrieve default values for the
                        given analysis options
    :param java.util.List[java.lang.String] analysisOptions: the analysis options for which to retrieve default values
    :return: mapping from analysis options to their default values.  An individual option
                    will be mapped to an empty String if the option is invalid.
    :rtype: java.util.Map[java.lang.String, java.lang.String]
    """


def getAnalysisOptionDescription(program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str]) -> str:
    """
    Returns the description of an analysis option name, as provided by the analyzer. This
    method returns an empty string if no description is available.
    
    :param ghidra.program.model.listing.Program program: the program to get the analysis option description from
    :param java.lang.String or str analysisOption: the analysis option to get the description for
    :return: the analysis description, or empty String if none has been provided
    :rtype: str
    """


def getAnalysisOptionDescriptions(program: ghidra.program.model.listing.Program, analysisOptions: java.util.List[java.lang.String]) -> java.util.Map[java.lang.String, java.lang.String]:
    """
    Returns descriptions mapping to the given list of analysis option names. This method
    returns an empty string for an analysis option if no description is available.
    
    :param ghidra.program.model.listing.Program program: the program to get the analysis option description from
    :param java.util.List[java.lang.String] analysisOptions: the lists of analysis options to get the description for
    :return: mapping between each analysis options and its description (description is empty
                string if none has been provided).
    :rtype: java.util.Map[java.lang.String, java.lang.String]
    """


def getBookmarks(address: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.listing.Bookmark]:
    """
    Returns all of the NOTE bookmarks defined at the specified address
    
    :param ghidra.program.model.address.Address address: the address to retrieve the bookmark
    :return: the bookmarks at the specified address
    :rtype: jpype.JArray[ghidra.program.model.listing.Bookmark]
    """


def getByte(address: ghidra.program.model.address.Address) -> int:
    """
    Returns the signed 'byte' value at the specified address in memory.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the signed 'byte' value at the specified address in memory
    :rtype: int
    :raises MemoryAccessException: if the memory is not readable
    """


def getBytes(address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
    """
    Reads length number of signed bytes starting at the specified address.
    Note: this could be inefficient if length is large
    
    :param ghidra.program.model.address.Address address: the address to start reading
    :param jpype.JInt or int length: the number of bytes to read
    :return: an array of signed bytes
    :rtype: jpype.JArray[jpype.JByte]
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    
    .. seealso::
    
        | :obj:`ghidra.program.model.mem.Memory`
    """


def getCategory() -> str:
    """
    Returns the category for this script.
    
    :return: the category for this script
    :rtype: str
    """


def getCodeUnitFormat() -> ghidra.program.model.listing.CodeUnitFormat:
    """
    Returns the code unit format established for the code browser listing
    or a default format if no tool (e.g., headless).
     
    
    This format object may be used to format any code unit (instruction/data) using
    the same option settings.
    
    :return: code unit format when in GUI mode, default format in headless
    :rtype: ghidra.program.model.listing.CodeUnitFormat
    """


def getCurrentAnalysisOptionsAndValues(program: ghidra.program.model.listing.Program) -> java.util.Map[java.lang.String, java.lang.String]:
    """
    Gets the given program's ANALYSIS_PROPERTIES and returns a HashMap of the
    program's analysis options to current values (values represented as strings).
     
    
    The string "(default)" is appended to the value if it represents the
    default value for the option it is assigned to.
    
    :param ghidra.program.model.listing.Program program: the program to get analysis options from
    :return: mapping of analysis options to current settings (represented as strings)
    :rtype: java.util.Map[java.lang.String, java.lang.String]
    """


def getCurrentProgram() -> ghidra.program.model.listing.Program:
    """
    Gets the current program.
    
    :return: the program
    :rtype: ghidra.program.model.listing.Program
    """


@typing.overload
def getDataAfter(data: ghidra.program.model.listing.Data) -> ghidra.program.model.listing.Data:
    """
    Returns the defined data after the specified data or null if no data exists.
    
    :param ghidra.program.model.listing.Data data: preceding data
    :return: the defined data after the specified data or null if no data exists
    :rtype: ghidra.program.model.listing.Data
    """


@typing.overload
def getDataAfter(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the defined data after the specified address or null if no data exists.
    
    :param ghidra.program.model.address.Address address: the data address
    :return: the defined data after the specified address or null if no data exists
    :rtype: ghidra.program.model.listing.Data
    """


def getDataAt(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the defined data at the specified address or null if no data exists.
    
    :param ghidra.program.model.address.Address address: the data address
    :return: the data at the specified address or null if no data exists
    :rtype: ghidra.program.model.listing.Data
    """


@typing.overload
def getDataBefore(data: ghidra.program.model.listing.Data) -> ghidra.program.model.listing.Data:
    """
    Returns the defined data before the specified data or null if no data exists.
    
    :param ghidra.program.model.listing.Data data: the succeeding data
    :return: the defined data before the specified data or null if no data exists
    :rtype: ghidra.program.model.listing.Data
    """


@typing.overload
def getDataBefore(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the defined data before the specified address or null if no data exists.
    
    :param ghidra.program.model.address.Address address: the data address
    :return: the defined data before the specified address or null if no data exists
    :rtype: ghidra.program.model.listing.Data
    """


def getDataContaining(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the defined data containing the specified address or null if no data exists.
    
    :param ghidra.program.model.address.Address address: the data address
    :return: the defined data containing the specified address or null if no data exists
    :rtype: ghidra.program.model.listing.Data
    """


def getDataTypes(name: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.program.model.data.DataType]:
    """
    Searches through the datatype manager of the current program and
    returns an array of datatypes that match the specified name.
    The datatype manager supports datatypes of the same name in different categories.
    A zero-length array indicates that no datatypes with the specified name exist.
    
    :param java.lang.String or str name: the name of the desired datatype
    :return: an array of datatypes that match the specified name
    :rtype: jpype.JArray[ghidra.program.model.data.DataType]
    """


def getDefaultLanguage(processor: ghidra.program.model.lang.Processor) -> ghidra.program.model.lang.Language:
    """
    Returns the default language provider for the specified processor name.
    
    :param ghidra.program.model.lang.Processor processor: the processor
    :return: the default language provider for the specified processor name
    :rtype: ghidra.program.model.lang.Language
    :raises LanguageNotFoundException: if no language provider exists for the processor
    
    .. seealso::
    
        | :obj:`ghidra.program.model.lang.Language`
    """


def getDemangled(mangled: typing.Union[java.lang.String, str]) -> str:
    """
    Returns a demangled version of the mangled string.
    
    :param java.lang.String or str mangled: the mangled string to demangled
    :return: a demangled version of the mangled string, or null if it could not be demangled
    :rtype: str
    """


def getDouble(address: ghidra.program.model.address.Address) -> float:
    """
    Returns the 'double' value at the specified address in memory.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the 'double' value at the specified address in memory
    :rtype: float
    :raises MemoryAccessException: if the memory is not readable
    """


def getEOLComment(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the EOL comment at the specified address.  The comment returned is the raw text
    of the comment.  Contrastingly, calling :meth:`GhidraScript.getEOLCommentAsRendered(Address) <GhidraScript.getEOLCommentAsRendered>` will
    return the text of the comment as it is rendered in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the EOL comment at the specified address or null
    if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`GhidraScript.getEOLCommentAsRendered(Address)`
    """


def getEOLCommentAsRendered(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the EOL comment at the specified address.  If you want the raw text,
    then you must call :meth:`getEOLComment(Address) <.getEOLComment>`.  This method returns the text as
    seen in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the EOL comment at the specified address or null if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`.getEOLComment(Address)`
    """


@typing.overload
def getEquate(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]) -> ghidra.program.model.symbol.Equate:
    """
    Returns the equate defined at the operand index of the instruction with the given value.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index
    :param jpype.JLong or int value: scalar equate value
    :return: the equate defined at the operand index of the instruction
    :rtype: ghidra.program.model.symbol.Equate
    """


@typing.overload
def getEquate(data: ghidra.program.model.listing.Data) -> ghidra.program.model.symbol.Equate:
    """
    Returns the equate defined on the data.
    
    :param ghidra.program.model.listing.Data data: the data
    :return: the equate defined on the data
    :rtype: ghidra.program.model.symbol.Equate
    """


def getEquates(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.program.model.symbol.Equate]:
    """
    Returns the equates defined at the operand index of the instruction.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index
    :return: the equate defined at the operand index of the instruction
    :rtype: java.util.List[ghidra.program.model.symbol.Equate]
    """


def getFirstData() -> ghidra.program.model.listing.Data:
    """
    Returns the first defined data in the current program.
    
    :return: the first defined data in the current program
    :rtype: ghidra.program.model.listing.Data
    """


def getFirstFunction() -> ghidra.program.model.listing.Function:
    """
    Returns the first function in the current program.
    
    :return: the first function in the current program
    :rtype: ghidra.program.model.listing.Function
    """


@typing.overload
def getFirstInstruction() -> ghidra.program.model.listing.Instruction:
    """
    Returns the first instruction in the current program.
    
    :return: the first instruction in the current program
    :rtype: ghidra.program.model.listing.Instruction
    """


@typing.overload
def getFirstInstruction(function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Instruction:
    """
    Returns the first instruction in the function.
    
    :param ghidra.program.model.listing.Function function: the function
    :return: the first instruction in the function
    :rtype: ghidra.program.model.listing.Instruction
    """


def getFloat(address: ghidra.program.model.address.Address) -> float:
    """
    Returns the 'float' value at the specified address in memory.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the 'float' value at the specified address in memory
    :rtype: float
    :raises MemoryAccessException: if the memory is not readable
    """


def getFragment(module: ghidra.program.model.listing.ProgramModule, fragmentName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramFragment:
    """
    Returns the fragment with the specified name
    defined in the given module.
    
    :param ghidra.program.model.listing.ProgramModule module: the parent module
    :param java.lang.String or str fragmentName: the fragment name
    :return: the fragment or null if one does not exist
    :rtype: ghidra.program.model.listing.ProgramFragment
    """


@deprecated("this method makes no sense in the new world order where function  names\n \t\t\t   no longer have to be unique. Use getGlobalFunctions(String)\n \t\t\t   Deprecated in Ghidra 7.4")
def getFunction(name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Function:
    """
    Returns the function with the specified name, or
    null if no function exists. (Now returns the first one it finds with that name)
    
    :param java.lang.String or str name: the name of the function
    :return: the function with the specified name, or
    null if no function exists
    :rtype: ghidra.program.model.listing.Function
    
    .. deprecated::
    
    this method makes no sense in the new world order where function  names
                    no longer have to be unique. Use :meth:`getGlobalFunctions(String) <.getGlobalFunctions>`
                    Deprecated in Ghidra 7.4
    """


@typing.overload
def getFunctionAfter(function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Function:
    """
    Returns the function defined after the specified function in address order.
    
    :param ghidra.program.model.listing.Function function: the function
    :return: the function defined after the specified function
    :rtype: ghidra.program.model.listing.Function
    """


@typing.overload
def getFunctionAfter(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
    """
    Returns the function defined after the specified address.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the function defined after the specified address
    :rtype: ghidra.program.model.listing.Function
    """


def getFunctionAt(entryPoint: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
    """
    Returns the function with the specified entry point, or
    null if no function exists.
    
    :param ghidra.program.model.address.Address entryPoint: the function entry point address
    :return: the function with the specified entry point, or
    null if no function exists
    :rtype: ghidra.program.model.listing.Function
    """


@typing.overload
def getFunctionBefore(function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Function:
    """
    Returns the function defined before the specified function in address order.
    
    :param ghidra.program.model.listing.Function function: the function
    :return: the function defined before the specified function
    :rtype: ghidra.program.model.listing.Function
    """


@typing.overload
def getFunctionBefore(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
    """
    Returns the function defined before the specified address.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the function defined before the specified address
    :rtype: ghidra.program.model.listing.Function
    """


def getFunctionContaining(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
    """
    Returns the function containing the specified address.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the function containing the specified address
    :rtype: ghidra.program.model.listing.Function
    """


def getGhidraVersion() -> str:
    """
    Returns the version of the Ghidra being run.
    
    :return: the version of the Ghidra being run
    :rtype: str
    """


def getGlobalFunctions(name: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.program.model.listing.Function]:
    """
    Returns a list of all functions in the global namespace with the given name.
    
    :param java.lang.String or str name: the name of the function
    :return: the function with the specified name, or
    :rtype: java.util.List[ghidra.program.model.listing.Function]
    """


@typing.overload
def getInstructionAfter(instruction: ghidra.program.model.listing.Instruction) -> ghidra.program.model.listing.Instruction:
    """
    Returns the instruction defined after the specified instruction or null
    if no instruction exists.
    The instruction that is returned does not have to be contiguous.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :return: the instruction defined after the specified instruction or null if no instruction exists
    :rtype: ghidra.program.model.listing.Instruction
    """


@typing.overload
def getInstructionAfter(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
    """
    Returns the instruction defined after the specified address or null
    if no instruction exists.
    The instruction that is returned does not have to be contiguous.
    
    :param ghidra.program.model.address.Address address: the address of the prior instruction
    :return: the instruction defined after the specified address or null if no instruction exists
    :rtype: ghidra.program.model.listing.Instruction
    """


def getInstructionAt(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
    """
    Returns the instruction at the specified address or null if no instruction exists.
    
    :param ghidra.program.model.address.Address address: the instruction address
    :return: the instruction at the specified address or null if no instruction exists
    :rtype: ghidra.program.model.listing.Instruction
    """


@typing.overload
def getInstructionBefore(instruction: ghidra.program.model.listing.Instruction) -> ghidra.program.model.listing.Instruction:
    """
    Returns the instruction defined before the specified instruction or null
    if no instruction exists.
    The instruction that is returned does not have to be contiguous.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :return: the instruction defined before the specified instruction or null if no instruction exists
    :rtype: ghidra.program.model.listing.Instruction
    """


@typing.overload
def getInstructionBefore(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
    """
    Returns the instruction defined before the specified address or null
    if no instruction exists.
    The instruction that is returned does not have to be contiguous.
    
    :param ghidra.program.model.address.Address address: the address of the instruction
    :return: the instruction defined before the specified address or null if no instruction exists
    :rtype: ghidra.program.model.listing.Instruction
    """


def getInstructionContaining(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
    """
    Returns the instruction containing the specified address or null if no instruction exists.
    
    :param ghidra.program.model.address.Address address: the instruction address
    :return: the instruction containing the specified address or null if no instruction exists
    :rtype: ghidra.program.model.listing.Instruction
    """


def getInt(address: ghidra.program.model.address.Address) -> int:
    """
    Returns the 'integer' value at the specified address in memory.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the 'integer' value at the specified address in memory
    :rtype: int
    :raises MemoryAccessException: if the memory is not readable
    """


def getLanguage(languageID: ghidra.program.model.lang.LanguageID) -> ghidra.program.model.lang.Language:
    """
    Returns the language provider for the specified language name.
    
    :param ghidra.program.model.lang.LanguageID languageID: the language name
    :return: the language provider for the specified language name
    :rtype: ghidra.program.model.lang.Language
    :raises LanguageNotFoundException: if no language provider exists
    
    .. seealso::
    
        | :obj:`ghidra.program.model.lang.Language`
    """


def getLastData() -> ghidra.program.model.listing.Data:
    """
    Returns the last defined data in the current program.
    
    :return: the last defined data in the current program
    :rtype: ghidra.program.model.listing.Data
    """


def getLastFunction() -> ghidra.program.model.listing.Function:
    """
    Returns the last function in the current program.
    
    :return: the last function in the current program
    :rtype: ghidra.program.model.listing.Function
    """


def getLastInstruction() -> ghidra.program.model.listing.Instruction:
    """
    Returns the last instruction in the current program.
    
    :return: the last instruction in the current program
    :rtype: ghidra.program.model.listing.Instruction
    """


def getLong(address: ghidra.program.model.address.Address) -> int:
    """
    Returns the 'long' value at the specified address in memory.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the 'long' value at the specified address in memory
    :rtype: int
    :raises MemoryAccessException: if the memory is not readable
    """


@typing.overload
def getMemoryBlock(name: typing.Union[java.lang.String, str]) -> ghidra.program.model.mem.MemoryBlock:
    """
    Returns the first memory block with the specified name.
    NOTE: if more than block exists with the same name, the first
    block with that name will be returned.
    
    :param java.lang.String or str name: the name of the requested block
    :return: the memory block with the specified name
    :rtype: ghidra.program.model.mem.MemoryBlock
    """


@typing.overload
def getMemoryBlock(address: ghidra.program.model.address.Address) -> ghidra.program.model.mem.MemoryBlock:
    """
    Returns the memory block containing the specified address,
    or null if no memory block contains the address.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the memory block containing the specified address
    :rtype: ghidra.program.model.mem.MemoryBlock
    """


def getMemoryBlocks() -> jpype.JArray[ghidra.program.model.mem.MemoryBlock]:
    """
    Returns an array containing all the memory blocks
    in the current program.
    
    :return: an array containing all the memory blocks
    :rtype: jpype.JArray[ghidra.program.model.mem.MemoryBlock]
    """


def getMonitor() -> ghidra.util.task.TaskMonitor:
    """
    Gets the current task monitor.
    
    :return: the task monitor
    :rtype: ghidra.util.task.TaskMonitor
    """


def getNamespace(parent: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
    """
    Returns the non-function namespace with the given name contained inside the
    specified parent namespace.
    Pass ``null`` for parent to indicate the global namespace.
    
    :param ghidra.program.model.symbol.Namespace parent: the parent namespace, or null for global namespace
    :param java.lang.String or str namespaceName: the requested namespace's name
    :return: the namespace with the given name or null if not found
    :rtype: ghidra.program.model.symbol.Namespace
    """


def getPlateComment(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the PLATE comment at the specified address.  The comment returned is the raw text
    of the comment.  Contrastingly, calling :meth:`GhidraScript.getPlateCommentAsRendered(Address) <GhidraScript.getPlateCommentAsRendered>` will
    return the text of the comment as it is rendered in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the PLATE comment at the specified address or null
    if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`GhidraScript.getPlateCommentAsRendered(Address)`
    """


def getPlateCommentAsRendered(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the PLATE comment at the specified address, as rendered.  Comments support
    annotations, which are displayed differently than the raw text.  If you want the raw text,
    then you must call :meth:`getPlateComment(Address) <.getPlateComment>`.  This method returns the text as
    seen in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the PLATE comment at the specified address or null
                if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`.getPlateComment(Address)`
    """


def getPostComment(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the POST comment at the specified address.  The comment returned is the raw text
    of the comment.  Contrastingly, calling :meth:`GhidraScript.getPostCommentAsRendered(Address) <GhidraScript.getPostCommentAsRendered>` will
    return the text of the comment as it is rendered in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the POST comment at the specified address or null
    if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`GhidraScript.getPostCommentAsRendered(Address)`
    """


def getPostCommentAsRendered(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the POST comment at the specified address.  If you want the raw text,
    then you must call :meth:`getPostComment(Address) <.getPostComment>`.  This method returns the text as
    seen in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the POST comment at the specified address or null if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`.getPostComment(Address)`
    """


def getPreComment(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the PRE comment at the specified address.  The comment returned is the raw text
    of the comment.  Contrastingly, calling :meth:`GhidraScript.getPreCommentAsRendered(Address) <GhidraScript.getPreCommentAsRendered>` will
    return the text of the comment as it is rendered in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the PRE comment at the specified address or null
    if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`GhidraScript.getPreCommentAsRendered(Address)`
    """


def getPreCommentAsRendered(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the PRE comment at the specified address.  If you want the raw text,
    then you must call :meth:`getPreComment(Address) <.getPreComment>`.  This method returns the text as
    seen in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the PRE comment at the specified address or null
            if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`.getPreComment(Address)`
    """


def getProgramFile() -> java.io.File:
    """
    Returns the :obj:`File` that the program was originally imported from.  It does not 
    necessarily still exist on the file system.
     
    
    For example, ``c:\temp\test.exe``.
    
    :return: the :obj:`File` that the program was originally imported from
    :rtype: java.io.File
    """


def getProjectRootFolder() -> ghidra.framework.model.DomainFolder:
    """
    This method looks up the current project and returns
    the root domain folder.
    
    :return: the root domain folder of the current project
    :rtype: ghidra.framework.model.DomainFolder
    """


@typing.overload
def getReference(instruction: ghidra.program.model.listing.Instruction, toAddress: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
    """
    Returns the reference from the instruction to the given address.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param ghidra.program.model.address.Address toAddress: the destination address
    :return: the reference from the instruction to the given address
    :rtype: ghidra.program.model.symbol.Reference
    """


@typing.overload
def getReference(data: ghidra.program.model.listing.Data, toAddress: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
    """
    Returns the reference from the data to the given address.
    
    :param ghidra.program.model.listing.Data data: the data
    :param ghidra.program.model.address.Address toAddress: the destination address
    :return: the reference from the data to the given address
    :rtype: ghidra.program.model.symbol.Reference
    """


def getReferencesFrom(address: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
    """
    Returns an array of the references FROM the given address.
    
    :param ghidra.program.model.address.Address address: the from address of the references
    :return: an array of the references FROM the given address
    :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
    """


def getReferencesTo(address: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
    """
    Returns an array of the references TO the given address.
    Note: If more than 4096 references exists to this address,
    only the first 4096 will be returned.
    If you need to access all the references, please
    refer to the method ``ReferenceManager::getReferencesTo(Address)``.
    
    :param ghidra.program.model.address.Address address: the from address of the references
    :return: an array of the references TO the given address
    :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
    """


def getRepeatableComment(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the repeatable comment at the specified address.  The comment returned is the raw text
    of the comment.  Contrastingly, calling :meth:`GhidraScript.getRepeatableCommentAsRendered(Address) <GhidraScript.getRepeatableCommentAsRendered>` will
    return the text of the comment as it is rendered in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the repeatable comment at the specified address or null
    if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`GhidraScript.getRepeatableCommentAsRendered(Address)`
    """


def getRepeatableCommentAsRendered(address: ghidra.program.model.address.Address) -> str:
    """
    Returns the repeatable comment at the specified address.  If you want the raw text,
    then you must call :meth:`getRepeatableComment(Address) <.getRepeatableComment>`.  This method returns the text as
    seen in the display.
    
    :param ghidra.program.model.address.Address address: the address to get the comment
    :return: the repeatable comment at the specified address or null if one does not exist
    :rtype: str
    
    .. seealso::
    
        | :obj:`.getRepeatableComment(Address)`
    """


def getReusePreviousChoices() -> bool:
    """
    Returns whether scripts will reuse previously selected values when showing the various
    ``ask`` methods.
    
    :return: true to reuse values; false to not reuse previous values
    :rtype: bool
    """


def getScriptAnalysisMode() -> GhidraScript.AnalysisMode:
    """
    Determines the behavior of Auto-Analysis while this script is executed and the manner
    in which this script is executed.  If a script overrides this method and returns DISABLED
    or SUSPENDED, this script will execute as an AnalysisWorker.  Note that this will only
    work reliably when the script is working with the currentProgram only and is not opening
    and changing other programs.  If multiple programs will be modified
    and auto-analysis should be disabled/suspended, the AutoAnalysisManager.scheduleWorker
    method should be used with the appropriate AutoAnalysisManager instance.
    
    :return: the analysis mode associated with this script.
    :rtype: GhidraScript.AnalysisMode
    
    .. seealso::
    
        | :obj:`AutoAnalysisManager.getAnalysisManager(Program)`
    
        | :obj:`AutoAnalysisManager.scheduleWorker(AnalysisWorker, Object, boolean, TaskMonitor)`
    
        | :obj:`AutoAnalysisManager.setIgnoreChanges(boolean)`
    """


def getScriptArgs() -> jpype.JArray[java.lang.String]:
    """
    Returns the script-specific arguments
    
    :return: The script-specific arguments.  Could be an empty array, but won't be null.
    :rtype: jpype.JArray[java.lang.String]
    """


def getScriptName() -> str:
    """
    Returns name of script
    
    :return: name of script
    :rtype: str
    """


def getShort(address: ghidra.program.model.address.Address) -> int:
    """
    Returns the 'short' value at the specified address in memory.
    
    :param ghidra.program.model.address.Address address: the address
    :return: the 'short' value at the specified address in memory
    :rtype: int
    :raises MemoryAccessException: if the memory is not readable
    """


def getSourceFile() -> generic.jar.ResourceFile:
    """
    Returns the script source file.
    
    :return: the script source file
    :rtype: generic.jar.ResourceFile
    """


def getState() -> GhidraState:
    """
    Returns the state object for this script after first synchronizing its state with its
    corresponding convenience variables.
    
    :return: the state object
    :rtype: GhidraState
    """


@deprecated("use getSymbols(String, Namespace)")
def getSymbol(name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the symbol with the given name in the given namespace if there is only one.
    Pass ``null`` for namespace to indicate the global namespace.
    
    :param java.lang.String or str name: the name of the symbol
    :param ghidra.program.model.symbol.Namespace namespace: the parent namespace, or null for global namespace
    :return: the symbol with the given name in the given namespace
    :rtype: ghidra.program.model.symbol.Symbol
    :raises IllegalStateException: if there is more than one symbol with that name.
    
    .. deprecated::
    
    use :meth:`getSymbols(String, Namespace) <.getSymbols>`
    """


@typing.overload
def getSymbolAfter(symbol: ghidra.program.model.symbol.Symbol) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the next non-default primary symbol defined
    after the given symbol.
    
    :param ghidra.program.model.symbol.Symbol symbol: the symbol to use as a starting point
    :return: the next non-default primary symbol
    :rtype: ghidra.program.model.symbol.Symbol
    """


@typing.overload
def getSymbolAfter(address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the next non-default primary symbol defined
    after the given address.
    
    :param ghidra.program.model.address.Address address: the address to use as a starting point
    :return: the next non-default primary symbol
    :rtype: ghidra.program.model.symbol.Symbol
    """


@typing.overload
@deprecated("Since the same label name can be at the same address if in a different namespace,\n this method is ambiguous. Use getSymbolAt(Address, String, Namespace) instead.")
def getSymbolAt(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the symbol with the specified address and name, or
    null if no symbol exists.
    
    :param ghidra.program.model.address.Address address: the symbol address
    :param java.lang.String or str name: the symbol name
    :return: the symbol with the specified address and name, or
    null if no symbol exists
    :rtype: ghidra.program.model.symbol.Symbol
    
    .. deprecated::
    
    Since the same label name can be at the same address if in a different namespace,
    this method is ambiguous. Use :meth:`getSymbolAt(Address, String, Namespace) <.getSymbolAt>` instead.
    """


@typing.overload
def getSymbolAt(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the symbol with the specified address, name, and namespace
    
    :param ghidra.program.model.address.Address address: the symbol address
    :param java.lang.String or str name: the symbol name
    :param ghidra.program.model.symbol.Namespace namespace: the parent namespace for the symbol.
    :return: the symbol with the specified address, name, and namespace, or
    null if no symbol exists
    :rtype: ghidra.program.model.symbol.Symbol
    """


@typing.overload
def getSymbolAt(address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the PRIMARY symbol at the specified address, or
    null if no symbol exists.
    
    :param ghidra.program.model.address.Address address: the symbol address
    :return: the PRIMARY symbol at the specified address, or
    null if no symbol exists
    :rtype: ghidra.program.model.symbol.Symbol
    """


@typing.overload
def getSymbolBefore(symbol: ghidra.program.model.symbol.Symbol) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the previous non-default primary symbol defined
    before the given symbol.
    
    :param ghidra.program.model.symbol.Symbol symbol: the symbol to use as a starting point
    :return: the previous non-default primary symbol
    :rtype: ghidra.program.model.symbol.Symbol
    """


@typing.overload
def getSymbolBefore(address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
    """
    Returns the previous non-default primary symbol defined
    after the previous address.
    
    :param ghidra.program.model.address.Address address: the address to use as a starting point
    :return: the next non-default primary symbol
    :rtype: ghidra.program.model.symbol.Symbol
    """


def getSymbols(name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> java.util.List[ghidra.program.model.symbol.Symbol]:
    """
    Returns a list of all the symbols with the given name in the given namespace.
    
    :param java.lang.String or str name: the name of the symbols to retrieve.
    :param ghidra.program.model.symbol.Namespace namespace: the namespace containing the symbols, or null for the global namespace.
    :return: a list of all the symbols with the given name in the given namespace.
    :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
    """


def getUndefinedDataAfter(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the undefined data after the specified address or null if no undefined data exists.
    
    :param ghidra.program.model.address.Address address: the undefined data address
    :return: the undefined data after the specified address or null if no undefined data exists
    :rtype: ghidra.program.model.listing.Data
    """


def getUndefinedDataAt(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the undefined data at the specified address or null if no undefined data exists.
    
    :param ghidra.program.model.address.Address address: the undefined data address
    :return: the undefined data at the specified address or null if no undefined data exists
    :rtype: ghidra.program.model.listing.Data
    """


def getUndefinedDataBefore(address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
    """
    Returns the undefined data before the specified address or null if no undefined data exists.
    
    :param ghidra.program.model.address.Address address: the undefined data address
    :return: the undefined data before the specified address or null if no undefined data exists
    :rtype: ghidra.program.model.listing.Data
    """


def getUserName() -> str:
    """
    Returns the username of the user running the script.
    
    :return: the username of the user running the script
    :rtype: str
    """


@typing.overload
def goTo(address: ghidra.program.model.address.Address) -> bool:
    """
    Sends a 'goto' event that navigates the listing to the specified
    address.
    
    :param ghidra.program.model.address.Address address: the address to 'goto'
    :return: true if the address is valid
    :rtype: bool
    """


@typing.overload
def goTo(symbol: ghidra.program.model.symbol.Symbol) -> bool:
    """
    Sends a 'goto' event that navigates the listing to the specified symbol.
    
    :param ghidra.program.model.symbol.Symbol symbol: the symbol to 'goto'
    :return: true if the symbol is valid
    :rtype: bool
    """


@typing.overload
def goTo(function: ghidra.program.model.listing.Function) -> bool:
    """
    Sends a 'goto' event that navigates the listing to the specified function.
    
    :param ghidra.program.model.listing.Function function: the function to 'goto'
    :return: true if the function is valid
    :rtype: bool
    """


def importFile(file: jpype.protocol.SupportsPath) -> ghidra.program.model.listing.Program:
    """
    Attempts to import the specified file. It attempts to detect the format and
    automatically import the file. If the format is unable to be determined, then
    null is returned.  For more control over the import process, :obj:`AutoImporter` may be
    directly called.
     
    
    NOTE: The returned :obj:`Program` is not automatically saved into the current project.
     
    
    NOTE: It is the responsibility of the script that calls this method to release the returned
    :obj:`Program` with :meth:`DomainObject.release(Object consumer) <DomainObject.release>` when it is no longer
    needed, where ``consumer`` is ``this``.
    
    :param jpype.protocol.SupportsPath file: the file to import
    :return: the newly imported program, or null
    :rtype: ghidra.program.model.listing.Program
    :raises java.lang.Exception: if any exceptions occur while importing
    """


def importFileAsBinary(file: jpype.protocol.SupportsPath, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
    """
    Imports the specified file as raw binary.  For more control over the import process,
    :obj:`AutoImporter` may be directly called.
     
    
    NOTE: It is the responsibility of the script that calls this method to release the returned
    :obj:`Program` with :meth:`DomainObject.release(Object consumer) <DomainObject.release>` when it is no longer
    needed, where ``consumer`` is ``this``.
    
    :param jpype.protocol.SupportsPath file: the file to import
    :param ghidra.program.model.lang.Language language: the language of the new program
    :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compilerSpec to use for the import.
    :return: the newly created program, or null
    :rtype: ghidra.program.model.listing.Program
    :raises java.lang.Exception: if any exceptions occur when importing
    """


def isAnalysisOptionDefaultValue(program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str], analysisValue: typing.Union[java.lang.String, str]) -> bool:
    """
    Returns a boolean value representing whether the specified value for the specified
    analysis option is actually the default value for that option.
    
    :param ghidra.program.model.listing.Program program: the program for which we want to verify the analysis option value
    :param java.lang.String or str analysisOption: the analysis option whose value we want to verify
    :param java.lang.String or str analysisValue: the analysis value to be compared to the option's default value
    :return: whether the given value for the given option is default or not
    :rtype: bool
    """


def isRunningHeadless() -> bool:
    """
    Returns whether this script is running in a headless (Non GUI) environment.
     
    
    This method should not be using GUI type script calls like showAddress()
    
    :return: true if the script is running without a GUI.
    :rtype: bool
    """


def loadPropertiesFile():
    ...


def loadVariablesFromState():
    ...


def openDataTypeArchive(archiveFile: jpype.protocol.SupportsPath, readOnly: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.FileDataTypeManager:
    """
    Opens an existing File Data Type Archive.
     
    
    **NOTE:** If archive has an assigned architecture, issues may arise due to a revised or
    missing :obj:`Language`/:obj:`CompilerSpec` which will result in a warning but not
    prevent the archive from being opened.  Such a warning condition will be logged and may 
    result in missing or stale information for existing datatypes which have architecture related
    data.  In some case it may be appropriate to 
    :meth:`check for warnings <FileDataTypeManager.getWarning>` on the returned archive
    object prior to its use.
    
    :param jpype.protocol.SupportsPath archiveFile: the archive file to open
    :param jpype.JBoolean or bool readOnly: should file be opened read only
    :return: the data type manager
    :rtype: ghidra.program.model.data.FileDataTypeManager
    :raises java.lang.Exception: if there is any exception
    """


def openProgram(program: ghidra.program.model.listing.Program):
    """
    Opens the specified program in the current tool.
    
    :param ghidra.program.model.listing.Program program: the program to open
    """


def parseAddress(val: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
    """
    Parses an address from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The address that was parsed from the string.
    :rtype: ghidra.program.model.address.Address
    :raises IllegalArgumentException: if there was a problem parsing an address from the string.
    """


def parseBoolean(val: typing.Union[java.lang.String, str]) -> bool:
    """
    Parses a boolean from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The boolean that was parsed from the string.
    :rtype: bool
    :raises IllegalArgumentException: if the parsed value is not a valid boolean.
    """


def parseBytes(val: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
    """
    Parses bytes from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The bytes that were parsed from the string.
    :rtype: jpype.JArray[jpype.JByte]
    :raises IllegalArgumentException: if there was a problem parsing bytes from the string.
    """


def parseChoice(val: typing.Union[java.lang.String, str], validChoices: java.util.List[T]) -> T:
    """
    Parses a choice from a string.
    
    :param java.lang.String or str val: The string to parse.
    :param java.util.List[T] validChoices: An array of valid choices.
    :return: The choice
    :rtype: T
    :raises IllegalArgumentException: if the parsed string was not a valid choice.
    """


@typing.overload
def parseChoices(s: typing.Union[java.lang.String, str], validChoices: java.util.List[T]) -> java.util.List[T]:
    """
    Parses choices from a string.  The string must be surrounded by quotes, with a ';' as the
    separator.
    
    :param java.lang.String or str s: The string to parse.
    :param java.util.List[T] validChoices: An array of valid choices.
    :return: The choices, if they found in the array of choices.
    :rtype: java.util.List[T]
    :raises IllegalArgumentException: if the parsed string did not contain any valid choices.
    """


@typing.overload
def parseChoices(val: typing.Union[java.lang.String, str], validChoices: java.util.List[T], stringRepresentationOfValidChoices: java.util.List[java.lang.String]) -> java.util.List[T]:
    """
    Parses choices from a string.
    
    :param java.lang.String or str val: The string to parse.
    :param java.util.List[T] validChoices: A list of valid choices.
    :param java.util.List[java.lang.String] stringRepresentationOfValidChoices: An corresponding array of valid choice string
            representations.
    :return: The choices
    :rtype: java.util.List[T]
    :raises IllegalArgumentException: if the parsed string did not contain any valid choices.
    """


def parseDirectory(val: typing.Union[java.lang.String, str]) -> java.io.File:
    """
    Parses a directory from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The directory that was parsed from the string.
    :rtype: java.io.File
    :raises IllegalArgumentException: if the parsed value is not a valid directory.
    """


def parseDomainFile(val: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
    """
    Parses a DomainFile from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The DomainFile that was parsed from the string.
    :rtype: ghidra.framework.model.DomainFile
    :raises IllegalArgumentException: if the parsed value is not a valid DomainFile.
    """


def parseDouble(val: typing.Union[java.lang.String, str]) -> float:
    """
    Parses a double from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The double that was parsed from the string.
    :rtype: float
    :raises IllegalArgumentException: if the parsed value is not a valid double.
    """


def parseInt(val: typing.Union[java.lang.String, str]) -> int:
    """
    Parses an integer from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The integer that was parsed from the string.
    :rtype: int
    :raises IllegalArgumentException: if the parsed value is not a valid integer.
    """


def parseLanguageCompileSpecPair(val: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
    """
    Parses a LanguageCompilerSpecPair from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The directory that was parsed from the LanguageCompilerSpecPair.
    :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
    :raises IllegalArgumentException: if the parsed value is not a valid LanguageCompilerSpecPair.
    """


def parseLong(val: typing.Union[java.lang.String, str]) -> int:
    """
    Parses a long from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The long that was parsed from the string.
    :rtype: int
    :raises IllegalArgumentException: if the parsed value is not a valid long.
    """


def parseProjectFolder(val: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFolder:
    """
    Parses a ProjectFolder from a string.
    
    :param java.lang.String or str val: The string to parse.
    :return: The ProjectFolder that was parsed from the string.
    :rtype: ghidra.framework.model.DomainFolder
    :raises IllegalArgumentException: if the parsed value is not a valid ProjectFolder.
    """


def popup(message: typing.Union[java.lang.String, str]):
    """
    Displays a popup dialog with the specified message. The dialog title
    will be the name of this script.
     
    
    In headless mode, the message is displayed in the log output.
    
    :param java.lang.String or str message: the message to display in the dialog
    """


def print(message: typing.Union[java.lang.String, str]):
    """
    Prints the message to the console - no line feed
     
    
    **Note: This method will not print out the name of the script,
    as does :meth:`println(String) <.println>`**
     
    
    If you would like the name of the script to precede you message, then you must add that
    yourself.  The :meth:`println(String) <.println>` does this via the following code:
     
        String messageWithSource = getScriptName() + "> " + message;
     
    
    :param java.lang.String or str message: the message to print
    
    .. seealso::
    
        | :obj:`.printf(String, Object...)`
    """


def printerr(message: typing.Union[java.lang.String, str]):
    """
    Prints the error message to the console followed by a line feed.
    
    :param java.lang.String or str message: the error message to print
    """


def printf(message: typing.Union[java.lang.String, str], *args: java.lang.Object):
    """
    A convenience method to print a formatted String using Java's ``printf``
    feature, which is similar to that of the C programming language.
    For a full description on Java's
    ``printf`` usage, see :obj:`java.util.Formatter`.
     
    
    For examples, see the included ``FormatExampleScript``.
     
    
    **Note: This method will not:**
     
    * print out the name of the script, as does :meth:`println(String) <.println>`
    * print a newline
    
    If you would like the name of the script to precede you message, then you must add that
    yourself.  The :meth:`println(String) <.println>` does this via the following code:
     
        String messageWithSource = getScriptName() + "> " + message;
     
    
    :param java.lang.String or str message: the message to format
    :param jpype.JArray[java.lang.Object] args: formatter arguments (see above)
    
    .. seealso::
    
        | :obj:`String.format(String, Object...)`
    
        | :obj:`java.util.Formatter`
    
        | :obj:`.print(String)`
    
        | :obj:`.println(String)`
    """


@typing.overload
def println():
    """
    Prints a newline.
    
    
    .. seealso::
    
        | :obj:`.printf(String, Object...)`
    """


@typing.overload
def println(message: typing.Union[java.lang.String, str]):
    """
    Prints the message to the console followed by a line feed.
    
    :param java.lang.String or str message: the message to print
    
    .. seealso::
    
        | :obj:`.printf(String, Object...)`
    """


def promptToKeepChangesOnException() -> bool:
    ...


def removeBookmark(bookmark: ghidra.program.model.listing.Bookmark):
    """
    Removes the specified bookmark.
    
    :param ghidra.program.model.listing.Bookmark bookmark: the bookmark to remove
    """


def removeData(data: ghidra.program.model.listing.Data):
    """
    Removes the given data from the current program.
    
    :param ghidra.program.model.listing.Data data: the data to remove
    :raises java.lang.Exception: if there is any exception
    """


def removeDataAt(address: ghidra.program.model.address.Address):
    """
    Removes the data containing the given address from the current program.
    
    :param ghidra.program.model.address.Address address: the address to remove data
    :raises java.lang.Exception: if there is any exception
    """


def removeEntryPoint(address: ghidra.program.model.address.Address):
    """
    Removes the entry point at the specified address.
    
    :param ghidra.program.model.address.Address address: address of entry point to remove
    """


@typing.overload
def removeEquate(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
    """
    Removes the equate defined at the operand index of the instruction with the given value.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index
    :param jpype.JLong or int value: scalar value corresponding to equate
    """


@typing.overload
def removeEquate(data: ghidra.program.model.listing.Data):
    """
    Removes the equate defined on the data.
    
    :param ghidra.program.model.listing.Data data: the data
    """


def removeEquates(instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int]):
    """
    Removes the equates defined at the operand index of the instruction.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction
    :param jpype.JInt or int operandIndex: the operand index
    """


def removeFunction(function: ghidra.program.model.listing.Function):
    """
    Removes the function from the current program.
    
    :param ghidra.program.model.listing.Function function: the function to remove
    """


def removeFunctionAt(entryPoint: ghidra.program.model.address.Address):
    """
    Removes the function with the given entry point.
    
    :param ghidra.program.model.address.Address entryPoint: the entry point of the function to remove
    """


def removeHighlight():
    """
    Clears the current highlight. Sets this script's highlight state (both the local variable
    currentHighlight and the ghidraState's currentHighlight) to null.  Also clears the tool's
    highlight if the tool exists.
    """


def removeInstruction(instruction: ghidra.program.model.listing.Instruction):
    """
    Removes the given instruction from the current program.
    
    :param ghidra.program.model.listing.Instruction instruction: the instruction to remove
    :raises java.lang.Exception: if there is any exception
    """


def removeInstructionAt(address: ghidra.program.model.address.Address):
    """
    Removes the instruction containing the given address from the current program.
    
    :param ghidra.program.model.address.Address address: the address to remove instruction
    :raises java.lang.Exception: if there is any exception
    """


def removeMemoryBlock(block: ghidra.program.model.mem.MemoryBlock):
    """
    Remove the memory block.
    NOTE: ALL ANNOTATION (disassembly, comments, etc) defined in this
    memory block will also be removed!
    
    :param ghidra.program.model.mem.MemoryBlock block: the block to be removed
    :raises java.lang.Exception: if there is any exception
    """


def removeReference(reference: ghidra.program.model.symbol.Reference):
    """
    Removes the given reference.
    
    :param ghidra.program.model.symbol.Reference reference: the reference to remove
    """


def removeSelection():
    """
    Clears the current selection.  Calling this method is equivalent to calling
    :meth:`setCurrentSelection(AddressSetView) <.setCurrentSelection>` with a null or empty AddressSet.
    """


def removeSymbol(address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> bool:
    """
    Deletes the symbol with the specified name at the specified address.
    
    :param ghidra.program.model.address.Address address: the address of the symbol to delete
    :param java.lang.String or str name: the name of the symbol to delete
    :return: true if the symbol was deleted
    :rtype: bool
    """


def resetAllAnalysisOptions(program: ghidra.program.model.listing.Program):
    """
    Reset all analysis options to their default values.
    
    :param ghidra.program.model.listing.Program program: the program for which all analysis options should be reset
    """


def resetAnalysisOption(program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str]):
    """
    Reset one analysis option to its default value.
    
    :param ghidra.program.model.listing.Program program: the program for which the specified analysis options should be reset
    :param java.lang.String or str analysisOption: the specified analysis option to reset (invalid options will be
                ignored)
    """


def resetAnalysisOptions(program: ghidra.program.model.listing.Program, analysisOptions: java.util.List[java.lang.String]):
    """
    Resets a specified list of analysis options to their default values.
    
    :param ghidra.program.model.listing.Program program: the program for which the specific analysis options should be reset
    :param java.util.List[java.lang.String] analysisOptions: the specified analysis options to reset (invalid options
                will be ignored)
    """


def run():
    """
    The run method is where the script specific code is placed.
    
    :raises java.lang.Exception: if any exception occurs.
    """


@typing.overload
def runCommand(cmd: ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]) -> bool:
    """
    Runs the specified command using the current program.
    
    :param ghidra.framework.cmd.Command[ghidra.program.model.listing.Program] cmd: the command to run
    :return: true if the command successfully ran
    :rtype: bool
    """


@typing.overload
def runCommand(cmd: ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]) -> bool:
    """
    Runs the specified background command using the current program.
    The command will be given the script task monitor.
    
    :param ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program] cmd: the background command to run
    :return: true if the background command successfully ran
    :rtype: bool
    """


@typing.overload
def runScript(scriptName: typing.Union[java.lang.String, str]):
    """
    Runs a script by name (allows current state to be changed by script).
     
    
    It attempts to locate the script in the directories
    defined in ``GhidraScriptUtil.getScriptDirectories()``.
     
    
    The script being run uses the same :obj:`GhidraState` (e.g., script variables) as
    this calling script.  Also, any changes to the state by the script being run will be
    reflected in this calling script's state.
    
    :param java.lang.String or str scriptName: the name of the script to run
    :raises IllegalArgumentException: if the script does not exist
    :raises java.lang.Exception: if any exceptions occur while running the script
    
    .. seealso::
    
        | :obj:`.runScriptPreserveMyState(String)`
    
        | :obj:`.runScript(String, GhidraState)`
    """


@typing.overload
def runScript(scriptName: typing.Union[java.lang.String, str], scriptArguments: jpype.JArray[java.lang.String]):
    """
    Runs a script by name with the provided arguments (allows current state to be changed by
    script).
     
    
    It attempts to locate the script in the directories
    defined in ``GhidraScriptUtil.getScriptDirectories()``.
     
    
    The script being run uses the same :obj:`GhidraState` (e.g., script variables) as
    this calling script.  Also, any changes to the state by the script being run will be
    reflected in this calling script's state.
    
    :param java.lang.String or str scriptName: the name of the script to run
    :param jpype.JArray[java.lang.String] scriptArguments: the arguments to pass to the script
    :raises IllegalArgumentException: if the script does not exist
    :raises java.lang.Exception: if any exceptions occur while running the script
    
    .. seealso::
    
        | :obj:`.runScriptPreserveMyState(String)`
    
        | :obj:`.runScript(String, GhidraState)`
    """


@typing.overload
def runScript(scriptName: typing.Union[java.lang.String, str], scriptState: GhidraState):
    """
    Runs a script by name using the given state.
     
    
    It attempts to locate the script in the directories
    defined in ``GhidraScriptUtil.getScriptDirectories()``.
     
    
    The script being run uses the given :obj:`GhidraState` (e.g., script variables)
    Any changes to the state by the script being run will be reflected in the given state
    object.  If the given object is the current state, this scripts state may be changed
    by the called script.
    
    :param java.lang.String or str scriptName: the name of the script to run
    :param GhidraState scriptState: the Ghidra state
    :raises IllegalArgumentException: if the script does not exist
    :raises java.lang.Exception: if any exceptions occur while running the script
    
    .. seealso::
    
        | :obj:`.runScriptPreserveMyState(String)`
    
        | :obj:`.runScript(String)`
    """


@typing.overload
def runScript(scriptName: typing.Union[java.lang.String, str], scriptArguments: jpype.JArray[java.lang.String], scriptState: GhidraState):
    """
    Runs a script by name with the given arguments using the given state.
     
    
    It attempts to locate the script in the directories
    defined in ``GhidraScriptUtil.getScriptDirectories()``.
     
    
    The script being run uses the given :obj:`GhidraState` (e.g., script variables)
    Any changes to the state by the script being run will be reflected in the given state
    object.  If the given object is the current state, this scripts state may be changed
    by the called script.
    
    :param java.lang.String or str scriptName: the name of the script to run
    :param jpype.JArray[java.lang.String] scriptArguments: the arguments to pass to the script
    :param GhidraState scriptState: the Ghidra state
    :raises IllegalArgumentException: if the script does not exist
    :raises java.lang.Exception: if any exceptions occur while running the script
    
    .. seealso::
    
        | :obj:`.runScriptPreserveMyState(String)`
    
        | :obj:`.runScript(String)`
    """


def runScriptPreserveMyState(scriptName: typing.Union[java.lang.String, str]) -> GhidraState:
    """
    Runs a script by name (does not allow current state to change).
     
    
    It attempts to locate the script in the directories
    defined in ``GhidraScriptUtil.getScriptDirectories()``.
     
    
    The script being run uses the same :obj:`GhidraState` (e.g., script variables) as
    this calling script.  However, any changes to the state by the script being run will NOT
    be reflected in this calling script's state.
    
    :param java.lang.String or str scriptName: the name of the script to run
    :return: a GhidraState object containing the final state of the run script.
    :rtype: GhidraState
    :raises IllegalArgumentException: if the script does not exist
    :raises java.lang.Exception: if any exceptions occur while running the script
    
    .. seealso::
    
        | :obj:`.runScript(String)`
    
        | :obj:`.runScript(String, GhidraState)`
    """


@typing.overload
def saveProgram(program: ghidra.program.model.listing.Program):
    """
    Saves the changes to the specified program.
    If the program does not already exist in the current project
    then it will be saved into the root folder.
    If a program already exists with the specified
    name, then a time stamp will be appended to the name to make it unique.
    
    :param ghidra.program.model.listing.Program program: the program to save
    :raises java.lang.Exception: if there is any exception
    """


@typing.overload
def saveProgram(program: ghidra.program.model.listing.Program, path: java.util.List[java.lang.String]):
    """
    Saves changes to the specified program.
     
    
    If the program does not already exist in the current project
    then it will be saved into a project folder path specified by the path parameter.
     
    
    If path is NULL, the program will be saved into the root folder.  If parts of the path are
    missing, they will be created if possible.
     
    
    If a program already exists with the specified name, then a time stamp will be appended
    to the name to make it unique.
    
    :param ghidra.program.model.listing.Program program: the program to save
    :param java.util.List[java.lang.String] path: list of string path elements (starting at the root of the project) that specify
    the project folder to save the program info.  Example: { "folder1", "subfolder2",
    "final_folder" }
    :raises java.lang.Exception: if there is any exception
    """


def setAnalysisOption(program: ghidra.program.model.listing.Program, optionName: typing.Union[java.lang.String, str], optionValue: typing.Union[java.lang.String, str]):
    """
    Allows user to set one analysis option by passing in the analysis option to
    be changed and the new value of that option. This method does the work of
    converting the option value to its actual object type (if needed).
    
    :param ghidra.program.model.listing.Program program: the program for which analysis options should be set
    :param java.lang.String or str optionName: the name of the option to be set
    :param java.lang.String or str optionValue: the new value of the option
    """


def setAnalysisOptions(program: ghidra.program.model.listing.Program, analysisSettings: collections.abc.Mapping):
    """
    Allows user to set analysis options by passing a mapping of analysis option to
    desired value.  This method does the work of converting the option value to its
    actual object type (if needed).
    
    :param ghidra.program.model.listing.Program program: the program for which analysis options should be set
    :param collections.abc.Mapping analysisSettings: a mapping from analysis options to desired new settings
    """


def setAnonymousServerCredentials() -> bool:
    """
    Enable use of anonymous read-only user connection to Ghidra Server in place of
    fixed username/password credentials.
     
    
    NOTE: Only used for Headless environment, other GUI environments should
    continue to prompt user for login credentials as needed.
    
    :return: true if active project is either private or shared project is
    connected to its server repository.  False is returned if not active
    project or an active shared project failed to connect.
    :rtype: bool
    """


@typing.overload
def setBackgroundColor(address: ghidra.program.model.address.Address, color: java.awt.Color):
    """
    Sets the background of the Listing at the given address to the given color.  See the
    Listing help page in Ghidra help for more information.
     
    
    This method is unavailable in headless mode.
     
    
    Note: you can use the :obj:`ColorizingService` directly to access more color changing
    functionality.  See the source code of this method to learn how to access services from
    a script.
    
    :param ghidra.program.model.address.Address address: The address at which to set the color
    :param java.awt.Color color: The color to set
    :raises ImproperUseException: if this method is run in headless mode
    
    .. seealso::
    
        | :obj:`.setBackgroundColor(AddressSetView, Color)`
    
        | :obj:`.clearBackgroundColor(Address)`
    
        | :obj:`ColorizingService`
    """


@typing.overload
def setBackgroundColor(addresses: ghidra.program.model.address.AddressSetView, color: java.awt.Color):
    """
    Sets the background of the Listing at the given addresses to the given color.  See the
    Listing help page in Ghidra help for more information.
     
    
    This method is unavailable in headless mode.
     
    
    Note: you can use the :obj:`ColorizingService` directly to access more color changing
    functionality.  See the source code of this method to learn how to access services from
    a script.
    
    :param ghidra.program.model.address.AddressSetView addresses: The addresses at which to set the color
    :param java.awt.Color color: The color to set
    :raises ImproperUseException: if this method is run in headless mode
    
    .. seealso::
    
        | :obj:`.setBackgroundColor(Address, Color)`
    
        | :obj:`.clearBackgroundColor(AddressSetView)`
    
        | :obj:`ColorizingService`
    """


def setByte(address: ghidra.program.model.address.Address, value: typing.Union[jpype.JByte, int]):
    """
    Sets the 'byte' value at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the 'byte'
    :param jpype.JByte or int value: the value to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setBytes(address: ghidra.program.model.address.Address, values: jpype.JArray[jpype.JByte]):
    """
    Sets the 'byte' values starting at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the bytes
    :param jpype.JArray[jpype.JByte] values: the values to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setCurrentHighlight(addressSet: ghidra.program.model.address.AddressSetView):
    """
    Sets the highlight state to the given address set.
     
    
    The actual behavior of the method depends on your environment, which can be GUI or
    headless:
     
    1. In the GUI environment this method will set the :obj:`.currentHighlight`
    variable to the given value, update the:obj:`GhidraState`'s highlight variable,
    and will set the Tool's highlight to the given value.
    2. In the headless environment this method will set the :obj:`.currentHighlight`
    variable to    the given value and update the GhidraState's highlight variable.
    
    
    :param ghidra.program.model.address.AddressSetView addressSet: the set of addresses to include in the highlight.  If this value is null,
    the current highlight will be cleared and the variables set to null.
    """


def setCurrentLocation(address: ghidra.program.model.address.Address):
    """
    Set the script :obj:`.currentAddress`, :obj:`.currentLocation`, and update state object.
    
    :param ghidra.program.model.address.Address address: the new address
    """


def setCurrentSelection(addressSet: ghidra.program.model.address.AddressSetView):
    """
    Sets the selection state to the given address set.
     
    
    The actual behavior of the method depends on your environment, which can be GUI or
    headless:
     
    1. In the GUI environment this method will set the :obj:`.currentSelection`
    variable to the given value, update the:obj:`GhidraState`'s selection
    variable,and will set the Tool's selection to the given value.
    2. In the headless environment this method will set the :obj:`.currentSelection`
    variable to the given value and update the GhidraState's selection variable.
    
    
    :param ghidra.program.model.address.AddressSetView addressSet: the set of addresses to include in the selection.  If this value is null,
    the current selection will be cleared and the variables set to null.
    """


def setDouble(address: ghidra.program.model.address.Address, value: typing.Union[jpype.JDouble, float]):
    """
    Sets the 'double' value at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the 'double'
    :param jpype.JDouble or float value: the value to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setEOLComment(address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
    """
    Sets an EOL comment at the specified address
    
    :param ghidra.program.model.address.Address address: the address to set the EOL comment
    :param java.lang.String or str comment: the EOL comment
    :return: true if the EOL comment was successfully set
    :rtype: bool
    """


def setFloat(address: ghidra.program.model.address.Address, value: typing.Union[jpype.JFloat, float]):
    """
    Sets the 'float' value at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the 'float'
    :param jpype.JFloat or float value: the value to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setInt(address: ghidra.program.model.address.Address, value: typing.Union[jpype.JInt, int]):
    """
    Sets the 'integer' value at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the 'integer'
    :param jpype.JInt or int value: the value to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setLong(address: ghidra.program.model.address.Address, value: typing.Union[jpype.JLong, int]):
    """
    Sets the 'long' value at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the 'long'
    :param jpype.JLong or int value: the value to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setPlateComment(address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
    """
    Sets a PLATE comment at the specified address
    
    :param ghidra.program.model.address.Address address: the address to set the PLATE comment
    :param java.lang.String or str comment: the PLATE comment
    :return: true if the PLATE comment was successfully set
    :rtype: bool
    """


def setPostComment(address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
    """
    Sets a POST comment at the specified address
    
    :param ghidra.program.model.address.Address address: the address to set the POST comment
    :param java.lang.String or str comment: the POST comment
    :return: true if the POST comment was successfully set
    :rtype: bool
    """


def setPotentialPropertiesFileLocations(locations: java.util.List[generic.jar.ResourceFile]):
    """
    Set potential locations of .properties files for scripts (including subscripts).
    This should be used when the .properties file is not located in the same directory
    as the script, and the user has supplied one or more potential locations for the
    .properties file(s).
    
    :param java.util.List[generic.jar.ResourceFile] locations: directories that contain .properties files
    """


def setPreComment(address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
    """
    Sets a PRE comment at the specified address
    
    :param ghidra.program.model.address.Address address: the address to set the PRE comment
    :param java.lang.String or str comment: the PRE comment
    :return: true if the PRE comment was successfully set
    :rtype: bool
    """


def setPropertiesFile(propertiesFile: jpype.protocol.SupportsPath):
    """
    Explicitly set the .properties file (used if a ResourceFile representing the
    GhidraScript is not available -- i.e., if running GhidraScript from a .class file
    or instantiating the actual GhidraScript object directly).
    
    :param jpype.protocol.SupportsPath propertiesFile: the actual .properties file for this GhidraScript
    :raises IOException: if there is an exception reading the properties
    """


def setPropertiesFileLocation(dirLocation: typing.Union[java.lang.String, str], basename: typing.Union[java.lang.String, str]):
    """
    Explicitly set the .properties file location and basename for this script (used
    if a ResourceFile representing the GhidraScript is not available -- i.e., if
    running GhidraScript from a .class file or instantiating the actual GhidraScript
    object directly).
    
    :param java.lang.String or str dirLocation: String representation of the path to the .properties file
    :param java.lang.String or str basename: base name of the file
    :raises IOException: if there is an exception loading the new properties file
    """


@typing.overload
def setReferencePrimary(reference: ghidra.program.model.symbol.Reference):
    """
    Sets the given reference as primary.
    
    :param ghidra.program.model.symbol.Reference reference: the reference to mark as primary
    """


@typing.overload
def setReferencePrimary(reference: ghidra.program.model.symbol.Reference, primary: typing.Union[jpype.JBoolean, bool]):
    """
    Sets the given reference as primary.
    
    :param ghidra.program.model.symbol.Reference reference: the reference
    :param jpype.JBoolean or bool primary: true if primary, false not primary
    """


def setRepeatableComment(address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
    """
    Sets a repeatable comment at the specified address
    
    :param ghidra.program.model.address.Address address: the address to set the repeatable comment
    :param java.lang.String or str comment: the repeatable comment
    :return: true if the repeatable comment was successfully set
    :rtype: bool
    """


def setReusePreviousChoices(reuse: typing.Union[jpype.JBoolean, bool]):
    """
    Sets whether the user's previously selected values should be used when showing the various
    ``ask`` methods.   This is true by default, meaning that previous choices will be shown
    instead of any provided default value.
    
    :param jpype.JBoolean or bool reuse: true to reuse values; false to not reuse previous values
    """


def setScriptArgs(scriptArgs: jpype.JArray[java.lang.String]):
    """
    Sets script-specific arguments
    
    :param jpype.JArray[java.lang.String] scriptArgs: The script-specific arguments to use.  For no scripts, use null or an
    empty array.
    """


def setServerCredentials(username: typing.Union[java.lang.String, str], password: typing.Union[java.lang.String, str]) -> bool:
    """
    Establishes fixed login credentials for Ghidra Server access.
     
    
    NOTE: Only used for Headless environment, other GUI environments should
    continue to prompt user for login credentials as needed.
    
    :param java.lang.String or str username: login name or null if not applicable or to use default name
    :param java.lang.String or str password: login password
    :return: true if active project is either private or shared project is
    connected to its server repository.  False is returned if not active
    project or an active shared project failed to connect.
    :rtype: bool
    """


def setShort(address: ghidra.program.model.address.Address, value: typing.Union[jpype.JShort, int]):
    """
    Sets the 'short' value at the specified address.
    
    :param ghidra.program.model.address.Address address: the address to set the 'short'
    :param jpype.JShort or int value: the value to set
    :raises MemoryAccessException: if memory does not exist or is uninitialized
    """


def setSourceFile(sourceFile: generic.jar.ResourceFile):
    """
    Set associated source file
    
    :param generic.jar.ResourceFile sourceFile: the source file
    """


def setToolStatusMessage(msg: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
    """
    Display a message in tools status bar.
     
    
    This method is unavailable in headless mode.
    
    :param java.lang.String or str msg: the text to display.
    :param jpype.JBoolean or bool beep: if true, causes the tool to beep.
    :raises ImproperUseException: if this method is run in headless mode
    """


@typing.overload
def show(addresses: jpype.JArray[ghidra.program.model.address.Address]):
    """
    Displays the address array in a table component. The table contains an address
    column, a label column, and a preview column.
     
    
    This method is unavailable in headless mode.
    
    :param jpype.JArray[ghidra.program.model.address.Address] addresses: the address array to display
    :raises ImproperUseException: if this method is run in headless mode
    """


@typing.overload
def show(title: typing.Union[java.lang.String, str], addresses: ghidra.program.model.address.AddressSetView):
    """
    Displays the given AddressSet in a table, in a dialog.
     
    
    This method is unavailable in headless mode.
    
    :param java.lang.String or str title: The title of the table
    :param ghidra.program.model.address.AddressSetView addresses: The addresses to display
    :raises ImproperUseException: if this method is run in headless mode
    """


def start():
    """
    Starts a transaction on the current program.
    """


@typing.overload
def toAddr(offset: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
    """
    Returns a new address with the specified offset in the default address space.
    
    :param jpype.JInt or int offset: the offset for the new address
    :return: a new address with the specified offset in the default address space
    :rtype: ghidra.program.model.address.Address
    """


@typing.overload
def toAddr(offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
    """
    Returns a new address with the specified offset in the default address space.
    
    :param jpype.JLong or int offset: the offset for the new address
    :return: a new address with the specified offset in the default address space
    :rtype: ghidra.program.model.address.Address
    """


@typing.overload
def toAddr(addressString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
    """
    Returns a new address inside the specified program as indicated by the string.
    
    :param java.lang.String or str addressString: string representation of the address desired
    :return: the address. Otherwise, return null if the string fails to evaluate
    to a legitimate address
    :rtype: ghidra.program.model.address.Address
    """


@typing.overload
def toHexString(b: typing.Union[jpype.JByte, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
    """
    Returns a hex string representation of the byte.
    
    :param jpype.JByte or int b: the integer
    :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
    :param jpype.JBoolean or bool header: true if "0x" should be prepended
    :return: the hex formatted string
    :rtype: str
    """


@typing.overload
def toHexString(s: typing.Union[jpype.JShort, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
    """
    Returns a hex string representation of the short.
    
    :param jpype.JShort or int s: the short
    :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
    :param jpype.JBoolean or bool header: true if "0x" should be prepended
    :return: the hex formatted string
    :rtype: str
    """


@typing.overload
def toHexString(i: typing.Union[jpype.JInt, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
    """
    Returns a hex string representation of the integer.
    
    :param jpype.JInt or int i: the integer
    :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
    :param jpype.JBoolean or bool header: true if "0x" should be prepended
    :return: the hex formatted string
    :rtype: str
    """


@typing.overload
def toHexString(l: typing.Union[jpype.JLong, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
    """
    Returns a hex string representation of the long.
    
    :param jpype.JLong or int l: the long
    :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
    :param jpype.JBoolean or bool header: true if "0x" should be prepended
    :return: the hex formatted string
    :rtype: str
    """


def updateStateFromVariables():
    ...


__all__ = ["MAX_REFERENCES_TO", "currentProgram", "monitor", "sourceFile", "state", "writer", "currentAddress", "currentLocation", "currentSelection", "currentHighlight", "propertiesFileParams", "potentialPropertiesFileLocs", "addEntryPoint", "addInstructionXref", "analyze", "analyzeAll", "analyzeChanges", "askAddress", "askBytes", "askChoice", "askChoices", "askDirectory", "askDomainFile", "askDouble", "askFile", "askInt", "askLanguage", "askLong", "askPassword", "askProgram", "askProjectFolder", "askString", "askValues", "askYesNo", "cleanup", "clearBackgroundColor", "clearListing", "closeProgram", "createAddressSet", "createAsciiString", "createBookmark", "createByte", "createChar", "createClass", "createDWord", "createData", "createDouble", "createDwords", "createEquate", "createExternalReference", "createFloat", "createFragment", "createFunction", "createHighlight", "createLabel", "createMemoryBlock", "createMemoryReference", "createNamespace", "createProgram", "createQWord", "createSelection", "createStackReference", "createSymbol", "createTableChooserDialog", "createUnicodeString", "createWord", "disassemble", "end", "execute", "find", "findBytes", "findPascalStrings", "findStrings", "getAddressFactory", "getAnalysisOptionDefaultValue", "getAnalysisOptionDefaultValues", "getAnalysisOptionDescription", "getAnalysisOptionDescriptions", "getBookmarks", "getByte", "getBytes", "getCategory", "getCodeUnitFormat", "getCurrentAnalysisOptionsAndValues", "getCurrentProgram", "getDataAfter", "getDataAt", "getDataBefore", "getDataContaining", "getDataTypes", "getDefaultLanguage", "getDemangled", "getDouble", "getEOLComment", "getEOLCommentAsRendered", "getEquate", "getEquates", "getFirstData", "getFirstFunction", "getFirstInstruction", "getFloat", "getFragment", "getFunction", "getFunctionAfter", "getFunctionAt", "getFunctionBefore", "getFunctionContaining", "getGhidraVersion", "getGlobalFunctions", "getInstructionAfter", "getInstructionAt", "getInstructionBefore", "getInstructionContaining", "getInt", "getLanguage", "getLastData", "getLastFunction", "getLastInstruction", "getLong", "getMemoryBlock", "getMemoryBlocks", "getMonitor", "getNamespace", "getPlateComment", "getPlateCommentAsRendered", "getPostComment", "getPostCommentAsRendered", "getPreComment", "getPreCommentAsRendered", "getProgramFile", "getProjectRootFolder", "getReference", "getReferencesFrom", "getReferencesTo", "getRepeatableComment", "getRepeatableCommentAsRendered", "getReusePreviousChoices", "getScriptAnalysisMode", "getScriptArgs", "getScriptName", "getShort", "getSourceFile", "getState", "getSymbol", "getSymbolAfter", "getSymbolAt", "getSymbolBefore", "getSymbols", "getUndefinedDataAfter", "getUndefinedDataAt", "getUndefinedDataBefore", "getUserName", "goTo", "importFile", "importFileAsBinary", "isAnalysisOptionDefaultValue", "isRunningHeadless", "loadPropertiesFile", "loadVariablesFromState", "openDataTypeArchive", "openProgram", "parseAddress", "parseBoolean", "parseBytes", "parseChoice", "parseChoices", "parseDirectory", "parseDomainFile", "parseDouble", "parseInt", "parseLanguageCompileSpecPair", "parseLong", "parseProjectFolder", "popup", "print", "printerr", "printf", "println", "promptToKeepChangesOnException", "removeBookmark", "removeData", "removeDataAt", "removeEntryPoint", "removeEquate", "removeEquates", "removeFunction", "removeFunctionAt", "removeHighlight", "removeInstruction", "removeInstructionAt", "removeMemoryBlock", "removeReference", "removeSelection", "removeSymbol", "resetAllAnalysisOptions", "resetAnalysisOption", "resetAnalysisOptions", "run", "runCommand", "runScript", "runScriptPreserveMyState", "saveProgram", "setAnalysisOption", "setAnalysisOptions", "setAnonymousServerCredentials", "setBackgroundColor", "setByte", "setBytes", "setCurrentHighlight", "setCurrentLocation", "setCurrentSelection", "setDouble", "setEOLComment", "setFloat", "setInt", "setLong", "setPlateComment", "setPostComment", "setPotentialPropertiesFileLocations", "setPreComment", "setPropertiesFile", "setPropertiesFileLocation", "setReferencePrimary", "setRepeatableComment", "setReusePreviousChoices", "setScriptArgs", "setServerCredentials", "setShort", "setSourceFile", "setToolStatusMessage", "show", "start", "toAddr", "toHexString", "updateStateFromVariables"]
