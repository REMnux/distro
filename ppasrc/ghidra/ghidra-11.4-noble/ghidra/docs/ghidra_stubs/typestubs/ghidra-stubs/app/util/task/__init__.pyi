from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.progmgr
import ghidra.framework.model
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


class ProgramOpener(java.lang.Object):
    """
    Helper class that contains the logic for opening program for all the various program locations
    and program states. It handles opening DomainFiles, URLs, versioned DomainFiles, and links
    to DomainFiles. It also handles upgrades and checkouts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, consumer: java.lang.Object):
        """
        Constructs this class with a consumer to use when opening a program.
        
        :param java.lang.Object consumer: the consumer for opening a program
        """

    def openProgram(self, locator: ghidra.app.plugin.core.progmgr.ProgramLocator, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Program:
        """
        Opens the program for the given location.
        This method is intended to be invoked from within a :obj:`Task` or for headless operations.
        
        :param ghidra.app.plugin.core.progmgr.ProgramLocator locator: the program location to open
        :param ghidra.util.task.TaskMonitor monitor: the TaskMonitor used for status and cancelling
        :return: the opened program or null if the operation failed or was cancelled
        :rtype: ghidra.program.model.listing.Program
        """

    def setNoCheckout(self):
        """
        Invoking this method prior to task execution will prevent the use of optional checkout which
        require prompting the user.
        """

    def setPromptText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text to use for the base action type for various prompts that can appear
        when opening programs. (The default is "Open".) For example, you may want to override
        this so be something like "Open Source", or "Open target".
        
        :param java.lang.String or str text: the text to use as the base action name.
        """

    def setSilent(self):
        """
        Invoking this method prior to task execution will prevent any confirmation interaction with
        the user (e.g., optional checkout, snapshot recovery, etc.).  Errors may still be displayed
        if they occur.
        """


class OpenProgramTask(ghidra.util.task.Task):
    """
    Task for opening one or more programs.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, programLocatorList: java.util.List[ghidra.app.plugin.core.progmgr.ProgramLocator], consumer: java.lang.Object):
        """
        Construct a task for opening one or more programs.
        
        :param java.util.List[ghidra.app.plugin.core.progmgr.ProgramLocator] programLocatorList: the list of program locations to open
        :param java.lang.Object consumer: the consumer to use for opening the programs
        """

    @typing.overload
    def __init__(self, locator: ghidra.app.plugin.core.progmgr.ProgramLocator, consumer: java.lang.Object):
        """
        Construct a task for opening a program.
        
        :param ghidra.app.plugin.core.progmgr.ProgramLocator locator: the program location to open
        :param java.lang.Object consumer: the consumer to use for opening the programs
        """

    @typing.overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int], consumer: java.lang.Object):
        """
        Construct a task for opening a program
        
        :param ghidra.framework.model.DomainFile domainFile: the :obj:`DomainFile` to open
        :param jpype.JInt or int version: the version to open (versions other than the current version will be
        opened read-only)
        :param java.lang.Object consumer: the consumer to use for opening the programs
        """

    @typing.overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, consumer: java.lang.Object):
        """
        Construct a task for opening the current version of a program
        
        :param ghidra.framework.model.DomainFile domainFile: the :obj:`DomainFile` to open
        :param java.lang.Object consumer: the consumer to use for opening the programs
        """

    @typing.overload
    def __init__(self, ghidraURL: java.net.URL, consumer: java.lang.Object):
        """
        Construct a task for opening a program from a URL
        
        :param java.net.URL ghidraURL: the URL to the program to be opened
        :param java.lang.Object consumer: the consumer to use for opening the programs
        """

    def getOpenProgram(self) -> OpenProgramRequest:
        """
        Get the first successful open program request
        
        :return: first successful open program request or null if none
        :rtype: OpenProgramRequest
        """

    def getOpenPrograms(self) -> java.util.List[OpenProgramRequest]:
        """
        Get all successful open program requests
        
        :return: all successful open program requests
        :rtype: java.util.List[OpenProgramRequest]
        """

    def setNoCheckout(self):
        """
        Invoking this method prior to task execution will prevent
        the use of optional checkout which require prompting the
        user.
        """

    def setOpenPromptText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text to use for the base action type for various prompts that can appear
        when opening programs. (The default is "Open".) For example, you may want to override
        this so be something like "Open Source", or "Open target".
        
        :param java.lang.String or str text: the text to use as the base action name.
        """

    def setSilent(self):
        """
        Invoking this method prior to task execution will prevent
        any confirmation interaction with the user (e.g., 
        optional checkout, snapshot recovery, etc.).  Errors
        may still be displayed if they occur.
        """

    @property
    def openProgram(self) -> OpenProgramRequest:
        ...

    @property
    def openPrograms(self) -> java.util.List[OpenProgramRequest]:
        ...


class OpenProgramRequest(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, locator: ghidra.app.plugin.core.progmgr.ProgramLocator, consumer: java.lang.Object):
        ...

    def getLocator(self) -> ghidra.app.plugin.core.progmgr.ProgramLocator:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the open Program instance which corresponds to this open request.
        
        :return: program instance or null if never opened.
        :rtype: ghidra.program.model.listing.Program
        """

    def release(self):
        """
        Release opened program.  This must be done once, and only once, on a successful 
        open request.  If handing ownership off to another consumer, they should be added
        as a program consumer prior to invoking this method.  Releasing the last consumer
        will close the program instance.
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def locator(self) -> ghidra.app.plugin.core.progmgr.ProgramLocator:
        ...



__all__ = ["ProgramOpener", "OpenProgramTask", "OpenProgramRequest"]
