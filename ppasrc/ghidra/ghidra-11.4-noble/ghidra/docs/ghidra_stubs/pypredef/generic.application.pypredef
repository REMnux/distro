from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.framework
import java.lang # type: ignore
import java.util # type: ignore
import utility.application


class GenericApplicationLayout(utility.application.ApplicationLayout):
    """
    A low-level implementation of :obj:`ApplicationLayout` that is suitable for basic applications.
    This class makes use of the :obj:`Module <GModule>` system to find application components at
    runtime.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], version: typing.Union[java.lang.String, str]):
        """
        Constructs a new application layout object with the given name and version.
        
        :param java.lang.String or str name: The name of the application.
        :param java.lang.String or str version: The version of the application.
        :raises IOException: if there was a problem getting a user directory.
        """

    @typing.overload
    def __init__(self, applicationProperties: ghidra.framework.ApplicationProperties):
        """
        Constructs a new application layout object with the given set of application
        properties.  The default Ghidra application root directory(s) will be used.
        
        :param ghidra.framework.ApplicationProperties applicationProperties: The properties object that will be read system properties.
        :raises IOException: if there was a problem getting a user directory.
        """

    @typing.overload
    def __init__(self, applicationRootDirs: collections.abc.Sequence, applicationProperties: ghidra.framework.ApplicationProperties):
        """
        Constructs a new application layout object with the given set of application
        properties.
        
        :param collections.abc.Sequence applicationRootDirs: list of application root directories which should be
        used to identify modules and resources.  The first entry will be treated as the
        installation root.
        :param ghidra.framework.ApplicationProperties applicationProperties: The properties object that will be read system properties.
        :raises IOException: if there was a problem getting a user directory.
        """

    @staticmethod
    def getDefaultApplicationRootDirs() -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Get the default list of Application directories.  In repo-based development mode this
        includes the root Ghidra directory within each repo.  When not in development mode, the
        requirement is that the current working directory correspond to the installation root.  The
        first entry will be the primary root in both cases.
        
        :return: root directories
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """



__all__ = ["GenericApplicationLayout"]
