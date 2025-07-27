from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin.format.dwarf
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore


class StorageVerificationDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Downgrades the function's signature commit mode to FORMAL-param-info-only if there are
    problems with param storage info.
     
    
    Does not check the function's return value storage as that typically won't have information
    because DWARF does not specify that.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ParamSpillDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Steal storage location from parameters that are defined in a function's local variable
    area, because the storage location isn't the parameter location during call, but its location
    after being spilled.
     
    Create a local variable at that storage location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SanityCheckDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Check for errors and prevent probable bad function info from being locked in
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DWARFFunctionFixup(ghidra.util.classfinder.ExtensionPoint):
    """
    Interface for add-in logic to fix/modify/tweak DWARF functions before they are written 
    to the Ghidra program.
     
    
    Use ``@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_*)`` to
    control the order of evaluation (higher numbers are run earlier).
     
    
    Fixups are found using :obj:`ClassSearcher`, and their class names must end
    in "DWARFFunctionFixup" (see ExtensionPoint.manifest). 
     
    
    Instance lifetime:
     
    
    New instances are not shared between programs or analysis sessions, but will be re-used to
    handle the various functions found in a single binary.
     
     
    If the implementation also implements :obj:`Closeable`, it will be called when the fixup
    is no longer needed.
    """

    class_: typing.ClassVar[java.lang.Class]
    PRIORITY_NORMAL_EARLY: typing.Final = 4000
    PRIORITY_NORMAL: typing.Final = 3000
    PRIORITY_NORMAL_LATE: typing.Final = 2000
    PRIORITY_LAST: typing.Final = 1000

    @staticmethod
    def findFixups() -> java.util.List[DWARFFunctionFixup]:
        """
        Return a list of all current :obj:`fixups <DWARFFunctionFixup>` found in the classpath
        by ClassSearcher.
        
        :return: list of all current fixups found in the classpath
        :rtype: java.util.List[DWARFFunctionFixup]
        """

    def fixupDWARFFunction(self, dfunc: ghidra.app.util.bin.format.dwarf.DWARFFunction):
        """
        Called before a :obj:`DWARFFunction` is used to create a Ghidra Function.
         
        
        If processing of the function should terminate (and the function be skipped), throw
        a :obj:`DWARFException`.
        
        :param ghidra.app.util.bin.format.dwarf.DWARFFunction dfunc: :obj:`DWARFFunction` info read from DWARF about the function
        """


class OutputParamCheckDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Complains about function parameters that are marked as 'output' and don't have storage
    locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RustDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Adjust functions in a Rust compile unit to use Rust calling convention, ignore any information
    about parameter storage locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ThisCallingConventionDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Update the function's calling convention (if unset) if there is a "this" parameter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ParamNameDWARFFunctionFixup(DWARFFunctionFixup):
    """
    Ensures that function parameter names are unique and valid
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["StorageVerificationDWARFFunctionFixup", "ParamSpillDWARFFunctionFixup", "SanityCheckDWARFFunctionFixup", "DWARFFunctionFixup", "OutputParamCheckDWARFFunctionFixup", "RustDWARFFunctionFixup", "ThisCallingConventionDWARFFunctionFixup", "ParamNameDWARFFunctionFixup"]
