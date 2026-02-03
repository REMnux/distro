from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.security
import java.io # type: ignore
import java.lang # type: ignore
import org.bouncycastle.crypto # type: ignore


class SSHKeyManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def getSSHPrivateKey(sshPrivateKeyFile: jpype.protocol.SupportsPath) -> org.bouncycastle.crypto.CipherParameters:
        """
        Return the SSH private key corresponding to the specified key file.
        If the specified key file is encrypted the currently installed password
        provider will be used to obtain the decrypt password.
        
        :param jpype.protocol.SupportsPath sshPrivateKeyFile: private ssh key file
        :return: private key cipher parameters (:obj:`RSAKeyParameters` or :obj:`DSAKeyParameters`)
        :rtype: org.bouncycastle.crypto.CipherParameters
        :raises FileNotFoundException: key file not found
        :raises IOException: if key file not found or key parse failed
        :raises InvalidKeyException: if key is not an SSH private key (i.e., PEM format)
        """

    @staticmethod
    @typing.overload
    def getSSHPrivateKey(sshPrivateKeyIn: java.io.InputStream) -> org.bouncycastle.crypto.CipherParameters:
        """
        Return the SSH private key corresponding to the specified key input stream.
        If the specified key is encrypted the currently installed password
        provider will be used to obtain the decrypt password.
        
        :param java.io.InputStream sshPrivateKeyIn: private ssh key resource input stream
        :return: private key cipher parameters (:obj:`RSAKeyParameters` or :obj:`DSAKeyParameters`)
        :rtype: org.bouncycastle.crypto.CipherParameters
        :raises FileNotFoundException: key file not found
        :raises IOException: if key file not found or key parse failed
        :raises InvalidKeyException: if key is not an SSH private key (i.e., PEM format)
        """

    @staticmethod
    def getSSHPublicKey(sshPublicKeyFile: jpype.protocol.SupportsPath) -> org.bouncycastle.crypto.CipherParameters:
        """
        Attempt to instantiate an SSH public key from the specified file
        which contains a single public key.
        
        :param jpype.protocol.SupportsPath sshPublicKeyFile: public ssh key file
        :return: public key cipher parameters :obj:`RSAKeyParameters` or :obj:`DSAKeyParameters`
        :rtype: org.bouncycastle.crypto.CipherParameters
        :raises FileNotFoundException: key file not found
        :raises IOException: if key file not found or key parse failed
        """

    @staticmethod
    def setProtectedKeyStorePasswordProvider(provider: ghidra.security.KeyStorePasswordProvider):
        """
        Set PKI protected keystore password provider
        
        :param ghidra.security.KeyStorePasswordProvider provider: key store password provider
        """



__all__ = ["SSHKeyManager"]
