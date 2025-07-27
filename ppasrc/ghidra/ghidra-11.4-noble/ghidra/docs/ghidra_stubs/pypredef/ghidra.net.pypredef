from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework
import ghidra.security
import java.io # type: ignore
import java.lang # type: ignore
import java.net.http # type: ignore
import java.security # type: ignore
import java.util # type: ignore
import javax.net.ssl # type: ignore
import javax.security.auth.x500 # type: ignore
import javax.swing.filechooser # type: ignore


class HttpClients(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def clearHttpClient():
        """
        Clears the currently cached :obj:`HttpClient`, forcing it to be
        rebuilt during the next call to :meth:`getHttpClient() <.getHttpClient>`.
        """

    @staticmethod
    def getHttpClient() -> java.net.http.HttpClient:
        """
        Returns a shared, plain (no special options) :obj:`HttpClient`.
        
        :return: a :obj:`HttpClient`
        :rtype: java.net.http.HttpClient
        :raises IOException: if error in PKI settings or crypto configuration
        """

    @staticmethod
    def newHttpClientBuilder() -> java.net.http.HttpClient.Builder:
        """
        Creates a HttpClient Builder using Ghidra SSL/TLS context info.
        
        :return: a new HttpClient Builder
        :rtype: java.net.http.HttpClient.Builder
        :raises IOException: if error in PKI settings or crypto configuration
        """


class ApplicationKeyManagerUtils(java.lang.Object):
    """
    ``ApplicationKeyManagerUtils`` provides public methods for utilizing
    the application PKI key management, including access to trusted issuers
    (i.e., CA certificates), token signing and validation, and the ability to
    generate keystores for testing or when a self-signed certificate will
    suffice.
    """

    class_: typing.ClassVar[java.lang.Class]
    RSA_TYPE: typing.Final = "RSA"
    BEGIN_CERT: typing.Final = "-----BEGIN CERTIFICATE-----"
    END_CERT: typing.Final = "-----END CERTIFICATE-----"
    PKCS_FILE_EXTENSIONS: typing.Final[jpype.JArray[java.lang.String]]
    PKCS_FILENAME_FILTER: typing.Final[javax.swing.filechooser.FileNameExtensionFilter]

    @staticmethod
    def createKeyEntry(alias: typing.Union[java.lang.String, str], dn: typing.Union[java.lang.String, str], durationDays: typing.Union[jpype.JInt, int], caEntry: java.security.KeyStore.PrivateKeyEntry, keyFile: jpype.protocol.SupportsPath, keystoreType: typing.Union[java.lang.String, str], subjectAlternativeNames: collections.abc.Sequence, protectedPassphrase: jpype.JArray[jpype.JChar]) -> java.security.KeyStore.PrivateKeyEntry:
        """
        Generate a new :obj:`X509Certificate` with RSA :obj:`KeyPair` and create/update a :obj:`KeyStore`
        optionally backed by a keyFile.
        
        :param java.lang.String or str alias: entry alias with keystore
        :param java.lang.String or str dn: distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
        :param jpype.JInt or int durationDays: number of days which generated certificate should remain valid
        :param java.security.KeyStore.PrivateKeyEntry caEntry: optional CA private key entry.  If null, a self-signed CA certificate will be generated.
        :param jpype.protocol.SupportsPath keyFile: optional file to load/store resulting :obj:`KeyStore` (may be null)
        :param java.lang.String or str keystoreType: support keystore type (e.g., "JKS", "PKCS12")
        :param collections.abc.Sequence subjectAlternativeNames: an optional list of subject alternative names to be included 
                    in certificate (may be null)
        :param jpype.JArray[jpype.JChar] protectedPassphrase: key and keystore protection password
        :return: newly generated keystore entry with key pair
        :rtype: java.security.KeyStore.PrivateKeyEntry
        :raises KeyStoreException: if error occurs while updating keystore
        """

    @staticmethod
    def createKeyStore(alias: typing.Union[java.lang.String, str], dn: typing.Union[java.lang.String, str], durationDays: typing.Union[jpype.JInt, int], caEntry: java.security.KeyStore.PrivateKeyEntry, keyFile: jpype.protocol.SupportsPath, keystoreType: typing.Union[java.lang.String, str], subjectAlternativeNames: collections.abc.Sequence, protectedPassphrase: jpype.JArray[jpype.JChar]) -> java.security.KeyStore:
        """
        Generate a new :obj:`X509Certificate` with RSA :obj:`KeyPair` and create/update a :obj:`KeyStore`
        optionally backed by a keyFile.
        
        :param java.lang.String or str alias: entry alias with keystore
        :param java.lang.String or str dn: distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
        :param jpype.JInt or int durationDays: number of days which generated certificate should remain valid
        :param java.security.KeyStore.PrivateKeyEntry caEntry: optional CA private key entry.  If null, a self-signed CA certificate will be 
                    generated.
        :param jpype.protocol.SupportsPath keyFile: optional file to load/store resulting :obj:`KeyStore` (may be null)
        :param java.lang.String or str keystoreType: support keystore type (e.g., "JKS", "PKCS12")
        :param collections.abc.Sequence subjectAlternativeNames: an optional list of subject alternative names to be included 
                    in certificate (may be null)
        :param jpype.JArray[jpype.JChar] protectedPassphrase: key and keystore protection password
        :return: keystore containing newly generated certification with key pair
        :rtype: java.security.KeyStore
        :raises KeyStoreException: if error occurs while updating keystore
        """

    @staticmethod
    def exportX509Certificates(certificates: jpype.JArray[java.security.cert.Certificate], outFile: jpype.protocol.SupportsPath):
        """
        Export X.509 certificates to the specified outFile.
        
        :param jpype.JArray[java.security.cert.Certificate] certificates: certificates to be stored
        :param jpype.protocol.SupportsPath outFile: output file
        :raises IOException: if error occurs writing to outFile
        :raises CertificateEncodingException: if error occurs while encoding certificate data
        """

    @staticmethod
    def getSignedToken(authorities: jpype.JArray[java.security.Principal], token: jpype.JArray[jpype.JByte]) -> SignedToken:
        """
        Sign the supplied token byte array using an installed certificate from
        one of the specified authorities
        
        :param jpype.JArray[java.security.Principal] authorities: trusted certificate authorities
        :param jpype.JArray[jpype.JByte] token: token byte array
        :return: signed token object
        :rtype: SignedToken
        :raises NoSuchAlgorithmException: algorithym associated within signing certificate not found
        :raises SignatureException: failed to generate SignedToken
        :raises CertificateException: error associated with signing certificate
        """

    @staticmethod
    def getTrustedIssuers() -> jpype.JArray[javax.security.auth.x500.X500Principal]:
        """
        Returns a list of trusted issuers (i.e., CA certificates) as established
        by the :obj:`ApplicationTrustManagerFactory`.
        
        :return: array of trusted Certificate Authorities
        :rtype: jpype.JArray[javax.security.auth.x500.X500Principal]
        :raises CertificateException: if failed to properly initialize trust manager
        due to CA certificate error(s).
        """

    @staticmethod
    def isMySignature(authorities: jpype.JArray[java.security.Principal], token: jpype.JArray[jpype.JByte], signature: jpype.JArray[jpype.JByte]) -> bool:
        """
        Verify that the specified sigBytes reflect my signature of the specified
        token.
        
        :param jpype.JArray[java.security.Principal] authorities: trusted certificate authorities
        :param jpype.JArray[jpype.JByte] token: byte array token
        :param jpype.JArray[jpype.JByte] signature: token signature
        :return: true if signature is my signature
        :rtype: bool
        :raises NoSuchAlgorithmException: algorithym associated within signing certificate not found
        :raises SignatureException: failed to generate SignedToken
        :raises CertificateException: error associated with signing certificate
        """

    @staticmethod
    def validateClient(certChain: jpype.JArray[java.security.cert.X509Certificate], authType: typing.Union[java.lang.String, str]):
        """
        Validate a client certificate ensuring that it is not expired and is
        trusted based upon the active trust managers.
        
        :param jpype.JArray[java.security.cert.X509Certificate] certChain: X509 certificate chain
        :param java.lang.String or str authType: authentication type (i.e., "RSA")
        :raises CertificateException: if certificate validation fails
        """


class ApplicationSSLSocketFactory(javax.net.ssl.SSLSocketFactory):
    """
    ``ApplicationSSLSocketFactory`` provides a replacement for the default
    ``SSLSocketFactory`` which utilizes the default SSLContext established
    by :obj:`SSLContextInitializer`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        ApplicationSSLSocketFactory constructor.  
        SSLContext initialization will be performed using :obj:`SSLContextInitializer`.
        """


class ApplicationTrustManagerFactory(java.lang.Object):
    """
    ``ApplicationTrustManagerFactory`` provides the ability to establish
    acceptable certificate authorities to be used with SSL connections and PKI 
    authentication.  
     
    
    The default behavior is for no trust authority to be established, in which case 
    SSL peers will not be authenticated.  If CA certificates have been set, all SSL
    connections which leverage this factory will perform peer authentication.  If an error
    occurs while reading the CA certs file, all peer authentication will fail based upon the 
    inability to choose a suitable client/server certificate.
     
    
    The application X.509 CA certificates file may be in the standard form (*.pem, *.crt, 
    *.cer, *.der) or may be in a Java JKS form (*.jks). The path to this file may be 
    established in one of two ways using the absolute file path:
     
    1. setting the system property ghidra.cacerts (takes precedence)
    2. setting the user preference ghidra.cacerts
    
     
    
    The application may choose to set the file path automatically based upon the presence of
    a *cacerts* file at a predetermined location.
    """

    @typing.type_check_only
    class WrappedTrustManager(javax.net.ssl.X509TrustManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OpenTrustManager(javax.net.ssl.X509TrustManager):
        """
        ``OpenTrustManager`` provides a means of adopting an "open" trust policy
        where any peer certificate will be considered acceptable.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    GHIDRA_CACERTS_PATH_PROPERTY: typing.Final = "ghidra.cacerts"
    """
    The X509 cacerts file to be used when authenticating remote 
    certificates is identified by either a system property or user
    preference *ghidra.cacerts*.  The system property takes precedence.
    """


    @staticmethod
    def hasCertificateAuthorities() -> bool:
        """
        Determine if certificate authorities are in place.  If no certificate authorities
        have been specified via the "ghidra.cacerts" property, all certificates will be 
        trusted.
        
        :return: true if certificate authorities are in place, else false.
        :rtype: bool
        """


class ApplicationKeyManagerFactory(java.lang.Object):
    """
    ``ApplicationKeyManagerFactory`` provides application keystore management
    functionality and the ability to generate X509KeyManager's for use with an SSLContext
    or other PKI related operations.  Access to keystore data (other than keystore path)
    is restricted to package access.  Certain public operations are exposed via the
    :obj:`ApplicationKeyManagerUtils` class.
    """

    @typing.type_check_only
    class ProtectedKeyStoreData(java.lang.Object):
        """
        ``ProtectedKeyStoreData`` provides a container for a keystore
        which has been successfully accessed using the specified password.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ApplicationKeyManager(javax.net.ssl.X509ExtendedKeyManager):
        """
        ``ApplicationKeyManager`` provides a wrapper for the X509 wrappedKeyManager whose
        instantiation is delayed until needed.  When a wrapper method is first invoked, the
        :meth:`ApplicationKeyManagerFactory.init() <ApplicationKeyManagerFactory.init>` method is called to open the keystore
        (which may require a password prompt) and establish the underlying X509KeyManager.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    KEYSTORE_PATH_PROPERTY: typing.Final = "ghidra.keystore"
    """
    Keystore path system property or user preference.  Setting the system
    property will take precedence over the user preference.
    """

    KEYSTORE_PASSWORD_PROPERTY: typing.Final = "ghidra.password"
    """
    Password system property may be set.  If set, this password will be used
    when accessing the keystore before attempting to use ``customPasswordProvider``
    if it has been set.
    """

    DEFAULT_PASSWORD: typing.Final = "changeme"

    @staticmethod
    def addSubjectAlternativeName(subjectAltName: typing.Union[java.lang.String, str]):
        """
        Add the optional self-signed subject alternative name to be used during initialization
        if no keystore defined.  Current application key manager will be invalidated.
        (NOTE: this is intended for server use only when client will not be performing
        CA validation).
        
        :param java.lang.String or str subjectAltName: name to be added to the current list of alternative subject names.
        A null value will clear all names currently set.  
        name will be used to generate a self-signed certificate and private key
        """

    @staticmethod
    def getKeyStore() -> str:
        """
        Get the keystore path associated with the active key manager or the
        preferred keystore path if not yet initialized.
        """

    @staticmethod
    def getPreferredKeyStore() -> str:
        """
        If the system property *ghidra.keystore* takes precedence in establishing 
        the keystore.  If using a GUI and the system property has not been set, the 
        user preference with the same name will be used.
        
        :return: active keystore path or null if currently not running with a keystore or
        one has not been set.
        :rtype: str
        """

    @staticmethod
    def getSubjectAlternativeName() -> java.util.List[java.lang.String]:
        """
        Get the current list of subject alternative names to be used for a self-signed certificate
        if no keystore defined.
        
        :return: list of subject alternative names to be used for a self-signed certificate
        if no keystore defined.
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def initialize() -> bool:
        """
        Initialize key manager if needed.  Doing this explicitly independent of an SSL connection
        allows application to bail before initiating connection.  This will get handshake failure
        if user forgets keystore password or other keystore problem.
        
        :return: true if key manager initialized, otherwise false
        :rtype: bool
        """

    @staticmethod
    def invalidateKeyManagers():
        """
        Invalidate the key managers associated with this factory
        """

    @staticmethod
    def setDefaultIdentity(identity: javax.security.auth.x500.X500Principal):
        """
        Set the default self-signed principal identity to be used during initialization
        if no keystore defined.  Current application key manager will be invalidated.
        (NOTE: this is intended for server use only when client will not be performing
        CA validation).
        
        :param javax.security.auth.x500.X500Principal identity: if not null and a KeyStore path has not be set, this
        identity will be used to generate a self-signed certificate and private key
        """

    @staticmethod
    def setKeyStore(path: typing.Union[java.lang.String, str], savePreference: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Set user keystore file path (e.g., certificate file with private key).
        This method will have no effect if the keystore had been set via the system
        property and an error will be displayed.  Otherwise, the keystore will
        be updated and the key manager re-initialized.  The user preference will be
        updated unless a failure occurred while attempting to open the keystore.
        This change will take immediate effect for the current executing application,
        however, it may still be superseded by a system property setting when running
        the application in the future. See :meth:`getKeyStore() <.getKeyStore>`.
        
        :param java.lang.String or str path: keystore file path or null to clear current key store and preference.
        :param jpype.JBoolean or bool savePreference: if true will be saved as user preference
        :return: true if successful else false if error occured (see log).
        :rtype: bool
        """

    @staticmethod
    def setKeyStorePasswordProvider(provider: ghidra.security.KeyStorePasswordProvider):
        """
        Set the active keystore password provider
        
        :param ghidra.security.KeyStorePasswordProvider provider: keystore password provider
        """

    @staticmethod
    def usingGeneratedSelfSignedCertificate() -> bool:
        """
        Determine if active key manager is utilizing a generated self-signed certificate.
        
        :return: true if using self-signed certificate.
        :rtype: bool
        """


class SignedToken(java.lang.Object):
    """
    ``SignedToken`` provides the result of a signed token byte array.
    """

    class_: typing.ClassVar[java.lang.Class]
    token: typing.Final[jpype.JArray[jpype.JByte]]
    """
    Original token byte array
    """

    signature: typing.Final[jpype.JArray[jpype.JByte]]
    """
    Token byte array signature
    """

    algorithm: typing.Final[java.lang.String]
    """
    Algorithm used for signing
    """

    certChain: typing.Final[jpype.JArray[java.security.cert.X509Certificate]]
    """
    Identity which corresponds to signature
    """



class SSLContextInitializer(ghidra.framework.ModuleInitializer):
    """
    Initialize the default SSLContext for use by all SSL connections (e.g., https).
    It is the responsibility of the Application to properly invoke this initializer 
    to ensure that the default SSLContext is properly established. While HTTPS URL connections
    will make use of this default SSLContext, other SSL connections may need to 
    specify the :obj:`ApplicationSSLSocketFactory` to leverage the applications
    default SSLContext.
     
    
    The property ``jdk.tls.client.protocols`` should be set to restrict secure
    client connections to a specific set of enabled TLS protocols (e.g., TLSv1.2,TLSv1.3).
    See `JDK and JRE Cryptographic Algorithms <https://java.com/en/configure_crypto.html>`_ 
    for details.
    
    
    .. seealso::
    
        | :obj:`ApplicationTrustManagerFactory`
    
        | :obj:`ApplicationKeyManagerFactory`
    
        | :obj:`ApplicationKeyManagerUtils`
    """

    class HttpsHostnameVerifier(javax.net.ssl.HostnameVerifier):
        """
        ``HttpsHostnameVerifier`` is required by HttpsURLConnection even
        if it does nothing.  The verify method will only be invoked if the default 
        behavior fails the connection attempt due to a hostname mismatch.
        
        
        .. seealso::
        
            | :obj:`HttpsURLConnection.setHostnameVerifier(HostnameVerifier)`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def initialize(reset: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Initialize default SSLContext with optional reset.
        This method is primarily intended for testing.
        
        :param jpype.JBoolean or bool reset: if true a complete reset will be done to force use of
        any new certificate or keystores previously used.
        :return: true if successful, else false (see logged error)
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def initialize() -> bool:
        """
        Initialize default SSLContext
        
        :return: true if successful, else false (see logged error)
        :rtype: bool
        """


@typing.type_check_only
class ApplicationKeyStore(java.lang.Object):
    """
    ``ApplicationKeyStore`` provides the ability to read X.509 certificates and 
    keystores in various formats. Certificate files (e.g., cacerts) may be in a standard
    X.509 form (*.pem, *.crt, *.cer, *.der) or Java JKS (*.jks) form, while keystores 
    for client/server may be in a PKCS12 form (*.p12, *.pks, *.pfx) or Java JKS (*.jks) form.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["HttpClients", "ApplicationKeyManagerUtils", "ApplicationSSLSocketFactory", "ApplicationTrustManagerFactory", "ApplicationKeyManagerFactory", "SignedToken", "SSLContextInitializer", "ApplicationKeyStore"]
