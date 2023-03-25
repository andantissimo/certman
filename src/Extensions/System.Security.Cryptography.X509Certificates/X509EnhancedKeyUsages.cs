namespace System.Security.Cryptography.X509Certificates;

public static class X509EnhancedKeyUsages
{
    public static readonly Oid ServerAuthentication = new("1.3.6.1.5.5.7.3.1", "Server Authentication");
    public static readonly Oid ClientAuthentication = new("1.3.6.1.5.5.7.3.2", "Client Authentication");
    public static readonly Oid CodeSigning          = new("1.3.6.1.5.5.7.3.3", "Code Signing");
}
