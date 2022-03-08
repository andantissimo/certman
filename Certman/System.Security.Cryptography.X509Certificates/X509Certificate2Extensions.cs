namespace System.Security.Cryptography.X509Certificates;

public static class X509Certificate2Extensions
{
    public static X509Certificate2 CopyWithKeyStorageFlags(this X509Certificate2 certificate, X509KeyStorageFlags keyStorageFlags)
    {
        return new(certificate.Export(X509ContentType.Pkcs12), default(string), keyStorageFlags);
    }

    public static AsymmetricAlgorithm? GetPrivateKey(this X509Certificate2 certificate)
    {
        return certificate.GetRSAPrivateKey()
            ?? certificate.GetDSAPrivateKey()
            ?? certificate.GetECDsaPrivateKey()
            ?? certificate.GetECDiffieHellmanPrivateKey() as AsymmetricAlgorithm;
    }

    public static bool? GetCertificateAuthority(this X509Certificate2 certificate)
    {
        return certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority;
    }

    public static string? GetSubjectKeyIdentifier(this X509Certificate2 certificate)
    {
        return certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier;
    }

    public static string? GetAuthorityKeyIdentifier(this X509Certificate2 certificate)
    {
        var rawData = certificate.Extensions.FirstOrDefault(x => x.Oid?.Value == Oids.AuthorityKeyIdentifier)?.RawData;
        if (rawData is null)
            return null;
        var (_, content) = new AsnReader(rawData, AsnEncodingRules.BER).ReadSequence().ReadValues()
            .FirstOrDefault(v => v.Tag.TagClass == TagClass.ContextSpecific && v.Tag.TagValue == 0);
        if (content.IsEmpty)
            return null;
        return Convert.ToHexString(content.Span);
    }

    public static string[]? GetSubjectAltName(this X509Certificate2 certificate)
    {
        var rawData = certificate.Extensions.FirstOrDefault(x => x.Oid?.Value == Oids.SubjectAltName)?.RawData;
        if (rawData is null)
            return null;
        return new AsnReader(rawData, AsnEncodingRules.BER).ReadSequence().ReadValues()
            .Where(v => v.Tag.TagClass == TagClass.ContextSpecific)
            .Select(v => v.Tag.TagValue switch
            {
                2 => $"DNS:{Encoding.ASCII.GetString(v.Content.Span)}",
                7 => $"IP:{new IPAddress(v.Content.Span)}",
                _ => $"[{v.Tag.TagValue}]:{Convert.ToHexString(v.Content.Span)}",
            })
            .ToArray();
    }
}
