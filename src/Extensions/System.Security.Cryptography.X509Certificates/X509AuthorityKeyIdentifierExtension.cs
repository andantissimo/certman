namespace System.Security.Cryptography.X509Certificates;

public class X509AuthorityKeyIdentifierExtension : X509Extension
{
    public X509AuthorityKeyIdentifierExtension(ReadOnlySpan<byte> authorityKeyIdentifier, bool critical)
        : base(Encode(authorityKeyIdentifier), critical)
    {
    }

    public X509AuthorityKeyIdentifierExtension(string authorityKeyIdentifier, bool critical)
        : this(Convert.FromHexString(authorityKeyIdentifier), critical)
    {
    }

    public static AsnEncodedData Encode(ReadOnlySpan<byte> authorityKeyIdentifier)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteOctetString(authorityKeyIdentifier, new(TagClass.ContextSpecific, 0));
        writer.PopSequence();
        return new(new Oid(Oids.AuthorityKeyIdentifier, "Authority Key Identifier"), writer.Encode());
    }
}
