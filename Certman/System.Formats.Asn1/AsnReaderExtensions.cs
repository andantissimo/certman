namespace System.Formats.Asn1;

public static class AsnReaderExtensions
{
    public static IEnumerable<(Asn1Tag Tag, ReadOnlyMemory<byte> Content)> ReadValues(this AsnReader reader)
    {
        while (reader.HasData)
        {
            yield return (reader.PeekTag(), reader.PeekContentBytes());
            _ = reader.ReadEncodedValue();
        }
    }
}
