namespace Certman.Converters;

public class X509Certificate2JsonConverter : JsonConverter<X509Certificate2>
{
    public override X509Certificate2? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotSupportedException();
    }

    public override void Write(Utf8JsonWriter writer, X509Certificate2 value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("subject", value.Subject);
        writer.WriteString("notAfter", value.NotAfter);
        writer.WriteString("notBefore", value.NotBefore);
        writer.WriteString("thumbprint", value.Thumbprint);
        if (value.GetSubjectAltName() is string[] san)
        {
            writer.WritePropertyName("subjectAltName");
            writer.WriteStartArray();
            foreach (var s in san)
                writer.WriteStringValue(s);
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
}
