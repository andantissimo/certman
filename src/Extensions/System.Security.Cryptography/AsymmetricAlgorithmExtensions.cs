namespace System.Security.Cryptography;

public static class AsymmetricAlgorithmExtensions
{
    /// <summary>
    /// <see href="https://github.com/dotnet/runtime/blob/v6.0.0/src/libraries/System.Security.Cryptography.Pkcs/tests/PrivateKeyHelpers.cs"/>
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    public static AsymmetricAlgorithm MakeExportable(this AsymmetricAlgorithm key)
    {
        const CngExportPolicies Exportability = CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport;

        if (key is RSACng rsa && (rsa.Key.ExportPolicy & Exportability) == CngExportPolicies.AllowExport)
        {
            var copy = RSA.Create();
            copy.ImportEncryptedPkcs8PrivateKey(
                nameof(MakeExportable),
                rsa.ExportEncryptedPkcs8PrivateKey(
                    nameof(MakeExportable),
                    new(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048)
                    ),
                out _);
            return copy;
        }

        if (key is DSACng dsa && (dsa.Key.ExportPolicy & Exportability) == CngExportPolicies.AllowExport)
        {
            var copy = DSA.Create();
            copy.ImportEncryptedPkcs8PrivateKey(
                nameof(MakeExportable),
                dsa.ExportEncryptedPkcs8PrivateKey(
                    nameof(MakeExportable),
                    new(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048)
                    ),
                out _);
            return copy;
        }

        if (key is ECDsaCng ecdsa && (ecdsa.Key.ExportPolicy & Exportability) == CngExportPolicies.AllowExport)
        {
            var copy = ECDsa.Create();
            copy.ImportEncryptedPkcs8PrivateKey(
                nameof(MakeExportable),
                ecdsa.ExportEncryptedPkcs8PrivateKey(
                    nameof(MakeExportable),
                    new(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048)
                    ),
                out _);
            return copy;
        }

        if (key is ECDiffieHellmanCng ecdh && (ecdh.Key.ExportPolicy & Exportability) == CngExportPolicies.AllowExport)
        {
            var copy = ECDiffieHellman.Create();
            copy.ImportEncryptedPkcs8PrivateKey(
                nameof(MakeExportable),
                ecdh.ExportEncryptedPkcs8PrivateKey(
                    nameof(MakeExportable),
                    new(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048)
                    ),
                out _);
            return copy;
        }

        return key;
    }
}
