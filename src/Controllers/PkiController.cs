﻿namespace Certman.Controllers;

[ApiController]
[Route("[controller]")]
public partial class PkiController : ControllerBase, IDisposable
{
    [GeneratedRegex(@"(?<=\bCN=)([^,]+)", RegexOptions.CultureInvariant)]
    private static partial Regex CommonNamePattern();

    [GeneratedRegex(@"[\s""#*/:<>?\\|]+", RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeCharPattern();

    private readonly ILogger _logger;

    private readonly X509Store _store;

    private IEnumerable<X509Certificate2> OwnCertificates => _store.Certificates.Where(c => c.HasPrivateKey);

    public PkiController(ILogger<PkiController> logger)
    {
        _logger = logger;

        _store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        _store.Open(OpenFlags.ReadWrite);
    }

    [HttpPost]
    public async Task<IActionResult> Import([FromForm] IFormFile file, [FromForm] string? password = null)
    {
        using var buffer = new MemoryStream((int)file.Length);
        await file.CopyToAsync(buffer).ConfigureAwait(false);
        try
        {
            using var cert = new X509Certificate2(
                buffer.ToArray(),
                password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            if (!cert.HasPrivateKey)
                return BadRequest("Private key required: {Name}", file.FileName);
            _store.Add(cert);
            return Ok(cert.Thumbprint);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return BadRequest("Invalid certificate file: {Name}", file.FileName);
        }
    }

    [HttpGet("ca")]
    [ResponseCache(NoStore = true)]
    public IActionResult GetAuthorities()
    {
        var authorities = OwnCertificates.Where(c => c.GetCertificateAuthority() == true);
        return new JsonResult(authorities);
    }

    [HttpPost("ca")]
    public IActionResult Issue([FromForm] string cn, [FromForm] int days = 3653)
    {
        var notBefore = HttpContext.Request.GetTypedHeaders().Date ?? DateTimeOffset.Now;

        X500DistinguishedName subject;
        try
        {
            subject = new($"CN={cn}");
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return BadRequest("Invalid CN: {CN}", cn);
        }
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true)
            );
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                critical: true)
            );
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(new PublicKey(key), critical: false)
            );
        using var cert = req.CreateSelfSigned(notBefore, notBefore + TimeSpan.FromDays(days));
        using var copy = cert.CopyWithKeyStorageFlags(X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        _store.Add(copy);
        return Ok(cert.Thumbprint);
    }

    [HttpGet("{thumbprint}")]
    [ResponseCache(NoStore = true)]
    public IActionResult GetChildren(string thumbprint)
    {
        var authority = OwnCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
        if (authority?.GetCertificateAuthority() != true)
            return NotFound();
        var authKeyId = authority.GetSubjectKeyIdentifier();
        if (authKeyId is null)
            return NotFound();
        var children = OwnCertificates
            .Where(c => c.Thumbprint != thumbprint && c.GetAuthorityKeyIdentifier() == authKeyId);
        return new JsonResult(children);
    }

    [HttpGet("{thumbprint}.crt")]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any)]
    public IActionResult GetCertificate(string thumbprint)
    {
        var cert = OwnCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
        if (cert is null)
            return NotFound();
        var pem = PemEncoding.Write("CERTIFICATE", cert.RawData);
        return File(Encoding.ASCII.GetBytes(pem), "application/x-pem-file", GetSafeFileName(cert, ".crt"));
    }

    [HttpGet("{thumbprint}.key")]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any)]
    public IActionResult GetPrivateKey(string thumbprint)
    {
        var cert = OwnCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
        if (cert is null)
            return NotFound();
        var key = cert.GetPrivateKey();
        if (key is null)
            return NotFound();
        using var exp = key.MakeExportable();
        var pem = PemEncoding.Write("PRIVATE KEY", exp.ExportPkcs8PrivateKey());
        return File(Encoding.ASCII.GetBytes(pem), "application/x-pem-file", GetSafeFileName(cert, ".key"));
    }

    [HttpGet("{thumbprint}.pfx")]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any)]
    public IActionResult Export(string thumbprint)
    {
        var cert = OwnCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
        if (cert is null)
            return NotFound();
        return File(cert.Export(X509ContentType.Pkcs12), "application/x-pkcs12", GetSafeFileName(cert, ".pfx"));
    }

    [HttpDelete("{thumbprint}")]
    public IActionResult Delete(string thumbprint)
    {
        var cert = OwnCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
        if (cert is null)
            return NoContent();
        if (cert.GetCertificateAuthority() == true && cert.GetSubjectKeyIdentifier() is string authKeyId)
        {
            var children = OwnCertificates
                .Where(c => c.Thumbprint != thumbprint && c.GetAuthorityKeyIdentifier() == authKeyId);
            foreach (var child in children.ToArray())
            {
                _store.Remove(child);
                child.Dispose();
            }
        }
        _store.Remove(cert);
        cert.Dispose();
        return NoContent();
    }

    [HttpPost("{thumbprint}")]
    public IActionResult Issue([FromRoute] string thumbprint, [FromForm] string cn, [FromForm] int days = 398, [FromForm] string[]? san = null)
    {
        var notBefore = HttpContext.Request.GetTypedHeaders().Date ?? DateTimeOffset.Now;
        var authority = OwnCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
        if (authority?.GetCertificateAuthority() != true)
            return NotFound();
        var authKeyId = authority.GetSubjectKeyIdentifier();
        if (authKeyId is null)
            return NotFound();
        var notAfter = notBefore + TimeSpan.FromDays(days);
        if (notAfter > authority.NotAfter)
            notAfter = authority.NotAfter;
        if (notBefore > notAfter)
            notBefore = notAfter;

        X500DistinguishedName subject;
        var sans = new SubjectAlternativeNameBuilder();
        try
        {
            subject = new($"CN={cn}");
            foreach (var name in new[] { cn }.Concat(san ?? []).Distinct())
            {
                if (IPAddress.TryParse(name, out var addr))
                    sans.AddIpAddress(addr);
                else
                    sans.AddDnsName(name);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return BadRequest("Invalid CN or SAN: {CN}, {SAN}", cn, san);
        }
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true)
            );
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                critical: true)
            );
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [X509EnhancedKeyUsages.ServerAuthentication, X509EnhancedKeyUsages.ClientAuthentication],
                critical: true)
            );
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(new PublicKey(key), critical: false)
            );
        req.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(Convert.FromHexString(authKeyId))
            );
        req.CertificateExtensions.Add(sans.Build());
        using var cert = req.Create(authority, notBefore, notAfter, Guid.NewGuid().ToByteArray())
                            .CopyWithPrivateKey(key);
        using var copy = cert.CopyWithKeyStorageFlags(X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        _store.Add(copy);
        return Ok(cert.Thumbprint);
    }

    public void Dispose()
    {
        _store?.Dispose();
        GC.SuppressFinalize(this);
    }

    private BadRequestResult BadRequest(string? message, params object?[] args)
    {
        #pragma warning disable CA2254
        _logger.LogDebug($"Bad request: {message}", args);
        #pragma warning restore CA2254
        return BadRequest();
    }

    private static string GetSafeFileName(X509Certificate2 cert, string suffix)
    {
        return $"{UnsafeCharPattern().Replace(CommonNamePattern().Match(cert.Subject).Value, "_")}{suffix}";
    }
}
