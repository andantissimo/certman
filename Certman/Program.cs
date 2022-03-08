var web = WebApplication.CreateBuilder(args);
web.Services.AddControllers()
    .AddJsonOptions(options => options.JsonSerializerOptions.Converters.Add(new X509Certificate2JsonConverter()));

var app = web.Build();
app.UseForwardedHeaders(new() { ForwardedHeaders = ForwardedHeaders.All });
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();
app.Run();
