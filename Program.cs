var builder = WebApplication.CreateBuilder(args);

// Bind to Railway PORT
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// Register minimal stuff for now
builder.Services.AddControllers();

var app = builder.Build();

// Comment OUT any auto-migrate for now (just to remove another failure point)
// using (var scope = app.Services.CreateScope())
// {
//     var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
//     db.Database.Migrate();
// }

// Simple health check
app.MapGet("/", () => "OK");

// Map controllers if you have them
app.MapControllers();

app.Run();
