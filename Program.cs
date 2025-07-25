using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using SmartCampusConnectBackend.Services;
using SmartCampusConnectBackend.Models;
using Microsoft.Extensions.FileProviders;
using SmartCampusConnectBackend.Hubs; // Add this using statement for your Hubs namespace
using System.Security.Claims; // Needed for ClaimTypes.Role

var builder = WebApplication.CreateBuilder(args);

// Explicitly tell Kestrel to listen on all available network interfaces for HTTP on port 5000.
// This makes the backend accessible from other devices on the same local network using your Mac's IP.
builder.WebHost.UseUrls("http://0.0.0.0:5000");


// Add services to the container.
// Configure MongoDB settings from appsettings.json
builder.Services.Configure<MongoDBSettings>(
    builder.Configuration.GetSection("MongoDB"));

// Register MongoDBService as a Singleton so it's created once and reused
builder.Services.AddSingleton<MongoDBService>();

// Add controllers for handling HTTP API requests
builder.Services.AddControllers();

// Configure Swagger/OpenAPI for API documentation (useful for testing API endpoints)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure JWT Authentication
builder.Services.AddAuthentication(options =>
{
    // Set default schemes for authentication, challenge, and forbidden responses
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options => // Configure the JWT Bearer authentication handler
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Define parameters for validating incoming JWT tokens
        ValidIssuer = builder.Configuration["Jwt:Issuer"],       // Validate the issuer of the token
        ValidAudience = builder.Configuration["Jwt:Audience"],   // Validate the audience of the token
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)), // Validate the signing key
        ValidateIssuer = true,           // Ensure issuer validation is active
        ValidateAudience = true,         // Ensure audience validation is active
        ValidateLifetime = true,         // Ensure token expiration is checked
        ValidateIssuerSigningKey = true, // Ensure signing key validation is active

        // Map JWT claims to .NET Core user claims, specifically for roles
        RoleClaimType = ClaimTypes.Role // Tells the JWT bearer to use the "role" claim from the JWT as the standard ClaimTypes.Role
    };

    // Add SignalR specific JWT handling:
    // When a SignalR connection is established, the token is often passed in the query string.
    // This event handler extracts the token from the query string for SignalR requests.
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Query["access_token"];

            // Check if the request path starts with our SignalR hub path
            var path = context.HttpContext.Request.Path;
            if (!string.IsNullOrEmpty(accessToken) &&
                (path.StartsWithSegments("/chatHub"))) // Match the SignalR hub path (e.g., ws://localhost:5000/chatHub?access_token=...)
            {
                // If it's a SignalR request with an access_token in the query string, set it as the token
                context.Token = accessToken;
            }
            return Task.CompletedTask; // Return a completed task as this is an async event
        }
    };
});

// Add Authorization services
builder.Services.AddAuthorization(options =>
{
    // Define a policy named "AdminOnly" that requires the "admin" role
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
});

// Add SignalR services for real-time communication
builder.Services.AddSignalR();

// Configure CORS (Cross-Origin Resource Sharing) policy
// This is crucial for allowing your frontend (on a different port/domain) to communicate with your backend
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin", // Define a named CORS policy
        builder => builder.WithOrigins(
                                "http://127.0.0.1:5500",    // Localhost IP for frontend
                                "http://localhost:5500",    // Localhost hostname for frontend
                                "http://10.30.1.117:5500"   // Your Mac's local network IP for frontend (if testing from other devices)
                           )
                          .AllowAnyHeader()      // Allow all HTTP headers
                          .AllowAnyMethod()      // Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
                          .AllowCredentials());  // CRUCIAL: Allows sending credentials (like JWT tokens, cookies) with cross-origin requests. Required for SignalR.
});

var app = builder.Build(); // Build the application instance

// Configure the HTTP request pipeline (middleware order matters!)

// Enable Swagger UI in Development environment for API testing
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Redirect HTTP requests to HTTPS (if HTTPS is configured and available)
app.UseHttpsRedirection();

// Serve static files from the wwwroot folder (e.g., uploaded images)
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(builder.Environment.WebRootPath, "images")), // Path to your wwwroot/images folder
    RequestPath = "/images" // URL path to access these images (e.g., http://localhost:5000/images/myimage.jpg)
});

// IMPORTANT: UseCors must be placed BEFORE UseAuthentication and UseAuthorization
// This ensures CORS headers are added to the response before authentication/authorization checks occur.
app.UseCors("AllowSpecificOrigin");

// Enable Authentication middleware (processes JWT tokens, etc.)
app.UseAuthentication();

// Enable Authorization middleware (checks user roles and policies)
app.UseAuthorization();

// Map controller endpoints (e.g., /api/auth, /api/listings)
app.MapControllers();

// Map your SignalR Hub endpoint
app.MapHub<ChatHub>("/chatHub"); // Clients will connect to ws://localhost:5000/chatHub

app.Run(); // Run the application
