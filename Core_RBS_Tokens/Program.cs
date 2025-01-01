using Core_RBS_Tokens.Models;
using Core_RBS_Tokens.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Add services to the container.
builder.Services.AddDbContext<SecurityDbContext>(options => 
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SecurityConnStr"));
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    // Use the EF Core for Creating, Managing Users and Roles
    .AddEntityFrameworkStores<SecurityDbContext>();

builder.Services.AddScoped<SecurityServices>();

#region The JSON Serialization
builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = null; // Use Pascal case
    options.SerializerOptions.DictionaryKeyPolicy = null; // Use Pascal case
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});
#endregion


#region Define Policies
builder.Services.AddAuthorization(options =>
{
    builder.Services.AddAuthorizationBuilder()
        .AddPolicy("AdminPolicy", policy =>
        {
            policy.RequireRole("Administrator");
        })
        .AddPolicy("AdminManagerPolicy", policy =>
        {
            policy.RequireRole("Administrator", "Manager");
        })
        .AddPolicy("AdminManagerClerkPolicy", policy =>
        {
            policy.RequireRole("Administrator", "Manager", "Clerk");
        });

    options.AddPolicy("AdminManagerPolicy", (policy) =>
    {
        policy.RequireRole("Administrator", "Manager");
    });

    options.AddPolicy("AdminManagerClerkPolicy", (policy) =>
    {
        policy.RequireRole("Administrator", "Manager", "Clerk");
    });
});
#endregion


#region Token Validation
// Read the Secret Key from the appsettings.json
var secretKeyString = builder.Configuration["JWTCoreSettings:SecretKey"];
if (string.IsNullOrEmpty(secretKeyString))
{
    throw new InvalidOperationException("Secret key is not configured properly.");
}
byte[] secretKey = Convert.FromBase64String(secretKeyString);
// set the Authentication Scheme
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Validate the token by receiving the token from the Authorization Request Header
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(secretKey),
        ValidateIssuer = false,
        ValidateAudience = false
    };
    options.Events = new JwtBearerEvents
    {
        // If the Token is expired then respond
        OnAuthenticationFailed = context =>
        {
            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                context.Response.Headers.Append("Authentication-Token-Expired", "true");
            }
            return Task.CompletedTask;
        }
    };
})
.AddCookie(options =>
{
    options.Events.OnRedirectToAccessDenied =
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});
#endregion

#region The CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("cors", (policy) =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});
#endregion

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("cors");

#region The code for the Accessing Code for CReating Administrator User and Role
IServiceProvider serviceProvider = builder.Services.BuildServiceProvider();
await AdminCreatorService.CreateApplicationAdministrator(serviceProvider);
#endregion



#region APIs
app.MapPost("/api/createuser", () => { });
app.MapPost("/api/createrole", () => { });
app.MapPost("/api/approveuser", () => { });
app.MapPost("/api/authuser", () => { });
#endregion






app.Run();

 