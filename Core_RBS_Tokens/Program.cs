using Core_RBS_Tokens.Models;
using Core_RBS_Tokens.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<SecurityDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SecurityConnStr"));
});

builder.Services.AddDbContext<SalesContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("AppConnStr"));
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    // Use the EF Core for Creating, Managing Users and Roles
    .AddEntityFrameworkStores<SecurityDbContext>().AddDefaultTokenProviders();

#region The CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("cors", (policy) =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});
#endregion

builder.Services.AddScoped<SecurityServices>();
builder.Services.AddScoped<SalesService>();

#region Define Policies
builder.Services.AddAuthentication();
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
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = null,
            ValidAudience = null,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKeyString))
        };
    });
#endregion

#region The JSON Serialization
builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = null; // Use Pascal case
    options.SerializerOptions.DictionaryKeyPolicy = null; // Use Pascal case
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});
#endregion

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Configure the HTTP request pipeline.
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("cors");
app.UseAuthentication();
app.UseAuthorization();

#region The code for the Accessing Code for Creating Administrator User and Role
using (var scope = app.Services.CreateScope())
{
    var serviceProvider = scope.ServiceProvider;
    await AdminCreatorService.CreateApplicationAdministrator(serviceProvider);
}
#endregion

#region APIs
// Create New User
app.MapPost("/api/createuser", async (SecurityServices serv, RegisterUser user) =>
{
    var response = await serv.RegisterUserAsync(user);
    return Results.Ok(response);
});
//Create New Role
app.MapPost("/api/createrole",  async (SecurityServices serv, RoleData role) =>
{
    var response = await serv.CreateRoleAsync(role);
    return Results.Ok(response);
}).WithOpenApi().RequireAuthorization("AdminPolicy");
// Assign Role to User
app.MapPost("/api/approveuser", async (SecurityServices serv, UserRole userrole) =>
{
    var response = await serv.AddRoleToUserAsync(userrole);
    return Results.Ok(response);
}).RequireAuthorization("AdminPolicy");
// Authenticate the User
app.MapPost("/api/authuser", async (SecurityServices serv, LoginUser user) =>
{
    var response = await serv.AuthUser(user);
    return Results.Ok(response);
});
// Get all Users
app.MapGet("/api/users", async (SecurityServices serv) =>
{
    var users = await serv.GetUsersAsync();
    return Results.Ok(users);
}).RequireAuthorization("AdminPolicy");

// Get All Roles
app.MapGet("/api/roles", async (SecurityServices serv) =>
{
    var roles = await serv.GetRolesAsync();
    return Results.Ok(roles);
}).RequireAuthorization("AdminPolicy");

app.MapGet("/api/orders", async (HttpRequest request, SecurityServices serv, SalesService sales) =>
{
    // If the User is adminstrator then return all orders else return orders created by the current Login User
    GetRequestInfo(request, serv, out string userName, out string roleName);
    var orders = await sales.GetAsync();
    if (orders?.Records == null)
    {
        return Results.NotFound("No orders found.");
    }
    if (roleName == "Administrator")
    {
        return Results.Ok(orders.Records);
    }
    var responseByUser = orders.Records.Where(order => order.CreatedBy?.Trim() == userName);
    return Results.Ok(responseByUser);
}).RequireAuthorization("AdminManagerClerkPolicy");

app.MapGet("/api/orders/{id}", async (HttpRequest request, SecurityServices serv, SalesService sales, int id) =>
{
    GetRequestInfo(request, serv, out string userName, out string roleName);
    var orders = await sales.GetAsync();
    if (orders?.Records == null)
    {
        return Results.NotFound("No orders found.");
    }
    var responseByUser = orders.Records.Where(order => order.CreatedBy?.Trim() == userName && order.OrderId == id).FirstOrDefault();
    return Results.Ok(responseByUser);
}).RequireAuthorization("AdminManagerClerkPolicy");


app.MapPost("/api/createorder", async (SalesService serv, Order order) =>
{
    var response = await serv.SaveOdreAsync(order);
    return Results.Ok(response);
}).RequireAuthorization("AdminManagerClerkPolicy");

app.MapPut("/api/updateorder/{id}", async (SalesService serv, int id, Order order) =>
{
    var response = await serv.UpdateOdreAsync(id, order);
    return Results.Ok(response);
}).RequireAuthorization("AdminManagerPolicy");

app.MapDelete("/api/deleteorder/{id}", async (SalesService serv, int id) =>
{
    var response = await serv.DeleteOrderAsync(id);
    return Results.Ok(response);
}).RequireAuthorization("AdminManagerPolicy");

app.MapPost("/api/processorder/{id}", async (SalesService serv, int id, Order order) =>
{
    var response = await serv.ApproveRejectOrderAsync(id, order);
    return Results.Ok(response);
}).RequireAuthorization("AdminPolicy");

#endregion

void GetRequestInfo(HttpRequest request, SecurityServices serv, out string userName, out string roleName)
{
    var headers = request.Headers["Authorization"];
    var receivedToken = headers[0].Split(" ");

    var authDetails =  serv.GetUserNameAndRoleFromToken(request.HttpContext);
    userName = authDetails[0];
    roleName = authDetails[1];

}
app.MapScalarApiReference();
app.Run();
