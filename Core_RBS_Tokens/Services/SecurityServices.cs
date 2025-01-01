using Core_RBS_Tokens.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Core_RBS_Tokens.Services
{
    public class SecurityServices
    {
         /// <summary>
        /// For Creating and Managing Users
        /// </summary>
        UserManager<IdentityUser> _userManager;
        /// <summary>
        /// Managing USer Logins
        /// </summary>
        SignInManager<IdentityUser> _signInManager;
        /// <summary>
        /// Create an Manage Roles
        /// </summary>
        RoleManager<IdentityRole> _roleManager;
        /// <summary>
        /// USed to read onfiguration from the appsettings.json
        /// </summary>
        IConfiguration _config;

        /// <summary>
        /// Inject THe UserManager and SignInManager in DI Container 
        /// These dependencies will be resolved using 
        /// The 'AddIdentityService<IdentityUser, IdentityRole>();
        /// </summary>
        /// <param name="userManager"></param>
        /// <param name="signInManager"></param>
        public SecurityServices(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager,
             IConfiguration config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _config = config;
        }

        public async Task<SecureResponse> RegisterUserAsync(RegisterUser user)
        {
            SecureResponse response = new SecureResponse();
            if (user == null)
            {
                response.StatucCode = 500;
                response.Message = "User Details are not passed";
            }
            else if (string.IsNullOrEmpty(user.Email))
            {
                response.StatucCode = 500;
                response.Message = "Email is not provided";
            }
            else
            {
                // CHeck if USer Already Exists
                var identityUser = await _userManager.FindByEmailAsync(user.Email);
                if (identityUser != null)
                {
                    response.StatucCode = 500;
                    response.Message = $"User {user.Email} is already exist";
                }
                else
                {
                    // Create user
                    var newUser = new IdentityUser()
                    {
                        Email = user.Email,
                        UserName = user.Email
                    };
                    // Create a user by hashing password 
                    var result = await _userManager.CreateAsync(newUser, user.Password);
                    if (result.Succeeded)
                    {
                        response.StatucCode = 201;
                        response.Message = $"User {user.Email} is created successfully";
                    }
                    else
                    {
                        response.StatucCode = 500;
                        response.Message = $"Some error occurred while creating the user";
                    }
                }
            }
            return response;
        }
        public async Task<SecureResponse> AuthUser(LoginUser user)
        {
            SecureResponse response = new SecureResponse();
            if (user == null)
            {
                response.StatucCode = 500;
                response.Message = "User login Details are not passed";
            }
            else if (string.IsNullOrEmpty(user.Email))
            {
                response.StatucCode = 500;
                response.Message = "Email is not provided";
            }
            else if (string.IsNullOrEmpty(user.Password))
            {
                response.StatucCode = 500;
                response.Message = "Password is not provided";
            }
            else
            {
                // Check if User Already does not Exists
                var identityUser = await _userManager.FindByEmailAsync(user.Email);
                if (identityUser == null)
                {
                    response.StatucCode = 500;
                    response.Message = $"User {user.Email} is not present";
                }
                else
                {
                    // Autenticate the user
                    // Get the LIst of ROles assigned to user
                    var roles = await _userManager.GetRolesAsync(identityUser);
                    if (roles.Count == 0)
                    {
                        response.StatucCode = 500;
                        response.Message = $"The user {user.Email} does not belong to any role, ad hence the user cannot access the application";
                    }
                    else
                    {
                        // Paramater 1: Login EMail
                        // Parameter 2: PAssword
                        // Parameter 3: Creaing Persistent Cookie on Browser, set it to false for API
                        // Parameter 4: Invalid login attempts will lock the user from login (5 attempts default)
                        var authStatus = await _signInManager.PasswordSignInAsync(user.Email, user.Password, false, lockoutOnFailure: true);

                        if (authStatus.Succeeded)
                        {
                            /*
                               Logic to Generate Token
                             */
                            #region Logic for Generating Token
                            //3b Read the secret key and the expiration from the configuration 
                            var secretKeyString = _config["JWTCoreSettings:SecretKey"];
                            if (string.IsNullOrEmpty(secretKeyString))
                            {
                                response.StatucCode = 500;
                                response.Message = "Secret key is not configured properly";
                                return response;
                            }
                            var secretKey = Convert.FromBase64String(secretKeyString);
                            var expiryTimeSpan = Convert.ToInt32(_config["JWTCoreSettings:ExpiryInMinuts"]);
                            //3c. logic to get the user role
                            // get the user object based on Email

                            IdentityUser usr = new IdentityUser(user.Email);
                            var role = await _userManager.GetRolesAsync(usr);

                            // if user is not associated with role then log off
                            if (role.Count == 0)
                            {
                                await _signInManager.SignOutAsync();
                                response.StatucCode = 500;
                                response.Message = "The User is not associated with Role";
                                return response;
                            }
                            else
                            { 
                                //3d set the expiry, subject, etc.
                            // note that Issuer and Audience will be null because 
                            // there is no third-party issuer
                            var securityTokenDescription = new SecurityTokenDescriptor()
                            {
                                Issuer = null,
                                Audience = null,
                                Subject = new ClaimsIdentity(new List<Claim> {
                                    new Claim("username",usr.Id,ToString()),
                                    new Claim("rolename",role[0] )
                                }),
                                Expires = DateTime.UtcNow.AddMinutes(expiryTimeSpan),
                                IssuedAt = DateTime.UtcNow,
                                NotBefore = DateTime.UtcNow,
                                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature)
                            };
                            //3e Now generate token using JwtSecurityTokenHandler
                            var jwtHandler = new JwtSecurityTokenHandler();
                            var jwToken = jwtHandler.CreateJwtSecurityToken(securityTokenDescription);
                            response.Token = jwtHandler.WriteToken(jwToken);
                            #endregion

                            response.StatucCode = 200;
                            response.RoleName = role[0];
                            response.Message = $"User {user.Email} Logged in successfuly";
                           }
                            
                        }
                        else
                        {
                            response.StatucCode = 500;
                            response.Message = $"Error Occurred for User {user.Email} Login";
                        }
                    }
                }
            }
            return response;
        }


        public async Task<SecureResponse> CreateRoleAsync(RoleData role)
        {
            SecureResponse response = new SecureResponse();
            if (role == null || string.IsNullOrEmpty(role.RoleName))
            {
                response.StatucCode = 500;
                response.Message = "Not a valid data";
            }
            else
            {
                // Check is role exist
                var roleInfo = await _roleManager.FindByNameAsync(role.RoleName);
                if (roleInfo != null)
                {
                    response.StatucCode = 500;
                    response.Message = $"Role {role.RoleName} is already exist";
                }
                else
                {
                    var identityRole = new IdentityRole() { Name = role.RoleName, NormalizedName = role.RoleName };
                    // Create a role
                    var result = await _roleManager.CreateAsync(identityRole);
                    if (result.Succeeded)
                    {
                        response.StatucCode = 200;
                        response.Message = $"Role {role.RoleName} is created successfully";
                    }
                    else
                    {
                        response.StatucCode = 500;
                        response.Message = "Error Occurred while creating role";
                    }
                }
            }
            return response;
        }

        public async Task<SecureResponse> AddRoleToUserAsync(UserRole userRole)
        {
            SecureResponse response = new SecureResponse();
            if (userRole == null || string.IsNullOrEmpty(userRole.RoleName) || string.IsNullOrEmpty(userRole.UserName))
            {
                response.StatucCode = 500;
                response.Message = "No valid information is available";
            }
            else
            {
                // 1. Check for role
                var role = await _roleManager.FindByNameAsync(userRole.RoleName);
                // 2. Check for user
                var user = await _userManager.FindByEmailAsync(userRole.UserName);

                if (role == null || user == null)
                {
                    response.StatucCode = 500;
                    response.Message = $"Either Role {userRole.RoleName} or User {userRole.UserName} is not available";
                }
                else
                {
                    // assing role to user
                    var result = await _userManager.AddToRoleAsync(user, role?.Name ?? string.Empty);
                    if (result.Succeeded)
                    {
                        response.StatucCode = 200;
                        response.Message = $"The User : {user.Email} is assgned to Role: {role.Name}";
                    }
                    else
                    {
                        response.StatucCode = 500;
                        response.Message = "Some error occurred while processing the user assignment to role request.";
                    }
                }
            }
            return response;
        }


           /// <summary>
        /// Thie method willaccept the token as inout parameter and wil receive token from it
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public async Task<string> GetUserFromTokenAsync(string token)
        {
            string userName = "";
            var jwtHandler = new JwtSecurityTokenHandler();
            // read the token values
            var jwtSecurityToken = jwtHandler.ReadJwtToken(token);
            // read claims
            var claims = jwtSecurityToken.Claims;
            // read first claim
            var userIdClaim = claims.First();
            // read the user Id
            var userId = userIdClaim.Value;
            // get the username from the userid
            var identityUser = await _userManager.FindByIdAsync(userId);
            userName = identityUser.UserName;
            return userName;
        }

        public string GetRoleFormToken(string token)
        {
            string roleName = "";
            var jwtHandler = new JwtSecurityTokenHandler();
            // read the token values
            var jwtSecurityToken = jwtHandler.ReadJwtToken(token);
            // read claims
            var claims = jwtSecurityToken.Claims;
            // read first two claim
            var roleClaim = claims.Take(2);
            // read the role
            var roleRecord = roleClaim.Last();
            // read the role name
            roleName = roleRecord.Value;
            return roleName;
        }
        
    }
    
}
