﻿using Core_RBS_Tokens.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Core_RBS_Tokens.Services
{
    /// <summary>
    /// This class is used to create Users and Roles and manage Authentication using the Token
    /// After Generating Toking
    /// </summary>
    public class SecurityServices
    {
        
        UserManager<IdentityUser> _userManager;
        SignInManager<IdentityUser> _signInManager;
        RoleManager<IdentityRole> _roleManager;
        IConfiguration _config;
      
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
                        
                        var authStatus = await _signInManager.PasswordSignInAsync(user.Email, user.Password, false, lockoutOnFailure: true);

                        if (authStatus.Succeeded)
                        {
                            
                            #region Logic for Generating Token
                            
                            var secretKeyString = _config["JWTCoreSettings:SecretKey"];
                            if (string.IsNullOrEmpty(secretKeyString))
                            {
                                response.StatucCode = 500;
                                response.Message = "Secret key is not configured properly";
                                return response;
                            }
                            var secretKey = Convert.FromBase64String(secretKeyString);
                            var expiryTimeSpan = Convert.ToInt32(_config["JWTCoreSettings:ExpiryInMinuts"]);
                             

                            IdentityUser usr = new IdentityUser(user.Email);
                                
                            
                            var claims = new[]
                                    {
                                        
                                        new Claim(ClaimTypes.Name, usr.UserName),
                                        new Claim(ClaimTypes.Role, roles[0])
                                    };

                                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKeyString));
                                    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                                    var token = new JwtSecurityToken(
                                        issuer: null,
                                        audience: null,
                                        claims: claims,
                                        expires: DateTime.Now.AddMinutes(60),
                                        signingCredentials: creds);

                                    response.Token = new JwtSecurityTokenHandler().WriteToken(token);
                            #endregion

                            response.StatucCode = 200;
                            response.RoleName = roles[0];
                            response.UserName = user.Email;
                            response.Message = $"User {user.Email} Logged in successfuly";
                           }
                            
                        //}
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

        public async Task<List<RoleData>> GetRolesAsync()
        {
            List<RoleData> roles = new List<RoleData>();
            roles = await Task.Run(() => (from r in _roleManager.Roles.ToList()
                                          select new RoleData()
                                          {
                                              RoleName = r.Name,
                                          }).ToList());
            return roles;
        }

        public async Task<List<Users>> GetUsersAsync()
        {
            List<Users> users = await Task.Run(() => (from u in _userManager.Users.ToList()
                                                      select new Users()
                                                      {
                                                          Email = u.Email,
                                                          UserName = u.UserName
                                                      }).ToList());
            return users;
        }
          
        public string[] GetUserNameAndRoleFromToken(HttpContext httpContext)
        {
            string[] data = new string[2];
            if (httpContext.User.Identity is ClaimsIdentity identity)
            {
                var username = identity.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
                var role = identity.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;
                data[0] = username;
                data[1] = role;
                return data;
            }
            return data;
        }
        
    }
    
}
