using System.ComponentModel.DataAnnotations;

namespace Blazor_Client.Models
{
    public class RegisterUser
    {
        /// <summary>
        /// UNique EMail
        /// </summary>
         [Required(ErrorMessage = "Email is Must")] 
        [EmailAddress]
        public string? Email { get; set; }
        [Required(ErrorMessage = "Password is Must")]
        [RegularExpression("^((?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])|(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[^a-zA-Z0-9])|(?=.*?[A-Z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])|(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])).{8,}$", 
            ErrorMessage = "Passwords must be minimum 8 characters and must be string password with uppercase character, number and sepcial character")]
        public string?  Password { get; set; }
        [Compare("Password")]
        public string? ConfirmPassword { get; set; }
    }

    public class LoginUser
    {
        [Required(ErrorMessage ="User Name is Must")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is Must")]
        public string? Password { get; set; }
    }

    public class SecureResponse
    {
        public string? UserName { get; set; }
        public string? Message { get; set; }
        public int StatucCode { get; set; }
        public string? RoleName { get; set; }
        public string? Token { get; set; }
    }
    /// <summary>
    /// Class to create a new Role
    /// </summary>
    public class RoleData
    {
        public string? RoleName { get; set;}
    }
    /// <summary>
    /// Class to assign Role to User
    /// </summary>
    public class UserRole
    {
        public string? UserName { get; set;}
        public string? RoleName { get; set;}
    }

    public class Users
    {
        public string? Email { get; set; }
        public string? UserName { get; set; }
    }
}
