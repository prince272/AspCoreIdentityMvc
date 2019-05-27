using System.ComponentModel.DataAnnotations;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Account
{
    public class ExternalLoginModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}