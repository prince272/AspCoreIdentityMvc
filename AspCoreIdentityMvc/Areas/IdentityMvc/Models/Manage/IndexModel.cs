using System.ComponentModel.DataAnnotations;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public partial class IndexModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Phone]
        [Display(Name = "Phone number")]
        public string PhoneNumber { get; set; }
    }
}