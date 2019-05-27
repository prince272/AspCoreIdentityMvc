using System.ComponentModel.DataAnnotations;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Account
{
    public class LoginWithRecoveryCodeModel
    {
        [Required]
        [DataType(DataType.Text)]
        [Display(Name = "Recovery Code")]
        public string RecoveryCode { get; set; }
    }
}