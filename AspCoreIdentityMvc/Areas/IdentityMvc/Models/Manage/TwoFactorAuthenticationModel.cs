using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public class TwoFactorAuthenticationModel
    {
        public bool Is2faEnabled { get; set; }

        [BindNever]
        public string StatusMessage { get; set; }
    }
}