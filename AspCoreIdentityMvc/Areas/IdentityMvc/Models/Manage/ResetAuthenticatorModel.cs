using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public class ResetAuthenticatorModel
    {
        [BindNever]
        public string StatusMessage { get; set; }
    }
}