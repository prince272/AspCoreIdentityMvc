using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public class GenerateRecoveryCodesModel
    {
        [BindNever]
        public string StatusMessage { get; set; }
    }
}