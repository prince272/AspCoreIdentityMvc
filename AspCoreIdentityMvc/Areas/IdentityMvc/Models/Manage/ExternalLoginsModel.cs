using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public class ExternalLoginsModel
    {
        [BindNever]
        public string StatusMessage { get; set; }
    }
}