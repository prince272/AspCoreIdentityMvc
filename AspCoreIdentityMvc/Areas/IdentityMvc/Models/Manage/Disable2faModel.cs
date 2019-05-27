using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public class Disable2faModel
    {
        [BindNever]
        public string StatusMessage { get; set; }
    }
}