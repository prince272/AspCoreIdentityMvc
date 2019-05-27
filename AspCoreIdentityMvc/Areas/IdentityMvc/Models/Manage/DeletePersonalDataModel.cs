using System.ComponentModel.DataAnnotations;

namespace AspCoreIdentityMvc.Areas.IdentityMvc.Models.Manage
{
    public class DeletePersonalDataModel
    {
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}