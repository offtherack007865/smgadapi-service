using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Models.ActiveDirectory
{
    public class UserInformation
    {
        public string Name { get; set; }
        public List<ADPrincipalObject> SecurityGroups { get; set; }
    }
}