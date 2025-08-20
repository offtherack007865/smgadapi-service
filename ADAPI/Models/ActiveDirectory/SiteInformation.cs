using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Models.ActiveDirectory
{
    public class SiteInformation
    {
        public int ID { get; set; }
        public string Name { get; set; }
        public string Phone { get; set; }
        public string OU { get; set; }
        public List<ADPrincipalObject> SecurityGroups { get; set; }
    }
}