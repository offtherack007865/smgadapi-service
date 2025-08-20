using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Models.ActiveDirectory
{
    public class ADObjectCheckList : ADPrincipalObject
    {
        public bool Checked { get; set; }
    }
}