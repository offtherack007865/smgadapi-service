using ADAPI.Models.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Web;

namespace ADAPI.Models.Wrapper
{
    public class WrapperModel
    {
        public WrapperModel()
        {
            this.SecurityGroups = new ObservableCollection<ADObjectCheckList>();
            this.OrganizationalGroups = new List<string>();
            this.User = new User();
            this.UserDistinguishedName = string.Empty;
            this.ADPrincipalObjectGroups = new List<ADPrincipalObject>();
        }
        public ObservableCollection<ADObjectCheckList> SecurityGroups { get; set; }
        public List<string> OrganizationalGroups { get; set; }
        public User User { get; set; }
        public string UserDistinguishedName { get; set; }
        public List<ADPrincipalObject> ADPrincipalObjectGroups { get; set; }
    }
}