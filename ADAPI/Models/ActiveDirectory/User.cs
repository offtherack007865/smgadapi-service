using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Models.ActiveDirectory
{
    public class User
    {
        public User()
        {

        }

        private string _username;
        public string FirstName { get; set; }
        public string MiddleInitial { get; set; }
        public string LastName { get; set; }
        public string JobDescription { get; set; }
        public string PhoneNumber { get; set; }
        public string OU { get; set; }
        public string DisplayName { get; set; }
        public string SiteName { get; set; }
        public string EmployeeId { get; set; }
        public string Department { get; set; }
        public string PrincipalName { get; set; }
        public string DistinguishedName { get; set; }
        public bool? IsEnabled { get; set; }
        public string EmailAddress { get; set; }
        public DateTime? LastLogOn { get; set; }
        public int BadLogOnCount { get; set; }
        public string Company { get; set; }
        public List<ADPrincipalObject> Groups { get; set; }
        public ADPrincipalObject Manager { get; set; }
        public string UserPassword { get; set; }
        public string Username
        {
            get { return _username; }
            set { _username = value; }
        }
        public User(string username)
        {
            _username = username;
            Groups = new List<ADPrincipalObject>();
            Manager = new ADPrincipalObject();
        }
    }
}