using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Models.Config
{
    public class APIConfiguration
    {
        public string Domain { get; set; }
        public string User { get; set; }
        public string Password { get; set; }
        public string DeveloperOne { get; set; }
        public string DeveloperTwo { get; set; }
        public string NetworkPath { get; set; }
        public string ADPath { get; set; }
    }
}