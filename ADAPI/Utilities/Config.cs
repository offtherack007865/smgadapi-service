using ADAPI.Models.Config;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Web;

namespace ADAPI.Utilities
{
    public static class Config
    {

        /// <summary>
        /// Gets Authentication related information based on configuration.
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static APIConfiguration GetAuthenticationInfo(string path)
        {
            APIConfiguration results = new APIConfiguration();
            NameValueCollection collection = ConfigurationManager.GetSection(path) as NameValueCollection;

            foreach (string item in collection)
            {
                switch (item)
                {
                    case "Password":
                        results.Password = collection["Password"];
                        break;
                    case "Domain":
                        results.Domain = collection["Domain"];
                        break;
                    case "User":
                        results.User = collection["User"];
                        break;
                    default:
                        break;
                }
            }

            return results;
        }

        /// <summary>
        /// Gets network information based on configuration
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static APIConfiguration GetNetworkInfo(string path)
        {
            APIConfiguration results = new APIConfiguration();
            NameValueCollection collection = ConfigurationManager.GetSection(path) as NameValueCollection;

            foreach (string item in collection)
            {
                switch (item)
                {
                    case "NetworkPath":
                        results.NetworkPath = collection["NetworkPath"];
                        break;
                    case "ADDisabledPath":
                        results.ADPath = collection["ADDisabledPath"];
                        break;
                    default:
                        break;
                }
            }

            return results;
        }
    }
}