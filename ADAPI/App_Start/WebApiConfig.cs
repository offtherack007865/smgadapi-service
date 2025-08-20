using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web.Http;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;
using ADAPI.APIHelper;
using System.Web.Http.Cors;

namespace ADAPI
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services
            // Configure Web API to use only bearer token authentication.
            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            //Make sure formatting is always correct.
            config.Formatters.JsonFormatter.SerializerSettings.Formatting = Newtonsoft.Json.Formatting.Indented;
            //Make sure data is returned in CamelCase.
            config.Formatters.JsonFormatter.SerializerSettings.ContractResolver = new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver();

            //format data returned instead of text to conent-header of application/json.
            config.Formatters.Add(new JsonFormatter());

            //If you choose to disable one of the formatters.
            config.Formatters.Remove(config.Formatters.XmlFormatter);

            //Automatically redirects api to https.
            config.Filters.Add(new SecurityAttribute());

            //enables specific Cross-origin resource sharing.
            EnableCorsAttribute cors = new EnableCorsAttribute("https://localhost:44397, https://sssadapi.summithealthcare.com", "*", "*");
            config.EnableCors(cors);
        }
    }
}
