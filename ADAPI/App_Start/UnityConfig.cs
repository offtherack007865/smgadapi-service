using ADAPI.APIWorker.Service;
using ADAPI.Controllers;
using ADAPI.Logging;
using ADAPI.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Web.Http;
using System.Web.Mvc;
using Unity;
using Unity.Injection;
using Unity.log4net;
using Unity.WebApi;

namespace ADAPI
{
    public static class UnityConfig
    {
        public static void RegisterComponents()
        {
            UnityContainer container = new UnityContainer();
            container.RegisterType<ILogger, Logger>();
            container.RegisterType<IADService, ADService>();
            container.AddNewExtension<Log4NetExtension>();
            container.RegisterType<IUserStore<ApplicationUser>, UserStore<ApplicationUser>>();
            //This DI injects a paramaterless constructor when using injection constructor.
            container.RegisterType<AccountController>(new InjectionConstructor());

            DependencyResolver.SetResolver(new Unity.Mvc5.UnityDependencyResolver(container));
            GlobalConfiguration.Configuration.DependencyResolver = new Unity.WebApi.UnityDependencyResolver(container);
        }
    }
}