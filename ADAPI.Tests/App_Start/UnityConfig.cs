using ADAPI.APIWorker.Service;
using ADAPI.Logging;
using System;
using System.Web.Mvc;
using Unity;
using Unity.log4net;
using Unity.Mvc5;

namespace ADAPI.Tests
{
    public static class UnityConfig
    {
        private static Lazy<IUnityContainer> container =
          new Lazy<IUnityContainer>(() =>
          {
              UnityContainer container = new UnityContainer();
              RegisterComponents(container);
              return container;
          });

        public static IUnityContainer Container => container.Value;
        public static void RegisterComponents(IUnityContainer container)
        {
            container.RegisterType<ILogger, Logger>();
            container.RegisterType<IADService, ADService>();
            container.AddNewExtension<Log4NetExtension>();
        }
    }
}