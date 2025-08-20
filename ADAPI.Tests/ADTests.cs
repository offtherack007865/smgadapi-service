using ADAPI.APIWorker.Service;
using ADAPI.Logging;
using NUnit.Framework;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Threading.Tasks;
using Unity;

namespace ADAPI.Tests
{
    [TestFixture]
    public class ADTests
    {
        private ILogger _logger;
        private IADService _service;
        public ADTests(ILogger logger, IADService service)
        {
            _logger = UnityConfig.Container.Resolve<ILogger>();
            _service = UnityConfig.Container.Resolve<IADService>();
        }

        [TestCase]
        public void DoesNameExist()
        {
            Task<bool> doesExist = _service.DoesUserNameExist("nscoffey");
            Assert.True(doesExist.Result);
        }

        [TestCase]
        public void GetSecGroups()
        {
            Collection<PSObject> secGroups = _service.GetSecurityGroups();
        }
    }
}
