using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADAPI.Logging
{
    public interface ILogger
    {
        void LogCritical(string message);
        void LogError(string message);
        void LogInfo(string message);
    }
}
