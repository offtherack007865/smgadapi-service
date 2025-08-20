using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Logging
{
    public class Logger : ILogger
    {
        private static ILog _logger;
        public Logger()
        {
            _logger = log4net.LogManager.GetLogger("logfile");
        }

        public void LogInfo(string message)
        {
            if (string.IsNullOrEmpty(message))
                _logger.Warn("Call for Logger to log info was executed, but message was empty");
            _logger.Info(message);
        }
        public void LogError(string message)
        {
            if (string.IsNullOrEmpty(message))
                _logger.Warn("Call for Logger to log error was executed, but error message was empty");
            _logger.Error(message);
        }
        public void LogCritical(string message)
        {
            if (string.IsNullOrEmpty(message))
                _logger.Warn("Call for Logger to log CRITCAL was executed, but critical message was empty");
            _logger.Fatal(message);
        }
    }
}