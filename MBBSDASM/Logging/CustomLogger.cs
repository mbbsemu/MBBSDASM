using NLog;
using NLog.Layouts;

namespace MBBSDASM.Logging
{
    public class CustomLogger : Logger
    {

        static CustomLogger()
        {
            var config = new NLog.Config.LoggingConfiguration();

            //Setup Console Logging
            var logconsole = new NLog.Targets.ConsoleTarget("logconsole")
            {
                Layout = Layout.FromString("${shortdate}\t${time}\t${message}")
            };
            config.AddTarget(logconsole);
            config.AddRuleForAllLevels(logconsole);

            LogManager.Configuration = config;
        }
    }
}
