using MBBSDASM.UI;
using MBBSDASM.UI.impl;

namespace MBBSDASM
{
    /// <summary>
    ///     Main ConsoleUI Entrypoint
    /// </summary>
    class Program
    {
        

        private static IUserInterface _userInterface;

        static void Main(string[] args)
        {
            //Set the interface based on the args passed in
            _userInterface = args.Length == 0 ? (IUserInterface) new InteractiveUI() : new ConsoleUI(args);

            _userInterface.Run();
        }

        
    }
}