using System;
using System.IO;
using System.Linq;
using System.Text;
using MBBSDASM.Dasm;
using MBBSDASM.Enums;
using MBBSDASM.Logging;
using MBBSDASM.Renderer.impl;
using NLog;

namespace MBBSDASM.UI.impl
{
    /// <summary>
    ///     ConsoleUI Class
    ///
    ///     This class is used when command line switches are passed into MBBSDASM, allowing users
    ///     to bypass the interactive UI functionality and work strictly with command line arguments
    /// </summary>
    public class ConsoleUI : IUserInterface
    {
        /// <summary>
        ///     Logger Implementation
        /// </summary>
        protected static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));

        /// <summary>
        ///     Args passed in via command line
        /// </summary>
        private readonly string[] _args;

        /// <summary>
        ///     Input File
        ///     Specified by the -i argument
        /// </summary>
        private string _sInputFile = string.Empty;

        /// <summary>
        ///     Output File
        ///     Specified with the -o argument
        /// </summary>
        private string _sOutputFile = string.Empty;

        /// <summary>
        ///     Minimal Disassembly
        ///     Specified with the -minimal argument
        ///     Will only do basic disassembly of opcodes
        /// </summary>
        private bool _bMinimal;

        /// <summary>
        ///     MBBS Analysis Mode
        ///     Specified with the -analysis argument
        ///     Will perform in-depth analysis of imported MBBS/WG functions and include detailed information and labeling
        /// </summary>
        private bool _bAnalysis;

        /// <summary>
        ///     Strings Analysis
        ///     Specified with the -string argument
        ///     Includes all strings discovered in DATA segments at the end of the disassembly output
        /// </summary>
        private bool _bStrings;

        /// <summary>
        ///     Default Constructor
        /// </summary>
        /// <param name="args">string - Command Line Arguments</param>
        public ConsoleUI(string[] args)
        {
            _args = args;
        }

        /// <summary>
        ///     (IUserInterface) Runs the specified User Interface
        /// </summary>
        public void Run()
        {
            try
            {
                //Command Line Values

                for (var i = 0; i < _args.Length; i++)
                {
                    switch (_args[i].ToUpper())
                    {
                        case "-I":
                            _sInputFile = _args[i + 1];
                            i++;
                            break;
                        case "-O":
                            _sOutputFile = _args[i + 1];
                            i++;
                            break;
                        case "-MINIMAL":
                            _bMinimal = true;
                            break;
                        case "-ANALYSIS":
                            _bAnalysis = true;
                            break;
                        case "-STRINGS":
                            _bStrings = true;
                            break;
                        case "-?":
                            Console.WriteLine("-I <file> -- Input File to DisassembleSegment");
                            Console.WriteLine("-O <file> -- Output File for Disassembly (Default ConsoleUI)");
                            Console.WriteLine("-MINIMAL -- Minimal Disassembler Output");
                            Console.WriteLine(
                                "-ANALYSIS -- Additional Analysis on Imported Functions (if available)");
                            Console.WriteLine(
                                "-STRINGS -- Output all strings found in DATA segments at end of Disassembly");
                            return;
                    }
                }

                //Verify Input File is Valid
                if (string.IsNullOrEmpty(_sInputFile) || !File.Exists(_sInputFile))
                    throw new Exception("Error: Please specify a valid input file");

                //Warn of Analysis not being available with minimal output
                if (_bMinimal && _bAnalysis)
                    _logger.Warn(
                        $"Warning: Analysis Mode unavailable with minimal output option, ignoring");

                _logger.Info($"Inspecting File: {_sInputFile}");

                //Perform Disassmebly
                var dasm = new Disassembler(_sInputFile);
                var inputFile = dasm.Disassemble(_bMinimal);

                //Apply Selected Analysis
                if (_bAnalysis)
                {
                    _logger.Info($"Performing Additional Analysis");
                    Analysis.MBBS.Analyze(inputFile);
                }

                _logger.Info($"Writing Disassembly Output");

                //Build Final Output
                var renderer = new StringRenderer(inputFile);
                var output = new StringBuilder();
                output.AppendLine($"; Disassembly of {inputFile.Path}{inputFile.FileName}");
                output.AppendLine($"; Description: {inputFile.NonResidentNameTable[0].Name}");
                output.AppendLine(";");

                //Render Segment Information to output
                output.Append(renderer.RenderSegmentInformation());
                output.Append(renderer.RenderEntryTable());
                output.AppendLine(";");
                output.Append(renderer.RenderDisassembly(_bAnalysis));

                //Write Strings to Output
                if (_bStrings)
                {
                    output.Append(renderer.RenderStrings());
                }

                if (string.IsNullOrEmpty(_sOutputFile))
                {
                    _logger.Info(output.ToString());
                }
                else
                {
                    _logger.Info($"{DateTime.Now} Writing Disassembly to {_sOutputFile}");
                    File.WriteAllText(_sOutputFile, output.ToString());
                }

                _logger.Info($"{DateTime.Now} Done!");
            }
            catch (Exception e)
            {
                _logger.Error(e);
                _logger.Error($"{DateTime.Now} Fatal Exception -- Exiting");
            }
        }
    }
}