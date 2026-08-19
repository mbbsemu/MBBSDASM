using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MBBSDASM.Dasm;
using MBBSDASM.Renderer.impl;
using NLog;
using Terminal.Gui;

namespace MBBSDASM.UI.impl
{
    public class InteractiveUI : IUserInterface
    {
        private string _selectedFile;
        private bool _DisassemblyLoaded;

        private bool _optionMBBSAnalysis;
        private bool _optionStrings;
        private bool _optionMinimal;
        private string _outputFile;

        private MenuBar _topMenuBar;
        private Window _mainWindow;
        private readonly ProgressBar _progressBar;
        private readonly Label _statusLabel;
        internal InteractiveUI()
        {
            //Console log output would draw over the TUI, so suspend logging for the interactive session
            LogManager.DisableLogging();

            //The curses driver reports a 0x0 terminal on macOS, blanking the UI and crashing
            //any view that sizes itself from Driver.Cols - the portable .NET driver works everywhere
            Application.UseSystemConsole = true;

            //The .NET driver paints straight onto the main screen, so switch to the alternate
            //screen first - exiting then restores whatever the terminal showed before launch
            System.Console.Write("\x1b[?1049h");
            Application.Init();

            //Define Main Window
            //Computed layout instead of absolute Rects: Application.Top.Frame isn't sized until
            //Application.Run() lays it out, so reading it here crashed on startup (Height was 0)
            _mainWindow = new Window(null)
            {
                X = 0,
                Y = 1,
                Width = Dim.Fill(),
                Height = Dim.Fill()
            };
            _mainWindow.Add(new Label(0, 0, $"--=[About {Constants.ProgramName}]=--"));
            _mainWindow.Add(new Label(0, 1, $"{Constants.ProgramName} is a x86 16-Bit NE Disassembler with advanced analysis for MajorBBS/Worldgroup modules"));
            _mainWindow.Add(new Label(0, 3, $"--=[Credits]=--"));
            _mainWindow.Add(new Label(0, 4, $"{Constants.ProgramName} is Copyright (c) 2019 Eric Nusbaum and is distributed under the 2-clause \"Simplified BSD License\". "));
            _mainWindow.Add(new Label(0, 5, "SharpDisam is Copyright (c) 2015 Justin Stenning and is distributed under the 2-clause \"Simplified BSD License\". "));
            _mainWindow.Add(new Label(0, 6, "Terminal.Gui is Copyright (c) 2017 Microsoft Corp and is distributed under the MIT License"));
            _mainWindow.Add(new Label(0, 8, $"--=[Code]=--"));
            _mainWindow.Add(new Label(0, 9, "http://www.github.com/enusbaum/mbbsdasm"));
            _progressBar = new ProgressBar
            {
                X = 1,
                Y = Pos.AnchorEnd(4),
                Width = Dim.Fill(3),
                Height = 1
            };
            _mainWindow.Add(_progressBar);
            _statusLabel = new Label("Ready!")
            {
                X = 1,
                Y = Pos.AnchorEnd(6),
                Width = Dim.Fill(3)
            };
            _mainWindow.Add(_statusLabel);
            Application.Top.Add(_mainWindow);

            //Draw Menu Items
            // Creates a menubar, the item "New" has a help menu.
            var menuItems = new List<MenuBarItem>();

            menuItems.Add(
                new MenuBarItem("_File", new MenuItem[]
                {
                    new MenuItem("_Disassemble", "", OpenFile),
                    new MenuItem("_Exit", "", () => { Application.Top.Running = false; })
                }));

            _topMenuBar = new MenuBar(menuItems.ToArray());
            Application.Top.Add(_topMenuBar);

        }

        public void Run()
        {
            //Run it
            Application.Run();
            Application.Shutdown();

            //The .NET console driver doesn't restore the terminal on shutdown, leaving mouse
            //tracking enabled (every mouse move types escape sequences into the shell) and the
            //alternate screen active - reset those modes by hand
            System.Console.Write("\x1b[?1003l\x1b[?1015l\x1b[?1006l\x1b[?1049l\x1b[?1l\x1b[?25h\x1b[0m");
        }

        private void OpenFile()
        {
            //Show Open File Dialog
            var fOpenDialog = new OpenDialog("Open File for Disassembly", "DisassembleSegment File")
            {
                CanChooseFiles = true,
                AllowsMultipleSelection = false,
                CanChooseDirectories = false,
                AllowedFileTypes = new[] {"dll", "exe", "DLL", "EXE"}
            };

            Application.Run(fOpenDialog);

            //Get Selected File
            _selectedFile = fOpenDialog.FilePaths.FirstOrDefault();

            //If nothing is selected, bail
            if (string.IsNullOrEmpty(_selectedFile))
                return;

            _outputFile = $"{_selectedFile.Substring(0, _selectedFile.Length -3)}asm";

            //Show Disassembly Options
            var analysisCheckBox = new CheckBox(20, 0, "Enhanced MBBS/WG Analysis") {Checked = true};
            var stringsCheckBox = new CheckBox(20, 1, "Process All Strings") { Checked = true };
            var disassemblyRadioGroup = new RadioGroup(0, 0, new NStack.ustring[] {"_Minimal", "_Normal"}, 1);

            var okBtn = new Button("OK", true);
            okBtn.Clicked += () =>
                {
                    Application.RequestStop();
                    _optionMBBSAnalysis = analysisCheckBox.Checked;
                    _optionStrings = stringsCheckBox.Checked;
                    _optionMinimal = disassemblyRadioGroup.SelectedItem == 0;
                    Task.Factory.StartNew(() => DoDisassembly());
                };

            var cancelBtn = new Button("Cancel", true);
            cancelBtn.Clicked += () => { Application.RequestStop (); };

            var fv = new FrameView(new Rect(0, 5, 55, 6), "Disassembly Options");
            fv.Add(disassemblyRadioGroup,analysisCheckBox,stringsCheckBox);

            var disOptionsDialog = new Dialog("Disassembly Options", 60, 16, new Button[]{okBtn,cancelBtn});
            disOptionsDialog.Add(
                new Label(0, 0, "Input File:"),
                new TextField(0, 1, 55, _selectedFile),
                new Label(0, 2, "Output File:"),
                new TextField(0, 3, 55, _outputFile),
                fv
            );

            Application.Run(disOptionsDialog);
        }

        private void DoDisassembly()
        {
            using (var dasm = new Disassembler(_selectedFile))
            {
                if (File.Exists(_outputFile))
                    File.Delete(_outputFile);

                SetProgress("Performing Disassembly...", 0f);
                var inputFile = dasm.Disassemble(_optionMinimal);

                //Apply Selected Analysis
                if (_optionMBBSAnalysis)
                {
                    SetProgress("Performing Additional Analysis...", 0f);
                    Analysis.MBBS.Analyze(inputFile);
                }
                SetProgress("Processing Segment Information...", .25f);

                var _stringRenderer = new StringRenderer(inputFile);

                File.AppendAllText(_outputFile, _stringRenderer.RenderSegmentInformation());
                SetProgress("Processing Entry Table...", .50f);

                File.AppendAllText(_outputFile, _stringRenderer.RenderEntryTable());
                SetProgress("Processing Disassembly...", .75f);

                File.AppendAllText(_outputFile, _stringRenderer.RenderDisassembly(_optionMBBSAnalysis));
                SetProgress("Processing Strings...", .85f);

                if (_optionStrings)
                    File.AppendAllText(_outputFile, _stringRenderer.RenderStrings());

                SetProgress("Done!", 1f);
            }

            //The completion dialog needs its event loop on the UI thread - running it from this
            //background thread leaves it unable to receive input, so it can never be dismissed
            Application.MainLoop.Invoke(() =>
            {
                var d = new Dialog($"Disassembly Complete!", 50, 12);
                d.Add(new Label(0, 0, $"Output File: {_outputFile}"),
                    new Label(0, 1, $"Bytes Written: {new FileInfo(_outputFile).Length}")
                );
                var okBtn = new Button("OK", true);
                okBtn.Clicked += () => { Application.RequestStop (); };
                d.AddButton(okBtn);
                Application.Run(d);
            });
        }

        /// <summary>
        ///     Updates the status label and progress bar on the UI thread
        /// </summary>
        private void SetProgress(string status, float fraction)
        {
            Application.MainLoop.Invoke(() =>
            {
                _statusLabel.Text = status;
                _progressBar.Fraction = fraction;
            });
        }
    }
}
