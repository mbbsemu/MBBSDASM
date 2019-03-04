using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MBBSDASM.Dasm;
using MBBSDASM.Renderer.impl;
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
            Application.Init();

            //Define Main Window
            _mainWindow = new Window(new Rect(0, 1, Application.Top.Frame.Width, Application.Top.Frame.Height - 1), null);
            _mainWindow.Add(new Label(0, 0, $"--=[About {Constants.ProgramName}]=--"));
            _mainWindow.Add(new Label(0, 1, $"{Constants.ProgramName} is a x86 16-Bit NE Disassembler with advanced analysis for MajorBBS/Worldgroup modules"));
            _mainWindow.Add(new Label(0, 3, $"--=[Credits]=--"));
            _mainWindow.Add(new Label(0, 4, $"{Constants.ProgramName} is Copyright (c) 2019 Eric Nusbaum and is distributed under the 2-clause \"Simplified BSD License\". "));
            _mainWindow.Add(new Label(0, 5, "SharpDisam is Copyright (c) 2015 Justin Stenning and is distributed under the 2-clause \"Simplified BSD License\". "));
            _mainWindow.Add(new Label(0, 6, "Terminal.Gui is Copyright (c) 2017 Microsoft Corp and is distributed under the MIT License"));
            _mainWindow.Add(new Label(0, 8, $"--=[Code]=--"));
            _mainWindow.Add(new Label(0, 9, "http://www.github.com/enusbaum/mbbsdasm"));
            _progressBar =
                new ProgressBar(new Rect(1, Application.Top.Frame.Height - 5, Application.Top.Frame.Width - 4, 1));
            _mainWindow.Add(_progressBar);
            _statusLabel = new Label(1, Application.Top.Frame.Height - 7, "Ready!");
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
            var disassemblyRadioGroup = new RadioGroup(0, 0, new[] {"_Minimal", "_Normal"}) {Selected = 1};

            var disOptionsDialog = new Dialog("Disassembly Options", 60, 16)
            {
                new Label(0, 0, "Input File:"),
                new TextField(0, 1, 55, _selectedFile),
                new Label(0, 2, "Output File:"),
                new TextField(0, 3, 55, _outputFile),
                new FrameView(new Rect(0, 5, 55, 6), "Disassembly Options")
                {
                    disassemblyRadioGroup,
                    analysisCheckBox,
                    stringsCheckBox
                }
            };
            disOptionsDialog.AddButton(new Button("OK", true) { Clicked = () =>
                {
                    Application.RequestStop();
                    _optionMBBSAnalysis = analysisCheckBox.Checked;
                    _optionStrings = stringsCheckBox.Checked;
                    _optionMinimal = disassemblyRadioGroup.Selected == 0;
                    Task.Factory.StartNew(() => DoDisassembly());
                }
            });
            disOptionsDialog.AddButton(new Button("Cancel", true) { Clicked = Application.RequestStop });

            Application.Run(disOptionsDialog);
        }

        private void DoDisassembly()
        {
            using (var dasm = new Disassembler(_selectedFile))
            {
                if (File.Exists(_outputFile))
                    File.Delete(_outputFile);

                _statusLabel.Text = "Performing Disassembly...";
                var inputFile = dasm.Disassemble(_optionMinimal);

                //Apply Selected Analysis
                if (_optionMBBSAnalysis)
                {
                    _statusLabel.Text = "Performing Additional Analysis...";
                    Analysis.MBBS.Analyze(inputFile);
                }
                _progressBar.Fraction = .25f;


                var _stringRenderer = new StringRenderer(inputFile);

                _statusLabel.Text = "Processing Segment Information...";
                File.AppendAllText(_outputFile, _stringRenderer.RenderSegmentInformation());
                _progressBar.Fraction = .50f;


                _statusLabel.Text = "Processing Entry Table...";
                File.AppendAllText(_outputFile, _stringRenderer.RenderEntryTable());
                _progressBar.Fraction = .75f;

 

                _statusLabel.Text = "Processing Disassembly...";
                File.AppendAllText(_outputFile, _stringRenderer.RenderDisassembly(_optionMBBSAnalysis));
                _progressBar.Fraction = .85f;


                if (_optionStrings)
                {
                    _statusLabel.Text = "Processing Strings...";
                    File.AppendAllText(_outputFile, _stringRenderer.RenderStrings());
                }

                _statusLabel.Text = "Done!";
                _progressBar.Fraction = 1f;
            }

            var d = new Dialog($"Disassembly Complete!", 50, 12)
            {
                new Label(0, 0, $"Output File: {_outputFile}"),
                new Label(0, 1, $"Bytes Written: {new FileInfo(_outputFile).Length}")
            };
            d.AddButton(new Button("OK", true) { Clicked = Application.RequestStop });
            Application.Run(d);
        }
    }
}
