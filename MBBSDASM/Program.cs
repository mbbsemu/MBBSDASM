using System;
using System.IO;
using System.Linq;
using System.Text;
using MBBSDASM.Artifacts;
using MBBSDASM.Enums;
using SharpDisasm.Udis86;

namespace MBBSDASM
{
    /// <summary>
    ///     Main Console Entrypoint
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("------------------------------------------------------");
            Console.WriteLine("MBBSDASM v1.1");
            Console.WriteLine("GitHub: http://www.github.com/enusbaum/mbbsdasm/");
            Console.WriteLine("------------------------------------------------------");

            if (args.Length == 0)
            {
                Console.WriteLine("Please use the -? option for help");
                return;
            }
            
            try
            {
                //Command Line Values
                var sInputFile = "";
                var sOutputFile = "";
                var bMinimal = false;
                var bAnalysis = false;

                for (var i = 0; i < args.Length; i++)
                {
                    switch (args[i].ToUpper())
                    {
                        case "-I":
                            sInputFile = args[i + 1];
                            i++;
                            break;
                        case "-O":
                            sOutputFile = args[i + 1];
                            i++;
                            break;
                        case "-MINIMAL":
                            bMinimal = true;
                            break;
                        case "-ANALYSIS":
                            bAnalysis = true;
                            break;
                        case "-?":
                            Console.WriteLine("-I <file> -- Input File to Disassemble");
                            Console.WriteLine("-O <file> -- Output File for Disassembly (Default Console)");
                            Console.WriteLine("-MINIMAL -- Minimal Disassembler Output");
                            Console.WriteLine("-ANALYSIS -- Additional Analysis on Imported Functions (if available)");
                            return;
                    }
                }

                //Verify Input File is Valid
                if (string.IsNullOrEmpty(sInputFile) || !File.Exists(sInputFile))
                    throw new Exception("Error: Please specify a valid input file");

                //Warn of Analysis not being available with minimal output
                if (bMinimal && bAnalysis)
                    Console.WriteLine($"{DateTime.Now} Warning: Analysis Mode unavailable with minimal output option, ignoring");

                Console.WriteLine($"{DateTime.Now} Inspecting File: {sInputFile}");

                //Read the entire file to memory
                var inputFile = new NEFile(sInputFile);
                
                //Decompile Each Segment
                foreach (var s in inputFile.SegmentTable)
                {
                    Console.WriteLine($"{DateTime.Now} Performing Disassembly of Segment {s.Ordinal}");
                    s.DisassemblyLines = Dasm.Disassembler.Disassemble(s);
                }

                //Skip Additional Analysis if they selected minimal
                if (!bMinimal)
                {
                    Console.WriteLine($"{DateTime.Now} Applying Relocation Info ");
                    Dasm.Disassembler.ApplyRelocationInfo(inputFile);

                    Console.WriteLine($"{DateTime.Now} Applying String References");
                    Dasm.Disassembler.ResolveStringReferences(inputFile);

                    Console.WriteLine($"{DateTime.Now} Resolving Jump Targets");
                    Dasm.Disassembler.ResolveJumpTargets(inputFile);

                    Console.WriteLine($"{DateTime.Now} Resolving Call Targets");
                    Dasm.Disassembler.ResolveCallTargets(inputFile);

                    Console.WriteLine($"{DateTime.Now} Identifying Entry Points");
                    Dasm.Disassembler.IdentifyEntryPoints(inputFile);

                    //Apply Selected Analysis
                    if (bAnalysis)
                    {
                        Console.WriteLine($"{DateTime.Now} Performing Imported Function Analysis");
                        Analysis.Analyzer.Analyze(inputFile);
                    }
                }

                //Build Final Output
                var output = new StringBuilder();
                
                output.AppendLine($"; Disassembly of {inputFile.Path}{inputFile.FileName}");
                output.AppendLine($"; Description: {inputFile.NonResidentNameTable[0].Name}");
                output.AppendLine(";");
                output.AppendLine(";-------------------------------------------");
                output.AppendLine("; Segment Information");
                output.AppendLine($"; Number of Code/Data Segments = {inputFile.WindowsHeader.SegmentTableEntries}");
                output.AppendLine(";-------------------------------------------");
                foreach (var s in inputFile.SegmentTable)
                {
                    output.AppendLine(
                        $"; Segment #{s.Ordinal:0000}\tOffset: {s.Offset:00000000}\tSize: {s.Data.Length:X4}h\t Flags: 0x{s.Flag:X4} -> {(s.Flags.Contains(EnumSegmentFlags.Code) ? "CODE" : "DATA")}, {(s.Flags.Contains(EnumSegmentFlags.Fixed) ? "FIXED" : "MOVABLE")}");
                }
                
                output.AppendLine(";-------------------------------------------");
                output.AppendLine("; Entry Table Information");
                output.AppendLine($"; Number of Entry Table Functions = {inputFile.EntryTable.Count}");
                output.AppendLine(";-------------------------------------------");
                foreach (var t in inputFile.NonResidentNameTable)
                {
                    if (t.IndexIntoEntryTable == 0)
                        continue;
                    
                    output.AppendLine($"; Addr:{inputFile.EntryTable.FirstOrDefault(x=> x.Ordinal == t.IndexIntoEntryTable)?.SegmentNumber:0000}.{inputFile.EntryTable.FirstOrDefault(x=> x.Ordinal == t.IndexIntoEntryTable)?.Offset:X4}\tOrd:{t.IndexIntoEntryTable:0000}d\tName: {t.Name}");
                }
                foreach (var t in inputFile.ResidentNameTable)
                {
                    if (t.IndexIntoEntryTable == 0)
                        continue;
                    
                    output.AppendLine($"; Addr:{inputFile.EntryTable.FirstOrDefault(x=> x.Ordinal == t.IndexIntoEntryTable)?.SegmentNumber:0000}.{inputFile.EntryTable.FirstOrDefault(x=> x.Ordinal == t.IndexIntoEntryTable)?.Offset:X4}\tOrd:{t.IndexIntoEntryTable:0000}d\tName: {t.Name}");
                }
                
                output.AppendLine(";");

                //Write Disassembly to output
                foreach (var s in inputFile.SegmentTable.Where(x => x.Flags.Contains(EnumSegmentFlags.Code)))
                {
                    output.AppendLine(";-------------------------------------------");
                    output.AppendLine($"; Start of Code for Segment {s.Ordinal}");
                    output.AppendLine("; FILE_OFFSET:SEG_NUM.SEG_OFFSET");
                    output.AppendLine(";-------------------------------------------");

                    //Allows us to line up all the comments in a segment along the same column
                    var maxDecodeLength = s.DisassemblyLines.Max(x => x.Disassembly.ToString().Length) + 21;
                    
                    foreach (var d in s.DisassemblyLines)
                    {
                        if (d.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ienter || d.Comments.Any(x=> x.StartsWith("Referenced by CALL")))
                        {
                            d.Comments.Insert(0, "/--- Begin Procedure");
                        }
                        
                        if (d.Disassembly.Mnemonic == ud_mnemonic_code.UD_Iretf || d.Disassembly.Mnemonic == ud_mnemonic_code.UD_Iret)
                        {
                            d.Comments.Insert(0, "\\--- End Procedure");
                        }

                        var sOutputLine = $"{d.Disassembly.Offset + s.Offset:X8}h:{s.Ordinal:0000}.{d.Disassembly.Offset:X4}h {d.Disassembly}";
                        if (d.Comments != null && d.Comments.Count > 0)
                        {
                            var newLine = false;
                            var firstCommentIndex = 0;
                            foreach (var c in d.Comments)
                            {
                                if (!newLine)
                                {  
                                    sOutputLine += $"{new string(' ', maxDecodeLength - sOutputLine.Length)}; {c}";
                                    
                                    //Set variables to help us keep the following comments lined up with the first one
                                    firstCommentIndex = sOutputLine.IndexOf(';');
                                    newLine = true;
                                    continue;
                                }
                                sOutputLine +=   $"\r\n{new string(' ', firstCommentIndex) }; {c}";                                
                            }
                        }
                        output.AppendLine(sOutputLine);
                    }
                    output.AppendLine();
                }

                if (string.IsNullOrEmpty(sOutputFile))
                {
                    Console.WriteLine(output.ToString());
                }
                else
                {
                    Console.WriteLine($"{DateTime.Now} Writing Disassembly to {sOutputFile}");
                    File.WriteAllText(sOutputFile, output.ToString());
                }
                Console.WriteLine($"{DateTime.Now} Done!");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine($"{DateTime.Now} Fatal Exception -- Exiting");
            }
        }
    }
}