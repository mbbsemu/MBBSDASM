using System;
using System.Linq;
using System.Text;
using MBBSDASM.Artifacts;
using MBBSDASM.Enums;

namespace MBBSDASM.Renderer.impl
{
    /// <summary>
    ///     String Renderer
    ///
    ///     Used to generate human readable string output of the disassembly. Mainly used to output to a text file
    /// </summary>
    public class StringRenderer
    {
        /// <summary>
        ///     Input File
        /// </summary>
        private readonly NEFile _inputFile;

        /// <summary>
        ///     Default Constructor
        /// </summary>
        /// <param name="inputFile"></param>
        public StringRenderer(NEFile inputFile)
        {
            _inputFile = inputFile;
        }

        /// <summary>
        ///     Renders the Segment Information as readable text
        /// </summary>
        /// <returns></returns>
        public string RenderSegmentInformation()
        {
            var output = new StringBuilder();

            output.AppendLine(";-------------------------------------------");
            output.AppendLine("; Segment Information");
            output.AppendLine($"; Number of Code/Data Segments = {_inputFile.WindowsHeader.SegmentTableEntries}");
            output.AppendLine(";-------------------------------------------");
            foreach (var s in _inputFile.SegmentTable)
            {
                output.AppendLine(
                    $"; Segment #{s.Ordinal:0000}\tOffset: {s.Offset:X8}\tSize: {s.Data.Length:X4}\t Flags: 0x{s.Flag:X4} -> {(s.Flags.Contains(EnumSegmentFlags.Code) ? "CODE" : "DATA")}, {(s.Flags.Contains(EnumSegmentFlags.Fixed) ? "FIXED" : "MOVABLE")}");
            }

            return output.ToString();
        }

        /// <summary>
        ///     Renders the Entry Table as readable text
        /// </summary>
        /// <returns></returns>
        public string RenderEntryTable()
        {
            var output = new StringBuilder();

            output.AppendLine(";-------------------------------------------");
            output.AppendLine("; Entry Table Information");
            output.AppendLine($"; Number of Entry Table Functions = {_inputFile.EntryTable.Count}");
            output.AppendLine(";-------------------------------------------");
            foreach (var t in _inputFile.NonResidentNameTable)
            {
                if (t.IndexIntoEntryTable == 0)
                    continue;

                output.AppendLine(
                    $"; Addr:{_inputFile.EntryTable.FirstOrDefault(x => x.Ordinal == t.IndexIntoEntryTable)?.SegmentNumber:0000}.{_inputFile.EntryTable.FirstOrDefault(x => x.Ordinal == t.IndexIntoEntryTable)?.Offset:X4}\tOrd:{t.IndexIntoEntryTable:0000}d\tName: {t.Name}");
            }

            foreach (var t in _inputFile.ResidentNameTable)
            {
                if (t.IndexIntoEntryTable == 0)
                    continue;

                output.AppendLine(
                    $"; Addr:{_inputFile.EntryTable.FirstOrDefault(x => x.Ordinal == t.IndexIntoEntryTable)?.SegmentNumber:0000}.{_inputFile.EntryTable.FirstOrDefault(x => x.Ordinal == t.IndexIntoEntryTable)?.Offset:X4}\tOrd:{t.IndexIntoEntryTable:0000}d\tName: {t.Name}");
            }

            return output.ToString();
        }

        /// <summary>
        ///     Renders the Disassembly output as readable text
        /// </summary>
        /// <param name="analysis"></param>
        /// <returns></returns>
        public string RenderDisassembly(bool analysis = false)
        {
            var output = new StringBuilder();

            //Write Disassembly to output
            foreach (var s in _inputFile.SegmentTable.Where(x => x.Flags.Contains(EnumSegmentFlags.Code)))
            {
                output.AppendLine(";-------------------------------------------");
                output.AppendLine($"; Start of Code for Segment {s.Ordinal}");
                output.AppendLine("; FILE_OFFSET:SEG_NUM.SEG_OFFSET BYTES DISASSEMBLY");
                output.AppendLine(";-------------------------------------------");

                //Allows us to line up all the comments in a segment along the same column
                var maxDecodeLength =
                    s.DisassemblyLines.Max(x =>
                        x.Disassembly.ToString().Length + Constants.MAX_INSTRUCTION_LENGTH + 1) + 21;

                //Write each line of the disassembly to the output stream
                foreach (var d in s.DisassemblyLines)
                {
                    //Label Entrypoints/Exported Functions
                    if (d.ExportedFunction != null)
                    {
                        d.Comments.Add($"Exported Function: {d.ExportedFunction.Name}");
                    }

                    //Label Branch Targets
                    foreach (var b in d.BranchFromRecords)
                    {
                        switch (b.BranchType)
                        {
                            case EnumBranchType.Call:
                                d.Comments.Add(
                                    $"Referenced by CALL at address: {b.Segment:0000}.{b.Offset:X4}h {(b.IsRelocation ? "(Relocation)" : string.Empty)}");
                                break;
                            case EnumBranchType.Conditional:
                            case EnumBranchType.Unconditional:
                                d.Comments.Add(
                                    $"{(b.BranchType == EnumBranchType.Conditional ? "Conditional" : "Unconditional")} jump from {b.Segment:0000}:{b.Offset:X4}h");
                                break;
                        }
                    }

                    //Label Branch Origins (Relocation)
                    foreach (var b in d.BranchToRecords.Where(x =>
                        x.IsRelocation && x.BranchType == EnumBranchType.Call))
                        d.Comments.Add($"CALL {b.Segment:0000}.{b.Offset:X4}h (Relocation)");

                    //Label Refereces by SEG ADDR (Internal)
                    foreach (var b in d.BranchToRecords.Where(x =>
                        x.IsRelocation && x.BranchType == EnumBranchType.SegAddr))
                        d.Comments.Add($"SEG ADDR of Segment {b.Segment}");

                    //Label String References
                    if (d.StringReference != null)
                        foreach (var sr in d.StringReference)
                            d.Comments.Add($"Possible String reference from SEG {sr.Segment} -> \"{sr.Value}\"");

                    //Only label Imports if Analysis is off, because Analysis does much more in-depth labeling
                    if (!analysis)
                    {
                        foreach (var b in d.BranchToRecords?.Where(x =>
                            x.IsRelocation && (x.BranchType == EnumBranchType.CallImport ||
                                               x.BranchType == EnumBranchType.SegAddrImport)))
                            d.Comments.Add(
                                $"{(b.BranchType == EnumBranchType.CallImport ? "call" : "SEG ADDR of")} {_inputFile.ImportedNameTable.FirstOrDefault(x => x.Ordinal == b.Segment)?.Name}.Ord({b.Offset:X4}h)");
                    }

                    var sOutputLine =
                        $"{d.Disassembly.Offset + s.Offset:X8}h:{s.Ordinal:0000}.{d.Disassembly.Offset:X4}h {BitConverter.ToString(d.Disassembly.Bytes).Replace("-", string.Empty).PadRight(Constants.MAX_INSTRUCTION_LENGTH, ' ')} {d.Disassembly}";
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

                            sOutputLine += $"\r\n{new string(' ', firstCommentIndex)}; {c}";
                        }
                    }

                    output.AppendLine(sOutputLine);
                }

                output.AppendLine();
            }

            return output.ToString();
        }

        /// <summary>
        ///     Renders strings in DATA segments as readable text
        /// </summary>
        /// <returns></returns>
        public string RenderStrings()
        {
            var output = new StringBuilder();

            foreach (var seg in _inputFile.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Data) && x.StringRecords?.Count > 0))
            {
                output.AppendLine(";-------------------------------------------");
                output.AppendLine($"; Start of Data for Segment {seg.Ordinal}");
                output.AppendLine("; FILE_OFFSET:SEG_NUM.SEG_OFFSET");
                output.AppendLine(";-------------------------------------------");
                foreach (var str in seg.StringRecords)
                    output.AppendLine(
                        $"{str.Offset + str.Offset:X8}h:{seg.Ordinal:0000}.{str.Offset:X4}h '{str.Value}'");
            }

            return output.ToString();
        }
    }
}
