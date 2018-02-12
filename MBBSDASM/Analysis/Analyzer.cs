using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using MBBSDASM.Analysis.Artifacts;
using MBBSDASM.Artifacts;
using MBBSDASM.Dasm;
using MBBSDASM.Enums;
using Newtonsoft.Json;
using SharpDisasm.Udis86;

namespace MBBSDASM.Analysis
{
    /// <summary>
    ///     Performs Analysis on Imported Functions using defined Module Definiton JSON files
    /// </summary>
    public static class Analyzer
    {
        private static readonly List<ModuleDefinition> ModuleDefinitions;

        /// <summary>
        ///     Default Constructor
        /// </summary>
        static Analyzer()
        {
            ModuleDefinitions = new List<ModuleDefinition>();

            //Load Definitions
            var assembly = typeof(Analyzer).GetTypeInfo().Assembly;
            foreach (var def in assembly.GetManifestResourceNames().Where(x => x.EndsWith("_def.json")))
            {
                using (var reader = new StreamReader(assembly.GetManifestResourceStream(def)))
                {
                    ModuleDefinitions.Add(JsonConvert.DeserializeObject<ModuleDefinition>(reader.ReadToEnd()));
                }
            }

            //Coverage Tracking
            foreach (var m in ModuleDefinitions)
            {
                var covered = m.Exports.Count(x => !string.IsNullOrEmpty(x.Signature));
                var total = m.Exports.Count;
            }
        }

        public static void Analyze(NEFile file)
        {
            ImportedFunctionIdentification(file);
            ForLoopIdentification(file);
        }

        /// <summary>
        ///     Identification Routine for MBBS/WG Imported Functions
        /// </summary>s
        /// <param name="file"></param>
        private static void ImportedFunctionIdentification(NEFile file)
        {
            Console.WriteLine($"{DateTime.Now} Identifying Imported Functions");
            
            if (!file.ImportedNameTable.Any(nt => ModuleDefinitions.Select(md => md.Name).Contains(nt.Name)))
            {
                Console.WriteLine($"{DateTime.Now} No known Module Definitions found in target file, skipping Imported Function Identification");
                return;
            }

            var trackedVariables = new List<TrackedVariable>();
            
            //Identify Functions and Label them with the module defition file
            foreach (var segment in file.SegmentTable.Where(x=> x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                //Function Definition Identification Pass
                foreach (var disassemblyLine in segment.DisassemblyLines.Where(x=> x.BranchToRecords.Any(y=> y.BranchType == EnumBranchType.CallImport)))
                {

                    var currentImport =
                        disassemblyLine.BranchToRecords.First(z => z.BranchType == EnumBranchType.CallImport);
                    
                    var currentModule =
                        ModuleDefinitions.FirstOrDefault(x =>
                            x.Name == file.ImportedNameTable.FirstOrDefault(y =>
                                y.Ordinal == currentImport.Segment)?.Name);

                    if (currentModule == null)
                        continue;

                    var ord = currentImport.Offset;
                    var definition = currentModule.Exports.FirstOrDefault(x => x.Ord == ord);

                    //Didn't have a definition for it?
                    if (definition == null)
                        continue;

                    //We'll replace the old external reference with ordinal with the actual function name/sig
                    disassemblyLine.Comments.Add(!string.IsNullOrEmpty(definition.Signature)
                        ? definition.Signature
                        : $"{currentModule.Name}.{definition.Name}");

                    //Attempt to Resolve the actual Method Signature if we have the definitions
                    if (!string.IsNullOrEmpty(definition.SignatureFormat) && definition.PrecedingInstructions != null &&
                        definition.PrecedingInstructions.Count > 0)
                    {
                        var values = new List<object>();
                        foreach (var pi in definition.PrecedingInstructions)
                        {
                            var i = segment.DisassemblyLines.FirstOrDefault(x =>
                                x.Ordinal == disassemblyLine.Ordinal + pi.Offset &&
                                x.Disassembly.Mnemonic.ToString().ToUpper().EndsWith(pi.Op));

                            if (i == null)
                                break;
                            
                            switch (pi.Type)
                            {
                                case "int":
                                    values.Add(i.Disassembly.Operands[0].LvalSDWord);
                                    break;
                                case "string":
                                    if (i.Comments.Any(x => x.Contains("reference")))
                                    {
                                        var resolvedStringComment = i.Comments.First(x => x.Contains("reference"));
                                        values.Add(resolvedStringComment.Substring(
                                            resolvedStringComment.IndexOf('\"')));
                                    }
                                    break;
                            }
                        }

                        //Only add the resolved signature if we correctly identified all the values we were expecting
                        if (values.Count == definition.PrecedingInstructions.Count)
                            disassemblyLine.Comments.Add(string.Format($"Resolved Signature: {definition.SignatureFormat}",
                                values.Select(x => x.ToString()).ToArray()));
                    }
                    
                    //Attempt to resolve a variable this method might be saving
                    if (definition.ReturnValues != null && definition.ReturnValues.Count > 0)
                    {
                        foreach (var rv in definition.ReturnValues)
                        {
                            var i = segment.DisassemblyLines.FirstOrDefault(x =>
                                x.Ordinal == disassemblyLine.Ordinal + rv.Offset &&
                                x.Disassembly.Mnemonic.ToString().ToUpper().EndsWith(rv.Op));
                            
                            if (i == null)
                                break;
                            
                            i.Comments.Add($"Return value saved to 0x{i.Disassembly.Operands[0].LvalUWord:X}h");
                            
                            if(!string.IsNullOrEmpty(rv.Comment))
                                i.Comments.Add(rv.Comment);
                            //Add this to our tracked variables, we'll go back through and re-label all instances after this analysis pass
                            trackedVariables.Add(new TrackedVariable() { Comment = rv.Comment, Segment = segment.Ordinal, Offset = i.Disassembly.Offset, Address = i.Disassembly.Operands[0].LvalUWord});
                        }
                    }

                    //Finally, append any comments that accompany the function definition
                    if (definition.Comments != null && definition.Comments.Count > 0)
                        disassemblyLine.Comments.AddRange(definition.Comments);
                }
                
                //Variable Tracking Labeling Pass
                foreach (var v in trackedVariables)
                {
                    foreach (var disassemblyLine in segment.DisassemblyLines.Where(x => x.Disassembly.ToString().Contains($"[0x{v.Address:X}]".ToLower()) && x.Disassembly.Offset != v.Offset))
                    {

                        disassemblyLine.Comments.Add($"Reference to variable created at {v.Segment:0000}.{v.Offset:X4}h");
                    }
                }
            }
        }

        /// <summary>
        ///     This method scans the disassembly for signatures of Turbo C++ FOR loops
        ///     and labels them appropriatley
        /// </summary>
        /// <param name="file"></param>
        private static void ForLoopIdentification(NEFile file)
        {
            /*
            *    Borland C++ compiled i++/i-- FOR loops look like:
            *    inc word [var]
            *    cmp word [var], condition (unconditional jump here from before beginning of for loop logic)
            *    conditional jump to beginning of for
            *
            *    So we'll search for this basic pattern
            */

            Console.WriteLine($"{DateTime.Now} Identifying FOR Loops");

            //Scan the code segments
            foreach (var segment in file.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                //Function Definition Identification Pass
                foreach (var disassemblyLine in segment.DisassemblyLines.Where(x =>
                    x.Disassembly.Mnemonic == ud_mnemonic_code.UD_Icmp &&
                    x.BranchFromRecords.Any(y => y.BranchType == EnumBranchType.Unconditional)))
                {


                    if (MnemonicGroupings.IncrementDecrementGroup.Contains(segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Disassembly.Mnemonic)
                        && segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).BranchToRecords.Count > 0
                        && segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).BranchToRecords.First(x => x.BranchType == EnumBranchType.Conditional)
                            .Offset < disassemblyLine.Disassembly.Offset)
                    {

                        if (MnemonicGroupings.IncrementGroup.Contains(segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Disassembly
                            .Mnemonic))
                        {
                            segment.DisassemblyLines
                                .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Comments
                                .Add("[FOR] Increment Value");
                        }
                        else
                        {
                            segment.DisassemblyLines
                                .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Comments
                                .Add("[FOR] Decrement Value");
                        }

                        disassemblyLine.Comments.Add("[FOR] Evaluate Break Condition");
                        segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).Comments
                            .Add("[FOR] Branch based on evaluation");
                    }
                }

            }
        }
    }
}