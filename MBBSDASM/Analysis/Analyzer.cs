using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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
                var covered = m.Exports.Count(x => !string.IsNullOrEmpty(x.Signature) || x.Comments.Count > 0);
                var total = m.Exports.Count;
            }
            
        }

        public static void Analyze(NEFile file)
        {
            ImportedFunctionIdentification(file);
            SubroutineIdentification(file);
            ForLoopIdentification(file);
            GlobalVariableIdentification(file);
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

            var trackedVariables = new List<TrackedOption>();
            
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
                            trackedVariables.Add(new TrackedOption() { Comment = rv.Comment, Segment = segment.Ordinal, Offset = i.Disassembly.Offset, Address = i.Disassembly.Operands[0].LvalUWord});
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
                        
                        //Label beginning of FOR logic by labeling source of unconditional jump
                        segment.DisassemblyLines
                            .First(x => x.Disassembly.Offset == disassemblyLine.BranchFromRecords
                                            .First(y => y.BranchType == EnumBranchType.Unconditional).Offset).Comments
                            .Add("[FOR] Beginning of FOR logic");
                        
                        segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).Comments
                            .Add("[FOR] Branch based on evaluation");
                    }
                }

            }
        }

        /// <summary>
        ///     This method scans the disassembled code and identifies subroutines, labeling them
        ///     appropriatley. This also allows for much more precise variable/argument tracking
        ///     if we properly know the scope of the routine.
        /// </summary>
        /// <param name="file"></param>
        private static void SubroutineIdentification(NEFile file)
        {
            Console.WriteLine($"{DateTime.Now} Identifying Subroutines");
            
            
            //Scan the code segments
            foreach (var segment in file.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                ushort subroutineId = 0;
                var bInSubroutine = false;
                var trackedLocalVariables = new List<TrackedVariable>();
                var bIsLongVariable = false;
                ushort highBits = 0;
                for (var i = 0; i < segment.DisassemblyLines.Count; i++)
                {
                    if (bInSubroutine)
                        segment.DisassemblyLines[i].SubroutineID = subroutineId;

                    if (segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Ienter || 
                        segment.DisassemblyLines[i].BranchFromRecords.Any(x => x.BranchType == EnumBranchType.Call) ||
                        segment.DisassemblyLines[i].ExportedFunction != null ||
                        //Previous instruction was the end of a subroutine, we must be starting one that's not
                        //referenced anywhere in the code
                        (i > 0 &&
                        (segment.DisassemblyLines[i - 1].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iretf ||
                        segment.DisassemblyLines[i - 1].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iret)))
                    {
                        subroutineId++;
                        bInSubroutine = true;
                        segment.DisassemblyLines[i].SubroutineID = subroutineId;
                        segment.DisassemblyLines[i].Comments.Insert(0, $"/---- BEGIN SUBROUTINE {subroutineId}");
                        continue;
                    }
                    
                    //Setting local variable
                    if (segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Imov &&
                        segment.DisassemblyLines[i].Disassembly.ToString().Contains(" [bp-"))
                    {
                        //mov word [bp-0x8], 0x1bf
                        var addressAndValue = segment.DisassemblyLines[i].Disassembly.ToString().Split('-');
                        
                        if (addressAndValue.Length != 2)
                            continue;

                        if (addressAndValue[1].Split(',').Length != 2)
                            continue;
                        
                        var addressString = addressAndValue[1].Split(',')[0].TrimEnd(']');
                        var address = Convert.ToUInt16(addressString, 16);
                        var valueString = addressAndValue[1].Split(',')[1].Trim();

                        if (!valueString.StartsWith("0x"))
                            continue;
                        
                        var value = Convert.ToUInt16(valueString, 16);
                        
                        //If the next op is also a mov, this MOST LIKELY means we're assigning the high and low 16-bit
                        //values of a long. We'll skip this one, save the value and move on.
                        if (!bIsLongVariable && segment.DisassemblyLines[i + 1].Disassembly.Mnemonic ==
                            ud_mnemonic_code.UD_Imov &&
                            segment.DisassemblyLines[i].Disassembly.ToString().Contains(" [bp-"))
                        {
                            bIsLongVariable = true;
                            highBits = value;
                        }
                        else
                        {
                            var setValue = 0;

                            //Concat the high and low byte values if we're setting a long
                            setValue = bIsLongVariable ? (highBits << 16) | value : value;

                            if (trackedLocalVariables.All(x => x.MemoryAddress != address))
                            {
                                trackedLocalVariables.Add(new TrackedVariable()
                                {
                                    MemoryAddress = address,
                                    Name = $"VAR{trackedLocalVariables.Count}",
                                   Values = new List<int>() 
                                });
                            }
                            
                            trackedLocalVariables.First(x => x.MemoryAddress == address).Values.Add(setValue);

                            segment.DisassemblyLines[i].Comments
                                .Add(
                                    $"{trackedLocalVariables.First(x => x.MemoryAddress == address).Name} = {setValue}{(bIsLongVariable ? " (Long)" : string.Empty)}");

                            bIsLongVariable = false;
                        }
                    }


                    if (bInSubroutine && (segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iret ||
                        segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iretf))
                    {
                        bInSubroutine = false;
                        segment.DisassemblyLines[i].Comments.Insert(0, $"\\---- END SUBROUTINE {subroutineId}");
                        trackedLocalVariables.Clear();
                    }
                }
            }
        }

        /// <summary>
        ///     Labels and tracks global variables
        /// 
        ///     These variables would be demonstrated in C++ by accessing them via
        ///     GLOBAL->Variable
        /// </summary>
        /// <param name="file"></param>
        private static void GlobalVariableIdentification(NEFile file)
        {
            var trackedGlobalVariables = new List<TrackedVariable>();
            
            Console.WriteLine($"{DateTime.Now} Identifying Global Variables");

            //Scan the code segments
            foreach (var segment in file.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                foreach (var t in segment.DisassemblyLines.Where(x =>
                    x.Disassembly.ToString().StartsWith("mov word [es:bx+")))
                {
                    //mov word [es:bx+0x8], 0x0
                    var addressAndValue = t.Disassembly.ToString().Split('+')[1].Split(',');

                    if (addressAndValue.Length != 2)
                        continue;

                    var addressString = addressAndValue[0].TrimEnd(']');
                    var address = Convert.ToUInt16(addressString, 16);
                    var valueString = addressAndValue[1].Trim();
                    var value = Convert.ToInt16(valueString, 16);

                    //New or existing?
                    if (trackedGlobalVariables.All(x => x.MemoryAddress != address))
                    {
                        trackedGlobalVariables.Add(new TrackedVariable()
                        {
                            Name = $"GLOBAL->VAR{trackedGlobalVariables.Count}",
                            MemoryAddress = address,
                            Values = new List<int>()
                        });
                    }

                    trackedGlobalVariables.First(x => x.MemoryAddress == address).Values.Add(value);
                }
            }
            
            //Now that we've identified every 'setter' for the global variables, let's go label comparisons and pushes
            //Scan the code segments
            foreach (var segment in file.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                foreach (var t in segment.DisassemblyLines.Where(x =>
                    x.Disassembly.ToString().Contains(" word [es:bx+")))
                {
                    //cmp word [es:bx+0x8], 0x0
                    var addressAndValue = t.Disassembly.ToString().Split('+')[1].Split(',');

                    if (addressAndValue.Length != 2)
                        continue;
                    
                    var addressString = addressAndValue[0].TrimEnd(']');
                    var address = Convert.ToUInt16(addressString, 16);
                    var valueString = addressAndValue[1].Trim();
                    var value = Convert.ToInt16(valueString, 16);
                    
                    var trackedVar = trackedGlobalVariables.FirstOrDefault(x => x.MemoryAddress == address);

                    if (trackedVar == null)
                        continue;
                    
                    switch (t.Disassembly.Mnemonic)
                    {
                        case ud_mnemonic_code.UD_Icmp:
                            t.Comments.Add(
                                trackedVar.isBool
                                    ? $"Compare {trackedVar.Name} == {(value == 0 ? "false" : "true")}"
                                    : $"Compare {trackedVar.Name} == {value}");
                            break;
                        case ud_mnemonic_code.UD_Ipush:
                            t.Comments.Add($"Push {trackedVar.Name} to stack");
                            break;
                        case ud_mnemonic_code.UD_Imov:
                            t.Comments.Add(
                                trackedVar.isBool
                                    ? $"{trackedVar.Name} = {(value == 0 ? "false" : "true")}"
                                    : $"{trackedVar.Name} = {value}");
                            break;
                    }
                }
            }
        }
    }
}