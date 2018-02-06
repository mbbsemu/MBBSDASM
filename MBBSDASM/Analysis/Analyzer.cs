using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using MBBSDASM.Analysis.Artifacts;
using MBBSDASM.Artifacts;
using MBBSDASM.Enums;
using Newtonsoft.Json;

namespace MBBSDASM.Analysis
{
    /// <summary>
    ///     Performs Analysis on Imported Functions using defined Module Definiton JSON files
    /// </summary>
    public static class Analyzer
    {
        private static readonly List<ModuleDefinition> _moduleDefinitions;

        /// <summary>
        ///     Default Constructor
        /// </summary>
        static Analyzer()
        {
            _moduleDefinitions = new List<ModuleDefinition>();

            //Load Definitions
            var assembly = typeof(Analyzer).GetTypeInfo().Assembly;
            foreach (var def in assembly.GetManifestResourceNames().Where(x => x.EndsWith("_def.json")))
            {
                using (var reader = new StreamReader(assembly.GetManifestResourceStream(def)))
                {
                    _moduleDefinitions.Add(JsonConvert.DeserializeObject<ModuleDefinition>(reader.ReadToEnd()));
                }
            }

            //Coverage Tracking
            foreach (var m in _moduleDefinitions)
            {
                var covered = m.Exports.Count(x => x.Comments.Count > 0);
                var total = m.Exports.Count;
            }
    }
        
        /// <summary>
        ///     Analysis Routine for the MBBS Analyzer
        /// </summary>
        /// <param name="file"></param>
        public static void Analyze(NEFile file)
        {
            var trackedVariables = new List<TrackedVariable>();
            
            //Identify Functions and Label them with the module defition file
            foreach (var segment in file.SegmentTable.Where(x=> x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                //Function Definition Identification Pass
                foreach (var disassemblyLine in segment.DisassemblyLines.Where(x=> x.Comments.Count > 0))
                {
                    var currentModule =
                        _moduleDefinitions.FirstOrDefault(x => disassemblyLine.Comments.Any(y => y.Contains(x.Name)));

                    if (currentModule == null)
                        continue;
                    
                    
                    var comment = disassemblyLine.Comments.First(x => x.Contains($"{currentModule.Name}.Ord"));
                    var ord = ushort.Parse(comment.Substring(comment.IndexOf('(') + 1, 4), NumberStyles.HexNumber);
                    var definition = currentModule.Exports.FirstOrDefault(x => x.Ord == ord);

                    //Didn't have a definition for it?
                    if (definition == null)
                        continue;

                    //Since we have the ACTUAL name, delete the original comment
                    disassemblyLine.Comments.Remove(disassemblyLine.Comments.First(x => x.Contains($"{currentModule.Name}.Ord")));

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
    }
}