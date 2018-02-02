using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using MBBSDASM.Analysis.Artifacts;
using MBBSDASM.Artifacts;
using MBBSDASM.Enums;
using Newtonsoft.Json;

namespace MBBSDASM.Analysis
{
    /// <summary>
    ///     Performs Analysis on Imported Functions using defined Module Definiton JSON files
    /// </summary>
    public class Analyzer
    {
        private readonly List<ModuleDefinition> _moduleDefinitions;

        /// <summary>
        ///     Default Constructor
        /// </summary>
        public Analyzer()
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
        }
        
        /// <summary>
        ///     Analysis Routine for the MBBS Analyzer
        /// </summary>
        /// <param name="file"></param>
        public void Analyze(NEFile file)
        {
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
                                default:
                                    break;
                            }
                        }

                        //Only if we found all the correct values, otherwise bail
                        if (values.Count == definition.PrecedingInstructions.Count)
                            disassemblyLine.Comments.Add(string.Format($"Resolved Signature: {definition.SignatureFormat}",
                                values.Select(x => x.ToString()).ToArray()));
                    }

                    //Finally, append any comments that accompany the function definition
                    if (definition.Comments != null && definition.Comments.Count > 0)
                        disassemblyLine.Comments.AddRange(definition.Comments);
                }
            }
        }
    }
}