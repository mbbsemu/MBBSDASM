using System.Collections.Concurrent;
using System.Collections.Generic;
using MBBSDASM.Artifacts;
using Instruction = SharpDisasm.Instruction;

namespace MBBSDASM.Dasm
{
    /// <summary>
    ///     Class that contains the actual disassembly obejct from SharpDisasm but also
    ///     additional Metadata
    /// </summary>
    public class DisassemblyLine
    {   
        public int Ordinal { get; set; }
        public Instruction Disassembly { get; set; }
        public List<string> Comments { get; set; }
        public ExportedFunctionRecord ExportedFunction { get; set; }
        public ConcurrentBag<BranchRecord> BranchToRecords { get; set; }
        public ConcurrentBag<BranchRecord> BranchFromRecords { get; set; }
        public List<StringRecord> StringReference { get; set; }
        public ushort SubroutineID { get; set; }
    }
}