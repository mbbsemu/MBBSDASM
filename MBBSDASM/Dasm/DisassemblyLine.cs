using System.Collections.Generic;
using SharpDisasm;

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
    }
}