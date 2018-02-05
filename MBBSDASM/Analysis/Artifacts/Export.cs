using System.Collections.Generic;

namespace MBBSDASM.Analysis.Artifacts
{
    public class Export
    {
        public string Name { get; set; }
        public ushort Ord { get; set; }
        public string Signature { get; set; }
        public string SignatureFormat { get; set; }
        public List<string> Comments { get; set; }
        public List<Instruction> PrecedingInstructions { get; set; }
        public List<ReturnValue> ReturnValues { get; set; }
    }
}