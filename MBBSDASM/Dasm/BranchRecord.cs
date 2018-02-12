using MBBSDASM.Enums;

namespace MBBSDASM.Dasm
{
    public class BranchRecord
    {
        public ushort Segment { get; set; }
        public ulong Offset { get; set; }
        public EnumBranchType BranchType { get; set; }
        public bool IsRelocation { get; set; }
    }
}