namespace MBBSDASM.Analysis.Artifacts
{
    public class TrackedVariable
    {
        public ushort Segment { get; set; }
        public ulong Offset { get; set; }
        public ushort Address { get; set; }
        public string Name { get; set; }
        public string Comment { get; set; }
    }
}