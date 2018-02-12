namespace MBBSDASM.Dasm
{
    public class StringReferenceRecord
    {
        public ushort Segment { get; set; }
        public ulong Offset { get; set; }
        public string Value { get; set; }
    }
}