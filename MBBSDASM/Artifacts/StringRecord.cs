namespace MBBSDASM.Artifacts
{
    public class StringRecord
    {
        public int Segment { get; set; }
        public int Offset { get; set; }
        public int Length { get; set; }
        public string Value { get; set; }
    }
}