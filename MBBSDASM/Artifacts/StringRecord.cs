using System.Linq;

namespace MBBSDASM.Artifacts
{
    public class StringRecord
    {
        public int Segment { get; set; }
        public int Offset { get; set; }
        public int Length { get; set; }
        public string Value { get; set; }

        /// <summary>
        ///     Returns TRUE if the string contains printable characters
        /// </summary>
        public bool IsPrintable
        {
            get { return Value.ToCharArray().Any(x => x > 32 && x < 126); }
        }
    }
}