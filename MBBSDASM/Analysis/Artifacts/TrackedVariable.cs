using System.Collections.Generic;
using System.Linq;

namespace MBBSDASM.Analysis.Artifacts
{
    public class TrackedVariable
    {
        public string Name { get; set; }
        public ushort MemoryAddress { get; set; }
        
        /// <summary>
        ///     We only track values to identify bool vs numeric
        ///     (sum(values) == 1 && count(values) == 2) == bool
        /// </summary>
        public List<int> Values { get; set; }

        public bool isBool => Values.Count >= 2 && Values.Max() <= 1;
    }
}