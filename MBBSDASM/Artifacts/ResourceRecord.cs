using System.Collections.Generic;

namespace MBBSDASM.Artifacts
{
    /// <summary>
    ///     Represents a single record in the Resource Table
    /// </summary>
    public class ResourceRecord
    {
     public List<ResourceEntry> ResourceEntries { get; set; }   
    }
}