using System.IO;
using System.Linq;
using MBBSDASM.Artifacts;
using MBBSDASM.Dasm;
using Xunit;

namespace MBBSDASM.Tests.Analysis
{
    /// <summary>
    ///     End-to-end tests for imported function identification: a code segment
    ///     calling into MAJORBBS via an IMPORTORDINAL relocation, with argument
    ///     values resolved from the preceding instructions
    /// </summary>
    public class SignatureResolutionTests
    {
        private const ushort HaskeyOrdinal = 334;
        private const ushort MsgscanOrdinal = 421;

        private static NEFile Analyze(byte[] code, byte[] relocations, byte[] dataSegment = null)
        {
            var inputFile = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(inputFile, MinimalNEFile.Build(code,
                    dataSegment: dataSegment, relocationRecords: relocations,
                    importedModule: "MAJORBBS"));
                var file = new Disassembler(inputFile).Disassemble();
                MBBSDASM.Analysis.MBBS.Analyze(file);
                return file;
            }
            finally
            {
                File.Delete(inputFile);
            }
        }

        [Fact]
        public void IntArgument_ResolvesSignature()
        {
            /*
            *   0000: 6A 05            push 0x5
            *   0002: 9A 00 00 00 00   call far MAJORBBS.334 (haskey)
            *   0007: C3               ret
            */
            var code = new byte[] {0x6A, 0x05, 0x9A, 0x00, 0x00, 0x00, 0x00, 0xC3};

            var file = Analyze(code, MinimalNEFile.ImportOrdinalRelocation(0x0003, HaskeyOrdinal));

            var callLine = file.SegmentTable[0].DisassemblyLines.First(x => x.Disassembly.Offset == 0x2);
            Assert.Contains("int haskey(lock);", callLine.Comments);
            Assert.Contains("Resolved Signature: int haskey(5);", callLine.Comments);
        }

        [Fact]
        public void StringArguments_ResolveSignature()
        {
            /*
            *   0000: 1E               push ds
            *   0001: 68 06 00         push 0x6    -> "VBL" in the data segment
            *   0004: 1E               push ds
            *   0005: 68 01 00         push 0x1    -> "FILE" in the data segment
            *   0008: 9A 00 00 00 00   call far MAJORBBS.421 (msgscan)
            *   000D: C3               ret
            */
            var code = new byte[]
            {
                0x1E,
                0x68, 0x06, 0x00,
                0x1E,
                0x68, 0x01, 0x00,
                0x9A, 0x00, 0x00, 0x00, 0x00,
                0xC3
            };
            var data = new byte[]
            {
                0x00,
                (byte) 'F', (byte) 'I', (byte) 'L', (byte) 'E', 0x00, //offset 1
                (byte) 'V', (byte) 'B', (byte) 'L', 0x00              //offset 6
            };

            var file = Analyze(code, MinimalNEFile.ImportOrdinalRelocation(0x0009, MsgscanOrdinal), data);

            var callLine = file.SegmentTable[0].DisassemblyLines.First(x => x.Disassembly.Offset == 0x8);
            Assert.Contains("Resolved Signature: char *msgscan(\"FILE\",\"VBL\");", callLine.Comments);
        }
    }
}
