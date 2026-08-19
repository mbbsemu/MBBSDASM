using System;
using System.IO;
using System.Linq;
using MBBSDASM.Dasm;
using MBBSDASM.Enums;
using MBBSDASM.Renderer.impl;
using Xunit;

namespace MBBSDASM.Tests.Renderer
{
    public class StringRendererTests
    {
        [Fact]
        public void RenderStrings_PrintsFileOffset()
        {
            //Data segment (at file offset 0x100) containing the string "HI" at segment offset 1
            var data = new byte[] {0x00, (byte) 'H', (byte) 'I', 0x00};

            var inputFile = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(inputFile, MinimalNEFile.Build(data, segmentFlags: 0x0001));
                var file = new Disassembler(inputFile).Disassemble();

                var output = new StringRenderer(file).RenderStrings();

                Assert.Contains("00000101h:0001.0001h 'HI'", output);
            }
            finally
            {
                File.Delete(inputFile);
            }
        }

        [Fact]
        public void RenderDisassembly_OrdersBranchCommentsBySegmentAndOffset()
        {
            //Branch records come from parallel analysis via ConcurrentBag, whose enumeration
            //order is unstable - rendered comments must be sorted regardless of insertion order
            var inputFile = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(inputFile, MinimalNEFile.Build(new byte[] {0xEB, 0xFE, 0xC3}));
                var file = new Disassembler(inputFile).Disassemble();

                var line = file.SegmentTable.First(x => x.DisassemblyLines?.Count > 0).DisassemblyLines[0];
                line.BranchFromRecords.Add(new BranchRecord {Segment = 1, Offset = 0x300, BranchType = EnumBranchType.Call});
                line.BranchFromRecords.Add(new BranchRecord {Segment = 1, Offset = 0x100, BranchType = EnumBranchType.Call});
                line.BranchFromRecords.Add(new BranchRecord {Segment = 1, Offset = 0x200, BranchType = EnumBranchType.Call});

                var output = new StringRenderer(file).RenderDisassembly();

                var first = output.IndexOf("CALL at address: 0001.0100h", StringComparison.Ordinal);
                var second = output.IndexOf("CALL at address: 0001.0200h", StringComparison.Ordinal);
                var third = output.IndexOf("CALL at address: 0001.0300h", StringComparison.Ordinal);
                Assert.True(first >= 0, "expected first CALL comment in output");
                Assert.True(first < second && second < third, "CALL comments must be ordered by offset");
            }
            finally
            {
                File.Delete(inputFile);
            }
        }

        [Fact]
        public void RenderDisassembly_IsRepeatable()
        {
            //Rendering must not mutate the model: a second render produces identical output
            var inputFile = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(inputFile, MinimalNEFile.Build(new byte[] {0xEB, 0xFE, 0xC3}));
                var file = new Disassembler(inputFile).Disassemble();

                var renderer = new StringRenderer(file);
                var first = renderer.RenderDisassembly();
                var second = renderer.RenderDisassembly();

                Assert.Equal(first, second);
            }
            finally
            {
                File.Delete(inputFile);
            }
        }
    }
}
