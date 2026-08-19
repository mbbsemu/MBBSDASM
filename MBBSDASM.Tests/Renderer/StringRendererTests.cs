using System.IO;
using MBBSDASM.Dasm;
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
