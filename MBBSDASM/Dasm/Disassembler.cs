using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using MBBSDASM.Artifacts;
using MBBSDASM.Enums;
using MBBSDASM.Logging;
using NLog;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace MBBSDASM.Dasm
{
    /// <summary>
    ///     Main Disassembler Class for 16-Bit x86 NE Format EXE/DLL Files
    /// </summary>
    public class Disassembler : IDisposable
    {
        protected static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));
        private NEFile _inputFile;

        public Disassembler(string inputFile)
        {
            _inputFile = new NEFile(inputFile);
        }


        public NEFile Disassemble(bool minimal = false)
        {
            //Decompile Each Segment
            foreach (var s in _inputFile.SegmentTable)
            {
                _logger.Info($"Performing Disassembly of Segment {s.Ordinal}");
                s.DisassemblyLines = DisassembleSegment(s);
            }

            //Skip Additional Analysis if they selected minimal
            if (!minimal)
            {
                _logger.Info($"Extracting Strings from DATA Segments");
                ProcessStrings(_inputFile);

                _logger.Info($"Applying Relocation Info ");
                ApplyRelocationInfo(_inputFile);

                _logger.Info($"Applying String References");
                ResolveStringReferences(_inputFile);

                _logger.Info($"Resolving Jump Targets");
                ResolveJumpTargets(_inputFile);

                _logger.Info($"Resolving Call Targets");
                ResolveCallTargets(_inputFile);

                _logger.Info($"Identifying Entry Points");
                IdentifyEntryPoints(_inputFile);
            }

            return _inputFile;
        }

        /// <summary>
        ///     Takes the raw binary code segment and feeds it into the x86 disassembler library
        /// </summary>
        /// <param name="segment"></param>
        /// <returns></returns>
        private List<DisassemblyLine> DisassembleSegment(Segment segment)
        {
            //Only DisassembleSegment Code Segments
            if (!segment.Flags.Contains(EnumSegmentFlags.Code))
                return new List<DisassemblyLine>();

            var output = new List<DisassemblyLine>();

            var disassembler = new SharpDisasm.Disassembler(segment.Data, ArchitectureMode.x86_16, 0, true);

            //Perform Raw Disassembly
            var ordinal = 0;
            foreach (var disassembly in disassembler.Disassemble())
            {
                output.Add(new DisassemblyLine
                {
                    Disassembly = disassembly,
                    Comments = new List<string>(),
                    Ordinal = ordinal,
                    BranchFromRecords = new ConcurrentBag<BranchRecord>(),
                    BranchToRecords = new ConcurrentBag<BranchRecord>()
                });
                ordinal++;
            }

            return output;
        }

        /// <summary>
        ///     Locates offsets for exported functions in the Entry table and labels them
        /// </summary>
        /// <param name="file"></param>
        private void IdentifyEntryPoints(NEFile file)
        {
            foreach (var entry in file.EntryTable)
            {
                var seg = file.SegmentTable.First(x => x.Ordinal == entry.SegmentNumber);

                var fnName = file.NonResidentNameTable.FirstOrDefault(x => x.IndexIntoEntryTable == entry.Ordinal)
                    ?.Name;

                if (string.IsNullOrEmpty(fnName))
                    fnName = file.ResidentNameTable.FirstOrDefault(x => x.IndexIntoEntryTable == entry.Ordinal)?.Name;

                seg.DisassemblyLines.Where(x => x.Disassembly.Offset == entry.Offset)
                    .FirstOrDefault(x =>
                    {
                        x.ExportedFunction = new ExportedFunctionRecord() {Name = fnName};
                        return true;
                    });

            }
        }

        /// <summary>
        ///     Reads the Relocation Table (if present) at the end of a segment and comments about the relocations that
        ///     are being applied. This identifies both internal and external function calls.
        /// </summary>
        /// <param name="file"></param>
        private void ApplyRelocationInfo(NEFile file)
        {
            Parallel.ForEach(file.SegmentTable, (segment) =>
            {
                if (!segment.Flags.Contains(EnumSegmentFlags.Code) &&
                    !segment.Flags.Contains(EnumSegmentFlags.HasRelocationInfo))
                    return;
                Parallel.ForEach(segment.RelocationRecords, (relocationRecord) =>
                {
                    var disAsm =
                        segment.DisassemblyLines.FirstOrDefault(x =>
                            x.Disassembly.Offset == relocationRecord.Offset - 1UL);

                    if (disAsm == null)
                        return;

                    switch (relocationRecord.Flag)
                    {
                        case EnumRecordsFlag.IMPORTORDINAL | EnumRecordsFlag.ADDITIVE:
                        case EnumRecordsFlag.IMPORTORDINAL:
                            disAsm.BranchToRecords.Add(new BranchRecord
                            {
                                IsRelocation = true,
                                BranchType =
                                    disAsm.Disassembly.Mnemonic == ud_mnemonic_code.UD_Icall
                                        ? EnumBranchType.CallImport
                                        : EnumBranchType.SegAddrImport,
                                Segment = relocationRecord.TargetTypeValueTuple.Item2,
                                Offset = relocationRecord.TargetTypeValueTuple.Item3
                            });
                            break;
                        case EnumRecordsFlag.INTERNALREF | EnumRecordsFlag.ADDITIVE:
                        case EnumRecordsFlag.INTERNALREF:
                            if (disAsm.Disassembly.Mnemonic == ud_mnemonic_code.UD_Icall)
                            {
                                //Set Target
                                file.SegmentTable
                                    .FirstOrDefault(x => x.Ordinal == relocationRecord.TargetTypeValueTuple.Item2)
                                    ?.DisassemblyLines
                                    .FirstOrDefault(y =>
                                        y.Disassembly.Offset == relocationRecord.TargetTypeValueTuple.Item4)
                                    ?.BranchFromRecords
                                    .Add(new BranchRecord()
                                    {
                                        Segment = segment.Ordinal,
                                        Offset = disAsm.Disassembly.Offset,
                                        IsRelocation = true,
                                        BranchType = EnumBranchType.Call
                                    });

                                //Set Origin
                                disAsm.BranchToRecords.Add(new BranchRecord()
                                {
                                    Segment = relocationRecord.TargetTypeValueTuple.Item2,
                                    Offset = relocationRecord.TargetTypeValueTuple.Item4,
                                    BranchType = EnumBranchType.Call,
                                    IsRelocation = true
                                });
                            }
                            else
                            {
                                disAsm.BranchToRecords.Add(new BranchRecord()
                                {
                                    IsRelocation = true,
                                    BranchType = EnumBranchType.SegAddr,
                                    Segment = relocationRecord.TargetTypeValueTuple.Item2
                                });
                            }

                            break;
                        case EnumRecordsFlag.IMPORTNAME:
                            disAsm.BranchToRecords.Add(new BranchRecord
                            {
                                IsRelocation = true,
                                BranchType = EnumBranchType.CallImport,
                                Segment = relocationRecord.TargetTypeValueTuple.Item3
                            });
                            break;
                        case EnumRecordsFlag.TARGET_MASK:
                            break;
                    }
                });
            });
        }

        /// <summary>
        ///     This looks at the op and operand of the instructions and makes a best guess at the instructions that are referencing string data
        ///     We inspect any instruction that interacts with the DX or DS regstiers, as these hold the data segments and then look at the address
        ///     being referenced by that instruction. If we find a string at the address specified in any of the data segments, we'll return it as a possibility.
        /// </summary>
        /// <param name="file"></param>
        private void ResolveStringReferences(NEFile file)
        {
            var flagNext = false;
            var dataSegmentToUse = 0;
            foreach (var segment in file.SegmentTable)
            {
                if (!segment.Flags.Contains(EnumSegmentFlags.Code) || segment.DisassemblyLines == null ||
                    segment.DisassemblyLines.Count == 0)
                    continue;

                foreach (var disassemblyLine in segment.DisassemblyLines)
                {

                    //mov opcode
                    if (disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Imov &&
                        //Filter out any mov's with relative register math, mostly false positives
                        !disassemblyLine.Disassembly.ToString().Contains("-") &&
                        !disassemblyLine.Disassembly.ToString().Contains("+") &&
                        !disassemblyLine.Disassembly.ToString().Contains(":"))
                    {
                        //MOV ax, SEG ADDR sets the current Data Segment to use
                        if (disassemblyLine.BranchToRecords.Any(x =>
                            x.IsRelocation && x.BranchType == EnumBranchType.SegAddr))
                            dataSegmentToUse = disassemblyLine.BranchToRecords.First().Segment;


                        if (dataSegmentToUse > 0)
                        {
                            //mov dx, ####
                            if (disassemblyLine.Disassembly.Operands[0].Base == ud_type.UD_R_DX &&
                                disassemblyLine.Disassembly.Operands.Length == 2 &&
                                disassemblyLine.Disassembly.Operands[1].LvalUWord > 0)
                            {
                                var f = file.SegmentTable
                                    .First(x => x.Ordinal == dataSegmentToUse);
                                if (f.StringRecords != null) {
                                    var filt = f.StringRecords.Where(y =>
                                        y.Offset == disassemblyLine.Disassembly.Operands[1].LvalUWord);
                                    if (filt != null)
                                        disassemblyLine.StringReference = filt.ToList();
                                }

                                continue;
                            }

                            //mov ax, ####
                            if (flagNext && disassemblyLine.Disassembly.Operands[0].Base == ud_type.UD_R_AX &&
                                disassemblyLine.Disassembly.Operands.Length == 2 &&
                                disassemblyLine.Disassembly.Operands[1].LvalUWord > 0)
                            {
                                flagNext = false;

                                disassemblyLine.StringReference = file.SegmentTable
                                    .First(x => x.Ordinal == dataSegmentToUse).StringRecords.Where(y =>
                                        y.Offset == disassemblyLine.Disassembly.Operands[1].LvalUWord).ToList();

                                continue;
                            }

                            //mov dx, ds is usually followed by a mov ax, #### which is a string reference
                            if (disassemblyLine.Disassembly.Operands.Length == 2 &&
                                disassemblyLine.Disassembly.Operands[0].Base == ud_type.UD_R_DX &&
                                disassemblyLine.Disassembly.Operands[1].Base == ud_type.UD_R_DS)
                            {
                                flagNext = true;
                                continue;
                            }
                        }
                    }

                    if (dataSegmentToUse >= 0)
                    {
                        //push #### following a push ds
                        if (flagNext && disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ipush &&
                            disassemblyLine.Disassembly.Operands[0].LvalUWord > 0)
                        {
                            flagNext = false;

                            var potential = new List<StringRecord>();
                            foreach (var s in file.SegmentTable.Where(x => x.StringRecords != null))
                            {
                                if (s.StringRecords.Any(x =>
                                    x.Offset == disassemblyLine.Disassembly.Operands[0].LvalUWord))
                                {
                                    potential.Add(s.StringRecords.First(x =>
                                        x.Offset == disassemblyLine.Disassembly.Operands[0].LvalUWord));
                                }
                            }

                            disassemblyLine.StringReference = potential.Where(x => x.IsPrintable).ToList();
                            continue;
                        }

                        //push ds followed by a push ####
                        if (disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ipush &&
                            disassemblyLine.Disassembly.Operands.Any(x => x.Base == ud_type.UD_R_DS))
                        {
                            flagNext = true;
                            continue;
                        }
                    }

                    flagNext = false;
                }
            }
        }

        /// <summary>
        ///     Scans through the disassembled code and adds comments on any Conditional or Unconditional Jump
        ///     Labels the destination where the source came from
        /// </summary>
        /// <param name="file"></param>
        private void ResolveJumpTargets(NEFile file)
        {

            //Setup variables to make if/where clauses much easier to read
            var jumpShortOps = new[]
            {
                0xEB, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
                0xE3
            };
            var jumpNearOps1stByte = new[] {0xE9, 0x0F};
            var jumpNearOps2ndByte = new[]
                {0x80, 0x81, 0x82, 0x83, 0x84, 0x5, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F};

            foreach (var segment in file.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                //Only op+operand <= 3 bytes, skip jmp word ptr because we won't be able to label those
                foreach (var disassemblyLine in segment.DisassemblyLines.Where(x =>
                    MnemonicGroupings.JumpGroup.Contains(x.Disassembly.Mnemonic) && x.Disassembly.Bytes.Length <= 3))
                {
                    ulong target = 0;

                    //Jump Short, Relative to next Instruction (8 bit)
                    if (jumpShortOps.Contains(disassemblyLine.Disassembly.Bytes[0]))
                    {
                        target = ToRelativeOffset8(disassemblyLine.Disassembly.Bytes[1],
                            disassemblyLine.Disassembly.Offset, disassemblyLine.Disassembly.Bytes.Length);
                    }

                    //Jump Near, Relative to next Instruction (16 bit)
                    //Check to see if it's a 1 byte unconditinoal or a 2 byte conditional
                    if (jumpNearOps1stByte.Contains(disassemblyLine.Disassembly.Bytes[0]) &&
                        (disassemblyLine.Disassembly.Bytes[0] == 0xE9 ||
                         jumpNearOps2ndByte.Contains(disassemblyLine.Disassembly.Bytes[1])))
                    {
                        target = ToRelativeOffset16(BitConverter.ToUInt16(disassemblyLine.Disassembly.Bytes,
                                disassemblyLine.Disassembly.Bytes[0] == 0xE9 ? 1 : 2),
                            disassemblyLine.Disassembly.Offset,
                            disassemblyLine.Disassembly.Bytes.Length);
                    }

                    //Set Target
                    segment.DisassemblyLines.FirstOrDefault(x => x.Disassembly.Offset == target)?.BranchFromRecords
                        .Add(new BranchRecord
                        {
                            Segment = segment.Ordinal,
                            Offset = disassemblyLine.Disassembly.Offset,
                            BranchType =
                                disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ijmp
                                    ? EnumBranchType.Unconditional
                                    : EnumBranchType.Conditional,
                            IsRelocation = false
                        });

                    //Set Origin
                    disassemblyLine.BranchToRecords.Add(new BranchRecord
                    {
                        Segment = segment.Ordinal,
                        Offset = target,
                        BranchType =
                            disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ijmp
                                ? EnumBranchType.Unconditional
                                : EnumBranchType.Conditional,
                        IsRelocation = false
                    });
                }
            }
        }

        /// <summary>
        ///     Scans through the code and adds comments to any Call
        ///     Labels the destination where the source came from
        /// </summary>
        /// <param name="file"></param>
        private void ResolveCallTargets(NEFile file)
        {
            foreach (var segment in file.SegmentTable.Where(x =>
                x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                //Only processing 3 byte calls
                foreach (var j in segment.DisassemblyLines.Where(x =>
                    x.Disassembly.Bytes[0] == 0xE8 && x.Disassembly.Bytes.Length <= 3))
                {

                    ulong target = (ushort) (BitConverter.ToUInt16(j.Disassembly.Bytes, 1) + j.Disassembly.Offset + 3);

                    //Set Target
                    segment.DisassemblyLines.FirstOrDefault(x =>
                        x.Disassembly.Offset == target)?.BranchFromRecords.Add(new BranchRecord()
                    {
                        Segment = segment.Ordinal,
                        Offset = j.Disassembly.Offset,
                        BranchType = EnumBranchType.Call,
                        IsRelocation = false
                    });

                    //Set Origin
                    j.BranchToRecords.Add(new BranchRecord()
                    {
                        Segment = segment.Ordinal,
                        Offset = target,
                        BranchType = EnumBranchType.Call,
                        IsRelocation = false
                    });
                }
            }
        }


        /// <summary>
        ///     Scans through DATA segments within the specified file extracting NULL terminated strings
        /// </summary>
        /// <param name="file"></param>
        private void ProcessStrings(NEFile file)
        {
            //Filter down potential segments
            foreach (var seg in file.SegmentTable.Where(x => x.Flags.Contains(EnumSegmentFlags.Data)))
            {
                seg.StringRecords = new List<StringRecord>();
                var sbBuffer = new StringBuilder();
                for (var i = 0; i < seg.Length; i++)
                {
                    if (seg.Data[i] == 0x0)
                    {
                        if (sbBuffer.Length > 0)
                        {
                            seg.StringRecords.Add(new StringRecord
                            {
                                Segment = seg.Ordinal,
                                Offset = i - sbBuffer.Length,
                                Length = sbBuffer.Length,
                                Value = sbBuffer.ToString()
                            });
                            sbBuffer.Clear();
                        }

                        continue;
                    }

                    sbBuffer.Append((char) seg.Data[i]);
                }
            }
        }


        /// <summary>
        ///     Calculates Relative Offset for 16bit Operand
        /// </summary>
        /// <param name="operand"></param>
        /// <param name="currentOffset"></param>
        /// <param name="instructionLength"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong ToRelativeOffset16(ushort operand, ulong currentOffset, int instructionLength)
        {
            if (operand < 0x7FFF)
            {
                //Near Forward Jump
                return operand + currentOffset + (ulong) instructionLength;
            }

            //Near Backwards Jump
            return currentOffset - (ushort) ~operand + (ulong) instructionLength;
        }

        /// <summary>
        ///     Calculates Relative Offset for 8bit Operand
        /// </summary>
        /// <param name="operand"></param>
        /// <param name="currentOffset"></param>
        /// <param name="instructionLength"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong ToRelativeOffset8(byte operand, ulong currentOffset, int instructionLength)
        {
            if (operand <= 0x7F)
            {
                //Short Forward Jump
                return operand + currentOffset + (ulong) instructionLength;
            }

            //Short Backwards Jump
            return (ulong) ((int) currentOffset + instructionLength - ((byte) ~operand + 1));
        }


        /// <inheritdoc />
        public void Dispose()
        {
            _inputFile = null;
        }
    }
}