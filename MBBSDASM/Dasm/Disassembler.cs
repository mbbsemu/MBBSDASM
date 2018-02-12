using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using MBBSDASM.Artifacts;
using MBBSDASM.Enums;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace MBBSDASM.Dasm
 {
     /// <summary>
     ///     Main Disassembler Class for 16-Bit x86 NE Format EXE/DLL Files
     /// </summary>
     public static class Disassembler
     {
         //RegEx for characters on the standard keyboard
         private static readonly Regex StringRegEx = new Regex(@"[\r\na-zA-Z0-9`!@#$%^&*()_+|\-=\\{}\[\]:"";'<>?,. /]", RegexOptions.Compiled);
         
         /// <summary>
         ///     Takes the raw binary code segment and feeds it into the x86 disassembler library
         /// </summary>
         /// <param name="segment"></param>
         /// <returns></returns>
         public static List<DisassemblyLine> Disassemble(Segment segment)
         {
             //Only Disassemble Code Segments
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
                     BranchFromRecords = new List<BranchRecord>(),
                     BranchToRecords = new List<BranchRecord>(),
                     StringReferenceRecords = new List<StringReferenceRecord>()
                 });
                 ordinal++;
             }

             return output;
         }

         /// <summary>
         ///     Locates offsets for exported functions in the Entry table and labels them
         /// </summary>
         /// <param name="file"></param>
         public static void IdentifyEntryPoints(NEFile file)
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
                         x.ExportedFunction = new ExportedFunctionRecord() { Name = fnName};
                         return true;
                     });

             }
         }

         /// <summary>
         ///     Reads the Relocation Table (if present) at the end of a segment and comments about the relocations that
         ///     are being applied. This identifies both internal and external function calls.
         /// </summary>
         /// <param name="file"></param>
         public static void ApplyRelocationInfo(NEFile file)
         {
             foreach (var segment in file.SegmentTable)
             {
                 if (!segment.Flags.Contains(EnumSegmentFlags.Code) &&
                     !segment.Flags.Contains(EnumSegmentFlags.HasRelocationInfo))
                     continue;

                 foreach (var relocationRecord in segment.RelocationRecords)
                 {
                     var disAsm =
                         segment.DisassemblyLines.FirstOrDefault(x => x.Disassembly.Offset == relocationRecord.Offset - (ulong) 1);

                     if (disAsm == null)
                         continue;

                     switch (relocationRecord.Flag)
                     {
                         case EnumRecordsFlag.IMPORTORDINAL | EnumRecordsFlag.ADDITIVE:
                         case EnumRecordsFlag.IMPORTORDINAL:
                             //disAsm.Comments.Add(
                             //    $"{(disAsm.Disassembly.Mnemonic == ud_mnemonic_code.UD_Icall ? "call" : "SEG ADDR of")} {file.ImportedNameTable.First(x => x.Ordinal == relocationRecord.TargetTypeValueTuple.Item2).Name}.Ord({relocationRecord.TargetTypeValueTuple.Item3:X4}h)");
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
                                     .Add(new BranchRecord() { Segment = segment.Ordinal, Offset = disAsm.Disassembly.Offset, IsRelocation = true, BranchType = EnumBranchType.Call});
                                 
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
                 }
             }
         }

         /// <summary>
         ///     This looks at the op and operand of the instructions and makes a best guess at the instructions that are referencing string data
         ///     We inspect any instruction that interacts with the DX or DS regstiers, as these hold the data segments and then look at the address
         ///     being referenced by that instruction. If we find a string at the address specified in any of the data segments, we'll return it as a possibility.
         /// </summary>
         /// <param name="file"></param>
         public static void ResolveStringReferences(NEFile file)
         {
             var flagNext = false;
             
             foreach (var segment in file.SegmentTable)
             {
                 if (!segment.Flags.Contains(EnumSegmentFlags.Code) || segment.DisassemblyLines == null || segment.DisassemblyLines.Count == 0)
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
                         //mov dx, ####
                         if (disassemblyLine.Disassembly.Operands[0].Base == ud_type.UD_R_DX &&
                             disassemblyLine.Disassembly.Operands.Length == 2 &&
                             disassemblyLine.Disassembly.Operands[1].LvalUWord > 0)
                         {
                             var stringReference = FindString(file.SegmentTable,
                                 disassemblyLine.Disassembly.Operands[1].LvalUWord);
                             if (stringReference == null)
                                 continue;

                             foreach (var sr in stringReference)
                                 disassemblyLine.StringReferenceRecords.Add(new StringReferenceRecord { Segment = sr.Item1, Value = sr.Item2});

                             continue;
                         }

                         //mov ax, ####
                         if (flagNext && disassemblyLine.Disassembly.Operands[0].Base == ud_type.UD_R_AX &&
                             disassemblyLine.Disassembly.Operands.Length == 2 &&
                             disassemblyLine.Disassembly.Operands[1].LvalUWord > 0)
                         {
                             flagNext = false;
                             var stringReference = FindString(file.SegmentTable,
                                 disassemblyLine.Disassembly.Operands[1].LvalUWord);
                             
                             if (stringReference == null)
                                 continue;
                             
                             foreach (var sr in stringReference)
                                 disassemblyLine.StringReferenceRecords.Add(new StringReferenceRecord { Segment = sr.Item1, Value = sr.Item2});

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

                     //push #### following a push ds
                     if (flagNext && disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ipush &&
                         disassemblyLine.Disassembly.Operands[0].LvalUWord > 0)
                     {
                         flagNext = false;
                         var stringReference = FindString(file.SegmentTable,
                             disassemblyLine.Disassembly.Operands[0].LvalUWord);
                         if (stringReference == null)
                             continue;

                         foreach (var sr in stringReference)
                             disassemblyLine.StringReferenceRecords.Add(new StringReferenceRecord { Segment = sr.Item1, Value = sr.Item2});

                         continue;
                     }

                     //push ds followed by a push ####
                     if (disassemblyLine.Disassembly.Mnemonic == ud_mnemonic_code.UD_Ipush &&
                         disassemblyLine.Disassembly.Operands.Any(x => x.Base == ud_type.UD_R_DS))
                     {
                         flagNext = true;
                         continue;
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
         public static void ResolveJumpTargets(NEFile file)
         {

             //Setup variables to make if/where clauses much easier to read
             var jumpShortOps = new[] {0xEB, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0xE3};
             var jumpNearOps1stByte = new[] {0xE9, 0x0F};
             var jumpNearOps2ndByte = new[]
                 {0x80, 0x81, 0x82, 0x83, 0x84, 0x5, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F};

             foreach (var segment in file.SegmentTable)
             {
                 if (!segment.Flags.Contains(EnumSegmentFlags.Code) || segment.DisassemblyLines == null ||
                     segment.DisassemblyLines.Count == 0)
                     continue;

                 //Only op+operand <= 3 bytes, skip jmp word ptr because we won't be able to label those
                 foreach (var disassemblyLine in segment.DisassemblyLines.Where(x => MnemonicGroupings.JumpGroup.Contains(x.Disassembly.Mnemonic) && x.Disassembly.Bytes.Length <= 3))
                 {
                     ulong target = 0;

                     //Jump Short, Relative to next Instruction (8 bit)
                     if (jumpShortOps.Contains(disassemblyLine.Disassembly.Bytes[0]))
                     {
                         target = ToRelativeOffset8(disassemblyLine.Disassembly.Bytes[1], disassemblyLine.Disassembly.Offset, disassemblyLine.Disassembly.Bytes.Length);
                     }

                     //Jump Near, Relative to next Instruction (16 bit)
                     //Check to see if it's a 1 byte unconditinoal or a 2 byte conditional
                     if (jumpNearOps1stByte.Contains(disassemblyLine.Disassembly.Bytes[0]) &&
                         (disassemblyLine.Disassembly.Bytes[0] == 0xE9 || jumpNearOps2ndByte.Contains(disassemblyLine.Disassembly.Bytes[1])))
                     {
                         target = ToRelativeOffset16(BitConverter.ToUInt16(disassemblyLine.Disassembly.Bytes,
                             disassemblyLine.Disassembly.Bytes[0] == 0xE9 ? 1 : 2), disassemblyLine.Disassembly.Offset, disassemblyLine.Disassembly.Bytes.Length);
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
         public static void ResolveCallTargets(NEFile file)
         {
             foreach (var segment in file.SegmentTable)
             {
                 if (!segment.Flags.Contains(EnumSegmentFlags.Code) || segment.DisassemblyLines == null ||
                     segment.DisassemblyLines.Count == 0)
                     continue;

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
         ///     Searches through the provided segments for the most likely string candidate
         /// 
         ///     Read all characters from the offset until the 1st null character or end of the segment (whichever comes first)
         ///     If the read string passes the RegEx, it's our best guess at the string reference
         /// </summary>
         /// <param name="segments"></param>
         /// <param name="offset"></param>
         /// <returns></returns>
         private static List<Tuple<ushort, string>> FindString(IEnumerable<Segment> segments, ushort offset)
         {   
             //Filter down potential segments
             var dataSegs = segments.Where(x => x.Flags.Contains(EnumSegmentFlags.Data) && x.Length >= offset && x.Length > 0);

             var output = new List<Tuple<ushort, string>>();
             foreach (var s in dataSegs)
             {
                 //Character preceding a string should always be a null character
                 //Except when it's CRLF.... because DOS yo....
                 if (offset > 0 && s.Data[offset - 1] != 0 && s.Data[offset -1] != 10 && s.Data[offset -1] != 13)
                     continue;

                 if (offset > s.Data.Length - 1)
                     continue;

                 //Find a Terminating End
                 var endOffset = offset;
                 while (s.Data[endOffset] != 0 && endOffset < s.Length)
                     endOffset++;

                 //0 length string? Keep searching
                 if (offset == endOffset)
                     continue;

                 var potentialString = Encoding.ASCII.GetString(s.Data, offset, endOffset - offset);
                 
                 if(!string.IsNullOrEmpty(StringRegEx.Replace(potentialString, string.Empty)))
                     continue;
                     
                 output.Add(new Tuple<ushort, string>(s.Ordinal, potentialString));
             }

             return output;
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
                 return operand + currentOffset + (ulong)instructionLength;
             }

             //Near Backwards Jump
             return currentOffset - (ushort) ~operand + (ulong)instructionLength;
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
                 return operand + currentOffset + (ulong)instructionLength;
             }

             //Short Backwards Jump
             return (ulong) ((int) currentOffset + instructionLength - ((byte) ~operand + 1));
         }
     }
 }