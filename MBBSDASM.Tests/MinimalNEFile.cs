using System;

namespace MBBSDASM.Tests
{
    /// <summary>
    ///     Builds the smallest NE file NEFile.Load will accept: MZ stub, NE header,
    ///     a fixed code segment (with an empty relocation table), and optionally an
    ///     entry table, a data segment, relocation records, and one imported module
    /// </summary>
    internal static class MinimalNEFile
    {
        public const ushort CodeWithRelocationInfo = 0x0100;

        public static byte[] Build(byte[] code, byte[] entryTable = null,
            ushort segmentFlags = CodeWithRelocationInfo, byte[] dataSegment = null,
            byte[] relocationRecords = null, string importedModule = null)
        {
            const int neHeaderOffset = 0x80;
            const int segmentTableOffset = 0x40;  //relative to NE header
            const int entryTableOffset = 0x50;    //relative to NE header
            const int codeDataOffset = 0x100;
            const int dataDataOffset = 0x180;

            //An empty entry table is a single end-of-table bundle
            entryTable = entryTable ?? new byte[] {0x00};

            //Tables are packed after the entry table: resident name terminator,
            //module reference table, imported names table
            var residentNameOffset = entryTableOffset + entryTable.Length;
            var moduleRefOffset = residentNameOffset + 1;
            var importedNamesOffset = moduleRefOffset + (importedModule != null ? 2 : 0);

            if (importedNamesOffset + (importedModule?.Length + 2 ?? 0) > 0x80)
                throw new InvalidOperationException("Tables overflow the space reserved before segment data");

            var segmentCount = dataSegment != null ? 2 : 1;
            var file = new byte[0x200];

            //MZ stub
            WriteUInt16(file, 0x00, 0x5A4D);            //'MZ'
            file[0x18] = 0x40;                          //relocation table at 0x40 -> NE offset at 0x3C is valid
            WriteUInt16(file, 0x3C, neHeaderOffset);

            //NE header
            file[neHeaderOffset] = (byte) 'N';
            file[neHeaderOffset + 1] = (byte) 'E';
            WriteUInt16(file, neHeaderOffset + 0x04, entryTableOffset);
            WriteUInt16(file, neHeaderOffset + 0x1C, (ushort) segmentCount);
            WriteUInt16(file, neHeaderOffset + 0x1E, (ushort) (importedModule != null ? 1 : 0));
            WriteUInt16(file, neHeaderOffset + 0x22, segmentTableOffset);
            WriteUInt16(file, neHeaderOffset + 0x26, (ushort) residentNameOffset);
            WriteUInt16(file, neHeaderOffset + 0x28, (ushort) moduleRefOffset);
            WriteUInt16(file, neHeaderOffset + 0x2A, (ushort) importedNamesOffset);
            WriteUInt32(file, neHeaderOffset + 0x2C, (uint) file.Length);   //non-resident names (empty)
            //LogicalSectorAlignmentShift (0x32), table lengths, and counts stay 0

            //Segment table: fixed code segment, then an optional data segment
            WriteUInt16(file, neHeaderOffset + segmentTableOffset, codeDataOffset);
            WriteUInt16(file, neHeaderOffset + segmentTableOffset + 2, (ushort) code.Length);
            WriteUInt16(file, neHeaderOffset + segmentTableOffset + 4, segmentFlags);
            WriteUInt16(file, neHeaderOffset + segmentTableOffset + 6, (ushort) code.Length);
            if (dataSegment != null)
            {
                WriteUInt16(file, neHeaderOffset + segmentTableOffset + 8, dataDataOffset);
                WriteUInt16(file, neHeaderOffset + segmentTableOffset + 10, (ushort) dataSegment.Length);
                WriteUInt16(file, neHeaderOffset + segmentTableOffset + 12, 0x0001); //data
                WriteUInt16(file, neHeaderOffset + segmentTableOffset + 14, (ushort) dataSegment.Length);
            }

            //Entry table; the resident name table terminator after it is already zeroed
            Array.Copy(entryTable, 0, file, neHeaderOffset + entryTableOffset, entryTable.Length);

            //Module reference and imported names tables (the first imported-names byte is unused)
            if (importedModule != null)
            {
                WriteUInt16(file, neHeaderOffset + moduleRefOffset, 1); //name offset within imported names table
                file[neHeaderOffset + importedNamesOffset + 1] = (byte) importedModule.Length;
                for (var i = 0; i < importedModule.Length; i++)
                    file[neHeaderOffset + importedNamesOffset + 2 + i] = (byte) importedModule[i];
            }

            //Code segment data, followed by its relocation table when the flag is set
            Array.Copy(code, 0, file, codeDataOffset, code.Length);
            if ((segmentFlags & 0x0100) != 0)
            {
                relocationRecords = relocationRecords ?? new byte[0];
                WriteUInt16(file, codeDataOffset + code.Length, (ushort) (relocationRecords.Length / 8));
                Array.Copy(relocationRecords, 0, file, codeDataOffset + code.Length + 2,
                    relocationRecords.Length);
            }

            if (dataSegment != null)
                Array.Copy(dataSegment, 0, file, dataDataOffset, dataSegment.Length);

            return file;
        }

        /// <summary>
        ///     A relocation record importing an ordinal from module 1 (8 bytes)
        /// </summary>
        public static byte[] ImportOrdinalRelocation(ushort operandOffset, ushort ordinal)
        {
            var record = new byte[8];
            record[0] = 0x03; //source type: 16-bit segment:offset pointer
            record[1] = 0x01; //IMPORTORDINAL
            WriteUInt16(record, 2, operandOffset);
            WriteUInt16(record, 4, 1); //module reference index
            WriteUInt16(record, 6, ordinal);
            return record;
        }

        private static void WriteUInt16(byte[] buffer, int offset, ushort value) =>
            Array.Copy(BitConverter.GetBytes(value), 0, buffer, offset, 2);

        private static void WriteUInt32(byte[] buffer, int offset, uint value) =>
            Array.Copy(BitConverter.GetBytes(value), 0, buffer, offset, 4);
    }
}
