using System.Collections.Generic;
using System.Linq;
using SharpDisasm.Udis86;

namespace MBBSDASM.Dasm
{
    public static class MnemonicGroupings
    {
        //All Conditional/Unconditional JUMP instructions
        public static readonly List<ud_mnemonic_code> JumpGroup = new List<ud_mnemonic_code>()
        {
            ud_mnemonic_code.UD_Ijmp,
            ud_mnemonic_code.UD_Ija,
            ud_mnemonic_code.UD_Ijae,
            ud_mnemonic_code.UD_Ijb,
            ud_mnemonic_code.UD_Ijbe,
            ud_mnemonic_code.UD_Ijcxz,
            ud_mnemonic_code.UD_Ijecxz,
            ud_mnemonic_code.UD_Ijg,
            ud_mnemonic_code.UD_Ijge,
            ud_mnemonic_code.UD_Ijl,
            ud_mnemonic_code.UD_Ijle,
            ud_mnemonic_code.UD_Ijno,
            ud_mnemonic_code.UD_Ijnp,
            ud_mnemonic_code.UD_Ijns,
            ud_mnemonic_code.UD_Ijnz,
            ud_mnemonic_code.UD_Ijo,
            ud_mnemonic_code.UD_Ijp,
            ud_mnemonic_code.UD_Ijs,
            ud_mnemonic_code.UD_Ijz
        };
        
        //Instructions used to increment/decrement a value
        public static List<ud_mnemonic_code> IncrementDecrementGroup => IncrementGroup.Concat(DecrementGroup).ToList();
        
        //Instructions used to increment a value
        public static readonly List<ud_mnemonic_code> IncrementGroup = new List<ud_mnemonic_code>()
        {
            ud_mnemonic_code.UD_Iinc,
            ud_mnemonic_code.UD_Iadd
        };
        
        //Instructions used to decrement a value
        public static readonly List<ud_mnemonic_code> DecrementGroup = new List<ud_mnemonic_code>()
        {
            ud_mnemonic_code.UD_Idec,
            ud_mnemonic_code.UD_Isub
        };

    }
}