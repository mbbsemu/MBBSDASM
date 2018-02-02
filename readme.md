# MBBSDASM
![](http://forthebadge.com/images/badges/made-with-c-sharp.svg)
![](http://forthebadge.com/images/badges/60-percent-of-the-time-works-every-time.svg)

**MBBSDASM** is a Disassembler for 16-bit Segmented Executable File Format ("New Executable", or just NE) files. The Disassembler itself is written in C# using .Net Core.

It was created to assist in my own personal education of The MajorBBS (MBBS) Bulletin Board System, which was one of the first multi-line, multi-user BBS systems available at the time of its hayday. MBBS loaded modules that were an early version of DLL's files built with Borland Turbo C++.

For more information on The Major BBS, check out the Wikipedia article [[here](https://en.wikipedia.org/wiki/The_Major_BBS)].

While **MBBSDASM** targets Major BBS files for analysis, any 16-bit NE EXE/DLL file is supported and should disassemble without issue. I've tested this with both Solitaire and Calculator from Windows 3.1 to verify.

# Current Features
**MBBSDASM** offers several disassembly/code analysis options that are configurable through the command line.

#### Minimal Disassembly (-minimal)
Minimal will output the disassembled x86 code segments labeled with SEGMENT:OFFSET with no additional analysis.

```asm
000019CBh:0002.13CBh push ds
000019CCh:0002.13CCh push 0xa0a3
000019CFh:0002.13CFh push ds
000019D0h:0002.13D0h push 0x1998
000019D3h:0002.13D3h call word 0x0:0xffff
000019D8h:0002.13D8h add sp, 0x8
000019DBh:0002.13DBh or ax, ax
000019DDh:0002.13DDh jnz 0x1404
000019DFh:0002.13DFh push ds
000019E0h:0002.13E0h push 0x1998
000019E3h:0002.13E3h call word 0x0:0xffff
000019E8h:0002.13E8h add sp, 0x4
000019EBh:0002.13EBh or ax, ax
000019EDh:0002.13EDh jz 0x1404
```
#### Normal Disassembly (default)
Normal will output the disassembled x86 code segments labeled with SEGMENT:OFFSET as well as processing:
* Processing Segment Relocation Table Entries
* Resolve External References
* String Reference Resolution (best guess)
* Identify and Label Conditional/Unconditional Jumps as well as Call's
```asm
000019CBh:0002.13CBh push ds  ; Conditional jump from 0002:13B6
000019CCh:0002.13CCh push 0xa0a3  ; Possible String reference from SEG 5 -> "NONE"
000019CFh:0002.13CFh push ds
000019D0h:0002.13D0h push 0x1998
000019D3h:0002.13D3h call word 0x0:0xffff  ; CALL MAJORBBS.Ord(0520)
000019D8h:0002.13D8h add sp, 0x8
000019DBh:0002.13DBh or ax, ax
000019DDh:0002.13DDh jnz 0x1404
000019DFh:0002.13DFh push ds
000019E0h:0002.13E0h push 0x1998
000019E3h:0002.13E3h call word 0x0:0xffff  ; CALL MAJORBBS.Ord(0334)
000019E8h:0002.13E8h add sp, 0x4
000019EBh:0002.13EBh or ax, ax
000019EDh:0002.13EDh jz 0x1404
```

#### MBBS Analysis Mode (-analysis)
MBBS Analysis mode enables **MBBSDASM** to provide additional detailed analysis of Major BBS Modules/DLL's with information provided from the Major BBS 6.25 Software Development Kit as well as GALACTICOMM's Developer's Guide for The Major BBS 6.2 [[link](http://software.bbsdocumentary.com/IBM/WINDOWS/MAJORBBS/devguide.pdf)]

Additional disassembly analysis includes:
* Automatic Documentation on a large portion of the most commonly used MAJORBBS & GALGSBL functions
* Provide Method Signatures in place of the External module calls
* Reverse Engineer and rebuild method signatures with the actual input values built from the x86 Assembly
```asm
000019CBh:0002.13CBh push ds  ; Conditional jump from 0002:13B6
000019CCh:0002.13CCh push 0xa0a3  ; Possible String reference from SEG 5 -> "NONE"
000019CFh:0002.13CFh push ds
000019D0h:0002.13D0h push 0x1998
000019D3h:0002.13D3h call word 0x0:0xffff  ; int match=sameas(char *stgl, char* stg2);
                                           ; Case-ignoring string match
                                           ; Returns 1 if match, 0 otherwise
000019D8h:0002.13D8h add sp, 0x8
000019DBh:0002.13DBh or ax, ax
000019DDh:0002.13DDh jnz 0x1404
000019DFh:0002.13DFh push ds
000019E0h:0002.13E0h push 0x1998
000019E3h:0002.13E3h call word 0x0:0xffff  ; int haskey(lock);
                                           ; Resolved Signature: int haskey(6552);
                                           ; Does the user have the specified key
000019E8h:0002.13E8h add sp, 0x4
000019EBh:0002.13EBh or ax, ax
000019EDh:0002.13EDh jz 0x1404
```
# What's Next
* Enhance MBBS Analysis
    * Variable Labeling and Tracking
    * Add additional auto-documentation of GALGSBL and MAJORBBS imported function
* Add support for Worldgroup Modules
    * Worldgroup 1.0/2.0
    * Worldgroup 3.0+ will require additional support for disassembly of 32-bit PE format EXE/DLL files

# Contribute
I'm always looking for updated/new information on several related topics. If you have any first hand knowledge, documentation or files you can send me related to:

* The MajorBBS/Worldgroup Development Documentation (beyond already available SDK docs)
* Unreleased/publically unavailable source code for commercial modules

Any information sent my way will be kept **strictly confidential** and will only be used as a point of reference for enhancing this research project. My goal here is to not let the past just rot away in ZIP files but give people a chance to learn how systems like The MajorBBS and Worldgroup worked.

Additionally, please feel free to submit pull requests with enhancements and bug reports with any issues you might be experiencing!

# Thanks

The project makes use of [SharpDiasm](https://github.com/spazzarama/SharpDisasm) to do the actual Disassmebly of the Code Segments into 16-bit x86 Assembly Language.

A big shoutout to the grey beards keeping this archaic software alive and still available 25+ years later, folks I've interacted with related to MBBS/WG over the years (you know who you are), and the people involved with The BBS Documentary [[link](http://www.bbsdocumentary.com/)]

# License

MBBSDASM is Copyright (c) 2017 Eric Nusbaum and is distributed under the 2-clause "Simplified BSD License". 

SharpDisam is Copyright (c) 2015 Justin Stenning and is distributed under the 2-clause "Simplified BSD License". 

Portions of the project are ported from Udis86 Copyright (c) 2002-2012, Vivek Thampi <vivek.mt@gmail.com> https://github.com/vmt/udis86 distributed under the 2-clause "Simplified BSD License".
