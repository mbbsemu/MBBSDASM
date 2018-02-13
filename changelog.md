# Changelog
## v1.3
* Enhanced FOR loop recognition
* Refactored Disassembled Branch Tracking/Labeling
* Enhanced Strings Extraction/Tracking/Labeling
	* Increased performance and accuracy of string reference lookup
	* Added -STRINGS command line to output all strings extracted from DATA segments to Disassembly output
* Additional Module Definiton Auto-Documentation
	* **MAJORBBS** : 594 functions documented of 1233 defined
	* **GALGSBL** : 97 functions documented of 101 defined
* Minor code refactoring
	
## v1.2
* Added Worldgroup 1.0/2.0 for DOS Support
* Added initial FOR loop recognition
* Enhanced String Reference resolution (fewer false positives)
* Additional Module Definiton Auto-Documentation
	* **MAJORBBS** : 460 functions documented of 1233 defined
	* **GALGSBL** : 97 functions documented of 101 defined
* Support of parsing MZ DOS Header
* Minor code refactoring

## v1.1
* Added initial support for variable tracking
* Added Procedure Auto-Identification
* Additional Module Definition Auto-Documentation 
	* **MAJORBBS**: 391 functions documented of 1210 defined
	* **GALGSBL**: 13 functions documented of 101 defined
* Support for identifying multiple possible string references (if n>1)
* Enhanced CALL tracking of INTERNALREF entries in Segment Reolcation Table
* Assembler comments now all ligned up on the same column per Segment
* Fixed references to hex numbers that were missing 'h' identifier

## v1.0
* Initial Release