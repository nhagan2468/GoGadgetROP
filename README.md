# GoGadgetROP
GoGadgetROP is a Ghidra script created to identify ROP gadgets inside a processed binary. It is meant to allow for ROP gadget finding only inside the executable portions of the binary and to allow searching binaries in any assembly language supported by Ghidra. It is designed to be used with Ghidra's script manager.

**Note: This project was developed with Ghidra 11.1.1. Your mileage may vary with other Ghidra versions.** 

## Installation
The checked out repository must be added to the Script Manager. In Ghidra, open the Script Manager and select the Script Directories icon to open the Bundle Manager. Add the checked out repository as a path. Press the refresh button to ensure that the script was imported into the manager.

## Usage 
In Ghidra, open the Script Manager. The script will be in the Analysis Directory on the lefthand side of the manager. You can run the script directly by highlighting the script in the window and pressing the green play button on the top right portion of the window.  

## Future Directions
* This currently only identifies RET instructions for gadgets that Ghidra has disassembled as RET instructions (not when the bytes for a RET are embedded inside another instruction such as a constant). To find these additional potential gadget, the codeblocks need to be removed and the blocks need to be re-disassembled along with handling the error cases associated with bytes that do not disassemble properly.
* The gadgets could be marked with some kind of tag in the binary once they are found. 

## References
* [Ghidra.re ghidra docs](https://ghidra.re/ghidra_docs/api/index.html) by the National Security Agency
* [Ghidra github page](https://github.com/NationalSecurityAgency/ghidra) by the National Security Agency
* [Ghidra Intermediate Class Slides](https://static.grumpycoder.net/pixel/docs/GhidraClass/Intermediate/Scripting_withNotes.html#Scripting.html)