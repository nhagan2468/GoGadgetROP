/* ###
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
//A script that will identify ROP gadgets in the executable areas of the program
//@nhagan2468 
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ISF.*;
import java.util.Arrays;

public class GadgetFinder extends GhidraScript {

    private byte[] retInstrBytes;
    private Program currProgram;
    private Listing progListing;

    public void run() throws Exception {
        /* Start with the current program and then get the set of executable addrs
         * to ensure that gadgets are only identified in executable memory */

        currProgram = currentProgram;
	Memory progMemory = currProgram.getMemory();
	
	progListing = currProgram.getListing();

	// Identify the byte(s) for a RET instruction in this architecture
	getRetBytes(currProgram);

	if (retInstrBytes == null) {
	    println("Unable to find a RET instruction in the binary, returning");
	}

        /* Loop through every memory block in the program that is executable and look 
	 * for potential gadgets in the memory block. */

	for (MemoryBlock block : progMemory.getBlocks()) {
	    monitor.checkCancelled();
	    if (block.isExecute() == false) {
		continue;
	    }

	    findGadgets(block);
	}

    }

    /* Function that takes in a Program object, and looks through the code units
     * to find a RET instruction. Once found, get the bytes for the instruction 
     * and save them to the class private member retInstrBytes. If no RET is found,
     * set retInstrBytes to null. */
    private void getRetBytes(Program currProg) throws Exception {
	// Set retInstrBytes to null in case no RETs are found
	retInstrBytes = null;

	// Iterate through all the code units (instructions) in the program
        CodeUnitIterator codeIter = currProg.getListing().getCodeUnits(true); 
	CodeUnit codeUnit;

	while (codeIter.hasNext() && !monitor.isCancelled()) {
	    codeUnit = codeIter.next();
	    // See if the Mnemonic for the codeUnit is a RET 
	    if (codeUnit.getMnemonicString().equalsIgnoreCase("RET")) {
		// If it is, set retInstrBytes to the bytes for the unit
		retInstrBytes = codeUnit.getBytes();
		print("RET bytes are: ");
		for (byte B : retInstrBytes) {
		    print(String.format("%02X ", B));
		}
		print("\n");
		break;
	    }
	}
    }

    /* Function that takes in a MemoryBlock, and looks through the instructions
     * to find a RET instruction. Once found, loops through the previous instructions 
     * and creates a gadget of the prior instructions. If the gadget only includes a RET,
     * the gadget is ignored. */
    private void findGadgets(MemoryBlock block) throws Exception {
	Instruction currInst, prevInst, firstInst = null;
	int maxNumInstructions = 5;
	Address gadgetEndAddr, gadgetStartAddr;

	// Get all of the instructions starting at the beginning of the block
	InstructionIterator instIter = progListing.getInstructions(block.getStart(), true);

	while(instIter.hasNext() && !monitor.isCancelled()) {
	    currInst = instIter.next();
	    if (currInst.getMnemonicString().equalsIgnoreCase("RET")) {
		// Found a RET instruction, grab the rest of the gadget
		firstInst = currInst;
		gadgetEndAddr = currInst.getMaxAddress();
		gadgetStartAddr = currInst.getMaxAddress();
		prevInst = currInst.getPrevious();

		for (int numInst = 0; (numInst < maxNumInstructions) && (prevInst != null); numInst++) {
		    if (prevInst.getMnemonicString().equalsIgnoreCase("RET")) { 
			// Break early if encountering another RET
			break;
		    }

		    // Move back the beginning of the gadget by this instruction
		    firstInst = prevInst;
		    gadgetStartAddr = firstInst.getMaxAddress();

		    // Get the next instruction
		    prevInst = prevInst.getPrevious();
		}

		// Only print out gadgets that are more than the RET instruction
		if (gadgetEndAddr != gadgetStartAddr) {
		    println("*** found gadget at addr: " + firstInst.getMinAddress() + " -> " + currInst.getMaxAddress());
		    prevInst = firstInst;
		    while (prevInst != null && prevInst.getMaxAddress() != gadgetEndAddr) {
		        println(" " + prevInst);
		        prevInst = prevInst.getNext();
		    }
		    println(" " + prevInst);	// Grab the RET instruction at the end

		}
	    }
	}
    }
}
