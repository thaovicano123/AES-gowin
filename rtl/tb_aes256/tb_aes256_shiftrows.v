//==============================================================================
// File: tb_aes256_shiftrows.v
// Description: Comprehensive Testbench for aes256_shiftrows.v
// 
// Test Coverage:
// 1. ShiftRows for encryption (mode=0)
// 2. InvShiftRows for decryption (mode=1)
// 3. Inverse property: InvShiftRows(ShiftRows(state)) = state
// 4. FIPS-197 test vectors
// 5. Row-specific patterns to verify each row shift
// 6. Edge cases and identity tests
//==============================================================================

`timescale 1ns / 1ps

module tb_aes256_shiftrows;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg         mode;           // 0=Encrypt, 1=Decrypt
    reg  [127:0] state_in;      // Input state (16 bytes)
    wire [127:0] state_out;     // Output state (16 bytes)
    
    // Error tracking
    integer errors;
    integer test_count;
    
    //==========================================================================
    // Helper: Extract byte from 128-bit state
    //==========================================================================
    function [7:0] get_byte;
        input [127:0] state;
        input integer byte_index;
    begin
        get_byte = state[byte_index*8 +: 8];
    end
    endfunction
    
    //==========================================================================
    // Helper: Set byte in 128-bit state
    //==========================================================================
    function [127:0] set_byte;
        input [127:0] state;
        input integer byte_index;
        input [7:0] value;
        reg [127:0] result;
        integer i;
    begin
        result = state;
        result[byte_index*8 +: 8] = value;
        set_byte = result;
    end
    endfunction
    
    //==========================================================================
    // Reference Implementation: ShiftRows (matching RTL logic)
    // FIPS-197 byte order: Byte[0] = MSB (bits[127:120])
    //==========================================================================
    function [127:0] ref_shiftrows;
        input [127:0] state;
        input encrypt_mode;  // 0=encrypt(shift left), 1=decrypt(shift right)
        reg [7:0] s00, s01, s02, s03;
        reg [7:0] s10, s11, s12, s13;
        reg [7:0] s20, s21, s22, s23;
        reg [7:0] s30, s31, s32, s33;
        reg [7:0] r00, r01, r02, r03;
        reg [7:0] r10, r11, r12, r13;
        reg [7:0] r20, r21, r22, r23;
        reg [7:0] r30, r31, r32, r33;
    begin
        // Extract bytes in FIPS-197 byte order (Byte[0]=MSB)
        // Column 0: bytes 0,1,2,3   Column 1: bytes 4,5,6,7
        // Column 2: bytes 8,9,10,11  Column 3: bytes 12,13,14,15
        s00 = state[127:120];  s01 = state[ 95: 88];
        s02 = state[ 63: 56];  s03 = state[ 31: 24];
        
        s10 = state[119:112];  s11 = state[ 87: 80];
        s12 = state[ 55: 48];  s13 = state[ 23: 16];
        
        s20 = state[111:104];  s21 = state[ 79: 72];
        s22 = state[ 47: 40];  s23 = state[ 15:  8];
        
        s30 = state[103: 96];  s31 = state[ 71: 64];
        s32 = state[ 39: 32];  s33 = state[  7:  0];
        
        // Row 0: no shift
        r00 = s00;
        r01 = s01;
        r02 = s02;
        r03 = s03;
        
        if (encrypt_mode == 0) begin
            // Encryption: Shift Left
            // Row 1: shift left 1 [s11, s12, s13, s10]
            r10 = s11;
            r11 = s12;
            r12 = s13;
            r13 = s10;
            
            // Row 2: shift left 2 [s22, s23, s20, s21]
            r20 = s22;
            r21 = s23;
            r22 = s20;
            r23 = s21;
            
            // Row 3: shift left 3 [s33, s30, s31, s32]
            r30 = s33;
            r31 = s30;
            r32 = s31;
            r33 = s32;
        end else begin
            // Decryption: Shift Right
            // Row 1: shift right 1 [s13, s10, s11, s12]
            r10 = s13;
            r11 = s10;
            r12 = s11;
            r13 = s12;
            
            // Row 2: shift right 2 (same as left 2)
            r20 = s22;
            r21 = s23;
            r22 = s20;
            r23 = s21;
            
            // Row 3: shift right 3 [s31, s32, s33, s30]
            r30 = s31;
            r31 = s32;
            r32 = s33;
            r33 = s30;
        end
        
        // Pack result (FIPS-197 byte order: Byte[0]=MSB)
        // Byte positions: [127:120]=r00, [119:112]=r10, [111:104]=r20, [103:96]=r30, etc.
        ref_shiftrows = {
            r00, r10, r20, r30,  // Bytes 0,1,2,3     (Column 0)
            r01, r11, r21, r31,  // Bytes 4,5,6,7     (Column 1)
            r02, r12, r22, r32,  // Bytes 8,9,10,11   (Column 2)
            r03, r13, r23, r33   // Bytes 12,13,14,15 (Column 3)
        };
    end
    endfunction
    
    //==========================================================================
    // DUT Instantiation
    //==========================================================================
    aes256_shiftrows dut (
        .mode_i(mode),
        .state_i(state_in),
        .state_o(state_out)
    );
    
    //==========================================================================
    // Helper Task: Check ShiftRows Transformation
    //==========================================================================
    task check_shiftrows;
        input [127:0] test_state;
        input test_mode;  // 0=encrypt, 1=decrypt
        input [255:0] test_name;
        reg [127:0] expected;
        integer i;
        integer byte_errors;
    begin
        byte_errors = 0;
        
        // Apply inputs
        mode = test_mode;
        state_in = test_state;
        #10;  // Wait for combinational logic
        
        // Calculate expected output
        expected = ref_shiftrows(test_state, test_mode);
        
        // Check output
        test_count = test_count + 1;
        if (state_out !== expected) begin
            errors = errors + 1;
            $display("ERROR [Test %0d]: %s", test_count, test_name);
            $display("  Mode: %s", test_mode ? "DECRYPT" : "ENCRYPT");
            $display("  Input:    %032h", test_state);
            $display("  Expected: %032h", expected);
            $display("  Got:      %032h", state_out);
            
            // Show which bytes are wrong
            for (i = 0; i < 16; i = i + 1) begin
                if (state_out[i*8 +: 8] !== expected[i*8 +: 8]) begin
                    byte_errors = byte_errors + 1;
                    $display("  Byte[%2d]: Expected %02h, Got %02h", 
                             i, expected[i*8 +: 8], state_out[i*8 +: 8]);
                end
            end
        end else begin
            $display("PASS [Test %0d]: %s", test_count, test_name);
        end
    end
    endtask
    
    //==========================================================================
    // Helper Task: Check Inverse Property
    //==========================================================================
    task check_inverse_property;
        input [127:0] original_state;
        input [255:0] test_name;
        reg [127:0] shifted;
        reg [127:0] recovered;
        reg [127:0] expected_shifted;
        reg [127:0] expected_recovered;
    begin
        // Shift (encrypt)
        mode = 0;
        state_in = original_state;
        #10;  // Wait for combinational logic
        shifted = state_out;
        expected_shifted = ref_shiftrows(original_state, 0);
        
        // InvShift (decrypt) - use the ACTUAL shifted output from DUT
        mode = 1;
        state_in = shifted;  // Feed back the actual output
        #10;  // Wait for combinational logic
        recovered = state_out;
        expected_recovered = ref_shiftrows(shifted, 1);
        
        // Check if we got back the original
        test_count = test_count + 1;
        if (recovered !== original_state) begin
            errors = errors + 1;
            $display("ERROR [Test %0d]: Inverse Property - %s", test_count, test_name);
            $display("  Original:         %032h", original_state);
            $display("  Shifted (actual): %032h", shifted);
            $display("  Shifted (expect): %032h", expected_shifted);
            $display("  Recov (actual):   %032h", recovered);
            $display("  Recov (expect):   %032h", original_state);
            if (shifted !== expected_shifted) begin
                $display("  NOTE: Shift step has mismatch!");
            end
        end else begin
            $display("PASS [Test %0d]: Inverse Property - %s", test_count, test_name);
        end
    end
    endtask
    
    //==========================================================================
    // Helper Task: Display state as 4x4 matrix
    //==========================================================================
    task display_state_matrix;
        input [255:0] label;
        input [127:0] state;
        integer r, c, idx;
    begin
        $display("%s", label);
        for (r = 0; r < 4; r = r + 1) begin
            $write("  ");
            for (c = 0; c < 4; c = c + 1) begin
                idx = r + c*4;  // Column-major order
                $write("%02h ", state[idx*8 +: 8]);
            end
            $write("\n");
        end
    end
    endtask
    
    //==========================================================================
    // Main Test Sequence
    //==========================================================================
    initial begin
        // Generate VCD for waveform viewing - MUST BE AT START!
        $dumpfile("tb_aes256_shiftrows.vcd");
        $dumpvars(0, tb_aes256_shiftrows);
        
        // Initialize
        errors = 0;
        test_count = 0;
        mode = 0;
        state_in = 128'h0;
        
        $display("================================================================================");
        $display("AES-256 ShiftRows Module Testbench");
        $display("================================================================================");
        $display("");
        
        //======================================================================
        // Test 1: Identity Cases
        //======================================================================
        $display("--- Test Section 1: Identity Cases ---");
        
        // All zeros - shifting doesn't change anything visually
        check_shiftrows(128'h00000000000000000000000000000000, 0, "All zeros - Encrypt");
        check_shiftrows(128'h00000000000000000000000000000000, 1, "All zeros - Decrypt");
        
        // All same value - shifting doesn't change anything
        check_shiftrows(128'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, 0, "All 0xAA - Encrypt");
        check_shiftrows(128'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, 1, "All 0xAA - Decrypt");
        $display("");
        
        //======================================================================
        // Test 2: Row-Specific Patterns
        //======================================================================
        $display("--- Test Section 2: Row-Specific Patterns ---");
        
        // Test each row independently with unique pattern
        // Row 0 only (bytes 0,4,8,12): should not shift
        check_shiftrows(128'h000000000000000000000000AA55AA55, 0, "Row 0 only - Encrypt");
        check_shiftrows(128'h000000000000000000000000AA55AA55, 1, "Row 0 only - Decrypt");
        
        // Row 1 only (bytes 1,5,9,13): should shift
        check_shiftrows(128'h00000000000000000000AA55AA550000, 0, "Row 1 only - Encrypt");
        check_shiftrows(128'h00000000000000000000AA55AA550000, 1, "Row 1 only - Decrypt");
        
        // Row 2 only (bytes 2,6,10,14): should shift
        check_shiftrows(128'h0000000000000000AA55AA5500000000, 0, "Row 2 only - Encrypt");
        check_shiftrows(128'h0000000000000000AA55AA5500000000, 1, "Row 2 only - Decrypt");
        
        // Row 3 only (bytes 3,7,11,15): should shift
        check_shiftrows(128'h00000000AA55AA550000000000000000, 0, "Row 3 only - Encrypt");
        check_shiftrows(128'h00000000AA55AA550000000000000000, 1, "Row 3 only - Decrypt");
        $display("");
        
        //======================================================================
        // Test 3: Sequential Pattern (Easy to Track Shifts)
        //======================================================================
        $display("--- Test Section 3: Sequential Pattern (Track Byte Movement) ---");
        
        // Create state with sequential bytes: 00 01 02 03 ... 0F
        state_in = 128'h0F0E0D0C0B0A09080706050403020100;
        
        display_state_matrix("Input State (Sequential 00-0F):", state_in);
        
        mode = 0;
        #10;
        display_state_matrix("After ShiftRows (Encrypt):", state_out);
        check_shiftrows(128'h0F0E0D0C0B0A09080706050403020100, 0, "Sequential 00-0F - Encrypt");
        
        mode = 1;
        state_in = 128'h0F0E0D0C0B0A09080706050403020100;
        #10;
        display_state_matrix("After InvShiftRows (Decrypt):", state_out);
        check_shiftrows(128'h0F0E0D0C0B0A09080706050403020100, 1, "Sequential 00-0F - Decrypt");
        $display("");
        
        //======================================================================
        // Test 4: FIPS-197 Test Vectors
        //======================================================================
        $display("--- Test Section 4: FIPS-197 Test Vectors ---");
        
        // FIPS-197 Appendix B - After SubBytes, before ShiftRows
        check_shiftrows(
            128'hd42711aee0bf98f1b8b45de51e415230,
            0,
            "FIPS-197 After SubBytes - Encrypt"
        );
        
        // FIPS-197 - Verify specific transformation
        // Input:  d4 e0 b8 1e
        //         27 bf b4 41
        //         11 98 5d 52
        //         ae f1 e5 30
        // Output: d4 e0 b8 1e
        //         bf b4 41 27
        //         5d 52 11 98
        //         30 ae f1 e5
        
        $display("");
        
        //======================================================================
        // Test 5: Inverse Property Tests
        //======================================================================
        $display("--- Test Section 5: Inverse Property (InvShiftRows(ShiftRows(x)) = x) ---");
        
        check_inverse_property(128'h00000000000000000000000000000000, "All zeros");
        check_inverse_property(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, "All ones");
        check_inverse_property(128'h0F0E0D0C0B0A09080706050403020100, "Sequential 00-0F");
        check_inverse_property(128'hF0E0D0C0B0A09080706050403020100F, "Sequential reversed");
        check_inverse_property(128'hd42711aee0bf98f1b8b45de51e415230, "FIPS-197 state");
        check_inverse_property(128'h193de3bea0f4e22b9ac68d2ae9f84808, "Random state 1");
        check_inverse_property(128'hb7e151628aed2a6abf7158809cf4f3c7, "Random state 2");
        $display("");
        
        //======================================================================
        // Test 6: Boundary and Corner Cases
        //======================================================================
        $display("--- Test Section 6: Boundary and Corner Cases ---");
        
        // Single byte set in each position
        check_shiftrows(128'h00000000000000000000000000000001, 0, "Byte 0 = 0x01 - Encrypt");
        check_shiftrows(128'h00000000000000000000000000000100, 0, "Byte 1 = 0x01 - Encrypt");
        check_shiftrows(128'h00000000000000000000000000010000, 0, "Byte 2 = 0x01 - Encrypt");
        check_shiftrows(128'h00000000000000000000000001000000, 0, "Byte 3 = 0x01 - Encrypt");
        
        // Checkerboard pattern
        check_shiftrows(128'hA5A5A5A5A5A5A5A55A5A5A5A5A5A5A5A, 0, "Checkerboard 1 - Encrypt");
        check_shiftrows(128'h5A5A5A5A5A5A5A5AA5A5A5A5A5A5A5A5, 1, "Checkerboard 2 - Decrypt");
        $display("");
        
        //======================================================================
        // Test 7: Specific Row Shift Verification
        //======================================================================
        $display("--- Test Section 7: Detailed Row Shift Verification ---");
        
        // Create a pattern where each row has distinct values
        // Row 0: 11 11 11 11
        // Row 1: 22 22 22 22
        // Row 2: 33 33 33 33
        // Row 3: 44 44 44 44
        state_in = 128'h44444444333333332222222211111111;
        
        $display("Test: Distinct rows pattern");
        display_state_matrix("  Input (each row same value):", state_in);
        
        mode = 0;
        #10;
        display_state_matrix("  After ShiftRows:", state_out);
        // Expected after shift left:
        // Row 0: 11 11 11 11 (no shift)
        // Row 1: 22 22 22 22 (shift left 1, but all same)
        // Row 2: 33 33 33 33 (shift left 2, but all same)
        // Row 3: 44 44 44 44 (shift left 3, but all same)
        check_shiftrows(128'h44444444333333332222222211111111, 0, "Distinct rows - Encrypt");
        
        // Create a pattern with distinct columns
        // Col 0: 11 22 33 44
        // Col 1: 55 66 77 88
        // Col 2: 99 AA BB CC
        // Col 3: DD EE FF 00
        state_in = 128'h00FFEEDDCCBBAA998877665544332211;
        
        $display("Test: Distinct columns pattern");
        display_state_matrix("  Input (each column distinct):", state_in);
        
        mode = 0;
        #10;
        display_state_matrix("  After ShiftRows:", state_out);
        check_shiftrows(128'h00FFEEDDCCBBAA998877665544332211, 0, "Distinct columns - Encrypt");
        $display("");
        
        //======================================================================
        // Test 8: Random Patterns
        //======================================================================
        $display("--- Test Section 8: Random Patterns ---");
        
        check_shiftrows(128'h3243f6a8885a308d313198a2e0370734, 0, "Random 1 - Encrypt");
        check_shiftrows(128'h3243f6a8885a308d313198a2e0370734, 1, "Random 1 - Decrypt");
        check_inverse_property(128'h3243f6a8885a308d313198a2e0370734, "Random 1");
        
        check_shiftrows(128'hb7e151628aed2a6abf7158809cf4f3c7, 0, "Random 2 - Encrypt");
        check_shiftrows(128'hb7e151628aed2a6abf7158809cf4f3c7, 1, "Random 2 - Decrypt");
        check_inverse_property(128'hb7e151628aed2a6abf7158809cf4f3c7, "Random 2");
        $display("");
        
        //======================================================================
        // Final Results
        //======================================================================
        $display("================================================================================");
        $display("Test Summary:");
        $display("  Total Tests: %0d", test_count);
        $display("  Errors:      %0d", errors);
        if (errors == 0) begin
            $display("  Status:      ALL TESTS PASSED ✓");
        end else begin
            $display("  Status:      TESTS FAILED ✗");
        end
        $display("================================================================================");
        
        #100;
        $finish;
    end

endmodule
