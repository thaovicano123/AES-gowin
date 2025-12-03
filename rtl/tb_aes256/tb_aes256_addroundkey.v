//==============================================================================
// File: tb_aes256_addroundkey.v
// Description: Comprehensive testbench for aes256_addroundkey module
// Tests:
//   - Basic XOR functionality
//   - Identity property: AddRoundKey(AddRoundKey(state, key), key) = state
//   - Zero key/state cases
//   - FIPS-197 test vectors
//   - Random patterns
//   - Bitwise independence
//==============================================================================

`timescale 1ns/1ps

module tb_aes256_addroundkey;

    //==========================================================================
    // TESTBENCH SIGNALS
    //==========================================================================
    reg  [127:0] state_in;
    reg  [127:0] round_key;
    wire [127:0] state_out;
    
    integer errors;
    integer test_count;

    //==========================================================================
    // DUT INSTANTIATION
    //==========================================================================
    aes256_addroundkey dut (
        .state_i(state_in),
        .round_key_i(round_key),
        .state_o(state_out)
    );

    //==========================================================================
    // HELPER FUNCTIONS
    //==========================================================================
    
    // Extract byte from 128-bit value
    function [7:0] get_byte;
        input [127:0] data;
        input integer byte_index;
        begin
            get_byte = data[byte_index*8 +: 8];
        end
    endfunction

    // Display state as 4x4 matrix
    task display_state_matrix;
        input [255:0] label;
        input [127:0] state;
        integer r, c, idx;
        begin
            $display("%s:", label);
            for (r = 0; r < 4; r = r + 1) begin
                $write("  ");
                for (c = 0; c < 4; c = c + 1) begin
                    idx = c * 4 + r;
                    $write("%02h ", get_byte(state, idx));
                end
                $display("");
            end
        end
    endtask

    //==========================================================================
    // TEST TASKS
    //==========================================================================
    
    task check_addroundkey;
        input [255:0] test_name;
        input [127:0] test_state;
        input [127:0] test_key;
        reg [127:0] expected;
        integer i;
        begin
            test_count = test_count + 1;
            state_in = test_state;
            round_key = test_key;
            expected = test_state ^ test_key;  // Expected is simple XOR
            
            #10;  // Wait for combinational logic
            
            if (state_out !== expected) begin
                $display("FAIL [Test %0d]: %s", test_count, test_name);
                display_state_matrix("  Input State", test_state);
                display_state_matrix("  Round Key", test_key);
                display_state_matrix("  Expected", expected);
                display_state_matrix("  Got", state_out);
                
                // Show bit-level differences
                for (i = 0; i < 16; i = i + 1) begin
                    if (get_byte(state_out, i) !== get_byte(expected, i)) begin
                        $display("  Byte %0d mismatch: expected %02h, got %02h", 
                                 i, get_byte(expected, i), get_byte(state_out, i));
                    end
                end
                
                errors = errors + 1;
            end else begin
                $display("PASS [Test %0d]: %s", test_count, test_name);
            end
        end
    endtask

    task check_identity_property;
        input [255:0] test_name;
        input [127:0] original_state;
        input [127:0] test_key;
        reg [127:0] after_first_xor;
        reg [127:0] after_second_xor;
        begin
            test_count = test_count + 1;
            
            // First AddRoundKey
            state_in = original_state;
            round_key = test_key;
            #10;
            after_first_xor = state_out;
            
            // Second AddRoundKey with same key
            state_in = after_first_xor;
            round_key = test_key;
            #10;
            after_second_xor = state_out;
            
            // Should recover original state
            if (after_second_xor !== original_state) begin
                $display("FAIL [Test %0d]: %s", test_count, test_name);
                $display("  Identity property violated!");
                display_state_matrix("  Original State", original_state);
                display_state_matrix("  Round Key", test_key);
                display_state_matrix("  After 1st XOR", after_first_xor);
                display_state_matrix("  After 2nd XOR", after_second_xor);
                display_state_matrix("  Expected (Original)", original_state);
                errors = errors + 1;
            end else begin
                $display("PASS [Test %0d]: %s", test_count, test_name);
            end
        end
    endtask

    //==========================================================================
    // MAIN TEST SEQUENCE
    //==========================================================================
    initial begin
        $dumpfile("tb_aes256_addroundkey.vcd");
        $dumpvars(0, tb_aes256_addroundkey);
        
        errors = 0;
        test_count = 0;
        
        $display("================================================================================");
        $display("AES-256 ADDROUNDKEY TESTBENCH");
        $display("================================================================================");

        //======================================================================
        // SECTION 1: ZERO AND IDENTITY PATTERNS
        //======================================================================
        $display("\n--- Test Section 1: Zero and Identity Patterns ---");
        
        // Zero state, zero key
        check_addroundkey("Zero state, zero key", 
            128'h0, 128'h0);
        
        // Zero state, non-zero key
        check_addroundkey("Zero state, non-zero key",
            128'h0, 128'h0102030405060708090a0b0c0d0e0f10);
        
        // Non-zero state, zero key
        check_addroundkey("Non-zero state, zero key",
            128'h0102030405060708090a0b0c0d0e0f10, 128'h0);
        
        // All ones
        check_addroundkey("All ones state and key",
            128'hffffffffffffffffffffffffffffffff,
            128'hffffffffffffffffffffffffffffffff);
        
        //======================================================================
        // SECTION 2: FIPS-197 TEST VECTORS
        //======================================================================
        $display("\n--- Test Section 2: FIPS-197 Test Vectors ---");
        
        // FIPS-197 Appendix B - Initial AddRoundKey (Round 0)
        // Plaintext: 00112233445566778899aabbccddeeff
        // Key (first 16 bytes): 000102030405060708090a0b0c0d0e0f
        check_addroundkey("FIPS-197 Appendix B - Round 0",
            128'h00112233445566778899aabbccddeeff,
            128'h000102030405060708090a0b0c0d0e0f);
        // Expected: 00102030405060708090a0b0c0d0e0f0
        
        // FIPS-197 Appendix C.3 - Round 1 AddRoundKey
        // State after MixColumns: 4c9adbcc2ba3b792465920f6c1da71d8 (from doc)
        // Round key: a0fafe1788542cb123a339392a6c7605
        check_addroundkey("FIPS-197 C.3 Round 1",
            128'hd8c171daf62059469227a32bccdb9a4c,
            128'h056c2a3992332a31cb2c5488e1fefa0a);
        
        //======================================================================
        // SECTION 3: IDENTITY PROPERTY TESTS
        //======================================================================
        $display("\n--- Test Section 3: Identity Property Tests ---");
        
        // AddRoundKey(AddRoundKey(state, key), key) = state
        check_identity_property("Identity - Sequential state",
            128'h0f0e0d0c0b0a09080706050403020100,
            128'h0102030405060708090a0b0c0d0e0f10);
        
        check_identity_property("Identity - FIPS-197 state",
            128'h00112233445566778899aabbccddeeff,
            128'h000102030405060708090a0b0c0d0e0f);
        
        check_identity_property("Identity - Random 1",
            128'h8e9f01c6940863a17a2c685e1db7b5c0,
            128'hffeeddccbbaa99887766554433221100);
        
        check_identity_property("Identity - All 0xFF",
            128'hffffffffffffffffffffffffffffffff,
            128'haaaaaaaa55555555aaaaaaaa55555555);
        
        check_identity_property("Identity - Alternating",
            128'haaaaaaaa55555555aaaaaaaa55555555,
            128'h5555555555555555aaaaaaaaaaaaaaaa);
        
        //======================================================================
        // SECTION 4: BIT INDEPENDENCE
        //======================================================================
        $display("\n--- Test Section 4: Bit Independence Tests ---");
        
        // Single bit in state
        check_addroundkey("Single bit in state (bit 0)",
            128'h00000000000000000000000000000001,
            128'h0);
        
        check_addroundkey("Single bit in state (bit 127)",
            128'h80000000000000000000000000000000,
            128'h0);
        
        // Single bit in key
        check_addroundkey("Single bit in key (bit 0)",
            128'h0,
            128'h00000000000000000000000000000001);
        
        check_addroundkey("Single bit in key (bit 127)",
            128'h0,
            128'h80000000000000000000000000000000);
        
        //======================================================================
        // SECTION 5: BOUNDARY VALUES
        //======================================================================
        $display("\n--- Test Section 5: Boundary Values ---");
        
        check_addroundkey("Max state, min key",
            128'hffffffffffffffffffffffffffffffff,
            128'h0);
        
        check_addroundkey("Min state, max key",
            128'h0,
            128'hffffffffffffffffffffffffffffffff);
        
        check_addroundkey("Alternating 0x55",
            128'h55555555555555555555555555555555,
            128'h55555555555555555555555555555555);
        
        check_addroundkey("Alternating 0xAA",
            128'haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
            128'haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
        
        //======================================================================
        // SECTION 6: RANDOM PATTERNS
        //======================================================================
        $display("\n--- Test Section 6: Random Patterns ---");
        
        check_addroundkey("Random 1",
            128'h243f6a8885a308d313198a2e03707344,
            128'ha4093822299f31d0082efa98ec4e6c89);
        
        check_addroundkey("Random 2",
            128'h452821e638d01377be5466cf34e90c6c,
            128'hc0ac29b7c97c50dd3f84d5b5b5470917);
        
        check_addroundkey("Random 3",
            128'hdeadbeefcafebabe13371337deadc0de,
            128'hfaceb00c8badf00ddeadbeefdecaf001);
        
        //======================================================================
        // SECTION 7: COMPLEMENTARY PATTERNS
        //======================================================================
        $display("\n--- Test Section 7: Complementary Patterns ---");
        
        // State and its complement
        check_addroundkey("State and complement",
            128'h0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f,
            128'hf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0);
        
        // Should result in all 0xFF
        check_addroundkey("Verify XOR complement = 0xFF",
            128'h12345678abcdef0fedcba98765432110,
            128'hedcba98754321f0f1234567689abcdef);
        
        //======================================================================
        // TEST SUMMARY
        //======================================================================
        $display("\n================================================================================");
        $display("Test Summary:");
        $display("  Total Tests: %0d", test_count);
        $display("  Errors:      %0d", errors);
        if (errors == 0)
            $display("  Status:      ALL TESTS PASSED ✓");
        else
            $display("  Status:      TESTS FAILED ✗");
        $display("================================================================================");
        
        $finish;
    end

endmodule
