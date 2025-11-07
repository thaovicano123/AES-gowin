//==============================================================================
// File: tb_aes256_mixcolumns.v
// Description: Comprehensive testbench for aes256_mixcolumns module
// Tests:
//   - MixColumns (encrypt mode)
//   - InvMixColumns (decrypt mode)
//   - Inverse property: InvMixColumns(MixColumns(x)) = x
//   - FIPS-197 test vectors
//   - Zero/identity patterns
//   - Random patterns
//==============================================================================

`timescale 1ns/1ps

module tb_aes256_mixcolumns;

    //==========================================================================
    // TESTBENCH SIGNALS
    //==========================================================================
    reg         mode;
    reg  [127:0] state_in;
    wire [127:0] state_out;
    
    integer errors;
    integer test_count;

    //==========================================================================
    // DUT INSTANTIATION
    //==========================================================================
    aes256_mixcolumns dut (
        .mode_i(mode),
        .state_i(state_in),
        .state_o(state_out)
    );

    //==========================================================================
    // HELPER FUNCTIONS
    //==========================================================================
    
    // Extract byte from 128-bit state
    function [7:0] get_byte;
        input [127:0] state;
        input integer byte_index;  // 0-15
        begin
            get_byte = state[byte_index*8 +: 8];
        end
    endfunction

    // Set byte in 128-bit state
    function [127:0] set_byte;
        input [127:0] state;
        input integer byte_index;
        input [7:0] value;
        reg [127:0] result;
        begin
            result = state;
            result[byte_index*8 +: 8] = value;
            set_byte = result;
        end
    endfunction

    // GF(2^8) multiplication reference
    function [7:0] gf_mult_ref;
        input [7:0] a, b;
        reg [7:0] p;
        reg [7:0] temp_a;
        integer i;
        begin
            p = 8'h00;
            temp_a = a;
            for (i = 0; i < 8; i = i + 1) begin
                if (b[i])
                    p = p ^ temp_a;
                
                if (temp_a[7])
                    temp_a = (temp_a << 1) ^ 8'h1B;
                else
                    temp_a = temp_a << 1;
            end
            gf_mult_ref = p;
        end
    endfunction

    // Reference MixColumns for a single column
    // FIPS-197 byte order: Byte[0] = MSB (bits[31:24])
    function [31:0] ref_mixcolumn;
        input encrypt_mode;
        input [31:0] col_in;
        reg [7:0] b0, b1, b2, b3;
        reg [7:0] r0, r1, r2, r3;
        begin
            // Extract bytes in FIPS-197 order
            b0 = col_in[31:24];  // Byte 0 (MSB)
            b1 = col_in[23:16];  // Byte 1
            b2 = col_in[15: 8];  // Byte 2
            b3 = col_in[ 7: 0];  // Byte 3 (LSB)
            
            if (encrypt_mode) begin
                // MixColumns matrix
                r0 = gf_mult_ref(b0, 8'h02) ^ gf_mult_ref(b1, 8'h03) ^ b2 ^ b3;
                r1 = b0 ^ gf_mult_ref(b1, 8'h02) ^ gf_mult_ref(b2, 8'h03) ^ b3;
                r2 = b0 ^ b1 ^ gf_mult_ref(b2, 8'h02) ^ gf_mult_ref(b3, 8'h03);
                r3 = gf_mult_ref(b0, 8'h03) ^ b1 ^ b2 ^ gf_mult_ref(b3, 8'h02);
            end else begin
                // InvMixColumns matrix
                r0 = gf_mult_ref(b0, 8'h0E) ^ gf_mult_ref(b1, 8'h0B) ^ gf_mult_ref(b2, 8'h0D) ^ gf_mult_ref(b3, 8'h09);
                r1 = gf_mult_ref(b0, 8'h09) ^ gf_mult_ref(b1, 8'h0E) ^ gf_mult_ref(b2, 8'h0B) ^ gf_mult_ref(b3, 8'h0D);
                r2 = gf_mult_ref(b0, 8'h0D) ^ gf_mult_ref(b1, 8'h09) ^ gf_mult_ref(b2, 8'h0E) ^ gf_mult_ref(b3, 8'h0B);
                r3 = gf_mult_ref(b0, 8'h0B) ^ gf_mult_ref(b1, 8'h0D) ^ gf_mult_ref(b2, 8'h09) ^ gf_mult_ref(b3, 8'h0E);
            end
            
            // Pack result (FIPS-197 byte order)
            ref_mixcolumn = {r0, r1, r2, r3};
        end
    endfunction

    // Reference MixColumns for full state
    // FIPS-197 byte order: Byte[0] = bits[127:120]
    function [127:0] ref_mixcolumns;
        input encrypt_mode;
        input [127:0] state;
        reg [31:0] col0, col1, col2, col3;
        begin
            // Extract columns in FIPS-197 order
            col0 = ref_mixcolumn(encrypt_mode, state[127: 96]);  // Bytes [0:3]
            col1 = ref_mixcolumn(encrypt_mode, state[ 95: 64]);  // Bytes [4:7]
            col2 = ref_mixcolumn(encrypt_mode, state[ 63: 32]);  // Bytes [8:11]
            col3 = ref_mixcolumn(encrypt_mode, state[ 31:  0]);  // Bytes [12:15]
            ref_mixcolumns = {col0, col1, col2, col3};
        end
    endfunction

    //==========================================================================
    // TEST TASKS
    //==========================================================================
    
    task check_mixcolumns;
        input [255:0] test_name;
        input test_mode;        // 0=Encrypt, 1=Decrypt
        input [127:0] test_state;
        reg [127:0] expected;
        integer byte_errors;
        integer i;
        begin
            test_count = test_count + 1;
            mode = test_mode;
            state_in = test_state;
            expected = ref_mixcolumns(test_mode == 0, test_state);
            
            #10;  // Wait for combinational logic
            
            byte_errors = 0;
            for (i = 0; i < 16; i = i + 1) begin
                if (get_byte(state_out, i) !== get_byte(expected, i)) begin
                    if (byte_errors == 0) begin
                        $display("FAIL [Test %0d]: %s", test_count, test_name);
                        $display("  Mode: %s", test_mode ? "Decrypt (InvMixColumns)" : "Encrypt (MixColumns)");
                        display_state_matrix("  Input", test_state);
                        display_state_matrix("  Expected", expected);
                        display_state_matrix("  Got", state_out);
                    end
                    $display("  Byte %0d mismatch: expected %02h, got %02h", 
                             i, get_byte(expected, i), get_byte(state_out, i));
                    byte_errors = byte_errors + 1;
                end
            end
            
            if (byte_errors > 0) begin
                errors = errors + 1;
            end else begin
                $display("PASS [Test %0d]: %s", test_count, test_name);
            end
        end
    endtask

    task check_inverse_property;
        input [255:0] test_name;
        input [127:0] original_state;
        reg [127:0] after_mix;
        reg [127:0] after_invmix;
        reg [127:0] expected_original;
        begin
            test_count = test_count + 1;
            
            // Apply MixColumns
            mode = 0;
            state_in = original_state;
            #10;
            after_mix = state_out;
            
            // Apply InvMixColumns
            mode = 1;
            state_in = after_mix;
            #10;
            after_invmix = state_out;
            
            expected_original = original_state;
            
            if (after_invmix !== expected_original) begin
                $display("FAIL [Test %0d]: %s", test_count, test_name);
                $display("  Inverse property violated!");
                display_state_matrix("  Original", original_state);
                display_state_matrix("  After MixColumns", after_mix);
                display_state_matrix("  After InvMixColumns", after_invmix);
                display_state_matrix("  Expected (Original)", expected_original);
                errors = errors + 1;
            end else begin
                $display("PASS [Test %0d]: %s", test_count, test_name);
            end
        end
    endtask

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
    // MAIN TEST SEQUENCE
    //==========================================================================
    initial begin
        $dumpfile("tb_aes256_mixcolumns.vcd");
        $dumpvars(0, tb_aes256_mixcolumns);
        
        errors = 0;
        test_count = 0;
        
        $display("================================================================================");
        $display("AES-256 MIXCOLUMNS TESTBENCH");
        $display("================================================================================");

        //======================================================================
        // SECTION 1: ZERO AND IDENTITY PATTERNS
        //======================================================================
        $display("\n--- Test Section 1: Zero and Identity Patterns ---");
        
        check_mixcolumns("All zeros - Encrypt", 0, 128'h0);
        check_mixcolumns("All zeros - Decrypt", 1, 128'h0);
        
        //======================================================================
        // SECTION 2: FIPS-197 TEST VECTORS
        //======================================================================
        $display("\n--- Test Section 2: FIPS-197 Test Vectors ---");
        
        // FIPS-197 Appendix C.3 - Round 1 MixColumns
        // Before MixColumns:
        // d4 e0 b8 1e
        // 27 bf b4 41
        // 11 98 5d 52
        // ae f1 e5 30
        check_mixcolumns("FIPS-197 C.3 Round 1 - Encrypt", 0, 
            128'h30e5f1ae52_5d_9811_41_b4bf27_1e_b8_e0_d4);
        
        // Expected after MixColumns:
        // 04 e0 48 28
        // 66 cb f8 06
        // 81 19 d3 26
        // e5 9a 7a 4c
        
        //======================================================================
        // SECTION 3: SINGLE COLUMN TESTS
        //======================================================================
        $display("\n--- Test Section 3: Single Column Tests ---");
        
        // Test column 0 only (others zero)
        check_mixcolumns("Single column 0 - Encrypt", 0,
            128'h00000000_00000000_00000000_db135345);
        
        check_mixcolumns("Single column 0 - Decrypt", 1,
            128'h00000000_00000000_00000000_db135345);
        
        // Test column 1 only
        check_mixcolumns("Single column 1 - Encrypt", 0,
            128'h00000000_00000000_f20a225a_00000000);
        
        check_mixcolumns("Single column 1 - Decrypt", 1,
            128'h00000000_00000000_f20a225a_00000000);
        
        //======================================================================
        // SECTION 4: SEQUENTIAL PATTERNS
        //======================================================================
        $display("\n--- Test Section 4: Sequential Patterns ---");
        
        // Sequential bytes 00-0F
        check_mixcolumns("Sequential 00-0F - Encrypt", 0,
            128'h0f0e0d0c_0b0a0908_07060504_03020100);
        
        check_mixcolumns("Sequential 00-0F - Decrypt", 1,
            128'h0f0e0d0c_0b0a0908_07060504_03020100);
        
        // Sequential bytes 10-1F
        check_mixcolumns("Sequential 10-1F - Encrypt", 0,
            128'h1f1e1d1c_1b1a1918_17161514_13121110);
        
        check_mixcolumns("Sequential 10-1F - Decrypt", 1,
            128'h1f1e1d1c_1b1a1918_17161514_13121110);
        
        //======================================================================
        // SECTION 5: INVERSE PROPERTY TESTS
        //======================================================================
        $display("\n--- Test Section 5: Inverse Property Tests ---");
        
        check_inverse_property("Inverse Property - All zeros",
            128'h0);
        
        check_inverse_property("Inverse Property - Sequential 00-0F",
            128'h0f0e0d0c_0b0a0908_07060504_03020100);
        
        check_inverse_property("Inverse Property - FIPS-197",
            128'h30e5f1ae52_5d_9811_41_b4bf27_1e_b8_e0_d4);
        
        check_inverse_property("Inverse Property - Random 1",
            128'h8e9f01c6_940863a1_7a2c685e_1db7b5c0);
        
        check_inverse_property("Inverse Property - Random 2",
            128'hffeeddcc_bbaa9988_77665544_33221100);
        
        check_inverse_property("Inverse Property - All 0xFF",
            128'hffffffff_ffffffff_ffffffff_ffffffff);
        
        check_inverse_property("Inverse Property - Alternating",
            128'haaaaaaaa_55555555_aaaaaaaa_55555555);
        
        //======================================================================
        // SECTION 6: BOUNDARY CASES
        //======================================================================
        $display("\n--- Test Section 6: Boundary Cases ---");
        
        check_mixcolumns("All 0xFF - Encrypt", 0,
            128'hffffffff_ffffffff_ffffffff_ffffffff);
        
        check_mixcolumns("All 0xFF - Decrypt", 1,
            128'hffffffff_ffffffff_ffffffff_ffffffff);
        
        check_mixcolumns("Alternating 0x55 - Encrypt", 0,
            128'h55555555_55555555_55555555_55555555);
        
        check_mixcolumns("Alternating 0xAA - Decrypt", 1,
            128'haaaaaaaa_aaaaaaaa_aaaaaaaa_aaaaaaaa);
        
        //======================================================================
        // SECTION 7: RANDOM PATTERNS
        //======================================================================
        $display("\n--- Test Section 7: Random Patterns ---");
        
        check_mixcolumns("Random 1 - Encrypt", 0,
            128'h8e9f01c6_940863a1_7a2c685e_1db7b5c0);
        
        check_mixcolumns("Random 1 - Decrypt", 1,
            128'h8e9f01c6_940863a1_7a2c685e_1db7b5c0);
        
        check_mixcolumns("Random 2 - Encrypt", 0,
            128'h0102030405060708090a0b0c0d0e0f10);
        
        check_mixcolumns("Random 2 - Decrypt", 1,
            128'h0102030405060708090a0b0c0d0e0f10);
        
        check_mixcolumns("Random 3 - Encrypt", 0,
            128'hdeadbeef_cafebabe_13371337_deadc0de);
        
        check_mixcolumns("Random 3 - Decrypt", 1,
            128'hdeadbeef_cafebabe_13371337_deadc0de);
        
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
