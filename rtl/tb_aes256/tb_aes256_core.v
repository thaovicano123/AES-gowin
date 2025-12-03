//==============================================================================
// File: tb_aes256_core.v
// Description: Testbench for AES-256 Core
// - Tests encryption and decryption with FIPS-197 test vectors
// - Verifies against Python implementation results
//==============================================================================

`timescale 1ns/1ps

module tb_aes256_core;

    //==========================================================================
    // TESTBENCH SIGNALS
    //==========================================================================
    reg         clk;
    reg         rst_n;
    reg         start_i;
    reg         mode_i;
    reg [127:0] plaintext_i;
    reg [255:0] key_i;
    wire [127:0] ciphertext_o;
    wire         valid_o;
    wire         busy_o;

    //==========================================================================
    // DUT INSTANTIATION
    //==========================================================================
    aes256_core dut (
        .clk(clk),
        .rst_n(rst_n),
        .start_i(start_i),
        .mode_i(mode_i),
        .plaintext_i(plaintext_i),
        .key_i(key_i),
        .ciphertext_o(ciphertext_o),
        .valid_o(valid_o),
        .busy_o(busy_o)
    );

    //==========================================================================
    // CLOCK GENERATION (100 MHz = 10ns period)
    //==========================================================================
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    //==========================================================================
    // TEST VECTORS
    //==========================================================================
    
    // FIPS-197 Appendix C.3 test vector for AES-256
    // FIXED: Now using correct FIPS-197 byte order (MSB = Byte 0)
    reg [127:0] test_plaintext;
    reg [255:0] test_key;
    reg [127:0] expected_ciphertext;

    initial begin
        // FIPS-197 byte order: leftmost byte = Byte[0] = bit[127:120]
        test_plaintext = 128'h00112233445566778899aabbccddeeff;
        test_key = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        expected_ciphertext = 128'h8ea2b7ca516745bfeafc49904b496089;
    end

    //==========================================================================
    // TEST PROCEDURE
    //==========================================================================
    integer test_pass;
    integer start_time, end_time, latency;
    
    initial begin
        // Initialize
        $display("========================================");
        $display("AES-256 Core Testbench");
        $display("========================================");
        
        test_pass = 0;
        rst_n = 0;
        start_i = 0;
        mode_i = 0;
        plaintext_i = 128'd0;
        key_i = 256'd0;

        // Reset sequence
        #20;
        rst_n = 1;
        #20;

        //======================================================================
        // TEST 1: FIPS-197 ENCRYPTION TEST
        //======================================================================
        $display("\n[TEST 1] FIPS-197 AES-256 Encryption Test");
        $display("----------------------------------------");
        $display("Plaintext:  %032h", test_plaintext);
        $display("Key:        %064h", test_key);
        $display("Expected:   %032h", expected_ciphertext);
        
        // Set inputs
        plaintext_i = test_plaintext;
        key_i = test_key;
        mode_i = 0;  // Encryption mode
        
        // Start encryption
        @(posedge clk);
        start_i = 1;
        @(posedge clk);
        start_i = 0;

        // Wait for completion
        wait(valid_o == 1);
        @(posedge clk);
        
        $display("Ciphertext: %032h", ciphertext_o);
        
        if (ciphertext_o == expected_ciphertext) begin
            $display("✓ ENCRYPTION TEST PASSED!");
            test_pass = test_pass + 1;
        end else begin
            $display("✗ ENCRYPTION TEST FAILED!");
        end

        #100;

        //======================================================================
        // TEST 2: DECRYPTION TEST (Reverse of encryption)
        //======================================================================
        $display("\n[TEST 2] AES-256 Decryption Test");
        $display("----------------------------------------");
        $display("Ciphertext: %032h", expected_ciphertext);
        $display("Key:        %064h", test_key);
        $display("Expected:   %032h", test_plaintext);
        
        // Set inputs for decryption
        plaintext_i = expected_ciphertext;  // Input is ciphertext
        key_i = test_key;
        mode_i = 1;  // Decryption mode
        
        // Start decryption
        @(posedge clk);
        start_i = 1;
        @(posedge clk);
        start_i = 0;

        // Wait for completion
        wait(valid_o == 1);
        @(posedge clk);
        
        $display("Plaintext:  %032h", ciphertext_o);
        
        if (ciphertext_o == test_plaintext) begin
            $display("✓ DECRYPTION TEST PASSED!");
            test_pass = test_pass + 1;
        end else begin
            $display("✗ DECRYPTION TEST FAILED!");
        end

        #100;

        //======================================================================
        // TEST 3: TIMING VERIFICATION
        //======================================================================
        $display("\n[TEST 3] Timing Verification");
        $display("----------------------------------------");
        
        // Set inputs
        plaintext_i = test_plaintext;
        key_i = test_key;
        mode_i = 0;  // Encryption mode
        
        // Measure latency
        @(posedge clk);
        start_time = $time;
        start_i = 1;
        @(posedge clk);
        start_i = 0;

        // Wait for completion
        wait(valid_o == 1);
        end_time = $time;
        
        latency = (end_time - start_time) / 10;  // Convert to clock cycles
        
        $display("Latency: %0d clock cycles", latency);
        $display("Expected: ~18-20 clock cycles (including key expansion)");
        
        if (latency >= 18 && latency <= 25) begin
            $display("✓ TIMING TEST PASSED!");
            test_pass = test_pass + 1;
        end else begin
            $display("✗ TIMING TEST FAILED!");
        end

        //======================================================================
        // FINAL REPORT
        //======================================================================
        #100;
        $display("\n========================================");
        $display("TEST SUMMARY");
        $display("========================================");
        $display("Tests Passed: %0d/3", test_pass);
        
        if (test_pass == 3) begin
            $display("✓ ALL TESTS PASSED!");
        end else begin
            $display("✗ SOME TESTS FAILED!");
        end
        $display("========================================\n");

        #100;
        $finish;
    end

    //==========================================================================
    // WAVEFORM DUMP (for debugging)
    //==========================================================================
    initial begin
        $dumpfile("aes256_core_tb.vcd");
        $dumpvars(0, tb_aes256_core);
    end

    //==========================================================================
    // TIMEOUT WATCHDOG
    //==========================================================================
    initial begin
        #100000;  // 100us timeout
        $display("\n✗ SIMULATION TIMEOUT!");
        $finish;
    end

endmodule
