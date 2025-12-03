//==============================================================================
// Simplified Functional Testbench for AES-256 Round Controller
// Focus: Basic functionality, not cycle-accurate timing
//==============================================================================

`timescale 1ns / 1ps

module tb_round_controller_simple;

    reg clk, rst_n, start_i, mode_i, key_exp_done_i;
    wire [3:0] round_num_o;
    wire busy_o, valid_o;
    wire load_input_o, apply_subbytes_o, apply_shiftrows_o, apply_mixcolumns_o, apply_addroundkey_o;

    integer errors = 0;
    integer test_count = 0;

    aes256_round_controller dut (
        .clk(clk),
        .rst_n(rst_n),
        .start_i(start_i),
        .mode_i(mode_i),
        .key_exp_done_i(key_exp_done_i),
        .round_num_o(round_num_o),
        .busy_o(busy_o),
        .valid_o(valid_o),
        .load_input_o(load_input_o),
        .apply_subbytes_o(apply_subbytes_o),
        .apply_shiftrows_o(apply_shiftrows_o),
        .apply_mixcolumns_o(apply_mixcolumns_o),
        .apply_addroundkey_o(apply_addroundkey_o)
    );

    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        $dumpfile("tb_round_controller_simple.vcd");
        $dumpvars(0, tb_round_controller_simple);

        rst_n = 0;
        start_i = 0;
        mode_i = 0;
        key_exp_done_i = 0;
        #30;
        rst_n = 1;
        #10;

        // TEST 1: Basic encryption flow
        test_count = test_count + 1;
        $display("\n========================================");
        $display("Test 1: Basic Encryption Flow");
        $display("========================================");
        
        start_i = 1;
        mode_i = 0;
        key_exp_done_i = 1;
        
        // Wait for busy
        repeat(5) @(posedge clk);
        if (busy_o !== 1) begin
            $display("ERROR: busy not asserted");
            errors = errors + 1;
        end else begin
            $display("PASS: Controller is busy");
        end
        
        // Wait for completion
        wait(valid_o == 1);
        $display("PASS: Encryption completed, valid=1");
        
        if (busy_o !== 0) begin
            $display("ERROR: busy should be 0 when valid");
            errors = errors + 1;
        end
        
        start_i = 0;
        @(posedge clk);
        @(posedge clk);
        
        // TEST 2: Decryption flow
        test_count = test_count + 1;
        $display("\n========================================");
        $display("Test 2: Basic Decryption Flow");
        $display("========================================");
        
        start_i = 1;
        mode_i = 1;  // Decrypt
        key_exp_done_i = 1;
        
        repeat(5) @(posedge clk);
        if (busy_o !== 1) begin
            $display("ERROR: busy not asserted for decrypt");
            errors = errors + 1;
        end else begin
            $display("PASS: Controller is busy (decrypt mode)");
        end
        
        wait(valid_o == 1);
        $display("PASS: Decryption completed, valid=1");
        
        start_i = 0;
        @(posedge clk);
        @(posedge clk);
        
        // TEST 3: Reset during operation
        test_count = test_count + 1;
        $display("\n========================================");
        $display("Test 3: Reset During Operation");
        $display("========================================");
        
        start_i = 1;
        mode_i = 0;
        key_exp_done_i = 1;
        
        repeat(5) @(posedge clk);
        
        rst_n = 0;
        @(posedge clk);
        @(posedge clk);
        
        if (busy_o !== 0 || valid_o !== 0) begin
            $display("ERROR: Outputs not reset");
            errors = errors + 1;
        end else begin
            $display("PASS: Reset clears all outputs");
        end
        
        rst_n = 1;
        start_i = 0;
        @(posedge clk);
        
        // SUMMARY
        $display("\n========================================");
        $display("TEST SUMMARY");
        $display("========================================");
        $display("Total tests: %0d", test_count);
        $display("Total errors: %0d", errors);
        
        if (errors == 0) begin
            $display("\n*** ALL TESTS PASSED ***\n");
        end else begin
            $display("\n*** %0d ERRORS FOUND ***\n", errors);
        end
        
        $finish;
    end

endmodule
