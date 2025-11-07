// ============================================================================
// Testbench for Galois Field GF(2^8) Multiplication Module
// Target: Simulation with GTKWave
// Description: Kiểm tra tất cả các phép nhân GF(2^8) với test vectors
// ============================================================================

`timescale 1ns / 1ps

module tb_gf_mult;

// ============================================================================
// Signals
// ============================================================================
reg  [7:0] a;
reg  [7:0] b;
wire [7:0] product;

integer i;
integer errors;

// ============================================================================
// DUT Instantiation
// ============================================================================
gf_mult uut (
    .a(a),
    .b(b),
    .product(product)
);

// ============================================================================
// Test Vectors - FIPS-197 và test cases đã verify
// ============================================================================
initial begin
    // Khởi tạo
    errors = 0;
    a = 8'h00;
    b = 8'h00;
    
    // Dump waveforms cho GTKWave
    $dumpfile("tb_gf_mult.vcd");
    $dumpvars(0, tb_gf_mult);
    
    $display("========================================");
    $display("GF(2^8) Multiplication Testbench");
    $display("========================================");
    
    // ========================================================================
    // Test 1: Nhân với 0x00 (kết quả luôn là 0x00)
    // ========================================================================
    $display("\n[Test 1] Multiplication by 0x00");
    #10;
    a = 8'h00; b = 8'h02; #10;
    check_result(8'h00, "0x00 * 0x02");
    
    a = 8'h57; b = 8'h00; #10;
    // Note: b=0x00 không được support trong module, sẽ trả về 0x00 (default)
    if (product == 8'h00)
        $display("  PASS: 0x57 * 0x00 = 0x%02h", product);
    else begin
        $display("  FAIL: 0x57 * 0x00 = 0x%02h (expected 0x00)", product);
        errors = errors + 1;
    end
    
    // ========================================================================
    // Test 2: Nhân với 0x01 (identity - kết quả = a)
    // ========================================================================
    $display("\n[Test 2] Multiplication by 0x01 (Identity)");
    #10;
    a = 8'h00; b = 8'h01; #10; check_result(8'h00, "0x00 * 0x01");
    a = 8'h01; b = 8'h01; #10; check_result(8'h01, "0x01 * 0x01");
    a = 8'h57; b = 8'h01; #10; check_result(8'h57, "0x57 * 0x01");
    a = 8'hFF; b = 8'h01; #10; check_result(8'hFF, "0xFF * 0x01");
    
    // ========================================================================
    // Test 3: Nhân với 0x02 (xtime operation)
    // ========================================================================
    $display("\n[Test 3] Multiplication by 0x02");
    #10;
    a = 8'h00; b = 8'h02; #10; check_result(8'h00, "0x00 * 0x02");
    a = 8'h01; b = 8'h02; #10; check_result(8'h02, "0x01 * 0x02");
    a = 8'h02; b = 8'h02; #10; check_result(8'h04, "0x02 * 0x02");
    a = 8'h57; b = 8'h02; #10; check_result(8'hAE, "0x57 * 0x02");
    a = 8'h83; b = 8'h02; #10; check_result(8'h1D, "0x83 * 0x02"); // bit[7]=1, cần XOR 0x1B
    a = 8'hCA; b = 8'h02; #10; check_result(8'h8F, "0xCA * 0x02");
    a = 8'hFF; b = 8'h02; #10; check_result(8'hE5, "0xFF * 0x02");
    
    // ========================================================================
    // Test 4: Nhân với 0x03
    // ========================================================================
    $display("\n[Test 4] Multiplication by 0x03");
    #10;
    a = 8'h00; b = 8'h03; #10; check_result(8'h00, "0x00 * 0x03");
    a = 8'h01; b = 8'h03; #10; check_result(8'h03, "0x01 * 0x03");
    a = 8'h02; b = 8'h03; #10; check_result(8'h06, "0x02 * 0x03");
    a = 8'h57; b = 8'h03; #10; check_result(8'hF9, "0x57 * 0x03"); // 0xAE XOR 0x57
    a = 8'h83; b = 8'h03; #10; check_result(8'h9E, "0x83 * 0x03");
    a = 8'hCA; b = 8'h03; #10; check_result(8'h45, "0xCA * 0x03");
    a = 8'hFF; b = 8'h03; #10; check_result(8'h1A, "0xFF * 0x03");
    
    // ========================================================================
    // Test 5: Nhân với 0x09 (cho InvMixColumns)
    // ========================================================================
    $display("\n[Test 5] Multiplication by 0x09");
    #10;
    a = 8'h00; b = 8'h09; #10; check_result(8'h00, "0x00 * 0x09");
    a = 8'h01; b = 8'h09; #10; check_result(8'h09, "0x01 * 0x09");
    a = 8'h02; b = 8'h09; #10; check_result(8'h12, "0x02 * 0x09");
    a = 8'h57; b = 8'h09; #10; check_result(8'hD9, "0x57 * 0x09");
    a = 8'h83; b = 8'h09; #10; check_result(8'hF7, "0x83 * 0x09");
    a = 8'hCA; b = 8'h09; #10; check_result(8'hC0, "0xCA * 0x09");
    a = 8'hFF; b = 8'h09; #10; check_result(8'h46, "0xFF * 0x09");
    
    // ========================================================================
    // Test 6: Nhân với 0x0B (cho InvMixColumns)
    // ========================================================================
    $display("\n[Test 6] Multiplication by 0x0B");
    #10;
    a = 8'h00; b = 8'h0B; #10; check_result(8'h00, "0x00 * 0x0B");
    a = 8'h01; b = 8'h0B; #10; check_result(8'h0B, "0x01 * 0x0B");
    a = 8'h02; b = 8'h0B; #10; check_result(8'h16, "0x02 * 0x0B");
    a = 8'h57; b = 8'h0B; #10; check_result(8'h77, "0x57 * 0x0B");
    a = 8'h83; b = 8'h0B; #10; check_result(8'hEA, "0x83 * 0x0B");
    a = 8'hCA; b = 8'h0B; #10; check_result(8'h4F, "0xCA * 0x0B");
    a = 8'hFF; b = 8'h0B; #10; check_result(8'hA3, "0xFF * 0x0B");
    
    // ========================================================================
    // Test 7: Nhân với 0x0D (cho InvMixColumns)
    // ========================================================================
    $display("\n[Test 7] Multiplication by 0x0D");
    #10;
    a = 8'h00; b = 8'h0D; #10; check_result(8'h00, "0x00 * 0x0D");
    a = 8'h01; b = 8'h0D; #10; check_result(8'h0D, "0x01 * 0x0D");
    a = 8'h02; b = 8'h0D; #10; check_result(8'h1A, "0x02 * 0x0D");
    a = 8'h57; b = 8'h0D; #10; check_result(8'h9E, "0x57 * 0x0D");
    a = 8'h83; b = 8'h0D; #10; check_result(8'hCD, "0x83 * 0x0D");
    a = 8'hCA; b = 8'h0D; #10; check_result(8'hC5, "0xCA * 0x0D");
    a = 8'hFF; b = 8'h0D; #10; check_result(8'h97, "0xFF * 0x0D");
    
    // ========================================================================
    // Test 8: Nhân với 0x0E (cho InvMixColumns)
    // ========================================================================
    $display("\n[Test 8] Multiplication by 0x0E");
    #10;
    a = 8'h00; b = 8'h0E; #10; check_result(8'h00, "0x00 * 0x0E");
    a = 8'h01; b = 8'h0E; #10; check_result(8'h0E, "0x01 * 0x0E");
    a = 8'h02; b = 8'h0E; #10; check_result(8'h1C, "0x02 * 0x0E");
    a = 8'h57; b = 8'h0E; #10; check_result(8'h67, "0x57 * 0x0E");
    a = 8'h83; b = 8'h0E; #10; check_result(8'h53, "0x83 * 0x0E");
    a = 8'hCA; b = 8'h0E; #10; check_result(8'h80, "0xCA * 0x0E");
    a = 8'hFF; b = 8'h0E; #10; check_result(8'h8D, "0xFF * 0x0E");
    
    // ========================================================================
    // Test 9: FIPS-197 MixColumns Example
    // ========================================================================
    $display("\n[Test 9] FIPS-197 MixColumns Example");
    $display("Input column: [D4, BF, 5D, 30]");
    #10;
    
    // First byte of result: 0x04
    // 0x02*D4 XOR 0x03*BF XOR 0x01*5D XOR 0x01*30
    a = 8'hD4; b = 8'h02; #10;
    $display("  0x02 * 0xD4 = 0x%02h", product);
    a = 8'hBF; b = 8'h03; #10;
    $display("  0x03 * 0xBF = 0x%02h", product);
    $display("  Result: 0xB3 XOR 0x7C XOR 0x5D XOR 0x30 = 0x04");
    
    // ========================================================================
    // Test 10: Kiểm tra các edge cases
    // ========================================================================
    $display("\n[Test 10] Edge Cases");
    #10;
    
    // Nhân hai số lớn
    a = 8'hFF; b = 8'h0D; #10;
    check_result(8'h97, "0xFF * 0x0D");
    
    a = 8'hFF; b = 8'h0E; #10;
    check_result(8'h8D, "0xFF * 0x0E");
    
    // Giá trị b không hợp lệ (không được support)
    a = 8'h57; b = 8'h07; #10;
    if (product == 8'h00)
        $display("  PASS: 0x57 * 0x07 = 0x00 (unsupported, returns default)");
    else begin
        $display("  FAIL: Unsupported b value should return 0x00, got 0x%02h", product);
        errors = errors + 1;
    end
    
    // ========================================================================
    // Final Summary
    // ========================================================================
    #10;
    $display("\n========================================");
    $display("Test Summary:");
    $display("========================================");
    if (errors == 0) begin
        $display("ALL TESTS PASSED!");
        $display("GF(2^8) multiplication module is CORRECT!");
    end else begin
        $display("TESTS FAILED: %0d errors found", errors);
        $display("GF(2^8) multiplication module has BUGS!");
    end
    $display("========================================\n");
    
    // Kết thúc simulation
    #100;
    $finish;
end

// ============================================================================
// Task để kiểm tra kết quả
// ============================================================================
task check_result;
    input [7:0] expected;
    input [80*8:1] test_name;
    begin
        if (product == expected) begin
            $display("  PASS: %0s = 0x%02h", test_name, product);
        end else begin
            $display("  FAIL: %0s = 0x%02h (expected 0x%02h)", test_name, product, expected);
            errors = errors + 1;
        end
    end
endtask

// ============================================================================
// Monitor - Hiển thị mọi thay đổi
// ============================================================================
initial begin
    $monitor("Time=%0t a=0x%02h b=0x%02h product=0x%02h", 
             $time, a, b, product);
end

endmodule
