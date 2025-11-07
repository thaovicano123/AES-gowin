// ============================================================================
// Galois Field GF(2^8) Multiplication Module
// Target: Tang Mega 60K (GOWIN GW5AT-LV60PG484AC1)
// Description: Nhân trong trường Galois GF(2^8) cho MixColumns
// Polynomial: 0x11B (x^8 + x^4 + x^3 + x + 1)
// ============================================================================

module gf_mult (
    input  wire [7:0] a,      // Toán hạng thứ nhất
    input  wire [7:0] b,      // Toán hạng thứ hai (thường là hằng số 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e)
    output wire [7:0] product // Kết quả nhân trong GF(2^8)
);

// ============================================================================
// Nhân với 0x02 (x) trong GF(2^8)
// ============================================================================
function [7:0] gf_mult_by_02;
    input [7:0] in;
    begin
        // Nếu bit cao = 1, shift left và XOR với 0x1b
        // Nếu bit cao = 0, chỉ shift left
        gf_mult_by_02 = (in[7] == 1'b1) ? ((in << 1) ^ 8'h1b) : (in << 1);
    end
endfunction

// ============================================================================
// Nhân với 0x03 (x + 1) trong GF(2^8)
// ============================================================================
function [7:0] gf_mult_by_03;
    input [7:0] in;
    begin
        // 0x03 * in = (0x02 * in) XOR in
        gf_mult_by_03 = gf_mult_by_02(in) ^ in;
    end
endfunction

// ============================================================================
// Nhân với 0x09 (x^3 + 1) trong GF(2^8)
// ============================================================================
function [7:0] gf_mult_by_09;
    input [7:0] in;
    reg [7:0] temp;
    begin
        temp = gf_mult_by_02(in);           // x
        temp = gf_mult_by_02(temp);         // x^2
        temp = gf_mult_by_02(temp);         // x^3
        gf_mult_by_09 = temp ^ in;          // x^3 + 1
    end
endfunction

// ============================================================================
// Nhân với 0x0b (x^3 + x + 1) trong GF(2^8)
// ============================================================================
function [7:0] gf_mult_by_0b;
    input [7:0] in;
    reg [7:0] temp;
    begin
        temp = gf_mult_by_02(in);           // x
        temp = gf_mult_by_02(temp) ^ in;    // x^2 + 1
        temp = gf_mult_by_02(temp) ^ in;    // x^3 + x + 1
        gf_mult_by_0b = temp;
    end
endfunction

// ============================================================================
// Nhân với 0x0d (x^3 + x^2 + 1) trong GF(2^8)
// ============================================================================
function [7:0] gf_mult_by_0d;
    input [7:0] in;
    reg [7:0] x2, x4, x8;
    begin
        x2 = gf_mult_by_02(in);             // x^2
        x4 = gf_mult_by_02(x2);             // x^4
        x8 = gf_mult_by_02(x4);             // x^8
        gf_mult_by_0d = x8 ^ x4 ^ in;       // x^8 XOR x^4 XOR 1 = 0x0D
    end
endfunction

// ============================================================================
// Nhân với 0x0e (x^3 + x^2 + x) trong GF(2^8)
// ============================================================================
function [7:0] gf_mult_by_0e;
    input [7:0] in;
    reg [7:0] x2, x4, x8;
    begin
        x2 = gf_mult_by_02(in);             // x^2
        x4 = gf_mult_by_02(x2);             // x^4
        x8 = gf_mult_by_02(x4);             // x^8
        gf_mult_by_0e = x8 ^ x4 ^ x2;       // x^8 XOR x^4 XOR x^2 = 0x0E
    end
endfunction

// ============================================================================
// Multiplexer - Chọn phép nhân dựa trên giá trị b
// ============================================================================
assign product = (b == 8'h01) ? a :
                 (b == 8'h02) ? gf_mult_by_02(a) :
                 (b == 8'h03) ? gf_mult_by_03(a) :
                 (b == 8'h09) ? gf_mult_by_09(a) :
                 (b == 8'h0b) ? gf_mult_by_0b(a) :
                 (b == 8'h0d) ? gf_mult_by_0d(a) :
                 (b == 8'h0e) ? gf_mult_by_0e(a) :
                 8'h00; // Default

endmodule
